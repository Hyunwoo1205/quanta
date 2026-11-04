"""Exercise the actual durable queue and a separate numerical process."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

import pytest

from quanta.job_store import ServiceError, TERMINAL
from quanta.service import ExecutionService
from quanta.worker import JobWorker, execute_job


ROOT = Path(__file__).resolve().parents[1]


def submitted(service, *, key="integration"):
    authored = json.loads((ROOT / "examples" / "pair_energy_forces.json").read_text())
    _, experiment = service.request("alice", "POST", "/v1/experiments", {"title": "Numerical process integration"})
    _, revision = service.request("alice", "POST", f"/v1/experiments/{experiment['experiment_id']}/revisions", {
        "schema_version": "0.2.0", "title": "Numerical process integration", "definition": authored["definition"],
    })
    _, run = service.request("alice", "POST", "/v1/runs", {"revision_id": revision["revision_id"]},
                             idempotency_key=key)
    return run


def terminal(service, run_id, *, timeout=30):
    deadline = time.monotonic() + timeout
    progress = []
    while time.monotonic() < deadline:
        _, run = service.request("alice", "GET", f"/v1/runs/{run_id}")
        progress.append(run["progress"]["completed_steps"])
        assert progress == sorted(progress)
        if run["execution_status"] in TERMINAL:
            return run
        time.sleep(0.05)
    pytest.fail("The numerical child did not reach a durable terminal state within 30 seconds")


def test_api_worker_result_artifacts_durable_reopen_and_replay(tmp_path):
    directory = tmp_path / "service"
    service = ExecutionService(directory)
    original = submitted(service)
    assert original["execution_status"] == "QUEUED"
    with JobWorker(directory) as worker:
        complete = terminal(service, original["run_id"])
        assert worker.error is None
        assert complete["execution_status"] == "SUCCEEDED", complete["diagnostics"]
        assert complete["progress"] == {"completed_steps": 1, "total_steps": 1,
                                         "active_step": None, "active_branch": None}
        status, result = service.request("alice", "GET", f"/v1/runs/{original['run_id']}/result")
        assert status == 200
        assert result["run_id"] == original["run_id"]
        assert result["execution_status"] == "SUCCEEDED"
        assert result["physical_validation_status"] == "unvalidated"
        assert result["steps"][0]["payload"]["energy_j"] == pytest.approx(4e-21, rel=1e-12)
        status, manifest = service.request("alice", "GET", f"/v1/runs/{original['run_id']}/artifacts")
        assert status == 200 and manifest["artifacts"]
        artifact = manifest["artifacts"][-1]
        status, raw = service.request("alice", "GET", f"/v1/artifacts/{artifact['artifact_id']}")
        assert status == 200
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]
        assert len(raw) == artifact["size_bytes"]
        with pytest.raises(ServiceError) as caught:
            service.request("bob", "GET", f"/v1/artifacts/{artifact['artifact_id']}")
        assert caught.value.status == 404
        status, replay = service.request("alice", "POST", f"/v1/runs/{original['run_id']}/replay",
                                         idempotency_key="replay-integration")
        assert status == 202 and replay["run_id"] != original["run_id"]
        assert replay["replay_of"] == original["run_id"]
        again = terminal(service, replay["run_id"])
        assert again["execution_status"] == "SUCCEEDED", again["diagnostics"]
        assert again["input_sha256"] == complete["input_sha256"]
        assert again["resolved_input_sha256"] == complete["resolved_input_sha256"]
        status, duplicate = service.request("alice", "POST", f"/v1/runs/{original['run_id']}/replay",
                                            idempotency_key="replay-integration")
        assert status == 202 and duplicate["run_id"] == replay["run_id"]
    reopened = ExecutionService(directory)
    assert reopened.request("alice", "GET", f"/v1/runs/{original['run_id']}/result")[1] == result
    assert reopened.request("alice", "GET", f"/v1/artifacts/{artifact['artifact_id']}")[1] == raw


def test_queued_cancellation_never_runs_in_numerical_worker(tmp_path):
    service = ExecutionService(tmp_path / "service")
    run = submitted(service)
    _, cancelled = service.request("alice", "POST", f"/v1/runs/{run['run_id']}/cancel")
    assert cancelled["execution_status"] == "CANCELLED"
    with JobWorker(service.directory):
        observed = terminal(service, run["run_id"])
    assert observed["execution_status"] == "CANCELLED"
    assert [event["execution_status"] for event in observed["events"]] == ["QUEUED", "CANCELLED"]
    assert observed["artifacts"] == []
    assert observed["progress"]["completed_steps"] == 0


def test_second_supervisor_cannot_recover_or_claim_first_workers_jobs(tmp_path):
    service = ExecutionService(tmp_path / "service")
    with JobWorker(service.directory):
        second = JobWorker(service.directory)
        with pytest.raises(ServiceError) as caught:
            second.start()
        assert caught.value.status == 409
        assert caught.value.code == "WORKER_ACTIVE"
    # Releasing the first supervisor transfers exclusive ownership cleanly.
    with JobWorker(service.directory) as replacement:
        assert replacement.error is None


def test_worker_refuses_accepted_plan_when_frozen_implementation_differs(tmp_path):
    service = ExecutionService(tmp_path / "service")
    run = submitted(service)
    # Emulate a stored frozen implementation that is unavailable in this install.
    job = service.store.get_job(run["run_id"])
    plan = deepcopy(job["plan"])
    plan["execution_manifests"]["implementation_manifest_sha256"] = "0" * 64
    import sqlite3
    with sqlite3.connect(service.store.path) as db:
        db.execute("UPDATE runs SET plan=? WHERE run_id=?", (json.dumps(plan), run["run_id"]))
    service.store.claim_next()
    execute_job(service.directory, run["run_id"])
    refused = service.store.get_run("alice", run["run_id"])
    assert refused["execution_status"] == "FAILED"
    assert refused["diagnostics"][0]["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE"
    assert refused["artifacts"] == []
    assert refused["progress"]["completed_steps"] == 0


@pytest.mark.parametrize("source_kind", ["queued_cancelled", "interrupted"])
def test_terminal_source_without_computation_can_replay_its_frozen_input(tmp_path, source_kind):
    service = ExecutionService(tmp_path / "service")
    run = submitted(service)
    if source_kind == "queued_cancelled":
        service.request("alice", "POST", f"/v1/runs/{run['run_id']}/cancel")
    else:
        service.store.claim_next()
        # A replacement owns the exclusive lock before recovering stale RUNNING.
        with JobWorker(service.directory):
            pass
    source = terminal(service, run["run_id"])
    assert source["execution_status"] == ("CANCELLED" if source_kind == "queued_cancelled" else "FAILED")
    assert source["artifacts"] == []
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "GET", f"/v1/runs/{run['run_id']}/result")
    assert caught.value.status == 409
    status, replay = service.request("alice", "POST", f"/v1/runs/{run['run_id']}/replay",
                                     idempotency_key="replay-without-computation")
    assert status == 202
    assert replay["execution_status"] == "QUEUED"
    assert replay["run_id"] != source["run_id"]
    assert replay["replay_of"] == source["run_id"]
    assert replay["input_sha256"] == source["input_sha256"]
    assert replay["resolved_input_sha256"] == source["resolved_input_sha256"]


def test_active_source_cannot_be_replayed(tmp_path):
    service = ExecutionService(tmp_path / "service")
    run = submitted(service)
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "POST", f"/v1/runs/{run['run_id']}/replay", idempotency_key="too-soon")
    assert caught.value.status == 409
    assert caught.value.code == "REPLAY_UNAVAILABLE"


def test_supervisor_enforces_hard_process_wall_limit_and_keeps_replayable_input(tmp_path, monkeypatch):
    service = ExecutionService(tmp_path / "service")
    run = submitted(service)
    # Only the supervisor receives this deliberately tiny policy. The separate
    # Python child imports the installed, unchanged registry and numerical code.
    import quanta.registry
    original_registry = quanta.registry.ContractRegistry
    policy = deepcopy(original_registry().resource_policy)
    policy["common_execution"]["wall_seconds_per_run"] = 0.05

    class SupervisorPolicy:
        resource_policy = policy

    with monkeypatch.context() as local:
        local.setattr(quanta.registry, "ContractRegistry", SupervisorPolicy)
        with JobWorker(service.directory, poll_seconds=0.01) as worker:
            stopped = terminal(service, run["run_id"])
            assert worker.error is None
    assert stopped["execution_status"] == "FAILED"
    assert stopped["diagnostics"][0]["code"] == "RESOURCE_LIMIT"
    assert stopped["artifacts"] == []
    assert service.store.get_report("alice", run["run_id"]) is None
    # No orphan process keeps ownership after the supervisor has reaped it.
    with JobWorker(service.directory):
        pass
    status, replay = service.request("alice", "POST", f"/v1/runs/{run['run_id']}/replay",
                                     idempotency_key="replay-after-hard-stop")
    assert status == 202 and replay["execution_status"] == "QUEUED"
    assert replay["resolved_input_sha256"] == stopped["resolved_input_sha256"]
