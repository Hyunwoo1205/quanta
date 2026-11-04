"""Storage guarantees exercised through reopen, owners and concurrent callers."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import threading
import json
from pathlib import Path

from quanta.planning import plan_experiment
from quanta.workflow import run_experiment, WorkflowCancelled

import pytest

from quanta.job_store import JobStore, ServiceError


def setup_store(tmp_path, **kwargs):
    store = JobStore(tmp_path, **kwargs)
    experiment = store.create_experiment("alice", "Pair experiment")
    source = json.loads((Path(__file__).resolve().parents[1] / "examples" / "pair_energy_forces.json").read_text())
    source["definition"]["system"]["particles"][0]["position_m"][0] = -0.0
    revision = store.create_revision("alice", experiment["experiment_id"], {
        "schema_version": "0.2.0", "title": "One revision", "definition": source["definition"]})
    plan = plan_experiment(revision)
    return store, experiment, revision, plan


def submit(store, revision, plan, key="same-key", **kwargs):
    return store.submit("alice", revision["revision_id"], plan, idempotency_key=key, **kwargs)


def terminal_report(store, run_id, status="SUCCEEDED"):
    def cancelled():
        raise WorkflowCancelled()
    job = store.get_job(run_id)
    return run_experiment(job["revision"], run_id=run_id,
                          control_check=cancelled if status == "CANCELLED" else None)


def test_revision_and_queue_survive_reopening_and_keep_signed_zero(tmp_path):
    store, experiment, revision, plan = setup_store(tmp_path)
    first, created = submit(store, revision, plan)
    assert created
    again = JobStore(tmp_path)
    assert again.get_revision("alice", revision["revision_id"]) == revision
    assert str(again.get_revision("alice", revision["revision_id"])["definition"]["system"]["particles"][0]["position_m"][0]) == "-0.0"
    assert again.get_experiment("alice", experiment["experiment_id"])["revision_ids"] == [revision["revision_id"]]
    claim = again.claim_next()
    assert claim["run_id"] == first["run_id"]
    assert claim["plan"] == plan and claim["revision"] == revision
    assert store.claim_next() is None


def test_owners_cannot_read_or_act_on_foreign_identifiers(tmp_path):
    store, experiment, revision, plan = setup_store(tmp_path)
    run, _ = submit(store, revision, plan)
    actions = [lambda: store.get_experiment("bob", experiment["experiment_id"]),
               lambda: store.get_revision("bob", revision["revision_id"]),
               lambda: store.get_run("bob", run["run_id"]),
               lambda: store.cancel("bob", run["run_id"]),
               lambda: store.submit("bob", revision["revision_id"], plan, idempotency_key="x"),
               lambda: store.list_experiments("bob", cursor=experiment["experiment_id"])]
    for action in actions:
        with pytest.raises(ServiceError) as exc:
            action()
        assert exc.value.status == 404
    assert store.list_experiments("bob") == {"items": [], "next_cursor": None}


def test_concurrent_same_request_admits_exactly_one_run(tmp_path):
    store, _, revision, plan = setup_store(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: submit(store, revision, plan), range(16)))
    assert len({r[0]["run_id"] for r in results}) == 1
    assert sum(created for _, created in results) == 1
    run = results[0][0]
    assert store.lookup_idempotency("alice", "/v1/runs", "same-key", {"revision_id": revision["revision_id"]})["run_id"] == run["run_id"]
    with pytest.raises(ServiceError) as exc:
        store.lookup_idempotency("alice", "/v1/runs", "same-key", {"revision_id": "another"})
    assert exc.value.code == "IDEMPOTENCY_CONFLICT"


def test_idempotency_endpoint_scope_expiry_and_queue_limit(tmp_path):
    clock = [1000.0]
    store, _, revision, plan = setup_store(tmp_path, clock=lambda: clock[0], max_queued=1)
    first, _ = submit(store, revision, plan)
    assert submit(store, revision, plan)[0]["run_id"] == first["run_id"]
    with pytest.raises(ServiceError) as exc:
        submit(store, revision, plan, key="different")
    assert exc.value.status == 429
    store.cancel("alice", first["run_id"])
    replay, _ = submit(store, revision, plan, endpoint="/v1/runs/source/replay")
    assert replay["run_id"] != first["run_id"]
    clock[0] += 86400
    new, created = submit(store, revision, plan)
    assert created and new["run_id"] != first["run_id"]
    assert store.get_run("alice", replay["run_id"])["diagnostics"][0]["code"] == "QUEUE_TIMEOUT"


def test_first_committed_cancel_or_success_wins_and_terminal_is_immutable(tmp_path):
    store, _, revision, plan = setup_store(tmp_path)
    first, _ = submit(store, revision, plan)
    ident = first["run_id"]
    store.claim_next()
    report = terminal_report(store, ident)
    barrier = threading.Barrier(2)
    def finish():
        barrier.wait()
        return store.finish(ident, report)
    def cancel():
        barrier.wait()
        return store.cancel("alice", ident)[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(finish), pool.submit(cancel)]
        [future.result() for future in futures]
    result = store.get_run("alice", ident)
    assert result["execution_status"] in {"SUCCEEDED", "CANCEL_REQUESTED"}
    if result["execution_status"] == "CANCEL_REQUESTED":
        assert store.get_report("alice", ident) is None
        assert store.finish(ident, report)["execution_status"] == "CANCEL_REQUESTED"
        result = store.finish(ident, terminal_report(store, ident, "CANCELLED"))
    before = deepcopy(result)
    assert store.cancel("alice", ident) == (before, False)
    assert store.fail(ident, "ENGINE_FAILURE", "late failure") == before
    assert store.finish(ident, report) == before
    statuses = [event["execution_status"] for event in result["events"]]
    assert statuses in [["QUEUED", "RUNNING", "SUCCEEDED"], ["QUEUED", "RUNNING", "CANCEL_REQUESTED", "CANCELLED"]]


def test_atomic_artifacts_preserve_bytes_and_are_owner_scoped(tmp_path):
    store, _, revision, plan = setup_store(tmp_path)
    first, _ = submit(store, revision, plan)
    store.claim_next()
    report = terminal_report(store, first["run_id"])
    artifact_id = report["result"]["artifacts"][0]["artifact_id"]
    wrong = deepcopy(report)
    wrong["artifact_contents"][artifact_id] += "x"
    with pytest.raises(ServiceError):
        store.finish(first["run_id"], wrong)
    assert store.get_run("alice", first["run_id"])["execution_status"] == "RUNNING"
    assert store.get_artifacts("alice", first["run_id"]) == []
    store.finish(first["run_id"], report)
    again = JobStore(tmp_path)
    assert again.get_report("alice", first["run_id"]) == report
    metadata, raw = again.get_artifact("alice", artifact_id)
    assert raw == report["artifact_contents"][artifact_id].encode()
    assert metadata == report["result"]["artifacts"][0]
    with pytest.raises(ServiceError) as exc:
        again.get_artifact("bob", artifact_id)
    assert exc.value.status == 404


def test_restart_marks_only_interrupted_run_and_leaves_new_work_queued(tmp_path):
    store, _, revision, plan = setup_store(tmp_path)
    first, _ = submit(store, revision, plan)
    second, _ = submit(store, revision, plan, "second")
    store.claim_next()
    store.cancel("alice", first["run_id"])
    again = JobStore(tmp_path)
    assert again.recover_interrupted() == 1
    assert again.get_run("alice", first["run_id"])["execution_status"] == "CANCELLED"
    assert again.get_run("alice", second["run_id"])["execution_status"] == "QUEUED"
    assert again.claim_next()["run_id"] == second["run_id"]
    assert again.recover_interrupted() == 1
    assert again.get_run("alice", second["run_id"])["execution_status"] == "FAILED"


def test_queue_timeout_never_starts_old_work_and_pagination_has_no_foreign_rows(tmp_path):
    now = [1000.0]
    store, experiment, revision, plan = setup_store(tmp_path, clock=lambda: now[0])
    run, _ = submit(store, revision, plan)
    now[0] += 600
    assert store.claim_next() is None
    assert store.get_run("alice", run["run_id"])["execution_status"] == "FAILED"
    assert [e["execution_status"] for e in store.get_run("alice", run["run_id"])["events"]] == ["QUEUED", "FAILED"]
    store.create_experiment("bob", "Invisible")
    second = store.create_experiment("alice", "Second")
    page = store.list_experiments("alice", limit=1)
    assert page["items"][0]["experiment_id"] == experiment["experiment_id"]
    page2 = store.list_experiments("alice", limit=1, cursor=page["next_cursor"])
    assert [x["experiment_id"] for x in page2["items"]] == [second["experiment_id"]]
    assert page2["next_cursor"] is None


def test_progress_never_decreases_and_recovery_clears_active_fields(tmp_path):
    store, _, revision, plan = setup_store(tmp_path)
    run, _ = submit(store, revision, plan)
    ident = run["run_id"]
    store.claim_next()
    completed = {"completed_steps": 1, "total_steps": 1, "active_step": "evaluate", "active_branch": 0}
    assert store.update_progress(ident, completed)
    with pytest.raises(ServiceError):
        store.update_progress(ident, {**completed, "completed_steps": 0})
    with pytest.raises(ServiceError):
        store.update_progress(ident, {**completed, "completed_steps": True})
    store.recover_interrupted()
    final = store.get_run("alice", ident)
    assert final["progress"] == {**completed, "active_step": None, "active_branch": None}
    assert not store.update_progress(ident, completed)


def test_valid_result_for_different_revision_cannot_replace_frozen_submission(tmp_path):
    store, experiment, revision, plan = setup_store(tmp_path)
    run, _ = submit(store, revision, plan)
    store.claim_next()
    different = store.create_revision("alice", experiment["experiment_id"], {
        "schema_version": "0.2.0", "title": "Different immutable revision", "definition": revision["definition"]})
    report = run_experiment(different, run_id=run["run_id"])
    with pytest.raises(ServiceError) as exc:
        store.finish(run["run_id"], report)
    assert exc.value.code == "REVISION_CONFLICT"
    assert store.get_report("alice", run["run_id"]) is None
    assert store.get_artifacts("alice", run["run_id"]) == []


@pytest.mark.parametrize("code,category,retryable", [
    ("RESOURCE_LIMIT", "resource", False),
    ("REGISTRY_SNAPSHOT_UNAVAILABLE", "support", False),
    ("ENGINE_FAILURE", "runtime", True),
])
def test_supervisor_failures_keep_registered_error_category(tmp_path, code, category, retryable):
    store, _, revision, plan = setup_store(tmp_path)
    run, _ = submit(store, revision, plan)
    store.claim_next()
    failed = store.fail(run["run_id"], code, "Supervisor stopped execution")
    assert failed["execution_status"] == "FAILED"
    assert failed["diagnostics"][0]["category"] == category
    assert failed["diagnostics"][0]["retryable"] is retryable
