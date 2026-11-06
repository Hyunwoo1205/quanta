"""Dynamics through real SQLite, authenticated HTTP and a numerical child.

The fixtures are synthetic classical systems. These tests exercise backend
integration and numerical evidence, not public TLS, real mail or a 3D viewer.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import threading
import time

import pytest

from quanta.hashing import canonical_bytes
from quanta.job_store import ServiceError, TERMINAL
from quanta.service import ExecutionService
from quanta.server import create_server
from quanta.worker import JobWorker, _cancelled_report, _execution_policy, execute_job

ROOT = Path(__file__).resolve().parents[1]
OWNER = "account-" + "a" * 32
FOREIGN = "account-" + "b" * 32
TOKEN = "synthetic-dynamics-http-token-0123456789abcdef"


def body(name="free", *, definition=None):
    if definition is None:
        request = json.loads((ROOT / f"contracts/v0.3.1/examples/{name}.request.json").read_text())
        definition = {"unit_system": "SI", **{k: request[k] for k in ("scales", "system", "numerics")},
            "observables": ["trajectory", "energy_components", "conservation_diagnostics"],
            "protocol": {"steps": [{"step_id": "integrate", "operation": "integrate",
                                     "source": "initial", "overrides": []}], "sweep": {"axes": []}},
            "extensions": {}}
    return {"schema_version": "0.4.0", "title": "Synthetic dynamics backend", "definition": definition}


def save(service, value=None, *, owner=OWNER):
    value = deepcopy(value or body())
    status, exp = service.request(owner, "POST", "/v1/experiments", {"title": value["title"]})
    assert status == 201
    status, rev = service.request(owner, "POST", f"/v1/experiments/{exp['experiment_id']}/revisions", value)
    assert status == 201 and rev["schema_version"] == "0.4.0"
    return exp, rev


def submit(service, revision, *, key="dynamics", owner=OWNER):
    status, run = service.request(owner, "POST", "/v1/runs", {"revision_id": revision["revision_id"]},
                                  idempotency_key=key)
    assert status == 202
    return run


def slow_free():
    """Legal pair-work load with a long actual integration cancellation window."""
    value = body()
    template = value["definition"]["system"]["particles"][0]
    value["definition"]["system"]["particles"] = [
        {**deepcopy(template), "id": f"p{i}", "position_m": [float(i), 0, 0],
         "velocity_m_per_s": [0, 0, 0], "mass_kg": 1} for i in range(64)]
    value["definition"]["numerics"].update(dt_s=1e-6, steps=200, sample_stride=20)
    return value


def wait_for(service, run_id, predicate=lambda r: r["execution_status"] in TERMINAL, *, owner=OWNER, timeout=40):
    expires = time.monotonic() + timeout
    previous = 0
    while time.monotonic() < expires:
        run = service.request(owner, "GET", f"/v1/runs/{run_id}")[1]
        assert run["progress"]["completed_steps"] >= previous
        previous = run["progress"]["completed_steps"]
        if predicate(run):
            return run
        time.sleep(0.02)
    pytest.fail("Dynamics backend did not reach its expected state within the fixed test deadline")


def check_artifacts(service, run_id, *, owner=OWNER):
    status, manifest = service.request(owner, "GET", f"/v1/runs/{run_id}/artifacts")
    assert status == 200 and manifest["artifacts"]
    documents = []
    for meta in manifest["artifacts"]:
        status, raw = service.request(owner, "GET", f"/v1/artifacts/{meta['artifact_id']}")
        assert status == 200 and isinstance(raw, bytes)
        assert len(raw) == meta["size_bytes"] and hashlib.sha256(raw).hexdigest() == meta["sha256"]
        with pytest.raises(ServiceError) as hidden:
            service.request(FOREIGN, "GET", f"/v1/artifacts/{meta['artifact_id']}")
        assert hidden.value.status == 404
        if meta["mime_type"].split(";", 1)[0] == "application/json":
            documents.append(json.loads(raw))
    return documents


def test_capabilities_preserve_default_and_scope_new_contract(tmp_path):
    caps = ExecutionService(tmp_path / "service").capabilities()
    assert caps["contract_version"] == "0.2.0"
    assert "quanta.pair_dynamics@0.1.0" not in caps["implemented_operations"]
    assert caps["supported_experiment_versions"] == ["0.2.0", "0.4.0"]
    dynamic = caps["experiment_contracts"]["0.4.0"]
    assert dynamic["implemented_operations"] == {"quanta.pair_dynamics@0.1.0": ["integrate"]}
    assert dynamic["protocol"] == {"max_steps": 1, "allowed_sources": ["initial"], "sweep": False,
        "overrides": False, "continuation": False, "static_to_dynamics_conversion": False}
    assert caps["execution"]["checkpoint_resume"] is False


def test_real_child_success_durable_reopen_and_new_input_replay(tmp_path):
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service)
    saved = deepcopy(rev)
    rev["definition"]["system"]["particles"][0]["mass_kg"] = 900
    assert service.request(OWNER, "GET", f"/v1/revisions/{rev['revision_id']}")[1] == saved
    run = submit(service, saved)
    assert submit(service, saved)["run_id"] == run["run_id"]
    with JobWorker(service.directory) as worker:
        done = wait_for(service, run["run_id"])
        assert done["execution_status"] == "SUCCEEDED", done["diagnostics"]
        assert done["progress"]["completed_steps"] == done["progress"]["total_steps"] == 1
        assert done["numerical_status"] == "pass" and done["resolution_status"] == "not_checked"
        assert done["physical_validation_status"] == "unvalidated"
        report = service.store.get_report(OWNER, run["run_id"])
        step = report["result"]["steps"][0]
        assert step["outcome"] == "SUCCEEDED" and step["state_ref"] is not None
        final = next(s for s in report["result"]["states"] if s["state_id"] == step["state_ref"])
        assert final["time_kind"] == "evolving"
        assert final["physical_time"] == {"value": 1, "unit": "s"}
        assert final["data"]["time_s"] == 1
        docs = check_artifacts(service, run["run_id"])
        assert any(d.get("scope") == "standalone_dynamics_integration" and d["execution_status"] == "SUCCEEDED" for d in docs)
        _, replay = service.request(OWNER, "POST", f"/v1/runs/{run['run_id']}/replay", {},
                                     idempotency_key="dynamics-replay")
        assert replay["run_id"] != run["run_id"] and replay["replay_of"] == run["run_id"]
        again = wait_for(service, replay["run_id"])
        assert again["execution_status"] == "SUCCEEDED", again["diagnostics"]
        assert again["input_sha256"] == done["input_sha256"]
        assert again["resolved_input_sha256"] == done["resolved_input_sha256"]
        repeated = service.store.get_report(OWNER, replay["run_id"])
        assert repeated["result"]["steps"][0]["payload"] == step["payload"]
        assert worker.error is None
    reopened = ExecutionService(service.directory)
    assert reopened.store.get_report(OWNER, run["run_id"]) == report
    for path in (f"/v1/revisions/{saved['revision_id']}", f"/v1/runs/{run['run_id']}",
                 f"/v1/runs/{run['run_id']}/result", f"/v1/runs/{run['run_id']}/artifacts"):
        with pytest.raises(ServiceError) as hidden:
            reopened.request(FOREIGN, "GET", path)
        assert hidden.value.status == 404


def test_failed_drift_publishes_only_accepted_partial_without_final_state(tmp_path):
    value = body()
    particles = value["definition"]["system"]["particles"]
    for p, x, vx in zip(particles, (-1, 1), (2, -2)):
        p["position_m"] = [x, 0, 0]
        p["velocity_m_per_s"] = [vx, 0, 0]
    value["definition"]["numerics"].update(dt_s=1, steps=2, sample_stride=1)
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service, value)
    run = submit(service, rev)
    with JobWorker(service.directory):
        done = wait_for(service, run["run_id"])
    assert done["execution_status"] == "FAILED" and done["partial"]
    report = service.store.get_report(OWNER, run["run_id"])
    step = report["result"]["steps"][0]
    assert step["outcome"] == "FAILED" and step["state_ref"] is None
    assert step["payload"]["legs"][0]["completed_steps"] == 0
    assert len(step["payload"]["legs"][0]["sampled_frames"]) == 1
    assert all(s["producer"]["kind"] != "step" for s in report["result"]["states"])
    assert any(d.get("scope") == "standalone_dynamics_integration" and d["final_state"] is None
               for d in check_artifacts(service, run["run_id"]))


@pytest.mark.parametrize("source_kind", ["queued_cancelled", "interrupted"])
def test_uncomputed_terminal_source_keeps_input_for_fresh_replay(tmp_path, source_kind):
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service)
    run = submit(service, rev)
    if source_kind == "queued_cancelled":
        service.request(OWNER, "POST", f"/v1/runs/{run['run_id']}/cancel")
    else:
        service.store.claim_next()
    with JobWorker(service.directory):
        done = wait_for(service, run["run_id"])
        assert done["execution_status"] == ("CANCELLED" if source_kind == "queued_cancelled" else "FAILED")
        assert done["artifacts"] == [] and done["progress"]["completed_steps"] == 0
        assert service.store.get_report(OWNER, run["run_id"]) is None
        _, replay = service.request(OWNER, "POST", f"/v1/runs/{run['run_id']}/replay", {},
                                    idempotency_key="fresh-after-stop")
        assert replay["run_id"] != run["run_id"]
        assert wait_for(service, replay["run_id"])["execution_status"] == "SUCCEEDED"


def test_actual_running_cancel_has_no_promoted_state(tmp_path):
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service, slow_free())
    run = submit(service, rev)
    with JobWorker(service.directory, poll_seconds=0.01) as worker:
        active = wait_for(service, run["run_id"], lambda r: r["progress"]["active_step"] == "integrate"
                          or r["execution_status"] in TERMINAL)
        assert active["execution_status"] == "RUNNING"
        service.request(OWNER, "POST", f"/v1/runs/{run['run_id']}/cancel")
        done = wait_for(service, run["run_id"])
        assert done["execution_status"] == "CANCELLED" and worker.error is None
    report = service.store.get_report(OWNER, run["run_id"])
    if report is not None:
        step = report["result"]["steps"][0]
        assert step["outcome"] == "CANCELLED" and step["state_ref"] is None and step["payload"] is None
    else:
        assert done["artifacts"] == []


def test_actual_hard_stop_retains_no_fabricated_result_and_worker_recovers(tmp_path, monkeypatch):
    import quanta.worker as worker_module
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service, slow_free())
    run = submit(service, rev)
    real = worker_module._execution_policy
    with monkeypatch.context() as local:
        local.setattr(worker_module, "_execution_policy", lambda job: {**real(job), "wall_seconds_per_run": 6})
        with JobWorker(service.directory, poll_seconds=0.005):
            active = wait_for(service, run["run_id"], lambda r: r["progress"]["active_step"] == "integrate"
                              or r["execution_status"] in TERMINAL)
            assert active["execution_status"] == "RUNNING"
            done = wait_for(service, run["run_id"])
    assert done["execution_status"] == "FAILED"
    assert done["diagnostics"][0]["code"] == "RESOURCE_LIMIT"
    assert done["artifacts"] == [] and service.store.get_report(OWNER, run["run_id"]) is None
    # Replay is a new invocation from the preserved immutable input; cancel that
    # new invocation so the heavy fixture need not finish all requested work.
    with JobWorker(service.directory):
        _, replay = service.request(OWNER, "POST", f"/v1/runs/{run['run_id']}/replay", {},
                                     idempotency_key="after-hard-stop")
        assert replay["run_id"] != run["run_id"] and replay["input_sha256"] == done["input_sha256"]
        service.request(OWNER, "POST", f"/v1/runs/{replay['run_id']}/cancel")
        assert wait_for(service, replay["run_id"])["execution_status"] == "CANCELLED"
        _, small = save(service)
        fresh = submit(service, small, key="new-small-after-hard-stop")
        assert wait_for(service, fresh["run_id"])["execution_status"] == "SUCCEEDED"


def test_cancel_before_publication_keeps_only_completed_step_evidence(tmp_path):
    from quanta.workflow import run_experiment
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service)
    run = submit(service, rev)
    service.store.claim_next()
    report = run_experiment(rev, run_id=run["run_id"])
    assert report["result"]["execution_status"] == "SUCCEEDED"
    service.store.cancel(OWNER, run["run_id"])
    refused = service.store.finish(run["run_id"], report)
    assert refused["execution_status"] == "CANCEL_REQUESTED" and refused["artifacts"] == []
    done = service.store.finish(run["run_id"], _cancelled_report(report))
    assert done["execution_status"] == "CANCELLED"
    stored = service.store.get_report(OWNER, run["run_id"])
    assert stored["result"]["steps"][0]["outcome"] == "SUCCEEDED"
    assert stored["result"]["steps"][0]["payload"] == report["result"]["steps"][0]["payload"]


def test_public_dynamics_admission_preserves_owner_slot_and_artifact_reservation(tmp_path, monkeypatch):
    import quanta.job_store as store_module
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service)
    run = submit(service, rev)
    assert submit(service, rev)["run_id"] == run["run_id"]
    with pytest.raises(ServiceError) as quota:
        submit(service, rev, key="second-active")
    assert quota.value.status == 429 and quota.value.details["resource"] == "active_runs"
    with pytest.raises(ServiceError) as hidden:
        submit(service, rev, owner=FOREIGN)
    assert hidden.value.status == 404
    service.store.cancel(OWNER, run["run_id"])
    monkeypatch.setattr(store_module, "ACCOUNT_ARTIFACT_BYTES", store_module.RUN_ARTIFACT_RESERVATION_BYTES - 1)
    with pytest.raises(ServiceError) as quota:
        submit(service, rev, key="reservation-too-large")
    assert quota.value.status == 429 and quota.value.details["resource"] == "artifact_bytes"


def test_changed_accepted_implementation_is_refused_before_calculation(tmp_path):
    service = ExecutionService(tmp_path / "service")
    _, rev = save(service)
    run = submit(service, rev)
    plan = service.store.get_job(run["run_id"])["plan"]
    plan["execution_manifests"]["implementation_manifest_sha256"] = "0" * 64
    with sqlite3.connect(service.store.path) as db:
        db.execute("UPDATE runs SET plan=? WHERE run_id=?", (json.dumps(plan), run["run_id"]))
    service.store.claim_next()
    execute_job(service.directory, run["run_id"])
    refused = service.store.get_run(OWNER, run["run_id"])
    assert refused["execution_status"] == "FAILED"
    assert refused["diagnostics"][0]["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE"
    assert refused["artifacts"] == []


def test_bad_frozen_child_policy_does_not_poison_the_next_owners_queue(tmp_path):
    service = ExecutionService(tmp_path / "service")
    _, first = save(service)
    bad = submit(service, first)
    plan = service.store.get_job(bad["run_id"])["plan"]
    ref = plan["execution_manifests"]["effective_resource_profile_sha256"]
    plan["captured_artifacts"][ref] += " "
    with sqlite3.connect(service.store.path) as db:
        db.execute("UPDATE runs SET plan=? WHERE run_id=?", (json.dumps(plan), bad["run_id"]))
    _, second = save(service, owner=FOREIGN)
    good = submit(service, second, owner=FOREIGN)
    with JobWorker(service.directory) as worker:
        refused = wait_for(service, bad["run_id"])
        assert refused["execution_status"] == "FAILED"
        assert refused["diagnostics"][0]["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE"
        assert refused["artifacts"] == [] and service.store.get_report(OWNER, bad["run_id"]) is None
        assert wait_for(service, good["run_id"], owner=FOREIGN)["execution_status"] == "SUCCEEDED"
        assert worker.error is None


def policy_job(common):
    raw = canonical_bytes({"common_execution": common})
    ref = hashlib.sha256(raw).hexdigest()
    return {"revision": {"schema_version": "0.4.0"}, "plan": {
        "execution_manifests": {"effective_resource_profile_sha256": ref},
        "captured_artifacts": {ref: raw.decode()}}}


def test_child_resource_policy_cannot_widen_captured_admission(monkeypatch):
    import quanta.registry as registry_module
    class Selected:
        resource_policy = {"common_execution": {"wall_seconds_per_run": 200, "memory_mib_per_run": 2048}}
        def validate_integrity(self):
            return []
    selected = []
    monkeypatch.setattr(registry_module, "experiment_registry", lambda revision: selected.append(revision["schema_version"]) or Selected())
    policy = _execution_policy(policy_job({"wall_seconds_per_run": 0.5, "memory_mib_per_run": 128}))
    assert selected == ["0.4.0"]
    assert policy["wall_seconds_per_run"] == 0.5 and policy["memory_mib_per_run"] == 128


def test_changed_policy_content_is_refused_by_admitted_digest(monkeypatch):
    import quanta.registry as registry_module
    class Selected:
        resource_policy = {"common_execution": {"wall_seconds_per_run": 120, "memory_mib_per_run": 1024}}
        def validate_integrity(self):
            return []
    monkeypatch.setattr(registry_module, "experiment_registry", lambda revision: Selected())
    job = policy_job(Selected.resource_policy["common_execution"])
    ref = next(iter(job["plan"]["captured_artifacts"]))
    job["plan"]["captured_artifacts"][ref] += " "
    with pytest.raises(ServiceError) as refused:
        _execution_policy(job)
    assert refused.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"


@pytest.mark.parametrize("bad", [True, 0, float("inf"), 10**1000],
                         ids=["boolean", "zero", "nonfinite", "integer_overflow"])
def test_invalid_selected_child_limit_is_a_structured_job_refusal(monkeypatch, bad):
    import quanta.registry as registry_module
    class Selected:
        resource_policy = {"common_execution": {"wall_seconds_per_run": bad, "memory_mib_per_run": 1024}}
        def validate_integrity(self):
            return []
    monkeypatch.setattr(registry_module, "experiment_registry", lambda revision: Selected())
    with pytest.raises(ServiceError) as refused:
        _execution_policy(policy_job({"wall_seconds_per_run": 120, "memory_mib_per_run": 1024}))
    assert refused.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"


def test_loopback_authenticated_http_save_run_download_and_replay(tmp_path):
    service = ExecutionService(tmp_path / "http-service")
    server = create_server(service, token=TOKEN, owner=OWNER, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, value=None, *, key=None, authenticated=True):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + TOKEN
        if key:
            headers["Idempotency-Key"] = key
        connection = http.client.HTTPConnection(*server.server_address, timeout=15)
        try:
            connection.request(method, path, body=None if value is None else json.dumps(value), headers=headers)
            response = connection.getresponse()
            raw = response.read(8 * 1024**2 + 1)
            assert len(raw) <= 8 * 1024**2
            return response.status, raw
        finally:
            connection.close()

    def document(*args, **kwargs):
        status, raw = request(*args, **kwargs)
        return status, json.loads(raw)

    def terminal(run_id):
        expires = time.monotonic() + 40
        while time.monotonic() < expires:
            status, run = document("GET", f"/v1/runs/{run_id}")
            assert status == 200
            if run["execution_status"] in TERMINAL:
                return run
            time.sleep(0.02)
        pytest.fail("HTTP dynamics child did not reach a terminal state")

    try:
        assert request("GET", "/v1/capabilities", authenticated=False)[0] == 401
        value = body("harmonic-refinement")
        assert document("POST", "/v1/validate", {k: value[k] for k in ("schema_version", "definition")})[1]["valid"]
        status, exp = document("POST", "/v1/experiments", {"title": value["title"]})
        assert status == 201
        status, rev = document("POST", f"/v1/experiments/{exp['experiment_id']}/revisions", value)
        assert status == 201
        with JobWorker(service.directory) as worker:
            status, run = document("POST", "/v1/runs", {"revision_id": rev["revision_id"]}, key="http-dynamics")
            assert status == 202
            done = terminal(run["run_id"])
            assert done["execution_status"] == "SUCCEEDED", done["diagnostics"]
            assert done["numerical_status"] == done["resolution_status"] == "pass"
            status, result = document("GET", f"/v1/runs/{run['run_id']}/result")
            assert status == 200 and result["physical_validation_status"] == "unvalidated"
            status, manifest = document("GET", f"/v1/runs/{run['run_id']}/artifacts")
            assert status == 200 and manifest["artifacts"]
            meta = manifest["artifacts"][-1]
            status, raw = request("GET", f"/v1/artifacts/{meta['artifact_id']}")
            assert status == 200 and len(raw) == meta["size_bytes"]
            assert hashlib.sha256(raw).hexdigest() == meta["sha256"]
            status, replay = document("POST", f"/v1/runs/{run['run_id']}/replay", {}, key="http-dynamics-replay")
            assert status == 202 and replay["run_id"] != run["run_id"]
            assert terminal(replay["run_id"])["execution_status"] == "SUCCEEDED"
            assert worker.error is None
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
