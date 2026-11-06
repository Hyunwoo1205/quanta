"""Dynamics bundles retain synchronized phase and exact standalone evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct

import pytest

from quanta.dynamics_results import transport_bytes
from quanta.hashing import canonical_bytes
from quanta.run_store import (BundleError, read_bundle, replay_bundle,
                              report_storage_bytes, validate_run_report, write_bundle)
from quanta.workflow import run_experiment


ROOT = Path(__file__).resolve().parents[1]


def authored(name="free_revision.json"):
    return json.loads((ROOT / "contracts/v0.4.0/examples" / name).read_text())


@pytest.fixture(scope="module")
def execution():
    report = run_experiment(authored())
    assert report["result"]["execution_status"] == "SUCCEEDED", report["result"]["errors"]
    assert validate_run_report(report)["valid"]
    return report


def detached(value):
    return json.loads(json.dumps(value))


def solver_record(report):
    row = report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"][0]
    return row, json.loads(report["captured_artifacts"][row["solver_report_sha256"]])


def republish_solver_record(report, inner, *, repair_publication=True):
    """Re-seal hashes so negative tests exercise semantic record checks."""
    row, _ = solver_record(report)
    if repair_publication and inner["provenance"] is not None:
        publication = inner["provenance"].pop("publication")
        publication["report_projection_sha256"] = hashlib.sha256(canonical_bytes(inner)).hexdigest()
        payload = inner["payload"]
        publication.update(payload_transport_bytes=len(transport_bytes(payload)) if payload is not None else 0,
            payload_transport_sha256=hashlib.sha256(transport_bytes(payload)).hexdigest() if payload is not None else None,
            payload_canonical_sha256=hashlib.sha256(canonical_bytes(payload)).hexdigest() if payload is not None else None)
        inner["provenance"]["publication"] = publication
        for _ in range(12):
            size = len(transport_bytes(inner))
            if size == publication["report_transport_bytes"]:
                break
            publication["report_transport_bytes"] = size
    raw = transport_bytes(inner)
    digest = hashlib.sha256(raw).hexdigest()
    row["solver_report_sha256"] = digest
    step = report["result"]["steps"][0]
    step["diagnostics"]["solver_report_sha256"] = digest
    ident = step["artifacts"][-1]["artifact_id"]
    for artifacts in (step["artifacts"], report["result"]["artifacts"]):
        for artifact in artifacts:
            if artifact["artifact_id"] == ident:
                artifact.update(sha256=digest, size_bytes=len(raw))
    report["artifact_contents"][ident] = raw.decode()
    report["captured_artifacts"][digest] = raw.decode()


def rehash_state(report, ident):
    states = report["result"]["states"]
    state = next(state for state in states if state["state_id"] == ident)
    runtime = report["resolved_record"]["runtime_evidence"]
    old_sha = report["state_content_hashes"][ident]
    projection = json.loads(report["captured_artifacts"][old_sha])
    for key in ("module_id", "module_version", "representation", "representation_version", "time_kind",
                "physical_time", "data_schema_ref", "data", "metadata_schema_ref", "metadata"):
        projection[key] = deepcopy(state[key])
    raw = canonical_bytes(projection)
    sha = hashlib.sha256(raw).hexdigest()
    report["captured_artifacts"][sha] = raw.decode()
    report["state_content_hashes"][ident] = sha
    runtime["state_content_hashes"][ident] = sha
    for index, mirror in enumerate(runtime["typed_states"]):
        if mirror["state_id"] == ident:
            runtime["typed_states"][index] = deepcopy(state)


def test_roundtrip_and_replay_preserve_phase_hashes_and_create_new_ids(execution, tmp_path):
    path = write_bundle(execution, tmp_path / "original")
    restored = read_bundle(path)
    assert restored == execution
    assert sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) == report_storage_bytes(execution)
    replayed = replay_bundle(path)
    assert replayed["result"]["execution_status"] == "SUCCEEDED"
    assert replayed["result"]["run_id"] != execution["result"]["run_id"]
    assert replayed["result"]["provenance"]["replay_of"] == execution["result"]["run_id"]
    assert sorted(replayed["state_content_hashes"].values()) == sorted(execution["state_content_hashes"].values())
    assert {s["state_id"] for s in replayed["result"]["states"]}.isdisjoint(
        s["state_id"] for s in execution["result"]["states"])


def test_physical_time_is_in_both_the_phase_and_scientific_projection(execution):
    for state in execution["result"]["states"]:
        value = state["data"]["time_s"]
        assert state["time_kind"] == "evolving"
        assert state["physical_time"] == {"value": value, "unit": "s"}
        projection = json.loads(execution["captured_artifacts"][execution["state_content_hashes"][state["state_id"]]])
        assert projection["physical_time"]["value"] == projection["data"]["time_s"] == value
        assert value == (1 if state["producer"]["kind"] == "step" else 0)


@pytest.mark.parametrize("member", ["envelope", "data", "both"])
def test_resealed_time_changes_cannot_detach_state_from_its_primary_trajectory(execution, member):
    report = detached(execution)
    state = next(s for s in report["result"]["states"] if s["producer"]["kind"] == "step")
    if member in {"envelope", "both"}:
        state["physical_time"]["value"] += 0.125
    if member in {"data", "both"}:
        state["data"]["time_s"] += 0.125
    rehash_state(report, state["state_id"])
    assert not validate_run_report(report)["valid"]


@pytest.mark.parametrize("mutation", ["request", "axes", "missing_proof", "extra_proof", "report_bytes",
                                     "source_inventory", "solver_contract", "initial_phase", "payload_carrier"])
def test_resealed_cross_record_dynamics_contradictions_are_rejected(execution, mutation):
    report = detached(execution)
    row, inner = solver_record(report)
    if mutation == "request":
        row["request"]["numerics"]["dt_s"] *= 2
    elif mutation == "axes":
        report["result"]["steps"][0]["numerical_status"] = "not_converged"
        report["result"]["numerical_status"] = "not_converged"
    elif mutation == "missing_proof":
        report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"].clear()
    elif mutation == "extra_proof":
        extra = deepcopy(row)
        extra["step_id"] = "invented"
        report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"].append(extra)
    elif mutation == "report_bytes":
        inner["provenance"]["publication"]["report_transport_bytes"] += 1
        republish_solver_record(report, inner, repair_publication=False)
    elif mutation == "source_inventory":
        provenance = inner["provenance"]
        filename = next(iter(provenance["source_files_sha256"]))
        sha = provenance["source_files_sha256"][filename]
        altered = provenance["captured_utf8_contents"][sha] + "\n# self-consistent invented source\n"
        changed_sha = hashlib.sha256(altered.encode()).hexdigest()
        provenance["captured_utf8_contents"][changed_sha] = altered
        provenance["source_files_sha256"][filename] = changed_sha
        provenance["implementation_manifest_sha256"] = hashlib.sha256(canonical_bytes({
            "package_version": provenance["package_version"], "files": provenance["source_files_sha256"]})).hexdigest()
        republish_solver_record(report, inner)
    elif mutation == "solver_contract":
        inner["provenance"]["contract_files_sha256"]["registry.json"] = "0" * 64
        republish_solver_record(report, inner)
    elif mutation == "initial_phase":
        state = next(s for s in report["result"]["states"] if s["producer"]["kind"] == "initial")
        state["data"]["system"]["particles"][0]["velocity_m_per_s"][0] += 1
        rehash_state(report, state["state_id"])
    else:
        # Change one raw frame carrier in both outer payload and its artifact,
        # keeping scientific JCS identity stable but contradicting the inner report.
        payload = report["result"]["steps"][0]["payload"]
        value = payload["legs"][0]["sampled_frames"][0]["forces_n"][0][0]
        assert value == 0
        payload["legs"][0]["sampled_frames"][0]["forces_n"][0][0] = -0.0 if struct.pack("!d",value) == struct.pack("!d",0.) else 0.
    assert not validate_run_report(report)["valid"], mutation


def test_signed_zero_report_and_trajectory_carriers_survive_bundle(execution, tmp_path):
    value = authored()
    value["definition"]["system"]["particles"][0]["position_m"][1] = -0.0
    value["definition"]["system"]["particles"][0]["velocity_m_per_s"][2] = -0.0
    report = run_experiment(value)
    assert report["result"]["execution_status"] == "SUCCEEDED", report["result"]["errors"]
    restored = read_bundle(write_bundle(report, tmp_path / "signed"))
    row, inner = solver_record(restored)
    raw = restored["captured_artifacts"][row["solver_report_sha256"]].encode()
    assert len(raw) == inner["provenance"]["publication"]["report_transport_bytes"]
    assert raw == transport_bytes(inner)
    frame = restored["result"]["steps"][0]["payload"]["legs"][0]["sampled_frames"][0]
    assert struct.pack("!d", frame["positions_m"][0][1]) == struct.pack("!d", -0.0)
    payload_artifact = restored["result"]["steps"][0]["artifacts"][0]
    persisted = json.loads(restored["artifact_contents"][payload_artifact["artifact_id"]])
    assert struct.pack("!d", persisted["legs"][0]["sampled_frames"][0]["positions_m"][0][1]) == struct.pack("!d", -0.0)


def test_historical_read_avoids_current_solver_provenance_gate_and_replay_refuses_change(execution, tmp_path, monkeypatch):
    import quanta.dynamics_results as results
    import quanta.planning as planning
    import quanta.workflow as workflow
    path = write_bundle(execution, tmp_path / "saved")
    monkeypatch.setattr(results, "_check_provenance", lambda *a, **k: pytest.fail("Historical read consulted current code"))
    assert read_bundle(path)["result"]["execution_status"] == "SUCCEEDED"
    original = planning.plan_experiment
    def changed_plan(*args, **kwargs):
        value = original(*args, **kwargs)
        value["resolved_input_sha256"] = "0" * 64
        return value
    monkeypatch.setattr(planning, "plan_experiment", changed_plan)
    monkeypatch.setattr(workflow, "run_experiment", lambda *a, **k: pytest.fail("Changed code was dispatched"))
    with pytest.raises(BundleError) as caught:
        replay_bundle(path)
    assert caught.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"


def test_initial_domain_failure_is_report_only_and_never_promoted(tmp_path):
    value = authored()
    value["definition"]["system"]["potential"]["expression"] = {"op": "log", "arg": {"op": "neg", "arg": {"op": "var", "name": "rho"}}}
    report = run_experiment(value)
    assert report["result"]["execution_status"] == "FAILED", report
    step = report["result"]["steps"][0]
    assert step["state_ref"] is None and step["payload"] is None and len(step["artifacts"]) == 1
    assert read_bundle(write_bundle(report, tmp_path / "failed"))["result"]["execution_status"] == "FAILED"
    changed = detached(report)
    changed["result"]["steps"][0]["outcome"] = "SUCCEEDED"
    changed["result"]["steps"][0]["state_ref"] = changed["result"]["states"][0]["state_id"]
    assert not validate_run_report(changed)["valid"]


@pytest.mark.parametrize("prepared", [False, True])
def test_discarded_or_unprepared_dynamics_cannot_claim_unobserved_axes(monkeypatch, prepared):
    import quanta.workflow as workflow
    from quanta.autodiff import CalculationError
    def refusal(*args, **kwargs):
        raise CalculationError("Synthetic host refusal", code="RESOURCE_LIMIT")
    if prepared:
        monkeypatch.setattr(workflow, "execute_dynamics", refusal)
        report = workflow.run_experiment(authored())
    else:
        report = workflow.run_experiment(authored(), control_check=refusal)
    assert report["result"]["execution_status"] == "FAILED"
    step = report["result"]["steps"][0]
    assert (step["source_binding"] is not None) == prepared
    assert not report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"]
    assert validate_run_report(report)["valid"]
    changed = detached(report)
    changed["result"]["steps"][0].update(numerical_status="pass", resolution_status="pass")
    changed["result"].update(numerical_status="pass", resolution_status="pass")
    assert not validate_run_report(changed)["valid"]


@pytest.mark.parametrize("host_resource", [False, True])
def test_cancelled_inner_report_requires_truthful_host_control_category(monkeypatch, host_resource):
    import quanta.workflow as workflow
    from quanta.autodiff import CalculationError
    from quanta.dynamics import integrate_dynamics_request
    from quanta.dynamics_workflow import execute_dynamics, solver_request
    def resource():
        raise CalculationError("Synthetic host wall refusal", code="RESOURCE_LIMIT")
    def invoke(definition, deadline):
        if host_resource:
            return execute_dynamics(definition, resource)
        return integrate_dynamics_request(solver_request(definition), check_cancel=lambda: True)
    monkeypatch.setattr(workflow, "execute_dynamics", invoke)
    report = workflow.run_experiment(authored())
    expected = "FAILED" if host_resource else "CANCELLED"
    assert report["result"]["execution_status"] == expected
    row, inner = solver_record(report)
    assert inner["execution_status"] == "CANCELLED" and inner["payload"] is None
    assert (row["control_error"] is not None) == host_resource
    assert validate_run_report(report)["valid"]
    changed = detached(report)
    opposite = "CANCELLED" if host_resource else "FAILED"
    changed["result"]["steps"][0]["outcome"] = opposite
    changed["result"]["execution_status"] = opposite
    if host_resource:
        from quanta.workflow import _issue
        changed["result"]["errors"].append(_issue("CANCELLED", "Invented cancellation"))
    assert not validate_run_report(changed)["valid"]


def test_numerical_failure_preserves_valid_partial_bundle_and_replays(tmp_path):
    value = authored("harmonic_revision.json")
    value["definition"]["numerics"].update(dt_s=0.05, steps=20, sample_stride=5,
                                            energy_drift_atol=0, refinement="none")
    report = run_experiment(value)
    assert report["result"]["execution_status"] == "FAILED", report["result"]["errors"]
    step = report["result"]["steps"][0]
    assert step["payload"] is not None and step["payload"]["partial"]
    assert step["state_ref"] is None and step["numerical_status"] == "not_converged"
    path = write_bundle(report, tmp_path / "partial")
    assert read_bundle(path)["result"]["steps"][0]["payload"] == step["payload"]
    replayed = replay_bundle(path)
    assert replayed["result"]["execution_status"] == "FAILED"
    assert replayed["result"]["run_id"] != report["result"]["run_id"]
    assert replayed["result"]["steps"][0]["state_ref"] is None


def test_resealed_finest_leg_cannot_replace_the_registered_primary_state(tmp_path):
    value = authored("harmonic_refinement_revision.json")
    report = run_experiment(value)
    assert report["result"]["execution_status"] == "SUCCEEDED", report["result"]["errors"]
    row, inner = solver_record(report)
    fine = inner["payload"]["legs"][-1]["sampled_frames"][-1]
    primary = inner["payload"]["legs"][0]["sampled_frames"][-1]
    assert fine["positions_m"] != primary["positions_m"]
    for particle, position, velocity in zip(inner["final_state"]["data"]["system"]["particles"],
                                             fine["positions_m"], fine["velocities_m_per_s"]):
        particle["position_m"], particle["velocity_m_per_s"] = deepcopy(position), deepcopy(velocity)
    content = {k: inner["final_state"][k] for k in ("data", "metadata", "physical_time")}
    inner["final_state"]["scientific_state_sha256"] = hashlib.sha256(canonical_bytes(content)).hexdigest()
    changed = detached(report)
    state = next(s for s in changed["result"]["states"] if s["producer"]["kind"] == "step")
    state["data"] = deepcopy(inner["final_state"]["data"])
    rehash_state(changed, state["state_id"])
    republish_solver_record(changed, inner)
    assert not validate_run_report(changed)["valid"]
