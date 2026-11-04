"""Local bundle integrity, safe transport, and trusted implementation replay."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from quanta.hashing import canonical_bytes
from quanta.run_store import BundleError, read_bundle, replay_bundle, report_storage_bytes, validate_run_report, write_bundle
from quanta.workflow import run_experiment

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def execution(pair):
    pair["definition"]["protocol"] = {"steps": [{"step_id": "evaluate", "operation": "energy_forces", "source": "initial", "overrides": []}], "sweep": {"axes": []}}
    pair["definition"]["observables"] = ["energy", "forces"]
    return run_experiment(pair)


def test_bundle_roundtrip_preserves_exact_assets_and_replays_with_new_ids(execution, tmp_path):
    assert validate_run_report(execution)["valid"]
    path = write_bundle(execution, tmp_path / "original")
    restored = read_bundle(path)
    assert restored == execution
    actual_size = sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
    assert actual_size == report_storage_bytes(execution)
    replayed = replay_bundle(path)
    assert replayed["result"]["execution_status"] == "SUCCEEDED"
    assert replayed["result"]["run_id"] != execution["result"]["run_id"]
    assert replayed["result"]["provenance"]["replay_of"] == execution["result"]["run_id"]
    for field in ("input_sha256", "resolved_input_sha256", "execution_fingerprint"):
        assert replayed["result"][field] == execution["result"][field]
    assert sorted(replayed["state_content_hashes"].values()) == sorted(execution["state_content_hashes"].values())


def test_negative_zero_fixed_coordinates_survive_record_transport_and_replay(pair, tmp_path):
    pair["definition"]["protocol"] = {"steps": [{"step_id": "evaluate", "operation": "energy_forces", "source": "initial", "overrides": []}], "sweep": {"axes": []}}
    pair["definition"]["observables"] = ["energy", "forces"]
    original = pair["definition"]["system"]["particles"][0]
    original["position_m"][0] = -0.0
    original["fixed"][0] = True
    report = run_experiment(pair)
    path = write_bundle(report, tmp_path / "signed")
    restored, replayed = read_bundle(path), replay_bundle(path)
    expected = struct.pack("!d", -0.0)
    for result in (report, restored, replayed):
        assert struct.pack("!d", result["plan"]["experiment"]["definition"]["system"]["particles"][0]["position_m"][0]) == expected
        assert struct.pack("!d", result["result"]["steps"][0]["payload"]["final_positions_m"][0][0]) == expected
        for state in result["result"]["states"]:
            assert struct.pack("!d", state["data"]["particles"][0]["position_m"][0]) == expected


@pytest.mark.parametrize("mutation", ["initial", "prepared_input", "step", "runtime_mirror", "effective_input", "branch_definition"])
def test_signed_zero_record_contradictions_are_rejected_without_changing_scientific_hashes(pair, tmp_path, mutation):
    pair["definition"]["protocol"] = {"steps": [{"step_id": "evaluate", "operation": "energy_forces", "source": "initial", "overrides": []}], "sweep": {"axes": []}}
    pair["definition"]["observables"] = ["energy", "forces"]
    pair["definition"]["system"]["particles"][0]["position_m"][0] = -0.0
    pair["definition"]["system"]["particles"][0]["fixed"][0] = True
    report = run_experiment(pair)
    path = write_bundle(report, tmp_path / "signed")

    def change_carrier(value):
        runtime = value["resolved_record"]["runtime_evidence"]
        if mutation == "effective_input":
            runtime["effective_step_inputs"][0]["definition"]["system"]["particles"][0]["position_m"][0] = 0.0
        elif mutation == "branch_definition":
            value["plan"]["branch_definitions"][0]["system"]["particles"][0]["position_m"][0] = 0.0
        else:
            kind = "initial" if mutation == "runtime_mirror" else mutation
            # Mutate both independently decoded copies so the state checks,
            # rather than only the duplicate runtime mirror, detect the change.
            stores = [runtime["typed_states"]]
            if mutation != "runtime_mirror":
                stores.append(value["result"]["states"])
            for states in stores:
                state = next(state for state in states if state["producer"]["kind"] == kind)
                state["data"]["particles"][0]["position_m"][0] = 0.0

    changed = json.loads(json.dumps(report))
    change_carrier(changed)
    # JCS intentionally normalizes signed zero: scientific identity is stable,
    # but record consistency must still reject a different coordinate carrier.
    assert canonical_bytes(changed) == canonical_bytes(report)
    assert not validate_run_report(changed)["valid"]
    with pytest.raises(BundleError, match="failed validation"):
        write_bundle(changed, tmp_path / "contradictory")

    document = json.loads((path / "bundle.json").read_text())
    change_carrier(document["report"])
    document["bundle_content_sha256"] = hashlib.sha256(canonical_bytes({key: value for key, value in document.items()
        if key != "bundle_content_sha256"})).hexdigest()
    raw = json.dumps(document, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    (path / "bundle.json").write_bytes(raw)
    (path / "bundle.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    with pytest.raises(BundleError, match="failed validation"):
        read_bundle(path)


def test_record_consistency_accepts_equivalent_integer_and_float_coordinates(execution, tmp_path):
    changed = json.loads(json.dumps(execution))
    runtime = changed["resolved_record"]["runtime_evidence"]
    for states in (changed["result"]["states"], runtime["typed_states"]):
        for state in states:
            state["data"]["particles"][0]["position_m"][0] = 0.0
    assert validate_run_report(changed)["valid"]
    assert read_bundle(write_bundle(changed, tmp_path / "equivalent")) == changed


@pytest.mark.parametrize("mutation", ["asset", "metadata", "missing", "symlink", "asset_name"])
def test_bundle_rejects_modified_missing_or_unsafe_files(execution, tmp_path, mutation):
    path = write_bundle(execution, tmp_path / mutation)
    asset = next((path / "assets").iterdir())
    if mutation == "asset":
        asset.write_bytes(asset.read_bytes() + b" ")
    elif mutation == "metadata":
        (path / "bundle.json").write_bytes((path / "bundle.json").read_bytes() + b" ")
    elif mutation == "missing":
        asset.unlink()
    elif mutation == "symlink":
        saved = asset.read_bytes()
        asset.unlink()
        outside = tmp_path / "outside"
        outside.write_bytes(saved)
        asset.symlink_to(outside)
    else:
        doc = json.loads((path / "bundle.json").read_text())
        doc["captured_artifact_hashes"].append("../outside")
        doc["bundle_content_sha256"] = hashlib.sha256(canonical_bytes({k: v for k, v in doc.items() if k != "bundle_content_sha256"})).hexdigest()
        raw = json.dumps(doc).encode()
        (path / "bundle.json").write_bytes(raw)
        (path / "bundle.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    with pytest.raises(BundleError):
        read_bundle(path)


@pytest.mark.parametrize("mutation", ["state_hash", "prepared_parent", "aggregate_axis", "metadata_shape", "profile"])
def test_report_verification_rejects_cross_record_contradictions(execution, mutation):
    changed = copy.deepcopy(execution)
    if mutation == "state_hash":
        key = next(iter(changed["state_content_hashes"]))
        changed["state_content_hashes"][key] = "0" * 64
    elif mutation == "prepared_parent":
        state = next(s for s in changed["result"]["states"] if s["producer"]["kind"] == "prepared_input")
        state["parent_state_refs"] = [state["state_id"]]
    elif mutation == "aggregate_axis":
        changed["result"]["numerical_status"] = "pass"
    elif mutation == "metadata_shape":
        # Keep the scientific content map and all bytes self-consistent, but
        # contradict the registered array shape's meaning.
        state = changed["result"]["states"][0]
        state["metadata"]["position_shape"] = [3, 3]
        sha = changed["state_content_hashes"][state["state_id"]]
        value = json.loads(changed["captured_artifacts"][sha])
        value["metadata"]["position_shape"] = [3, 3]
        raw = canonical_bytes(value).decode()
        new_sha = hashlib.sha256(raw.encode()).hexdigest()
        changed["captured_artifacts"][new_sha] = raw
        changed["state_content_hashes"][state["state_id"]] = new_sha
    else:
        sha = changed["plan"]["execution_manifests"]["effective_resource_profile_sha256"]
        profile = json.loads(changed["captured_artifacts"][sha])
        profile["common_execution"]["wall_seconds_per_run"] *= 2
        raw = canonical_bytes(profile).decode()
        new_sha = hashlib.sha256(raw.encode()).hexdigest()
        changed["captured_artifacts"][new_sha] = raw
        changed["plan"]["execution_manifests"]["effective_resource_profile_sha256"] = new_sha
    assert not validate_run_report(changed)["valid"]


def test_existing_output_is_preserved_and_incomplete_bundle_is_not_readable(execution, tmp_path):
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    marker = occupied / "keep.txt"
    marker.write_text("user content")
    with pytest.raises(BundleError, match="already exists"):
        write_bundle(execution, occupied)
    assert marker.read_text() == "user content"
    with pytest.raises(BundleError):
        read_bundle(occupied)


def test_replay_refuses_changed_frozen_implementation_without_running_it(execution, tmp_path, monkeypatch):
    import quanta.planning as planning
    import quanta.workflow as workflow

    path = write_bundle(execution, tmp_path / "saved")
    original = planning.plan_experiment

    def changed_plan(*args, **kwargs):
        value = original(*args, **kwargs)
        value["resolved_input_sha256"] = "0" * 64
        return value

    monkeypatch.setattr(planning, "plan_experiment", changed_plan)
    monkeypatch.setattr(workflow, "run_experiment", lambda *a, **k: pytest.fail("Changed implementation was dispatched"))
    with pytest.raises(BundleError) as caught:
        replay_bundle(path)
    assert caught.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"


def test_failed_partial_bundle_can_be_verified_and_replayed(pair, tmp_path):
    pair["definition"]["numerics"]["max_evaluations"] = 1
    report = run_experiment(pair)
    assert report["result"]["execution_status"] == "FAILED"
    path = write_bundle(report, tmp_path / "failed")
    assert read_bundle(path)["result"]["partial"]
    replayed = replay_bundle(path)
    assert replayed["result"]["execution_status"] == "FAILED"
    assert replayed["result"]["run_id"] != report["result"]["run_id"]
    assert replayed["result"]["provenance"]["replay_of"] == report["result"]["run_id"]


def test_cli_plan_run_replay_and_missing_input(tmp_path):
    command = [sys.executable, "-m", "quanta"]
    example = ROOT / "examples/pair_workflow.json"
    planned = subprocess.run([*command, "plan", str(example)], text=True, capture_output=True)
    assert planned.returncode == 0, planned.stdout + planned.stderr
    plan = json.loads(planned.stdout)
    assert len(plan["frozen_plan"]["branch_bases"]) == 2
    assert len(plan["frozen_plan"]["expanded_steps"]) == 6
    bundle, replay_dir = tmp_path / "run", tmp_path / "replay"
    run = subprocess.run([*command, "run", str(example), "--output-dir", str(bundle), "--format", "text"], text=True, capture_output=True)
    assert run.returncode == 0 and "SUCCEEDED" in run.stdout, run.stdout + run.stderr
    replay = subprocess.run([*command, "replay", str(bundle), "--output-dir", str(replay_dir)], text=True, capture_output=True)
    assert replay.returncode == 0, replay.stdout + replay.stderr
    result = json.loads(replay.stdout)["result"]
    assert result["execution_status"] == "SUCCEEDED" and result["provenance"]["replay_of"]
    assert validate_run_report(read_bundle(replay_dir))["valid"]
    missing = subprocess.run([*command, "run", str(tmp_path / "missing.json")], text=True, capture_output=True)
    assert missing.returncode == 2 and json.loads(missing.stdout)["errors"][0]["code"] == "INPUT_READ"
