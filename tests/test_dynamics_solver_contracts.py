"""Immutable solver opt-in never upgrades the older validation-only contract."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from jsonschema import ValidationError
from referencing.exceptions import Unresolvable

from quanta.dynamics_validation import validate_dynamics_request, _prepare_dynamics_request
from quanta.registry import ContractRegistry

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "contracts/v0.3.1"


def request(name="harmonic.request.json", version="0.3.1"):
    return json.loads((ROOT / "contracts" / ("v" + version) / "examples" / name).read_text())


def reseal(bundle, name):
    path = bundle / "SHA256SUMS.json"
    sums = json.loads(path.read_text())
    sums[name] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    path.write_text(json.dumps(sums, indent=2) + "\n")


def test_solver_registry_is_explicit_and_preserves_old_modes():
    assert ContractRegistry().contract_version == "0.2.0"
    old = ContractRegistry(contract_version="0.3.0")
    new = ContractRegistry(contract_version="0.3.1")
    assert old.validate_integrity() == new.validate_integrity() == []
    assert old.data["execution_supported"] is False
    assert new.data["execution_supported"] is True
    assert new.data["generic_experiment_supported"] is False
    module = new.get_module("quanta.pair_dynamics", "0.1.0")
    assert module["implementation_status"] == "standalone_velocity_verlet"
    assert module["report_schema_ref"] == "dynamics_report.schema.json"
    assert module["capabilities"]["generic_experiment_supported"] is False
    assert ContractRegistry().get_module("quanta.pair_dynamics", "0.1.0") is None


@pytest.mark.parametrize("name", ["harmonic.request.json", "harmonic-refinement.request.json", "free.request.json"])
def test_valid_solver_request_is_admitted_without_time_integration(name):
    value = request(name)
    before = copy.deepcopy(value)
    result = validate_dynamics_request(value)
    assert value == before
    assert result["valid"] and result["executable"]
    assert result["contract_version"] == "0.3.1"
    assert result["initial_force_evaluation_performed"] is True
    assert result["dynamics_simulation_executed"] is False
    assert result["execution_scope"] == "standalone_solver_request"
    assert "payload" not in result and "final_state" not in result


def test_old_request_stays_validation_only():
    result = validate_dynamics_request(request(version="0.3.0"))
    assert result["valid"] is True
    assert result["contract_version"] == "0.3.0"
    assert result["executable"] is False
    assert result["dynamics_simulation_executed"] is False
    assert "execution_scope" not in result


def test_old_request_does_not_satisfy_new_request_schema():
    new = ContractRegistry(contract_version="0.3.1")
    with pytest.raises(ValidationError):
        new.validator("dynamics_request.schema.json").validate(request(version="0.3.0"))


@pytest.mark.parametrize("version", ["0.2.0", "0.3.0"])
def test_registry_injection_cannot_change_request_version(version):
    result = validate_dynamics_request(request(), registry=ContractRegistry(contract_version=version))
    assert result["valid"] is False
    assert result["initial_force_evaluation_performed"] is False
    assert result["errors"][0]["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE"


def test_private_preparation_counts_one_initial_force_and_detaches_input(monkeypatch):
    from quanta.pair_kernel import PairForceKernel
    original = PairForceKernel.evaluate
    calls = []
    def count(self, *args, **kwargs):
        calls.append(True)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(PairForceKernel, "evaluate", count)
    value = request()
    before = copy.deepcopy(value)
    report, prepared = _prepare_dynamics_request(value)
    assert report["valid"] and prepared is not None
    assert len(calls) == 1
    assert prepared["initial_force"].energy_j == 1.5
    assert prepared["initial_diagnostics"]["total_energy_j"] == 1.916015625
    assert prepared["deadline_monotonic"] > prepared["validation_started_monotonic"]
    assert value == before
    prepared["request"]["system"]["particles"][0]["position_m"][0] = 987
    assert value == before
    assert "initial_force" not in report
    assert not any("monotonic" in key for key in report)


def test_invalid_preparation_returns_no_executable_snapshot():
    value = request()
    value["system"]["particles"][0]["mass_kg"] = 0
    report, prepared = _prepare_dynamics_request(value)
    assert report["valid"] is False and report["executable"] is False
    assert prepared is None and report["errors"]


def test_report_schema_distinguishes_failed_input_and_success_claims():
    registry = ContractRegistry(contract_version="0.3.1")
    failed = {"report_version":"0.1.0", "scope":"standalone_dynamics_integration",
        "contract_version":"0.3.1", "module_ref":{"module_id":"quanta.pair_dynamics",
        "module_version":"0.1.0", "solver_id":"velocity_verlet_forward_ad", "solver_version":"0.1.0"},
        "operation":"integrate", "input_validation_status":"failed", "execution_status":"FAILED",
        "numerical_status":"not_checked", "resolution_status":"not_checked",
        "physical_validation_status":"unvalidated", "partial":False, "input_sha256":None,
        "errors":[{"code":"INPUT_SCHEMA", "category":"input", "message":"Synthetic invalid input",
        "path":None, "step_id":None, "branch_index":None, "retryable":False, "details":{}}],
        "warnings":[], "payload":None, "final_state":None, "provenance":None,
        "dynamics_simulation_executed":False, "initial_force_evaluation_performed":False}
    validator = registry.validator("dynamics_report.schema.json")
    validator.validate(failed)
    for changes in ({"execution_status":"SUCCEEDED"}, {"partial":True},
                    {"dynamics_simulation_executed":True}, {"errors":[]},
                    {"numerical_status":"pass"}, {"resolution_status":"pass"}):
        bad = copy.deepcopy(failed)
        bad.update(changes)
        with pytest.raises(ValidationError):
            validator.validate(bad)
    failed["execution_status"] = "CANCELLED"
    failed["input_validation_status"] = "pass"
    failed["dynamics_simulation_executed"] = True
    validator.validate(failed)


@pytest.mark.parametrize("version", ["0.2.0", "0.3.0"])
def test_explicit_version_mismatch_is_not_silently_reinterpreted(version):
    with pytest.raises(ValueError, match="differs"):
        ContractRegistry(ROOT / "contracts" / ("v" + version), contract_version="0.3.1")


def test_new_solver_alias_is_version_local_and_offline():
    registry = ContractRegistry(contract_version="0.3.1")
    resolver = registry.offline_registry.resolver()
    assert resolver.lookup("https://quanta.invalid/contracts/v0.3.1/dynamics_report.schema.json").contents["$id"].endswith(":0.3.1")
    for uri in ["https://quanta.invalid/contracts/v0.3.0/dynamics_report.schema.json", "https://example.invalid/schema.json"]:
        with pytest.raises(Unresolvable):
            resolver.lookup(uri)


@pytest.mark.parametrize("mutation", ["digest", "missing", "remote_report", "claim_generic"])
def test_solver_bundle_tampering_fails_before_initial_force(tmp_path, mutation):
    bundle = tmp_path / "contracts"
    shutil.copytree(BUNDLE, bundle)
    path = bundle / "dynamics_report.schema.json"
    if mutation == "digest":
        path.write_bytes(path.read_bytes() + b"\n")
    elif mutation == "missing":
        path.unlink()
    elif mutation == "remote_report":
        value = json.loads(path.read_text())
        value["properties"]["final_state"] = {"$ref":"https://example.invalid/state.json"}
        path.write_text(json.dumps(value))
        reseal(bundle, path.name)
    else:
        path = bundle / "registry.json"
        value = json.loads(path.read_text())
        value["generic_experiment_supported"] = True
        path.write_text(json.dumps(value))
        reseal(bundle, path.name)
    registry = ContractRegistry(bundle, contract_version="0.3.1")
    assert registry.validate_integrity()
    report = validate_dynamics_request(request(), registry=registry)
    assert report["valid"] is False
    assert report["initial_force_evaluation_performed"] is False


def test_solver_contract_keeps_frozen_prior_bundle_hashes():
    # Pin the complete existing digest manifests, then verify every listed byte.
    expected = {"0.2.0":"95aae5662cdfe7a015c6d3342b6660410efcd6ce4d822eb90d22d6bf6c4b3c4a",
                "0.3.0":"8fdc3a520a657c7481d5d488f7ca1c4595c27193677827c655389cfffe4da2b2"}
    for version, sha in expected.items():
        bundle = ROOT / "contracts" / ("v" + version)
        manifest = bundle / "SHA256SUMS.json"
        assert hashlib.sha256(manifest.read_bytes()).hexdigest() == sha
        digests = json.loads(manifest.read_text())
        assert set(digests) == {str(path.relative_to(bundle)) for path in bundle.rglob("*")
                                if path.is_file() and path != manifest}
        for relative, digest in digests.items():
            assert hashlib.sha256((bundle / relative).read_bytes()).hexdigest() == digest
