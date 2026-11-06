"""Versioned standalone dynamics schemas remain isolated from executable 0.2."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from jsonschema import ValidationError
from referencing.exceptions import Unresolvable

from quanta.registry import ContractRegistry


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "contracts" / "v0.3.0"
OLD_MANIFEST_SHA = "95aae5662cdfe7a015c6d3342b6660410efcd6ce4d822eb90d22d6bf6c4b3c4a"


def read(name):
    return json.loads((BUNDLE / name).read_text())


def reseal(bundle, name):
    sums_path = bundle / "SHA256SUMS.json"
    sums = json.loads(sums_path.read_text())
    sums[name] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    sums_path.write_text(json.dumps(sums, indent=2) + "\n")


def test_new_bundle_is_explicit_and_has_no_solver_or_generic_experiment_claim():
    old = ContractRegistry()
    new = ContractRegistry(contract_version="0.3.0")
    assert old.contract_version == "0.2.0"
    assert old.get_module("quanta.pair_dynamics", "0.1.0") is None
    assert new.contract_version == "0.3.0"
    assert new.validate_integrity() == []
    module = new.get_module("quanta.pair_dynamics", "0.1.0")
    assert module["implementation_status"] == "validation_ready_execution_not_implemented"
    assert module["request_scope"] == "standalone_solver_request"
    assert module["capabilities"]["execution_supported"] is False
    assert module["capabilities"]["generic_experiment_supported"] is False
    assert "definition_schema_ref" not in module
    assert new.data["default_for_existing_experiments"] is False
    assert new.get_module("quanta.pair_dynamics", "0.1.1") is None
    assert new.get_module("quanta.pair_static", "0.1.0") is None


@pytest.mark.parametrize("version", ["0.3.1", "v0.3.0", "../v0.3.0", "", 0.3, [], False])
def test_unsupported_selector_never_falls_back(version):
    with pytest.raises(ValueError, match="Unsupported bundled contract version"):
        ContractRegistry(contract_version=version)


def test_explicit_selector_cannot_load_other_version_directory():
    with pytest.raises(ValueError, match="differs"):
        ContractRegistry(ROOT / "contracts" / "v0.2.0", contract_version="0.3.0")
    with pytest.raises(ValueError, match="differs"):
        ContractRegistry(BUNDLE, contract_version="0.2.0")
    assert ContractRegistry(BUNDLE).contract_version == "0.3.0"


def test_default_directory_cannot_claim_a_different_contract_version(tmp_path, monkeypatch):
    import quanta.registry as module
    fake_root = tmp_path / "source"
    bundle = fake_root / "contracts" / "v0.2.0"
    shutil.copytree(ROOT / "contracts" / "v0.2.0", bundle)
    path = bundle / "registry.json"
    data = json.loads(path.read_text())
    data["contract_version"] = "0.3.0"
    path.write_text(json.dumps(data))
    reseal(bundle, "registry.json")
    monkeypatch.setattr(module, "__file__", str(fake_root / "src" / "quanta" / "registry.py"))
    with pytest.raises(ValueError, match="differs"):
        ContractRegistry()


@pytest.mark.parametrize("name", ["harmonic.request.json", "harmonic-refinement.request.json", "free.request.json"])
def test_versioned_standalone_examples_validate_without_draft_marker(name):
    registry = ContractRegistry(contract_version="0.3.0")
    module = registry.get_module("quanta.pair_dynamics", "0.1.0")
    value = read("examples/" + name)
    assert value["contract_version"] == "0.3.0"
    assert "draft_schema_version" not in value
    registry.validator(module["request_schema_ref"]).validate(value)
    registry.validator("urn:quanta:schema:pair-dynamics-request:0.3.0").validate(value)
    assert registry.get_observable("quanta.pair_dynamics", "0.1.0", "trajectory")["execution_supported"] is False


def test_draft_and_version_mismatch_are_not_automatically_converted():
    registry = ContractRegistry(contract_version="0.3.0")
    value = read("examples/harmonic.request.json")
    value["draft_schema_version"] = "0.1.0"
    value.pop("contract_version")
    with pytest.raises(ValidationError):
        registry.validator("dynamics_request.schema.json").validate(value)
    value.pop("draft_schema_version")
    value["contract_version"] = "0.2.0"
    with pytest.raises(ValidationError):
        registry.validator("dynamics_request.schema.json").validate(value)


def test_evolving_state_schema_carries_scales_and_actual_scientific_time():
    registry = ContractRegistry(contract_version="0.3.0")
    value = read("examples/harmonic.request.json")
    state = {"contract_version":"0.3.0", "module_id":"quanta.pair_dynamics", "module_version":"0.1.0",
             "representation":"particles_phase_space_3d", "representation_version":"0.1.0",
             "time_kind":"evolving", "time_s":1, "scales":value["scales"], "system":value["system"]}
    registry.validator("dynamics_state.schema.json").validate(state)
    for key in ("time_s", "scales"):
        missing = copy.deepcopy(state)
        missing.pop(key)
        with pytest.raises(ValidationError):
            registry.validator("dynamics_state.schema.json").validate(missing)
    state["time_kind"] = "static"
    with pytest.raises(ValidationError):
        registry.validator("dynamics_state.schema.json").validate(state)


def test_new_schemas_have_no_old_or_remote_schema_resolution_alias():
    registry = ContractRegistry(contract_version="0.3.0")
    for reference in ("urn:quanta:schema:pair-dynamics-request:0.2.0",
                      "https://quanta.invalid/contracts/v0.2.0/dynamics_request.schema.json",
                      "https://example.invalid/schema.json", "../v0.2.0/registry.json", "/etc/passwd"):
        with pytest.raises(ValueError):
            registry.resolve_schema(reference)
    # Exercise the actual referencing registry: an old-version URI cannot
    # resolve through the new bundle alias and cannot trigger network fallback.
    resolver = registry.offline_registry.resolver()
    with pytest.raises(Unresolvable):
        resolver.lookup("https://quanta.invalid/contracts/v0.2.0/dynamics_request.schema.json")
    assert resolver.lookup("https://quanta.invalid/contracts/v0.3.0/dynamics_request.schema.json").contents["$id"].endswith(":0.3.0")


@pytest.mark.parametrize("mutation", ["tamper", "missing", "remote_ref", "resource_binding", "execution_claim", "port_role"])
def test_tampered_or_incompatible_new_bundle_fails_integrity(tmp_path, mutation):
    bundle = tmp_path / "bundle"
    shutil.copytree(BUNDLE, bundle)
    target = bundle / "dynamics_request.schema.json"
    if mutation == "tamper":
        target.write_bytes(target.read_bytes() + b"\n")
    elif mutation == "missing":
        target.unlink()
    elif mutation == "remote_ref":
        value = json.loads(target.read_text())
        value["properties"]["scales"] = {"$ref":"https://example.invalid/arbitrary-schema.json"}
        target.write_text(json.dumps(value))
        reseal(bundle, target.name)
    elif mutation == "resource_binding":
        target = bundle / "resource_policy.json"
        value = json.loads(target.read_text())
        value["profiles"]["pair_dynamics_cpu"]["module_versions"] = []
        target.write_text(json.dumps(value))
        reseal(bundle, target.name)
    else:
        target = bundle / "registry.json"
        value = json.loads(target.read_text())
        if mutation == "port_role":
            value["modules"][0]["ports"][1]["direction"] = "input"
        else:
            value["execution_supported"] = True
        target.write_text(json.dumps(value))
        reseal(bundle, target.name)
    errors = ContractRegistry(bundle, contract_version="0.3.0").validate_integrity()
    assert errors and all(e["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE" for e in errors)


def test_old_frozen_bundle_remains_byte_exact():
    old = ROOT / "contracts" / "v0.2.0"
    assert hashlib.sha256((old / "SHA256SUMS.json").read_bytes()).hexdigest() == OLD_MANIFEST_SHA
    sums = json.loads((old / "SHA256SUMS.json").read_text())
    assert all(hashlib.sha256((old/name).read_bytes()).hexdigest() == sha for name,sha in sums.items())
    assert ContractRegistry().validate_integrity() == []
