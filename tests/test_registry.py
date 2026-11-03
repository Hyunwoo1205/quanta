"""Frozen local registry integrity and schema dispatch checks."""

import hashlib
import json
import shutil

import pytest

from quanta.registry import ContractRegistry
from quanta.validation import validate_experiment


def test_bundled_registry_integrity_has_no_errors(contract_dir):
    assert ContractRegistry(contract_dir).validate_integrity() == []


def test_module_and_observable_manifests_validate_against_common_schemas(contract_dir):
    registry = ContractRegistry(contract_dir)
    data = json.loads((contract_dir / "registry.json").read_text())
    for entry in data["modules"]:
        registry.validator("module_manifest.schema.json").validate(entry)
        assert entry["implementation_status"] == "planned_not_implemented"
        assert entry["validation"]["status"] == "not_executed"
    for entry in data["observables"]:
        registry.validator("observable_manifest.schema.json").validate(entry)
        assert entry["validation"]["status"] == "not_executed"


def test_registered_full_definitions_validate_and_module_lookup_is_exact(contract_dir, pair, quantum):
    registry = ContractRegistry(contract_dir)
    for value in (pair, quantum):
        system = value["definition"]["system"]
        module = registry.get_module(system["module_id"], system["module_version"])
        registry.validator(module["definition_schema_ref"]).validate(value["definition"])
    # The public interface may report absence with None or a lookup exception;
    # neither path may silently return the registered 0.1.0 implementation.
    try:
        missing = registry.get_module("quanta.pair_static", "0.1.1")
    except (KeyError, ValueError):
        pass
    else:
        assert missing is None


def test_schema_resolution_refuses_remote_and_path_traversal(contract_dir):
    registry = ContractRegistry(contract_dir)
    for ref in ("https://example.invalid/schema.json", "../registry.json", "/etc/passwd"):
        with pytest.raises((KeyError, ValueError)):
            registry.resolve_schema(ref)


def test_contract_tampering_is_detected_without_running_any_engine(contract_dir, tmp_path):
    for name in ("module_inputs.schema.json", "registry.json", "semantic_rules.json"):
        modified = tmp_path / name.replace(".json", "")
        shutil.copytree(contract_dir, modified)
        target = modified / name
        target.write_bytes(target.read_bytes() + b"\n")
        errors = ContractRegistry(modified).validate_integrity()
        assert errors and all(isinstance(error, dict) for error in errors), name


def test_hash_consistent_null_module_manifest_is_a_structured_registry_failure(contract_dir, tmp_path, pair):
    bundle = tmp_path / "invalid-registry"
    shutil.copytree(contract_dir, bundle)
    registry_path = bundle / "registry.json"
    data = json.loads(registry_path.read_text())
    data["modules"] = [None]
    registry_path.write_text(json.dumps(data, indent=2) + "\n")
    sums_path = bundle / "SHA256SUMS.json"
    sums = json.loads(sums_path.read_text())
    sums["registry.json"] = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    sums_path.write_text(json.dumps(sums, indent=2) + "\n")
    report = validate_experiment(pair, registry=ContractRegistry(bundle))
    assert report["valid"] is False, report
    assert report["input_sha256"] is None
    assert report["physical_validation_status"] == "unvalidated"
    assert any(error["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE" for error in report["errors"]), report
