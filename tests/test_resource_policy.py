"""Resolved policy ceilings must govern validation, not copied constants."""

import hashlib
import json
import shutil

from quanta.registry import ContractRegistry
from quanta.validation import validate_experiment


def registry_with_policy(contract_dir, tmp_path, section, field, limit):
    bundle = tmp_path / "contracts"
    shutil.copytree(contract_dir, bundle)
    policy_path = bundle / "resource_policy.json"
    policy = json.loads(policy_path.read_text())
    target = policy
    for key in section:
        target = target[key]
    target[field] = limit
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")
    manifest_path = bundle / "SHA256SUMS.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resource_policy.json"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    registry = ContractRegistry(bundle)
    assert registry.validate_integrity() == []
    return registry


def assert_resource_rejection(report):
    assert report["valid"] is False, report
    assert report["input_sha256"] is None, report
    assert report["physical_validation_status"] == "unvalidated", report
    assert any(error["code"] == "RESOURCE_LIMIT" for error in report["errors"]), report


def test_registered_ast_node_policy_is_enforced(contract_dir, tmp_path, pair):
    registry = registry_with_policy(
        contract_dir, tmp_path, ["profiles", "initial_cpu_modules"], "max_ast_nodes", 1)
    assert_resource_rejection(validate_experiment(pair, registry=registry))


def test_registered_input_byte_policy_is_enforced(contract_dir, tmp_path, pair):
    registry = registry_with_policy(
        contract_dir, tmp_path, ["common_execution"], "max_input_bytes", 1)
    assert_resource_rejection(validate_experiment(json.dumps(pair).encode(), registry=registry))
