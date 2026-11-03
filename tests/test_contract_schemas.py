"""Synthetic carrier checks only: fixtures are not scientific results."""

import copy

from quanta.registry import ContractRegistry


ID = "11e11111-1111-4111-8111-111111111111"
DIGEST = "0" * 64


def test_artifact_discriminator_does_not_force_array_metadata_on_other_kinds():
    validator = ContractRegistry().validator("artifact.schema.json")
    base = {"contract_version": "0.2.0", "artifact_id": ID, "sha256": DIGEST,
            "size_bytes": 0}
    kinds = [
        {"kind": "text", "mime_type": "text/plain", "encoding": "UTF-8"},
        {"kind": "image", "mime_type": "image/png", "width_px": 1, "height_px": 1},
        {"kind": "config", "mime_type": "application/json", "format": "json",
         "schema_ref": "experiment.schema.json"},
    ]
    for fields in kinds:
        fixture = {**base, **fields}
        assert validator.is_valid(fixture), fixture
        assert not validator.is_valid({**fixture, "shape": [1]})
    array = {**base, "kind": "array", "mime_type": "application/octet-stream",
             "dtype": "float64", "shape": [1], "unit": "J", "axis_order": ["sample"],
             "precision": {"real_dtype": "float64", "complex_encoding": "none", "finite_only": True}}
    assert validator.is_valid(array)
    del array["precision"]
    assert not validator.is_valid(array)


def test_static_state_requires_null_physical_time_and_registered_metadata(pair):
    registry = ContractRegistry()
    fixture = {
        "contract_version": "0.2.0", "state_id": ID,
        "module_id": "quanta.pair_static", "module_version": "0.1.0",
        "representation": "particles_3d", "representation_version": "0.1.0",
        "time_kind": "static", "physical_time": None,
        "data_schema_ref": "module_inputs.schema.json#/$defs/pairSystem",
        "data": pair["definition"]["system"],
        "metadata_schema_ref": "state.schema.json#/$defs/particleMetadata",
        "metadata": {
            "state_role": "configuration", "spatial_dimension": 3,
            "coordinate_system": "cartesian", "coordinate_labels": ["x", "y", "z"],
            "length_unit": "m", "position_shape": [2, 3], "boundary": "nonperiodic",
            "precision": {"real_dtype": "float64", "complex_encoding": "none", "finite_only": True},
        },
        "producer": {"kind": "initial", "revision_id": pair["revision_id"]},
        "resolved_input_sha256": DIGEST, "parent_state_refs": [],
    }
    validator = registry.validator("state.schema.json")
    assert validator.is_valid(fixture)
    # Metadata/data need their own registered second validation, beyond envelope.
    registry.validator(fixture["data_schema_ref"]).validate(fixture["data"])
    registry.validator(fixture["metadata_schema_ref"]).validate(fixture["metadata"])
    fixture["physical_time"] = {"value": 0, "unit": "s"}
    assert not validator.is_valid(fixture)


def empty_result():
    return {
        "schema_version": "0.2.0", "run_id": ID, "revision_id": ID,
        "input_sha256": DIGEST, "resolved_input_sha256": None, "execution_fingerprint": None,
        "execution_status": "QUEUED", "partial": True, "numerical_status": "not_checked",
        "resolution_status": "not_checked", "physical_validation_status": "unvalidated",
        "physical_validation_evidence_refs": [], "steps": [], "states": [], "warnings": [],
        "errors": [], "artifacts": [],
        "provenance": {
            "registry_snapshot_sha256": DIGEST, "module_manifest_sha256": DIGEST,
            "implementation_manifest_sha256": None, "environment_manifest_sha256": None,
            "constants_manifest_sha256": None, "resource_policy_version": "0.2.0",
            "replay_of": None, "started_at": None, "finished_at": None,
        },
    }


def test_unprepared_failure_does_not_invent_successful_binding_hash_or_state():
    validator = ContractRegistry().validator("result.schema.json")
    fixture = empty_result()
    fixture["execution_status"] = "FAILED"
    fixture["provenance"]["finished_at"] = "2026-11-03T12:00:00Z"
    fixture["steps"] = [{
        "branch_index": 0, "step_id": "skipped", "module_id": "quanta.pair_static",
        "module_version": "0.1.0", "resolved_input_sha256": None, "state_ref": None,
        "source_binding": None, "outcome": "SKIPPED", "partial": True,
        "numerical_status": "not_checked", "resolution_status": "not_checked",
        "diagnostics": {"reason": "source preparation unavailable"},
        "payload_schema_ref": "module_results/pair_static.schema.json", "payload": None,
        "artifacts": [],
    }]
    assert validator.is_valid(fixture)
    false_success = copy.deepcopy(fixture)
    false_success["steps"][0]["outcome"] = "SUCCEEDED"
    assert not validator.is_valid(false_success)
    fixture["partial"] = False
    assert not validator.is_valid(fixture)


def test_common_physical_validation_claim_requires_evidence_even_for_future_profiles():
    # Current module validation stays unvalidated; this checks only the common carrier.
    validator = ContractRegistry().validator("result.schema.json")
    fixture = empty_result()
    assert validator.is_valid(fixture)
    fixture["physical_validation_status"] = "validated"
    assert not validator.is_valid(fixture)
    fixture["physical_validation_evidence_refs"] = [{
        "evidence_artifact_id": ID, "scope": "synthetic schema exercise",
        "source_run_id": None, "validation_record_sha256": DIGEST,
    }]
    assert validator.is_valid(fixture)
