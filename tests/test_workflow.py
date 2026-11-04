"""Scientific control flow and runtime evidence, checked independently of dispatch."""
import copy
import hashlib
import json
import math
import shutil
import uuid

import pytest
import rfc8785

from quanta.registry import ContractRegistry
from quanta.workflow import run_experiment


SCIENTIFIC = ("unit_system", "scales", "system", "numerics", "extensions")
CONTENT = ("module_id", "module_version", "representation", "representation_version", "time_kind",
           "physical_time", "data_schema_ref", "data", "metadata_schema_ref", "metadata")


def digest(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def step(name, operation="energy_forces", source="initial", overrides=None):
    return {"step_id": name, "operation": operation, "source": source, "overrides": overrides or []}


def energy_only(pair):
    authored = copy.deepcopy(pair)
    authored["definition"]["observables"] = ["energy"]
    authored["definition"]["protocol"]["steps"] = [step("measure")]
    return authored


def assert_result(report, registry=None, *, success=True):
    registry = registry or ContractRegistry()
    assert report["valid"], report["errors"]
    result = report["result"]
    registry.validator("result.schema.json").validate(result)
    assert result["execution_status"] == ("SUCCEEDED" if success else "FAILED"), result["errors"]
    assert result["partial"] is (not success)
    assert result["physical_validation_status"] == "unvalidated"
    assert result["physical_validation_evidence_refs"] == []
    assert uuid.UUID(result["run_id"]).version == 4
    for state in result["states"]:
        registry.validator("state.schema.json").validate(state)
        registry.validator(state["data_schema_ref"]).validate(state["data"])
        registry.validator(state["metadata_schema_ref"]).validate(state["metadata"])
        assert uuid.UUID(state["state_id"]).version == 4
    for record in result["steps"]:
        if record["payload"] is not None:
            registry.validator(record["payload_schema_ref"]).validate(record["payload"])
        for artifact in record["artifacts"]:
            registry.validator("artifact.schema.json").validate(artifact)
    for artifact in result["artifacts"]:
        registry.validator("artifact.schema.json").validate(artifact)
    return result


def states_by_id(result):
    return {state["state_id"]: state for state in result["states"]}


def record_map(result):
    return {(entry["branch_index"], entry["step_id"]): entry for entry in result["steps"]}


def registry_limits(contract_dir, tmp_path, **limits):
    path = tmp_path / "contracts"
    shutil.copytree(contract_dir, path)
    policy_path = path / "resource_policy.json"
    policy = json.loads(policy_path.read_text())
    policy["common_execution"].update(limits)
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")
    manifest_path = path / "SHA256SUMS.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resource_policy.json"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    registry = ContractRegistry(path)
    assert registry.validate_integrity() == []
    return registry


def test_pair_chain_passes_actual_relaxed_coordinates_to_the_next_step(pair):
    pair["definition"]["protocol"]["steps"] = [step("settle", "relax"), step("measure", source="settle")]
    before = copy.deepcopy(pair)
    report = run_experiment(pair)
    result = assert_result(report)
    settled, measured = result["steps"]
    assert settled["payload"]["free_gradient_inf"] <= pair["definition"]["numerics"]["gradient_tolerance"]
    assert measured["payload"]["initial_positions_m"] == settled["payload"]["final_positions_m"]
    assert measured["payload"]["final_positions_m"] == measured["payload"]["initial_positions_m"]
    assert math.isclose(measured["payload"]["final_positions_m"][1][0], 1e-9, rel_tol=1e-6)
    assert abs(measured["payload"]["energy_j"] / 1e-19) <= 1e-12
    assert measured["source_binding"]["source_state_ref"] == settled["state_ref"]
    assert measured["source_binding"]["source_output_port"] == "configuration_out"
    assert measured["source_binding"]["conversion_ref"] is None
    assert result["numerical_status"] == "pass"
    assert pair == before


def test_sweep_branches_match_independent_harmonic_values_and_remain_isolated(pair):
    pair = energy_only(pair)
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": [2, 4]},
        {"path": "/system/potential/parameters/rho0", "values": [0.8, 1.0]}]
    report = run_experiment(pair)
    result = assert_result(report)
    expected = [0.5 * k * (1.2 - r0)**2 for k, r0 in [(2, 0.8), (2, 1.0), (4, 0.8), (4, 1.0)]]
    assert [entry["branch_index"] for entry in result["steps"]] == [0, 1, 2, 3]
    for entry, value in zip(result["steps"], expected):
        assert math.isclose(entry["payload"]["energy_j"] / 1e-19, value, rel_tol=1e-12, abs_tol=1e-12)
    initial_refs = report["resolved_record"]["runtime_evidence"]["initial_state_refs"]
    assert len(initial_refs) == 4
    assert len({record["state_ref"] for record in initial_refs}) == 4
    states = states_by_id(result)
    assert [states[record["state_ref"]]["data"]["potential"]["parameters"] for record in initial_refs] == [
        {"k": 2, "rho0": 0.8}, {"k": 2, "rho0": 1.0}, {"k": 4, "rho0": 0.8}, {"k": 4, "rho0": 1.0}]


def test_inherited_overrides_reset_and_original_source_are_distinct(pair):
    pair = energy_only(pair)
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": [2, 3]}]
    pair["definition"]["protocol"]["steps"] = [
        step("changed", overrides=[{"path": "/system/potential/parameters/k", "value": 4},
                                   {"path": "/system/particles/1/position_m/0", "value": 1.4e-9}]),
        step("inherited", source="changed", overrides=[
            {"path": "/system/particles/1/position_m/0", "value": 1.6e-9}]),
        step("reset")]
    before = copy.deepcopy(pair)
    report = run_experiment(pair)
    result = assert_result(report)
    records, states = record_map(result), states_by_id(result)
    for branch, base_k in enumerate([2, 3]):
        first, second, reset = [records[branch, name] for name in ("changed", "inherited", "reset")]
        assert math.isclose(first["payload"]["energy_j"] / 1e-19, 0.5 * 4 * 0.4**2, rel_tol=1e-12)
        assert math.isclose(second["payload"]["energy_j"] / 1e-19, 0.5 * 4 * 0.6**2, rel_tol=1e-12)
        assert math.isclose(reset["payload"]["energy_j"] / 1e-19, 0.5 * base_k * 0.2**2, rel_tol=1e-12)
        binding = second["source_binding"]
        original = states[binding["source_state_ref"]]
        prepared = states[binding["effective_input_state_ref"]]
        assert original["state_id"] == first["state_ref"]
        assert original["state_id"] != prepared["state_id"] != second["state_ref"]
        assert original["data"]["particles"][1]["position_m"][0] == 1.4e-9
        assert prepared["data"]["particles"][1]["position_m"][0] == 1.6e-9
        assert prepared["data"]["potential"]["parameters"]["k"] == 4
        assert prepared["parent_state_refs"] == [original["state_id"]]
        reset_source = states[reset["source_binding"]["source_state_ref"]]
        assert reset_source["producer"]["kind"] == "initial"
        assert reset_source["data"]["potential"]["parameters"]["k"] == base_k
        assert reset_source["data"]["particles"][1]["position_m"][0] == 1.2e-9
    assert pair == before


def test_empty_active_observables_still_produce_required_state_without_optional_outputs(pair):
    pair["definition"]["observables"] = ["optimization_history"]
    report = run_experiment(pair)
    result = assert_result(report)
    first, second = result["steps"]
    assert first["outcome"] == second["outcome"] == "SUCCEEDED"
    assert "optimization_history" not in first["payload"]
    assert "pair_energies" not in first["payload"]
    assert first["state_ref"] is not None
    assert second["payload"]["optimization_history"]
    assert report["plan"]["frozen_plan"]["expanded_steps"][0]["active_observable_refs"] == []


def test_failed_partial_is_not_a_state_and_only_dependents_are_skipped(pair):
    pair["definition"]["numerics"]["max_evaluations"] = 1
    pair["definition"]["protocol"]["steps"] = [
        step("limited", "relax"), step("dependent", source="limited"), step("independent")]
    report = run_experiment(pair)
    result = assert_result(report, success=False)
    limited, dependent, independent = result["steps"]
    assert [item["outcome"] for item in result["steps"]] == ["FAILED", "SKIPPED", "SUCCEEDED"]
    assert limited["partial"] and limited["payload"] is not None
    assert limited["state_ref"] is None
    assert dependent["state_ref"] is dependent["source_binding"] is dependent["resolved_input_sha256"] is None
    assert dependent["payload"] is None and dependent["partial"]
    assert independent["state_ref"] is not None and not independent["partial"]
    assert not any(state["producer"].get("kind") == "step" and state["producer"].get("step_id") in {"limited", "dependent"}
                   for state in result["states"])
    assert any(error["code"] == "RESOURCE_LIMIT" and error["step_id"] == "limited" for error in result["errors"])


def test_failed_branch_does_not_prevent_other_branches_from_running(pair):
    pair["definition"]["numerics"]["max_evaluations"] = 1
    pair["definition"]["protocol"]["steps"] = [step("relax", "relax")]
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/particles/1/position_m/0", "values": [1.2e-9, 1e-9]}]
    report = run_experiment(pair)
    result = assert_result(report, success=False)
    assert [(entry["branch_index"], entry["outcome"]) for entry in result["steps"]] == [(0, "FAILED"), (1, "SUCCEEDED")]
    assert result["steps"][1]["payload"]["free_gradient_inf"] == 0
    assert result["steps"][1]["payload"]["evaluations"] == 1


def test_state_and_step_hashes_follow_separate_contract_projections(pair):
    pair = energy_only(pair)
    pair["definition"]["protocol"]["steps"] = [
        step("first"), step("shifted", source="first", overrides=[
            {"path": "/system/particles/1/position_m/0", "value": 1.4e-9}])]
    report = run_experiment(pair)
    result = assert_result(report)
    evidence = report["resolved_record"]["runtime_evidence"]
    state_hashes = report["state_content_hashes"]
    states = states_by_id(result)
    contexts = evidence["state_unit_contexts"]
    for state_id, state in states.items():
        projection = {name: copy.deepcopy(state[name]) for name in CONTENT}
        projection["unit_context"] = contexts[state_id]
        assert set(contexts[state_id]) == {"unit_system", "scales"}
        assert state_hashes[state_id] == digest(projection)
    expanded = {(item["branch_index"], item["step_id"]): item for item in report["plan"]["frozen_plan"]["expanded_steps"]}
    records = record_map(result)
    for entry in evidence["effective_step_inputs"]:
        key = entry["branch_index"], entry["step_id"]
        planned, actual = expanded[key], records[key]
        source_ref = actual["source_binding"]["source_state_ref"]
        projection = {
            "contract_version": "0.2.0",
            "effective_definition": {name: entry["definition"][name] for name in SCIENTIFIC},
            "operation": planned["operation"], "active_observable_refs": planned["active_observable_refs"],
            "frozen_bindings": entry["projection"]["frozen_bindings"],
            "source_scientific_content_sha256": state_hashes[source_ref]}
        assert entry["projection"] == projection
        assert entry["resolved_input_sha256"] == actual["resolved_input_sha256"] == digest(projection)
        assert actual["resolved_input_sha256"] != result["resolved_input_sha256"]
        prepared_ref = actual["source_binding"]["effective_input_state_ref"]
        assert states[prepared_ref]["resolved_input_sha256"] == actual["resolved_input_sha256"]
    # An override changes the prepared content, but the hash input remains the
    # unchanged successful source selected before that override.
    changed = result["steps"][1]["source_binding"]
    assert state_hashes[changed["source_state_ref"]] != state_hashes[changed["effective_input_state_ref"]]
    assert report["resolved_record"]["frozen_plan"] == report["plan"]["frozen_plan"]
    assert digest(report["plan"]["frozen_plan"]) == result["resolved_input_sha256"]


def test_new_run_ids_do_not_change_scientific_content_hashes_or_execution_identity(pair):
    pair = energy_only(pair)
    first, second = run_experiment(pair), run_experiment(pair)
    a, b = assert_result(first), assert_result(second)
    assert a["run_id"] != b["run_id"]
    assert {state["state_id"] for state in a["states"]}.isdisjoint({state["state_id"] for state in b["states"]})
    assert a["input_sha256"] == b["input_sha256"]
    assert a["resolved_input_sha256"] == b["resolved_input_sha256"]
    assert a["execution_fingerprint"] == b["execution_fingerprint"]
    assert [entry["resolved_input_sha256"] for entry in a["steps"]] == [entry["resolved_input_sha256"] for entry in b["steps"]]
    assert sorted(first["state_content_hashes"].values()) == sorted(second["state_content_hashes"].values())
    assert len(set(first["state_content_hashes"].values())) == 1


def test_equal_sweep_values_keep_distinct_branches_but_equal_scientific_step_hashes(pair):
    pair = energy_only(pair)
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": [2, 2]}]
    report = run_experiment(pair)
    result = assert_result(report)
    first, second = result["steps"]
    assert first["branch_index"] == 0 and second["branch_index"] == 1
    assert first["state_ref"] != second["state_ref"]
    assert first["resolved_input_sha256"] == second["resolved_input_sha256"]
    assert len(set(report["state_content_hashes"].values())) == 1


def test_state_scientific_identity_includes_unit_context_even_when_data_is_equal(pair):
    pair = energy_only(pair)
    first = run_experiment(pair)
    pair["definition"]["scales"]["length_m"] = 2e-9
    second = run_experiment(pair)
    a, b = assert_result(first), assert_result(second)
    a_initial = next(state for state in a["states"] if state["producer"]["kind"] == "initial")
    b_initial = next(state for state in b["states"] if state["producer"]["kind"] == "initial")
    assert a_initial["data"] == b_initial["data"]
    assert a_initial["metadata"] == b_initial["metadata"]
    assert first["state_content_hashes"][a_initial["state_id"]] != second["state_content_hashes"][b_initial["state_id"]]


def test_changed_recorded_environment_changes_fingerprint_without_changing_scientific_input(pair, monkeypatch):
    from quanta import workflow

    pair = energy_only(pair)
    observed = workflow.environment_report()
    assert observed["valid"]
    monkeypatch.setattr(workflow, "environment_report", lambda: copy.deepcopy(observed))
    first = run_experiment(pair)
    # Controlled manifest fault injection: the unchanged numerical backend is
    # not presented as a real alternative environment measurement.
    observed["numpy_build_configuration"]["workflow_test_observation"] = "changed captured field"
    second = run_experiment(pair)
    a, b = assert_result(first), assert_result(second)
    assert a["input_sha256"] == b["input_sha256"]
    assert a["resolved_input_sha256"] == b["resolved_input_sha256"]
    assert a["provenance"]["implementation_manifest_sha256"] == b["provenance"]["implementation_manifest_sha256"]
    assert a["provenance"]["environment_manifest_sha256"] != b["provenance"]["environment_manifest_sha256"]
    assert a["execution_fingerprint"] != b["execution_fingerprint"]
    assert a["steps"][0]["payload"] == b["steps"][0]["payload"]


def test_artifact_byte_hashes_and_bound_execution_manifests_are_actual(pair):
    report = run_experiment(energy_only(pair))
    result = assert_result(report)
    artifacts = {artifact["artifact_id"]: artifact for artifact in result["artifacts"]}
    for record in result["steps"]:
        for artifact in record["artifacts"]:
            assert artifact["artifact_id"] in artifacts
            assert artifacts[artifact["artifact_id"]] == artifact
    assert set(report["artifact_contents"]) == artifacts.keys()
    for identity, metadata in artifacts.items():
        raw = report["artifact_contents"][identity].encode("utf-8")
        assert metadata["size_bytes"] == len(raw)
        assert metadata["sha256"] == hashlib.sha256(raw).hexdigest()
    for sha, text in report["captured_artifacts"].items():
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == sha
    manifests = report["plan"]["execution_manifests"]
    projection = {"contract_version": "0.2.0", "run_resolved_input_sha256": result["resolved_input_sha256"],
                  **manifests, "environment_manifest_sha256": result["provenance"]["environment_manifest_sha256"]}
    assert set(projection) == {"contract_version", "run_resolved_input_sha256", "implementation_manifest_sha256",
        "dependency_manifest_sha256", "constants_manifest_sha256", "resource_policy_sha256",
        "effective_resource_profile_sha256", "environment_manifest_sha256"}
    assert all(projection[name] in report["captured_artifacts"] for name in projection if name.endswith("manifest_sha256") or name in {"resource_policy_sha256", "effective_resource_profile_sha256"})
    assert result["execution_fingerprint"] == digest(projection)
    environment = json.loads(report["captured_artifacts"][result["provenance"]["environment_manifest_sha256"]])
    dependency = json.loads(report["captured_artifacts"][manifests["dependency_manifest_sha256"]])
    expected_versions = {item["name"]: item["version"] for item in dependency["locked_distributions"]}
    assert len(expected_versions) == 20
    assert environment["locked_distribution_versions"] == expected_versions
    assert environment["package_distribution"]["version"] == environment["package_distribution"]["expected_version"]


def test_quantum_independent_initial_steps_and_mass_change_follow_the_plan(quantum):
    quantum["definition"]["numerics"].update(n_points=31, refinement_levels=0)
    quantum["definition"]["observables"] = ["energies"]
    quantum["definition"]["protocol"]["steps"] = [step("light", "eigenstates"),
        step("heavy", "eigenstates", overrides=[{"path": "/system/mass_kg", "value": 4e-30}])]
    report = run_experiment(quantum)
    result = assert_result(report)
    light, heavy = result["steps"]
    for a, b in zip(light["payload"]["energies_j"], heavy["payload"]["energies_j"]):
        assert math.isclose(a, 4 * b, rel_tol=1e-8)
    assert light["source_binding"]["source_alias"] == heavy["source_binding"]["source_alias"] == "initial"
    assert result["numerical_status"] == "pass"
    assert result["resolution_status"] == "not_checked"
    quantum["definition"]["protocol"]["steps"][1]["source"] = "light"
    rejected = run_experiment(quantum)
    assert not rejected["valid"] and rejected["result"] is None
    assert any(error["code"] == "PORT_INCOMPATIBLE" for error in rejected["errors"])


def test_quantum_numerics_changes_step_identity_without_changing_initial_state_content(quantum):
    quantum["definition"]["numerics"].update(n_points=31, refinement_levels=0)
    quantum["definition"]["observables"] = ["energies"]
    quantum["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/numerics/n_points", "values": [31, 63]}]
    report = run_experiment(quantum)
    result = assert_result(report)
    initial = report["resolved_record"]["runtime_evidence"]["initial_state_refs"]
    assert initial[0]["state_ref"] != initial[1]["state_ref"]
    assert report["state_content_hashes"][initial[0]["state_ref"]] == report["state_content_hashes"][initial[1]["state_ref"]]
    assert result["steps"][0]["resolved_input_sha256"] != result["steps"][1]["resolved_input_sha256"]


def test_invalid_input_has_no_fabricated_run_or_scientific_identity():
    report = run_experiment('{"schema_version":"0.2.0","schema_version":"0.2.0"}')
    assert not report["valid"]
    assert report["result"] is None
    assert report["errors"]
    assert not report.get("state_content_hashes")


@pytest.mark.parametrize("scope", ["step", "run"])
def test_captured_time_limits_distinguish_local_failure_from_global_stop(pair, contract_dir, tmp_path, monkeypatch, scope):
    from quanta import workflow

    pair = energy_only(pair)
    pair["definition"]["protocol"]["steps"] = [step("first"), step("independent")]
    limits = {"wall_seconds_per_step": 0.25 if scope == "step" else 2,
              "wall_seconds_per_run": 0.25 if scope == "run" else 2}
    registry = registry_limits(contract_dir, tmp_path, **limits)
    clock, calls = [0.0], [0]
    original = workflow._dispatch

    def delayed_first(definition, operation, selected_registry, check_deadline):
        value = original(definition, operation, selected_registry, check_deadline)
        calls[0] += 1
        if calls[0] == 1:
            clock[0] = 0.3
            check_deadline()
        return value

    monkeypatch.setattr(workflow.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(workflow, "_dispatch", delayed_first)
    report = run_experiment(pair, registry=registry)
    result = assert_result(report, registry, success=False)
    first, second = result["steps"]
    assert first["outcome"] == "FAILED" and first["state_ref"] is None
    assert result["errors"][0]["code"] == "RESOURCE_LIMIT"
    assert result["errors"][0]["details"]["scope"] == scope
    if scope == "step":
        assert second["outcome"] == "SUCCEEDED"
    else:
        assert second["outcome"] == "SKIPPED"
        assert second["source_binding"] is second["resolved_input_sha256"] is None


def test_evidence_too_large_for_policy_is_rejected_before_run_acceptance(pair, contract_dir, tmp_path):
    registry = registry_limits(contract_dir, tmp_path, max_artifact_bytes_per_run=1)
    report = run_experiment(energy_only(pair), registry=registry)
    assert report["valid"]  # The scientific definition and symbolic plan are valid.
    assert report["result"] is None
    assert any(error["code"] == "RESOURCE_LIMIT" for error in report["errors"])
    assert report["state_content_hashes"] == {}


@pytest.mark.parametrize("fault", ["mismatch", "missing"])
def test_transitive_locked_dependency_fault_stops_before_fingerprint_or_dispatch(pair, monkeypatch, fault):
    from quanta import workflow

    original_version = workflow.metadata.version
    calls = []

    def faulty_version(name):
        if name == "attrs":
            if fault == "missing":
                raise workflow.metadata.PackageNotFoundError(name)
            return "0.0.0"
        return original_version(name)

    def forbidden_dispatch(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("A locked-environment rejection cannot dispatch a numerical kernel")

    monkeypatch.setattr(workflow.metadata, "version", faulty_version)
    monkeypatch.setattr(workflow, "_dispatch", forbidden_dispatch)
    # The earlier six-library observation remains valid: attrs is a separate
    # transitive lock entry, so this failure must come from the complete lock.
    assert workflow.environment_report()["valid"]
    report = run_experiment(energy_only(pair))
    result = assert_result(report, success=False)
    assert calls == []
    assert result["execution_fingerprint"] is None
    assert result["provenance"]["started_at"] is None
    assert result["states"] == []
    assert all(record["outcome"] == "SKIPPED" and record["resolved_input_sha256"] is None
               and record["source_binding"] is None for record in result["steps"])
    assert result["errors"][0]["code"] == "MODEL_UNSUPPORTED"
    environment = json.loads(report["captured_artifacts"][result["provenance"]["environment_manifest_sha256"]])
    assert not environment["valid"]
    assert len(environment["locked_distribution_versions"]) == 20
    assert environment["locked_distribution_versions"]["attrs"] == (None if fault == "missing" else "0.0.0")
    expected_code = "ENV_DEPENDENCY" if fault == "missing" else "ENV_LOCK_VERSION"
    assert any(error["code"] == expected_code and error["path"] == "/locked_distribution_versions/attrs"
               for error in environment["errors"])
