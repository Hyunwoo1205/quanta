"""Contract-level rejection checks; no numerical engine is executed here."""

import copy
import json
import math

import pytest

from quanta.validation import validate_experiment


def rejected(value, path=None, codes=None):
    report = validate_experiment(value)
    assert report["valid"] is False, report
    assert report["input_sha256"] is None, report
    assert report["physical_validation_status"] == "unvalidated", report
    assert report["errors"] and all(isinstance(e, dict) for e in report["errors"]), report
    assert all("path" in e and (e["path"] is None or isinstance(e["path"], str))
               for e in report["errors"]), report
    if path is not None:
        assert any(e["path"] is not None and e["path"].startswith(path)
                   for e in report["errors"]), report
    if codes is not None:
        assert any(e["code"] in codes for e in report["errors"]), report
    return report


@pytest.mark.parametrize("fixture_name", ["pair", "quantum"])
def test_frozen_examples_are_valid_without_claiming_physics(fixture_name, request):
    value = request.getfixturevalue(fixture_name)
    report = validate_experiment(value)
    assert report["valid"] is True, report
    assert report["errors"] == [], report
    assert isinstance(report["warnings"], list)
    assert report["schema_version"] == "0.2.0"
    assert report["physical_validation_status"] == "unvalidated"
    assert len(report["input_sha256"]) == 64
    assert report["module_ref"]


def test_validate_does_not_mutate_author_input(pair):
    original = copy.deepcopy(pair)
    assert validate_experiment(pair)["valid"]
    assert pair == original


def test_strict_json_rejects_duplicate_keys_in_nested_object(pair):
    raw = json.dumps(pair).replace('"k": 2,', '"k": 2,"k": 3,')
    assert raw != json.dumps(pair)
    rejected(raw, codes={"INPUT_SCHEMA"})


def test_strict_json_rejects_nonfinite_tokens_and_overflow(pair):
    raw = json.dumps(pair)
    for spelling in ("NaN", "Infinity", "-Infinity", "1e9999"):
        rejected(raw.replace('"k": 2,', '"k": ' + spelling + ','), codes={"INPUT_SCHEMA"})
    # The binary64 profile must also reject an integer it cannot represent,
    # rather than silently changing authored scientific input while parsing.
    unrepresentable = copy.deepcopy(pair)
    unrepresentable["definition"]["system"]["potential"]["parameters"]["k"] = 9007199254740993
    rejected(unrepresentable, codes={"INPUT_SCHEMA", "INPUT_SEMANTIC"})
    rejected(json.dumps(unrepresentable), codes={"INPUT_SCHEMA", "INPUT_SEMANTIC"})
    pair["definition"]["scales"]["length_m"] = math.nan
    rejected(pair, codes={"INPUT_SCHEMA"})


def test_strict_json_rejects_invalid_utf8_and_lone_surrogates(pair):
    rejected(b'{"title":"\xff"}', codes={"INPUT_SCHEMA"})
    candidate = copy.deepcopy(pair)
    candidate["title"] = "\ud800"
    rejected(json.dumps(candidate), codes={"INPUT_SCHEMA"})
    pair["title"] = "\udfff"
    rejected(pair, codes={"INPUT_SCHEMA"})


def test_oversized_raw_json_is_rejected_before_hashing(pair):
    # Added legal whitespace isolates the ingest byte ceiling from title limits.
    raw = json.dumps(pair).encode() + b" " * 1048576
    rejected(raw, codes={"RESOURCE_LIMIT"})


def test_uuid_datetime_version_and_unknown_fields_are_asserted(pair):
    mutations = [("experiment_id", "not-a-uuid"), ("created_at", "2026-99-99"),
                 ("schema_version", "0.1.0"), ("unexpected", 1)]
    for key, value in mutations:
        candidate = copy.deepcopy(pair)
        candidate[key] = value
        rejected(candidate, codes={"INPUT_SCHEMA"})


def test_unknown_exact_module_version_is_unsupported(pair):
    pair["definition"]["system"]["module_version"] = "99.0.0"
    rejected(pair, "/definition/system", {"MODEL_UNSUPPORTED"})


def test_generic_envelope_does_not_enable_unregistered_future_module(pair):
    pair["definition"]["system"]["module_id"] = "future.field_model"
    pair["definition"]["system"]["representation"] = "field_4d"
    rejected(pair, "/definition/system", {"MODEL_UNSUPPORTED"})


def test_module_specific_schema_rejects_solver_boundary_extensions_and_units(pair):
    for key, value in (("solver", "arbitrary_engine"), ("boundary", "periodic"),
                       ("unit_system", "reduced"), ("extensions", {"future": {}})):
        candidate = copy.deepcopy(pair)
        target = candidate["definition"]
        if key == "solver":
            target = target["numerics"]
        elif key == "boundary":
            target = target["system"]
        target[key] = value
        rejected(candidate, "/definition", {"INPUT_SCHEMA"})


def test_positive_scales_mass_and_min_distance_are_required(pair, quantum):
    for experiment, path, key in ((pair, "scales", "length_m"), (pair, "scales", "energy_j"),
                                  (pair, "system", "min_distance_m"),
                                  (quantum, "system", "mass_kg")):
        candidate = copy.deepcopy(experiment)
        candidate["definition"][path][key] = 0
        rejected(candidate, "/definition/" + path, {"INPUT_SCHEMA"})


def test_pair_distance_checks_all_pairs_not_just_adjacent(pair):
    particles = pair["definition"]["system"]["particles"]
    particles.append({"id": "p3", "position_m": [0, 0, 0], "fixed": [False, False, False]})
    rejected(pair, "/definition/system/particles", {"INPUT_SEMANTIC"})


def test_duplicate_particle_ids_and_all_fixed_relax_are_rejected(pair):
    duplicate = copy.deepcopy(pair)
    duplicate["definition"]["system"]["particles"][1]["id"] = "p1"
    rejected(duplicate, "/definition/system/particles", {"INPUT_SEMANTIC"})
    for particle in pair["definition"]["system"]["particles"]:
        particle["fixed"] = [True, True, True]
    rejected(pair, "/definition", {"INPUT_SEMANTIC"})


def test_all_fixed_energy_forces_remains_valid(pair):
    definition = pair["definition"]
    definition["protocol"]["steps"] = [definition["protocol"]["steps"][0]]
    definition["observables"] = ["energy", "forces"]
    for particle in definition["system"]["particles"]:
        particle["fixed"] = [True, True, True]
    assert validate_experiment(pair)["valid"] is True


def test_ast_rejects_unsupported_op_variable_and_undefined_parameter(pair):
    for expression, codes in (
        ({"op": "eval", "text": "2+2"}, {"INPUT_SCHEMA"}),
        ({"op": "var", "name": "xi"}, {"INPUT_SEMANTIC"}),
        ({"op": "param", "name": "missing"}, {"INPUT_SEMANTIC"}),
        ({"op": "pow", "arg": {"op": "const", "value": 2}, "exponent": 13}, {"INPUT_SCHEMA"}),
    ):
        candidate = copy.deepcopy(pair)
        candidate["definition"]["system"]["potential"]["expression"] = expression
        rejected(candidate, "/definition/system/potential", codes)


def test_ast_rejects_domain_and_overflow_failures(pair):
    for expression in (
        {"op": "log", "arg": {"op": "const", "value": -1}},
        {"op": "sqrt", "arg": {"op": "const", "value": -1}},
        {"op": "div", "args": [{"op": "const", "value": 1}, {"op": "const", "value": 0}]},
        {"op": "exp", "arg": {"op": "const", "value": 1000}},
    ):
        candidate = copy.deepcopy(pair)
        candidate["definition"]["system"]["potential"]["expression"] = expression
        rejected(candidate, "/definition/system/potential", {"EXPRESSION_DOMAIN"})


def test_ast_depth_node_count_and_parameter_count_are_bounded(pair):
    deep = {"op": "const", "value": 1}
    for _ in range(17):
        deep = {"op": "neg", "arg": deep}
    broad = {"op": "add", "args": [
        {"op": "add", "args": [
            {"op": "add", "args": [{"op": "const", "value": 1} for _ in range(8)]}
            for _ in range(8)]} for _ in range(2)]}
    for expression in (deep, broad):
        candidate = copy.deepcopy(pair)
        candidate["definition"]["system"]["potential"]["expression"] = expression
        rejected(candidate, "/definition/system/potential", {"RESOURCE_LIMIT", "INPUT_SEMANTIC"})
    pair["definition"]["system"]["potential"]["parameters"].update({f"p{i}": 1 for i in range(33)})
    rejected(pair, "/definition/system/potential", {"INPUT_SCHEMA", "RESOURCE_LIMIT", "INPUT_SEMANTIC"})


def test_protocol_sources_must_be_earlier_and_step_ids_unique(pair):
    for kind in ("forward", "unknown", "duplicate"):
        candidate = copy.deepcopy(pair)
        steps = candidate["definition"]["protocol"]["steps"]
        if kind == "duplicate":
            steps[1]["step_id"] = steps[0]["step_id"]
        else:
            steps[0]["source"] = "relax" if kind == "forward" else "absent"
        rejected(candidate, "/definition/protocol", {"INPUT_SEMANTIC"})


def test_quantum_output_is_not_a_configuration_input(quantum):
    quantum["definition"]["protocol"]["steps"].append(
        {"step_id": "again", "operation": "eigenstates", "source": "spectrum", "overrides": []})
    rejected(quantum, "/definition/protocol", {"PORT_INCOMPATIBLE", "INPUT_SEMANTIC"})


def test_observable_requires_an_eligible_operation_but_can_span_steps(pair):
    # The mixed original protocol is valid although one observable is relax-only.
    assert validate_experiment(pair)["valid"] is True
    pair["definition"]["protocol"]["steps"] = pair["definition"]["protocol"]["steps"][:1]
    rejected(pair, "/definition/observables", {"INPUT_SEMANTIC"})


def test_override_whitelist_existing_targets_and_boolean_types(pair):
    for path, value in (("/scales/length_m", 2e-9),
                        ("/system/potential/parameters/new", 1),
                        ("/system/particles/1/fixed/0", 0),
                        ("/system/particles/1/position_m/0", True)):
        candidate = copy.deepcopy(pair)
        candidate["definition"]["protocol"]["steps"][0]["overrides"] = [{"path": path, "value": value}]
        rejected(candidate, "/definition/protocol", {"INPUT_SEMANTIC", "INPUT_SCHEMA"})


def test_duplicate_and_overlapping_override_paths_are_rejected(pair):
    for patches in (
        [{"path": "/system/particles/1/position_m/0", "value": 1e-9}] * 2,
        [{"path": "/system/particles/1/position_m", "value": [1e-9, 0, 0]},
         {"path": "/system/particles/1/position_m/0", "value": 1e-9}],
    ):
        candidate = copy.deepcopy(pair)
        candidate["definition"]["protocol"]["steps"][0]["overrides"] = patches
        rejected(candidate, "/definition/protocol", {"INPUT_SEMANTIC", "INPUT_SCHEMA"})


def test_allowed_overrides_are_revalidated_for_collisions_and_domains(pair, quantum):
    pair["definition"]["protocol"]["steps"][0]["overrides"] = [
        {"path": "/system/particles/1/position_m/0", "value": 0}]
    rejected(pair, "/definition", {"INPUT_SEMANTIC"})
    quantum["definition"]["protocol"]["steps"][0]["overrides"] = [
        {"path": "/system/domain/b_m", "value": -1e-9}]
    rejected(quantum, "/definition", {"INPUT_SEMANTIC"})


def test_initial_source_resets_prior_overrides_instead_of_inheriting(pair):
    definition = pair["definition"]
    definition["observables"] = ["energy"]
    definition["system"]["potential"]["expression"] = {"op": "log", "arg": {
        "op": "sub", "args": [{"op": "param", "name": "k"}, {"op": "param", "name": "rho0"}]}}
    definition["protocol"]["steps"] = [
        {"step_id": "first", "operation": "energy_forces", "source": "initial", "overrides": [
            {"path": "/system/potential/parameters/k", "value": 1.25}]},
        {"step_id": "reset", "operation": "energy_forces", "source": "initial", "overrides": [
            {"path": "/system/potential/parameters/rho0", "value": 1.5}]},
    ]
    assert validate_experiment(pair)["valid"] is True
    # Base k remains 2: validation must not mutate it with the first patch.
    assert definition["system"]["potential"]["parameters"]["k"] == 2


def test_previous_source_inherits_authored_overrides_before_current_patches(pair):
    definition = pair["definition"]
    definition["observables"] = ["energy"]
    definition["system"]["potential"]["expression"] = {"op": "log", "arg": {
        "op": "sub", "args": [{"op": "param", "name": "k"}, {"op": "param", "name": "rho0"}]}}
    definition["protocol"]["steps"] = [
        {"step_id": "first", "operation": "energy_forces", "source": "initial", "overrides": [
            {"path": "/system/potential/parameters/k", "value": 1.25}]},
        {"step_id": "inherited", "operation": "energy_forces", "source": "first", "overrides": [
            {"path": "/system/potential/parameters/rho0", "value": 1.5}]},
    ]
    rejected(pair, "/definition", {"EXPRESSION_DOMAIN"})


def test_after_relax_source_defers_domain_checks_that_require_actual_output_coordinates(pair):
    definition = pair["definition"]
    definition["observables"] = ["energy"]
    definition["system"]["potential"]["parameters"]["k"] = 1
    definition["system"]["potential"]["expression"] = {"op": "sqrt", "arg": {
        "op": "sub", "args": [{"op": "var", "name": "rho"}, {"op": "param", "name": "k"}]}}
    definition["protocol"]["steps"] = [
        {"step_id": "first", "operation": "relax", "source": "initial", "overrides": []},
        {"step_id": "after", "operation": "energy_forces", "source": "first", "overrides": [
            {"path": "/system/potential/parameters/k", "value": 1.3}]},
    ]
    report = validate_experiment(pair)
    assert report["valid"] is True, report
    assert report["physical_validation_status"] == "unvalidated"
    assert any(warning["code"] == "STATE_DEPENDENT_CHECK_DEFERRED"
               and warning["step_id"] == "after" and warning["branch_index"] == 0
               for warning in report["warnings"]), report
    # An energy_forces source preserves coordinates, so the same patched domain
    # can be checked now instead of being mistaken for unknown solver output.
    definition["protocol"]["steps"][0]["operation"] = "energy_forces"
    rejected(pair, "/definition", {"EXPRESSION_DOMAIN"})


def test_sweep_values_must_be_numeric_and_targets_cannot_be_fixed_masks(pair):
    for path, values in (("/system/particles/1/fixed/0", [False, True]),
                         ("/system/potential/parameters/k", [True]),
                         ("/system/potential/parameters/missing", [1])):
        candidate = copy.deepcopy(pair)
        candidate["definition"]["protocol"]["sweep"]["axes"] = [{"path": path, "values": values}]
        rejected(candidate, "/definition/protocol", {"INPUT_SEMANTIC", "INPUT_SCHEMA"})


def test_sweep_revalidates_each_branch_and_enforces_expanded_step_limit(pair):
    collision = copy.deepcopy(pair)
    collision["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/particles/1/position_m/0", "values": [1e-9, 0]}]
    rejected(collision, "/definition", {"INPUT_SEMANTIC"})
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": list(range(1, 10))}]
    rejected(pair, "/definition/protocol", {"RESOURCE_LIMIT", "INPUT_SEMANTIC"})


def test_exact_expanded_step_limit_is_allowed(pair):
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": list(range(1, 9))}]
    assert validate_experiment(pair)["valid"] is True


def test_duplicate_sweep_targets_and_unregistered_operations_are_rejected(pair):
    duplicate_axes = copy.deepcopy(pair)
    duplicate_axes["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": [1, 2]},
        {"path": "/system/potential/parameters/k", "values": [3, 4]},
    ]
    rejected(duplicate_axes, "/definition/protocol", {"INPUT_SEMANTIC"})
    pair["definition"]["protocol"]["steps"][0]["operation"] = "eigenstates"
    rejected(pair, "/definition/protocol", {"MODEL_UNSUPPORTED", "INPUT_SEMANTIC"})


def test_quantum_domain_order_and_finest_grid_limit(quantum):
    reversed_domain = copy.deepcopy(quantum)
    reversed_domain["definition"]["system"]["domain"] = {"a_m": 1e-9, "b_m": 0}
    rejected(reversed_domain, "/definition/system/domain", {"INPUT_SEMANTIC"})
    quantum["definition"]["numerics"].update(n_points=2047, refinement_levels=2)
    rejected(quantum, "/definition/numerics", {"RESOURCE_LIMIT", "INPUT_SEMANTIC"})


def test_quantum_finest_grid_boundary_and_independent_initial_steps(quantum):
    quantum["definition"]["numerics"].update(n_points=1023, refinement_levels=2)
    quantum["definition"]["protocol"]["steps"].append(
        {"step_id": "other", "operation": "eigenstates", "source": "initial", "overrides": []})
    assert validate_experiment(quantum)["valid"] is True


def test_many_invalid_protocol_steps_have_a_bounded_schema_error_report(pair):
    pair["definition"]["protocol"]["steps"] = [{} for _ in range(500)]
    report = rejected(pair, "/definition/protocol", {"INPUT_SCHEMA"})
    assert len(report["errors"]) <= 100
