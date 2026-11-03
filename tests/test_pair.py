"""A01--A03 and SI equivalence for the single energy/force evaluator.

References use closed-form harmonic mechanics and independent central
differences, not the production differentiation implementation.
"""

import copy
import math

import numpy as np
import pytest

from quanta.pair import evaluate_pair
from quanta.registry import ContractRegistry


@pytest.fixture
def registry():
    return ContractRegistry()


@pytest.fixture
def definition(pair):
    d = copy.deepcopy(pair["definition"])
    d["protocol"]["steps"] = [{"step_id": "evaluate", "operation": "energy_forces",
                               "source": "initial", "overrides": []}]
    d["observables"] = ["energy", "forces", "pair_energies", "final_positions"]
    d["scales"] = {"length_m": 2e-9, "energy_j": 7e-20}
    d["system"]["potential"]["parameters"] = {"k": 2.7, "rho0": 0.8}
    reduced = np.array([[-0.3, 0.2, 0.1], [1.2, -0.4, 0.5],
                        [0.15, 1.3, -0.7], [-0.8, -0.7, 1.1]])
    set_positions(d, reduced * d["scales"]["length_m"])
    d["system"]["particles"][0]["fixed"] = [True, True, True]
    d["system"]["particles"][1]["fixed"] = [False, True, False]
    return d


def set_positions(definition, positions):
    old_particles = definition["system"]["particles"]
    definition["system"]["particles"] = [
        {"id": f"p{i}", "position_m": list(map(float, position)),
         "fixed": copy.deepcopy(old_particles[i]["fixed"]) if i < len(old_particles) else [False]*3}
        for i, position in enumerate(positions)]


def reduced_output(payload, definition):
    e0 = definition["scales"]["energy_j"]
    f0 = e0 / definition["scales"]["length_m"]
    return payload["energy_j"]/e0, np.asarray(payload["forces_n"])/f0


def harmonic_closed_form(positions, k, rest):
    """Vectorized analytic reference in reduced coordinates, without an AST."""
    x = np.asarray(positions)
    i, j = np.triu_indices(len(x), 1)
    displacement = x[i]-x[j]
    radii = np.linalg.norm(displacement, axis=1)
    energy = 0.5*k*np.dot(radii-rest, radii-rest)
    pair_force = -k*(radii-rest)[:, None]*displacement/radii[:, None]
    forces = np.zeros_like(x)
    np.add.at(forces, i, pair_force)
    np.add.at(forces, j, -pair_force)
    return float(energy), forces


def normalized_max(actual, reference):
    return float(np.max(np.abs(np.asarray(actual)-reference)) / max(1.0, float(np.max(np.abs(reference)))))


def test_a01_harmonic_energy_and_each_force_component(definition, registry, record_property):
    l0 = definition["scales"]["length_m"]
    positions = np.array([p["position_m"] for p in definition["system"]["particles"]])/l0
    reference_e, reference_f = harmonic_closed_form(positions, 2.7, 0.8)
    actual_e, actual_f = reduced_output(evaluate_pair(definition, registry=registry), definition)
    np.testing.assert_allclose(actual_e, reference_e, atol=1e-10, rtol=1e-10)
    np.testing.assert_allclose(actual_f, reference_f, atol=1e-10, rtol=1e-10)
    record_property("A01_energy_abs_error", abs(actual_e-reference_e))
    record_property("A01_force_max_abs_error", float(np.max(np.abs(actual_f-reference_f))))


def test_two_body_force_direction_and_fixed_coordinate_reactions(definition, registry):
    l0 = definition["scales"]["length_m"]
    set_positions(definition, np.array([[0, 0, 0], [1.02, 1.36, 0]])*l0)
    definition["system"]["particles"][0]["fixed"] = [True]*3
    definition["system"]["particles"][1]["fixed"] = [False, True, True]
    definition["system"]["potential"]["parameters"] = {"k": 2.5, "rho0": 1.1}
    payload = evaluate_pair(definition, registry=registry)
    energy, forces = reduced_output(payload, definition)
    np.testing.assert_allclose(energy, 0.45, atol=1e-10, rtol=1e-10)
    np.testing.assert_allclose(forces, [[0.9, 1.2, 0], [-0.9, -1.2, 0]], atol=1e-10, rtol=1e-10)
    assert payload["free_gradient_inf"] == pytest.approx(0.9, abs=1e-10, rel=1e-10)


def test_a02_central_differences_at_three_reduced_steps(definition, registry, record_property):
    # A smooth nonquadratic potential exercises more than the harmonic derivative.
    definition["system"]["potential"] = {"parameters": {}, "expression": {
        "op": "add", "args": [
            {"op": "exp", "arg": {"op": "neg", "arg": {"op": "var", "name": "rho"}}},
            {"op": "mul", "args": [{"op": "const", "value": 0.15},
                                       {"op": "pow", "arg": {"op": "var", "name": "rho"}, "exponent": 3}]},
            {"op": "sin", "arg": {"op": "var", "name": "rho"}},
        ]}}
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    _, forces = reduced_output(evaluate_pair(definition, registry=registry), definition)
    residuals = []
    for step in (1e-4, 1e-5, 1e-6):
        gradient = np.empty_like(forces)
        for particle in range(len(forces)):
            for axis in range(3):
                plus, minus = copy.deepcopy(definition), copy.deepcopy(definition)
                plus["system"]["particles"][particle]["position_m"][axis] += step*l0
                minus["system"]["particles"][particle]["position_m"][axis] -= step*l0
                gradient[particle, axis] = (
                    evaluate_pair(plus, registry=registry)["energy_j"]/e0
                    - evaluate_pair(minus, registry=registry)["energy_j"]/e0)/(2*step)
        residual = float(np.max(np.abs(forces+gradient))/max(1.0, float(np.max(np.abs(forces)))))
        residuals.append(residual)
        record_property(f"A02_residual_h_{step:g}", residual)
    assert any(residuals[i] <= 1e-6 and residuals[i+1] <= 1e-6 for i in range(2)), residuals


def test_a03_translation_rotation_permutation_and_internal_balance(definition, registry, record_property):
    l0 = definition["scales"]["length_m"]
    positions = np.array([p["position_m"] for p in definition["system"]["particles"]])
    baseline = evaluate_pair(definition, registry=registry)
    energy, forces = reduced_output(baseline, definition)
    axis = np.array([1., 2., 3.])/math.sqrt(14)
    skew = np.array([[0, -axis[2], axis[1]], [axis[2], 0, -axis[0]], [-axis[1], axis[0], 0]])
    angle = 0.73
    rotation = np.eye(3)*math.cos(angle)+(1-math.cos(angle))*np.outer(axis, axis)+math.sin(angle)*skew
    translated, rotated, permuted = (copy.deepcopy(definition) for _ in range(3))
    set_positions(translated, positions+np.array([2.1, -3.2, 0.7])*l0)
    set_positions(rotated, positions@rotation.T)
    permutation = [2, 0, 3, 1]
    permuted["system"]["particles"] = [copy.deepcopy(definition["system"]["particles"][i]) for i in permutation]
    residuals = {}
    for name, candidate, expected_forces in (("translation", translated, forces),
                                             ("rotation", rotated, forces@rotation.T),
                                             ("permutation", permuted, forces[permutation])):
        transformed_e, transformed_f = reduced_output(evaluate_pair(candidate, registry=registry), candidate)
        residuals[name+"_energy"] = abs(transformed_e-energy)/max(1, abs(energy))
        residuals[name+"_forces"] = normalized_max(transformed_f, expected_forces)
    residuals["net_force"] = float(np.max(np.abs(np.sum(forces, axis=0))))
    residuals["net_torque"] = float(np.max(np.abs(np.sum(np.cross(positions/l0, forces), axis=0))))
    for name, residual in residuals.items():
        record_property("A03_"+name, residual)
        assert residual <= 1e-10, (name, residual)


def test_same_physical_model_with_different_reduced_scales(definition, registry):
    # k_phys, rest length and coordinates stay fixed while L0/E0 and reduced
    # potential coefficients change together.
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    physical_k = 2.7*e0/l0**2
    physical_rest = 0.8*l0
    baseline = evaluate_pair(definition, registry=registry)
    for length_ratio, energy_ratio in ((0.25, 7), (3.5, 0.2)):
        candidate = copy.deepcopy(definition)
        length, energy = l0*length_ratio, e0*energy_ratio
        candidate["scales"] = {"length_m": length, "energy_j": energy}
        candidate["system"]["potential"]["parameters"] = {
            "k": physical_k*length**2/energy, "rho0": physical_rest/length}
        actual = evaluate_pair(candidate, registry=registry)
        assert abs(actual["energy_j"]-baseline["energy_j"])/e0 <= 1e-10
        np.testing.assert_allclose(np.asarray(actual["forces_n"])/(e0/l0),
                                   np.asarray(baseline["forces_n"])/(e0/l0), atol=1e-10, rtol=1e-10)


def test_payload_schema_all_pair_indices_and_unchanged_positions(definition, registry):
    original = copy.deepcopy(definition)
    payload = evaluate_pair(definition, registry=registry)
    registry.validator("module_results/pair_static.schema.json").validate(payload)
    assert definition == original
    positions = [p["position_m"] for p in definition["system"]["particles"]]
    assert payload["initial_positions_m"] == positions == payload["final_positions_m"]
    assert np.asarray(payload["forces_n"]).shape == (len(positions), 3)
    assert payload["iterations"] == 0 and payload["evaluations"] == 1
    assert payload["minimum_confirmed"] is False
    assert "optimization_history" not in payload
    expected_pairs = {(i, j) for i in range(len(positions)) for j in range(i+1, len(positions))}
    pairs = payload["pair_energies"]
    assert len(pairs) == len(expected_pairs)
    assert {(p["i"], p["j"]) for p in pairs} == expected_pairs
    assert abs(sum(p["energy_j"] for p in pairs)-payload["energy_j"])/definition["scales"]["energy_j"] <= 1e-13
    for pair in pairs:
        distance = math.dist(positions[pair["i"]], positions[pair["j"]])
        assert pair["distance_m"] == pytest.approx(distance, rel=2e-14, abs=0)
    assert np.isfinite(payload["forces_n"]).all()
    assert math.isfinite(payload["energy_j"]) and math.isfinite(payload["free_gradient_inf"])


def test_optional_pair_array_omitted_and_all_fixed_forces_are_retained(definition, registry):
    definition["observables"] = ["energy"]
    baseline = evaluate_pair(definition, registry=registry)
    for particle in definition["system"]["particles"]:
        particle["fixed"] = [True]*3
    payload = evaluate_pair(definition, registry=registry)
    assert "pair_energies" not in payload
    assert payload["forces_n"] == baseline["forces_n"]
    assert payload["free_gradient_inf"] == 0
    assert np.any(np.asarray(payload["forces_n"]) != 0)


@pytest.mark.parametrize("distance,min_distance", [(0, 1e-17), (1e-9, 1e-9), (0.5e-9, 1e-9)])
def test_direct_pair_api_rejects_collision_or_minimum_distance_violation(definition, registry, distance, min_distance):
    set_positions(definition, [[0, 0, 0], [distance, 0, 0]])
    definition["system"]["min_distance_m"] = min_distance
    with pytest.raises(ValueError):
        evaluate_pair(definition, registry=registry)


@pytest.mark.parametrize("mutation", ["bad_scale", "nonfinite_position", "bad_mask", "bad_variable"])
def test_direct_pair_api_rejects_invalid_scientific_inputs(definition, registry, mutation):
    if mutation == "bad_scale":
        definition["scales"]["length_m"] = 0
    elif mutation == "nonfinite_position":
        definition["system"]["particles"][0]["position_m"][0] = math.inf
    elif mutation == "bad_mask":
        definition["system"]["particles"][0]["fixed"][0] = 1
    else:
        definition["system"]["potential"]["expression"] = {"op": "var", "name": "xi"}
    with pytest.raises(ValueError):
        evaluate_pair(definition, registry=registry)


def test_pair_api_rejects_finite_reduced_value_with_derivative_overflow(definition, registry):
    l0 = definition["scales"]["length_m"]
    set_positions(definition, [[0, 0, 0], [354.8*l0, 0, 0]])
    definition["system"]["potential"]["expression"] = {
        "op": "exp", "arg": {"op": "mul", "args": [
            {"op": "const", "value": 2}, {"op": "var", "name": "rho"}]}}
    with pytest.raises(ValueError):
        evaluate_pair(definition, registry=registry)


@pytest.mark.parametrize("failure", ["energy_restore", "force_restore", "energy_sum"])
def test_si_restoration_and_accumulation_overflow_are_explicit(definition, registry, failure):
    definition["scales"]["energy_j"] = 1e308
    if failure == "force_restore":
        # F0 itself and U are finite. Only F0*f'(rho) exceeds binary64.
        definition["scales"]["length_m"] = 1
        set_positions(definition, [[0, 0, 0], [0.1, 0, 0]])
        expression = {"op": "mul", "args": [{"op": "const", "value": 2},
                                                  {"op": "var", "name": "rho"}]}
    else:
        expression = {"op": "const", "value": 2 if failure == "energy_restore" else 0.5}
    definition["system"]["potential"] = {"parameters": {}, "expression": expression}
    with pytest.raises(ValueError):
        evaluate_pair(definition, registry=registry)


@pytest.mark.parametrize("failure", ["energy_restore", "force_restore"])
def test_nonzero_si_energy_or_force_underflow_is_explicit(definition, registry, failure):
    definition["scales"]["energy_j"] = 1e-200
    if failure == "energy_restore":
        expression = {"op": "const", "value": 1e-200}
    else:
        # U, f' and F0 are representable; their force product is not.
        definition["scales"]["length_m"] = 1
        set_positions(definition, [[0, 0, 0], [1, 0, 0]])
        expression = {"op": "add", "args": [{"op": "const", "value": 1}, {
            "op": "mul", "args": [{"op": "const", "value": 1e-200},
                                        {"op": "var", "name": "rho"}]}]}
    definition["system"]["potential"] = {"parameters": {}, "expression": expression}
    with pytest.raises(ValueError):
        evaluate_pair(definition, registry=registry)


def test_exact_zero_energy_and_force_are_valid_outputs(definition, registry):
    definition["system"]["potential"] = {"parameters": {}, "expression": {"op": "const", "value": 0}}
    payload = evaluate_pair(definition, registry=registry)
    assert payload["energy_j"] == 0
    np.testing.assert_array_equal(payload["forces_n"], np.zeros((4, 3)))
    assert payload["free_gradient_inf"] == 0
