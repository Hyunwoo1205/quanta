"""Independent stationary-state references, units and bounded failure semantics."""

import copy
import math

import numpy as np
import pytest

import quanta.quantum as quantum_engine
from quanta.quantum import QuantumError, eigenstates
from quanta.registry import ContractRegistry


# Exact SI Planck constant, independent of the production module's constant.
HBAR = 6.62607015e-34 / (2 * math.pi)
OPTIONAL = {"density_per_m", "x_mean_m", "x2_mean_m2", "kinetic_mean_j", "potential_mean_j"}


@pytest.fixture
def definition(quantum):
    value = copy.deepcopy(quantum["definition"])
    value["numerics"].update(n_points=63, states=4, refinement_levels=0)
    return value


@pytest.fixture
def registry():
    return ContractRegistry()


def checks(payload):
    return {check["id"]: check for check in payload["diagnostics"]["checks"]}


def assert_payload(payload, definition, registry, *, n=None):
    registry.validator("module_results/quantum_stationary.schema.json").validate(payload)
    count = definition["numerics"]["states"]
    n = definition["numerics"]["n_points"] if n is None else n
    x = np.asarray(payload["x_m"])
    real, imag = np.asarray(payload["states"]["real"]), np.asarray(payload["states"]["imag"])
    assert payload["operation"] == "eigenstates"
    assert x.shape == (n + 2,)
    assert real.shape == imag.shape == (count, n + 2)
    assert len(payload["energies_j"]) == count
    assert np.isfinite(x).all() and np.isfinite(real).all()
    assert np.isfinite(payload["energies_j"]).all()
    assert (np.diff(x) > 0).all()
    assert np.array_equal(imag, np.zeros_like(imag))
    assert np.array_equal(real[:, [0, -1]], np.zeros((count, 2)))
    assert x[0] == definition["system"]["domain"]["a_m"]
    assert x[-1] == definition["system"]["domain"]["b_m"]
    assert (np.diff(payload["energies_j"]) > 0).all()
    for name in ("weighted_normalization", "weighted_orthogonality", "eigen_residual", "boundary_zero"):
        assert checks(payload)[name]["status"] == "pass"


def sine_reference(definition, n=None):
    n = definition["numerics"]["n_points"] if n is None else n
    count = definition["numerics"]["states"]
    a, b = (definition["system"]["domain"][name] for name in ("a_m", "b_m"))
    dx = (b - a) / (n + 1)
    indices = np.arange(1, count + 1)
    energies = 4 * (HBAR ** 2 / (2 * definition["system"]["mass_kg"])) / dx**2 * np.sin(indices * np.pi / (2 * (n + 1))) ** 2
    grid_indices = np.arange(n + 2)
    states = np.sqrt(2 / (b - a)) * np.sin(indices[:, None] * np.pi * grid_indices / (n + 1))
    states[:, [0, -1]] = 0
    return energies, states, dx


def test_zero_potential_matches_exact_discrete_spectrum_and_sine_states(definition, registry):
    before = copy.deepcopy(definition)
    payload = eigenstates(definition, registry=registry)
    assert_payload(payload, definition, registry)
    expected_energy, expected_states, dx = sine_reference(definition)
    scale = definition["scales"]["energy_j"]
    np.testing.assert_allclose(np.asarray(payload["energies_j"]) / scale, expected_energy / scale,
                               rtol=1e-8, atol=1e-10)
    actual = np.asarray(payload["states"]["real"])
    # A global sign has no physical effect. Compare signed overlap rather than
    # choosing one branch of the sine's maxima at symmetric points.
    overlaps = np.sum(actual * expected_states, axis=1) * dx
    np.testing.assert_allclose(np.abs(overlaps), 1, rtol=0, atol=1e-11)
    np.testing.assert_allclose(actual * np.sign(overlaps)[:, None], expected_states,
                               rtol=1e-9, atol=1e-8 / math.sqrt(dx))
    np.testing.assert_allclose(actual @ actual.T * dx, np.eye(4), rtol=0, atol=1e-10)
    assert definition == before
    assert [row["n_points"] for row in payload["grid_results"]] == [63]
    assert checks(payload)["grid_energy_convergence"]["status"] == "not_checked"


def test_all_optional_observables_have_si_weights_and_discrete_operator_meanings(definition, registry):
    payload = eigenstates(definition, registry=registry)
    expected_energy, states, dx = sine_reference(definition)
    x = np.asarray(payload["x_m"])
    density = states**2
    assert OPTIONAL <= payload.keys()
    np.testing.assert_allclose(payload["density_per_m"], np.asarray(payload["states"]["real"])**2,
                               rtol=1e-12, atol=0)
    np.testing.assert_allclose(np.sum(payload["density_per_m"], axis=1) * dx, 1, atol=1e-10, rtol=0)
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    np.testing.assert_allclose(np.asarray(payload["x_mean_m"]) / l0,
                               np.sum(density * x, axis=1) * dx / l0, rtol=1e-10, atol=1e-10)
    np.testing.assert_allclose(np.asarray(payload["x2_mean_m2"]) / l0**2,
                               np.sum(density * x*x, axis=1) * dx / l0**2, rtol=1e-10, atol=1e-10)
    np.testing.assert_allclose(np.asarray(payload["kinetic_mean_j"]) / e0, expected_energy / e0,
                               rtol=1e-8, atol=1e-10)
    assert payload["potential_mean_j"] == [0.0] * 4


def test_core_state_remains_when_only_energies_requested(definition, registry):
    definition["observables"] = ["energies"]
    payload = eigenstates(definition, registry=registry)
    assert_payload(payload, definition, registry)
    assert not OPTIONAL & payload.keys()


@pytest.mark.parametrize("observable,field", [
    ("density", "density_per_m"), ("x_mean", "x_mean_m"), ("x2_mean", "x2_mean_m2"),
    ("kinetic_mean", "kinetic_mean_j"), ("potential_mean", "potential_mean_j")])
def test_each_optional_observable_is_selected_independently(definition, registry, observable, field):
    definition["observables"] = [observable]
    payload = eigenstates(definition, registry=registry)
    assert_payload(payload, definition, registry)
    assert OPTIONAL & payload.keys() == {field}


@pytest.mark.parametrize("offset", [2.5, -2.5])
def test_constant_potential_shifts_energy_but_preserves_states_and_kinetic(definition, registry, offset):
    base = eigenstates(definition, registry=registry)
    definition["system"]["potential"] = {"expression": {"op": "param", "name": "offset"},
                                          "parameters": {"offset": offset}}
    shifted = eigenstates(definition, registry=registry)
    e0 = definition["scales"]["energy_j"]
    np.testing.assert_allclose((np.asarray(shifted["energies_j"]) - base["energies_j"]) / e0,
                               offset, rtol=1e-9, atol=1e-9)
    np.testing.assert_allclose(shifted["density_per_m"], base["density_per_m"], rtol=1e-9, atol=1e-6)
    np.testing.assert_allclose(np.asarray(shifted["kinetic_mean_j"]) / e0,
                               np.asarray(base["kinetic_mean_j"]) / e0, rtol=1e-9, atol=1e-9)
    np.testing.assert_allclose(np.asarray(shifted["potential_mean_j"]) / e0, offset, atol=1e-12, rtol=1e-12)


def test_arbitrary_smooth_potential_matches_independent_dense_operator(definition, registry):
    definition["numerics"].update(n_points=31, states=3)
    definition["system"]["domain"] = {"a_m": -2e-9, "b_m": -1e-9}
    definition["system"]["potential"] = {
        "expression": {"op": "add", "args": [
            {"op": "mul", "args": [{"op": "const", "value": 0.3}, {"op": "var", "name": "xi"}]},
            {"op": "cos", "arg": {"op": "var", "name": "xi"}}]}, "parameters": {}}
    payload = eigenstates(definition, registry=registry)
    assert_payload(payload, definition, registry)
    e0, l0 = definition["scales"]["energy_j"], definition["scales"]["length_m"]
    a, b = (definition["system"]["domain"][name] for name in ("a_m", "b_m"))
    dx_si = (b-a)/32
    xi = np.arange(1, 32) * dx_si / l0
    potential = 0.3 * xi + np.cos(xi)
    kinetic = HBAR**2 / (2 * definition["system"]["mass_kg"] * dx_si**2 * e0)
    matrix = np.diag(2 * kinetic + potential) + np.diag(np.full(30, -kinetic), 1) + np.diag(np.full(30, -kinetic), -1)
    expected, _ = np.linalg.eigh(matrix)
    energies = np.asarray(payload["energies_j"]) / e0
    np.testing.assert_allclose(energies, expected[:3], rtol=1e-8, atol=1e-10)
    psi = np.asarray(payload["states"]["real"])
    q = psi[:, 1:-1].T * math.sqrt(dx_si)
    residual = matrix @ q - q * energies
    ratios = np.linalg.norm(residual, axis=0) / ((np.linalg.norm(matrix, ord=np.inf) + np.abs(energies)) * np.linalg.norm(q, axis=0))
    assert np.max(ratios) <= 1e-12
    # The asymmetric potential has a unique largest component in each state.
    assert all(row[np.argmax(np.abs(row))] > 0 for row in psi)
    density = psi[:, 1:-1]**2
    potential_mean = np.sum(density * potential, axis=1) * dx_si
    np.testing.assert_allclose(np.asarray(payload["potential_mean_j"]) / e0, potential_mean, rtol=1e-10, atol=1e-10)
    np.testing.assert_allclose((np.asarray(payload["potential_mean_j"]) + payload["kinetic_mean_j"]) / e0,
                               energies, rtol=1e-10, atol=1e-10)


def test_si_solution_is_independent_of_chosen_length_and_energy_scales(definition, registry):
    baseline = eigenstates(definition, registry=registry)
    definition["scales"] = {"length_m": 2e-10, "energy_j": 3e-21}
    rescaled = eigenstates(definition, registry=registry)
    np.testing.assert_allclose(np.asarray(rescaled["energies_j"]) / 1e-20,
                               np.asarray(baseline["energies_j"]) / 1e-20, rtol=1e-8, atol=1e-10)
    np.testing.assert_allclose(rescaled["density_per_m"], baseline["density_per_m"], rtol=1e-8, atol=1e-5)
    np.testing.assert_allclose(np.asarray(rescaled["x_m"]) / 1e-9,
                               np.asarray(baseline["x_m"]) / 1e-9, rtol=0, atol=1e-14)


def test_domain_translation_changes_absolute_position_expectations(definition, registry):
    baseline = eigenstates(definition, registry=registry)
    shift = 4e-9
    definition["system"]["domain"] = {"a_m": shift, "b_m": shift + 1e-9}
    translated = eigenstates(definition, registry=registry)
    np.testing.assert_allclose(np.asarray(translated["energies_j"]) / 1e-20,
                               np.asarray(baseline["energies_j"]) / 1e-20, rtol=1e-8, atol=1e-10)
    np.testing.assert_allclose(np.asarray(translated["x_mean_m"]) / 1e-9,
                               (np.asarray(baseline["x_mean_m"]) + shift) / 1e-9, rtol=1e-10, atol=1e-10)
    expected_x2 = np.asarray(baseline["x2_mean_m2"]) + 2 * shift * np.asarray(baseline["x_mean_m"]) + shift**2
    np.testing.assert_allclose(np.asarray(translated["x2_mean_m2"]) / 1e-18,
                               expected_x2 / 1e-18, rtol=1e-10, atol=1e-10)


def test_zero_potential_mass_scaling_has_inverse_energy_dependence(definition, registry):
    baseline = eigenstates(definition, registry=registry)
    definition["system"]["mass_kg"] *= 4
    heavy = eigenstates(definition, registry=registry)
    np.testing.assert_allclose(np.asarray(heavy["energies_j"]) / 1e-20,
                               np.asarray(baseline["energies_j"]) / (4e-20), rtol=1e-8, atol=1e-10)
    np.testing.assert_allclose(heavy["density_per_m"], baseline["density_per_m"], rtol=1e-8, atol=1e-6)


def test_requested_refinements_publish_finest_grid_with_actual_grid_energies(definition, registry):
    definition["numerics"].update(n_points=31, refinement_levels=2, grid_energy_rtol=1e-2)
    payload = eigenstates(definition, registry=registry)
    assert_payload(payload, definition, registry, n=127)
    assert [row["n_points"] for row in payload["grid_results"]] == [31, 63, 127]
    e0 = definition["scales"]["energy_j"]
    for row in payload["grid_results"]:
        expected, _, _ = sine_reference(definition, row["n_points"])
        np.testing.assert_allclose(np.asarray(row["energies_j"]) / e0, expected / e0, rtol=1e-8, atol=1e-10)
        assert row["atol"] == definition["numerics"]["grid_energy_atol"]
        assert row["rtol"] == definition["numerics"]["grid_energy_rtol"]
    assert payload["energies_j"] == payload["grid_results"][-1]["energies_j"]
    assert checks(payload)["grid_energy_convergence"]["status"] == "pass"


def test_resolution_failure_retains_valid_finest_solution_but_is_not_success(definition, registry):
    definition["numerics"].update(refinement_levels=1, grid_energy_atol=1e-14, grid_energy_rtol=1e-12)
    before = copy.deepcopy(definition)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    error = caught.value
    assert error.code == "NUM_NOT_CONVERGED"
    assert error.numerical_status == "pass"
    assert error.resolution_status == "not_converged"
    partial = error.partial_payload
    assert_payload(partial, definition, registry, n=127)
    assert [row["n_points"] for row in partial["grid_results"]] == [63, 127]
    assert checks(partial)["grid_energy_convergence"]["status"] == "not_converged"
    assert definition == before


def test_domain_error_is_reported_before_any_solution_is_published(definition, registry):
    definition["system"]["potential"] = {"expression": {"op": "log", "arg": {"op": "var", "name": "xi"}},
                                          "parameters": {}}
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    assert caught.value.code == "EXPRESSION_DOMAIN"
    assert caught.value.partial_payload is None
    assert caught.value.numerical_status == caught.value.resolution_status == "not_checked"


def test_excessive_refinement_is_rejected_without_partial_or_silent_grid_reduction(definition, registry):
    definition["numerics"].update(n_points=4095, refinement_levels=1)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    assert caught.value.code == "RESOURCE_LIMIT"
    assert caught.value.partial_payload is None
    assert caught.value.numerical_status == caught.value.resolution_status == "not_checked"


def test_collapsed_si_grid_is_rejected_without_a_fabricated_uniform_coordinate_array(definition, registry):
    definition["system"]["domain"] = {"a_m": 1.0, "b_m": math.nextafter(1.0, math.inf)}
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    assert caught.value.code in {"INPUT_SEMANTIC", "NUM_NOT_CONVERGED", "ENGINE_FAILURE"}
    assert caught.value.partial_payload is None


def test_nonzero_energy_outside_si_carrier_is_rejected_instead_of_rounded_to_zero(definition, registry):
    # The reduced spectrum is finite positive, but its SI energies are smaller
    # than the least positive binary64 carrier. Input validation permits it.
    definition["numerics"].update(n_points=31, states=1)
    definition["scales"] = {"length_m": 1e50, "energy_j": 1e-250}
    definition["system"].update(domain={"a_m": 0.0, "b_m": 1e100}, mass_kg=1e100)
    definition["observables"] = ["energies"]
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    assert caught.value.code == "EXPRESSION_DOMAIN"
    assert caught.value.partial_payload is None


def test_solver_exception_before_first_complete_grid_has_no_partial(definition, registry, monkeypatch):
    def broken_solver(*args, **kwargs):
        raise np.linalg.LinAlgError("injected solver failure")

    monkeypatch.setattr(quantum_engine, "eigh_tridiagonal", broken_solver)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    error = caught.value
    assert error.code == "ENGINE_FAILURE"
    assert error.partial_payload is None
    assert error.numerical_status == error.resolution_status == "not_checked"


def test_later_solver_exception_preserves_only_the_last_complete_grid(definition, registry, monkeypatch):
    definition["numerics"]["refinement_levels"] = 1
    original = quantum_engine.eigh_tridiagonal
    called = []

    def second_solver_fails(diagonal, *args, **kwargs):
        called.append(len(diagonal))
        if len(called) == 2:
            raise np.linalg.LinAlgError("injected refinement failure")
        return original(diagonal, *args, **kwargs)

    monkeypatch.setattr(quantum_engine, "eigh_tridiagonal", second_solver_fails)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    error = caught.value
    assert error.code == "ENGINE_FAILURE"
    assert called == [63, 127]
    assert error.numerical_status == "pass" and error.resolution_status == "not_checked"
    assert_payload(error.partial_payload, definition, registry, n=63)
    assert [row["n_points"] for row in error.partial_payload["grid_results"]] == [63]
    assert checks(error.partial_payload)["grid_energy_convergence"]["status"] == "not_checked"


def test_solver_success_with_bad_residual_cannot_publish_a_solution(definition, registry, monkeypatch):
    original = quantum_engine.eigh_tridiagonal

    def wrong_energies(*args, **kwargs):
        values, vectors = original(*args, **kwargs)
        return values + 1.0, vectors

    monkeypatch.setattr(quantum_engine, "eigh_tridiagonal", wrong_energies)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    assert caught.value.code == "NUM_NOT_CONVERGED"
    assert caught.value.partial_payload is None
    assert caught.value.numerical_status == "not_converged"
    assert caught.value.resolution_status == "not_checked"


@pytest.mark.parametrize("accepted_grids", [0, 1])
def test_wall_expiry_after_solver_keeps_only_already_checked_grids(definition, registry, monkeypatch, accepted_grids):
    definition["numerics"]["refinement_levels"] = accepted_grids
    registry.resource_policy["common_execution"]["wall_seconds_per_step"] = 0.25
    clock = [0.0]
    called = []
    original = quantum_engine.eigh_tridiagonal

    def elapsed_solver(diagonal, *args, **kwargs):
        called.append(len(diagonal))
        result = original(diagonal, *args, **kwargs)
        if len(called) == accepted_grids + 1:
            clock[0] = 0.3
        return result

    monkeypatch.setattr(quantum_engine.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(quantum_engine, "eigh_tridiagonal", elapsed_solver)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    error = caught.value
    assert error.code == "RESOURCE_LIMIT"
    assert error.details["stop_reason"] == "wall_time_limit"
    assert error.details["limit_seconds"] == 0.25
    assert error.resolution_status == "not_checked"
    if accepted_grids:
        assert_payload(error.partial_payload, definition, registry, n=63)
        assert error.numerical_status == "pass"
        assert [row["n_points"] for row in error.partial_payload["grid_results"]] == [63]
    else:
        assert error.partial_payload is None and error.numerical_status == "not_checked"


@pytest.mark.parametrize("levels", [0, 1])
def test_wall_expiry_in_final_payload_check_prevents_success_without_erasing_evidence(definition, registry, monkeypatch, levels):
    definition["numerics"].update(refinement_levels=levels, grid_energy_rtol=0.05)
    clock = [0.0]
    original = quantum_engine._check_payload
    final_grid_checks = []

    def slow_final_check(payload, **kwargs):
        original(payload, **kwargs)
        if kwargs["completed_grids"] == levels + 1:
            final_grid_checks.append(payload)
            if len(final_grid_checks) == 2:
                clock[0] = 61.0

    monkeypatch.setattr(quantum_engine.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(quantum_engine, "_check_payload", slow_final_check)
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    error = caught.value
    assert error.code == "RESOURCE_LIMIT"
    assert error.details["stop_reason"] == "wall_time_limit"
    assert error.numerical_status == "pass"
    assert error.resolution_status == ("pass" if levels else "not_checked")
    assert_payload(error.partial_payload, definition, registry, n=(64 * 2**levels - 1))
    assert len(error.partial_payload["grid_results"]) == levels + 1


def test_payload_byte_limit_cannot_publish_an_oversized_grid(definition, registry):
    registry.resource_policy["common_execution"]["max_artifact_bytes_per_run"] = 10
    with pytest.raises(QuantumError) as caught:
        eigenstates(definition, registry=registry)
    assert caught.value.code == "RESOURCE_LIMIT"
    assert caught.value.details["limit"] == 10
    assert caught.value.partial_payload is None
