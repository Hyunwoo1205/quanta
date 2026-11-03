"""Constrained stationarity, A04 and bounded-failure optimizer contracts.

Analytic harmonic geometry is independent of the optimizer. Solver stubs
exercise acceptance/publication rules without asserting an L-BFGS-B path.
"""

import copy
import hashlib
import json
import math
import shutil
import struct

import numpy as np
import pytest
from scipy.optimize import OptimizeResult

import quanta.relaxation as relaxation
from quanta.registry import ContractRegistry
from quanta.relaxation import RelaxationError, relax_pair


@pytest.fixture
def registry():
    return ContractRegistry()


@pytest.fixture
def definition(pair):
    value = copy.deepcopy(pair["definition"])
    value["protocol"]["steps"] = [{"step_id": "relax", "operation": "relax",
                                   "source": "initial", "overrides": []}]
    value["observables"] = ["energy", "forces", "final_positions", "pair_energies", "optimization_history"]
    value["system"]["particles"][0]["position_m"] = [0.0, -0.0, 0.0]
    value["system"]["particles"][1]["position_m"] = [1.2e-9, -0.0, 0.0]
    return value


def bits(value):
    return struct.pack(">d", float(value))


def assert_fixed_unchanged(payload, definition):
    for index, particle in enumerate(definition["system"]["particles"]):
        for axis, fixed in enumerate(particle["fixed"]):
            if fixed:
                assert bits(payload["final_positions_m"][index][axis]) == bits(particle["position_m"][axis])


def assert_payload(payload, definition, registry):
    registry.validator("module_results/pair_static.schema.json").validate(payload)
    assert payload["operation"] == "relax"
    assert payload["minimum_confirmed"] is False
    assert payload["initial_positions_m"] == [p["position_m"] for p in definition["system"]["particles"]]
    assert np.asarray(payload["forces_n"]).shape == (len(definition["system"]["particles"]), 3)
    assert np.isfinite(payload["forces_n"]).all()
    assert math.isfinite(payload["energy_j"]) and math.isfinite(payload["free_gradient_inf"])
    assert_fixed_unchanged(payload, definition)
    if "optimization_history" in definition["observables"]:
        history = payload["optimization_history"]
        assert [row["iteration"] for row in history] == list(range(payload["iterations"]+1))
        assert len(history) == payload["iterations"]+1
        assert history[-1]["energy_j"] == payload["energy_j"]
        assert history[-1]["free_gradient_inf"] == payload["free_gradient_inf"]


def assert_failed(error, definition, registry, stop_reason, numerical_status=None):
    assert isinstance(error, ValueError)
    assert isinstance(error.code, str) and isinstance(error.path, str)
    assert isinstance(error.details, dict)
    assert error.numerical_status in {"pass", "not_converged"}
    if numerical_status is not None:
        assert error.numerical_status == numerical_status
    partial = error.partial_payload
    assert partial is not None
    assert_payload(partial, definition, registry)
    assert partial["stop_reason"] == stop_reason
    assert partial["evaluations"] <= definition["numerics"]["max_evaluations"]
    assert partial["iterations"] <= definition["numerics"]["max_iterations"]
    return partial


def assert_harmonic_result_matches_final_geometry(payload, definition):
    """Closed-form energy/force at the reported final points, without the AST."""
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    points = np.asarray(payload["final_positions_m"])
    displacement = (points[0]-points[1])/l0
    distance = float(np.linalg.norm(displacement))
    parameters = definition["system"]["potential"]["parameters"]
    extension = distance-parameters["rho0"]
    expected_energy = 0.5*parameters["k"]*extension**2
    first_force = -parameters["k"]*extension*displacement/distance
    expected_forces = np.array([first_force, -first_force])
    np.testing.assert_allclose(payload["energy_j"]/e0, expected_energy, atol=1e-10, rtol=1e-10)
    np.testing.assert_allclose(np.asarray(payload["forces_n"])/(e0/l0), expected_forces,
                               atol=1e-10, rtol=1e-10)
    expected_free_gradient = max(abs(expected_forces[i, axis])
                                 for i, particle in enumerate(definition["system"]["particles"])
                                 for axis, fixed in enumerate(particle["fixed"]) if not fixed)
    assert payload["free_gradient_inf"] == pytest.approx(expected_free_gradient, abs=1e-10, rel=1e-10)


def test_a04_constrained_harmonic_pair_matches_rest_distance(definition, registry, record_property):
    original = copy.deepcopy(definition)
    payload = relax_pair(definition, registry=registry)
    assert_payload(payload, definition, registry)
    assert_harmonic_result_matches_final_geometry(payload, definition)
    l0 = definition["scales"]["length_m"]
    distance_error = abs(math.dist(*payload["final_positions_m"])/l0-1)
    assert payload["free_gradient_inf"] <= 1e-6
    assert distance_error <= 1e-6
    assert payload["stop_reason"] == "gradient_tolerance"
    assert payload["energy_j"]/definition["scales"]["energy_j"] <= 1e-12
    assert payload["evaluations"] > 1 and payload["iterations"] > 0
    assert definition == original
    assert_fixed_unchanged(payload, original)
    for index, particle in enumerate(original["system"]["particles"]):
        for axis, coordinate in enumerate(particle["position_m"]):
            assert bits(definition["system"]["particles"][index]["position_m"][axis]) == bits(coordinate)
            assert bits(payload["initial_positions_m"][index][axis]) == bits(coordinate)
    record_property("A04_free_gradient_inf", payload["free_gradient_inf"])
    record_property("A04_rest_distance_error_reduced", distance_error)
    record_property("A04_iterations", payload["iterations"])
    record_property("A04_evaluations", payload["evaluations"])


@pytest.mark.parametrize("distance,k", [(1.0, 2.0), (1.0+2e-7, 2.0), (1.0, -2.0)])
def test_initial_stationarity_uses_free_gradient_without_claiming_minimum(definition, registry, monkeypatch, distance, k):
    def solver_must_not_run(*args, **kwargs):
        pytest.fail("The already accepted initial gradient satisfies the tolerance")

    monkeypatch.setattr(relaxation, "minimize", solver_must_not_run)
    l0 = definition["scales"]["length_m"]
    definition["system"]["particles"][1]["position_m"][0] = distance*l0
    definition["system"]["potential"]["parameters"]["k"] = k
    payload = relax_pair(definition, registry=registry)
    assert_payload(payload, definition, registry)
    assert payload["iterations"] == 0 and payload["evaluations"] == 1
    assert payload["free_gradient_inf"] <= definition["numerics"]["gradient_tolerance"]
    assert payload["stop_reason"] == "gradient_tolerance"
    # Negative curvature is stationary too; no stability certificate is inferred.
    assert payload["minimum_confirmed"] is False


def test_free_gradient_excludes_nonzero_fixed_coordinate_reactions(definition, registry):
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    definition["system"]["particles"][1]["position_m"] = [0.0, 1.2*l0, 0.0]
    payload = relax_pair(definition, registry=registry)
    assert_payload(payload, definition, registry)
    assert payload["free_gradient_inf"] == 0
    assert payload["iterations"] == 0 and payload["evaluations"] == 1
    np.testing.assert_allclose(np.asarray(payload["forces_n"])/(e0/l0),
                               [[0, 0.4, 0], [0, -0.4, 0]], atol=1e-10, rtol=1e-10)


def test_multifree_harmonic_geometry_and_translated_physical_units(definition, registry):
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    offset = np.array([0.35, -0.27, 0.8])
    relative = np.array([1.2, 0.9, -0.6])
    definition["system"]["particles"][0]["position_m"] = (offset*l0).tolist()
    definition["system"]["particles"][1]["position_m"] = ((offset+relative)*l0).tolist()
    definition["system"]["particles"][1]["fixed"] = [False, False, False]
    baseline = relax_pair(definition, registry=registry)
    assert_payload(baseline, definition, registry)
    assert_harmonic_result_matches_final_geometry(baseline, definition)
    assert baseline["free_gradient_inf"] <= 1e-6
    assert abs(math.dist(*baseline["final_positions_m"])/l0-1) <= 1e-6
    for length_ratio, energy_ratio, shift in ((2.5, 0.2, np.zeros(3)),
                                             (1, 1, np.array([3., -2., 1.]))):
        candidate = copy.deepcopy(definition)
        length, energy = length_ratio*l0, energy_ratio*e0
        candidate["scales"] = {"length_m": length, "energy_j": energy}
        candidate["system"]["potential"]["parameters"] = {
            "k": (2*e0/l0**2)*length**2/energy, "rho0": l0/length}
        for particle in candidate["system"]["particles"]:
            particle["position_m"] = (np.asarray(particle["position_m"])+shift*l0).tolist()
        result = relax_pair(candidate, registry=registry)
        assert_payload(result, candidate, registry)
        assert_harmonic_result_matches_final_geometry(result, candidate)
        assert result["free_gradient_inf"] <= candidate["numerics"]["gradient_tolerance"]
        assert abs(math.dist(*result["final_positions_m"])/l0-1) <= 1e-6
        assert abs(result["energy_j"])/e0 <= 1e-12
        assert np.max(np.abs(np.asarray(result["forces_n"])/(e0/l0))) <= 1e-6
        if length_ratio == energy_ratio == 1:
            np.testing.assert_allclose(np.asarray(result["final_positions_m"])/l0-shift,
                                       np.asarray(baseline["final_positions_m"])/l0, atol=1e-6, rtol=0)
        # The sphere of radial minima is nonunique. Changing reduced scales
        # need not make a solver select the same point on that sphere.


def test_all_fixed_relaxation_is_rejected_without_a_partial_state(definition, registry):
    for particle in definition["system"]["particles"]:
        particle["fixed"] = [True]*3
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    assert captured.value.partial_payload is None
    assert captured.value.numerical_status == "not_checked"


def test_actual_evaluation_limit_one_preserves_initial_reactions(definition, registry):
    definition["numerics"]["max_evaluations"] = 1
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "evaluation_limit", "not_converged")
    assert captured.value.code == "RESOURCE_LIMIT"
    assert partial["iterations"] == 0 and partial["evaluations"] == 1
    assert partial["final_positions_m"] == partial["initial_positions_m"]
    e0, l0 = definition["scales"]["energy_j"], definition["scales"]["length_m"]
    np.testing.assert_allclose(np.asarray(partial["forces_n"])/(e0/l0),
                               [[0.4, 0, 0], [-0.4, 0, 0]], atol=1e-10, rtol=1e-10)


def test_actual_quartic_iteration_limit_one_is_not_convergence(definition, registry):
    definition["numerics"]["max_iterations"] = 1
    definition["system"]["particles"][1]["position_m"][0] = 2.3*definition["scales"]["length_m"]
    definition["system"]["potential"] = {"parameters": {}, "expression": {
        "op": "mul", "args": [{"op": "const", "value": 0.25}, {
            "op": "pow", "exponent": 4, "arg": {"op": "sub", "args": [
                {"op": "var", "name": "rho"}, {"op": "const", "value": 1}]}}]}}
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "iteration_limit", "not_converged")
    assert captured.value.code == "RESOURCE_LIMIT"
    assert partial["iterations"] == 1
    assert partial["free_gradient_inf"] > definition["numerics"]["gradient_tolerance"]
    assert partial["evaluations"] >= 2


def test_solver_energy_only_success_cannot_override_unconverged_gradient(definition, registry, monkeypatch):
    definition["numerics"]["energy_ftol"] = 1e-4

    def energy_only_stop(fun, x0, *args, **kwargs):
        energy, gradient = fun(np.array(x0, copy=True))
        return OptimizeResult(x=np.array(x0, copy=True), fun=energy, jac=gradient,
                              success=True, status=0, nit=0, nfev=9999,
                              message="CONVERGENCE: REL_REDUCTION_OF_F_<=_FACTR*EPSMCH")

    monkeypatch.setattr(relaxation, "minimize", energy_only_stop)
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "energy_tolerance_without_gradient", "not_converged")
    assert partial["free_gradient_inf"] > definition["numerics"]["gradient_tolerance"]
    assert partial["evaluations"] == 1


def test_actual_kernel_counts_ignore_solver_report_and_cached_duplicates(definition, registry, monkeypatch):
    definition["numerics"].update(max_evaluations=2, max_iterations=1)
    calls = []

    def accepted_stationary_step(fun, x0, *args, **kwargs):
        x0 = np.array(x0, copy=True)
        assert x0.shape == (1,)
        for _ in range(3):
            calls.append(fun(x0.copy()))
        final = x0.copy()
        # Reduced displacements are independent of the solver's origin choice.
        final[0] -= 0.2
        energy, gradient = fun(final.copy())
        kwargs["callback"](final.copy())
        return OptimizeResult(x=final, fun=energy, jac=gradient,
                              success=True, status=0, nit=3000, nfev=4000,
                              message="CONVERGENCE: NORM_OF_PROJECTED_GRADIENT_<=_PGTOL")

    monkeypatch.setattr(relaxation, "minimize", accepted_stationary_step)
    result = relax_pair(definition, registry=registry)
    assert_payload(result, definition, registry)
    assert len(calls) == 3
    assert result["evaluations"] == 2
    assert result["iterations"] == 1
    assert result["stop_reason"] == "gradient_tolerance"


@pytest.mark.parametrize("invalid_trial", ["collision", "log_domain"])
def test_invalid_trial_retains_last_accepted_state_and_excludes_trial_history(definition, registry, monkeypatch, invalid_trial):
    if invalid_trial == "log_domain":
        definition["system"]["potential"] = {"parameters": {"wall": 0.9}, "expression": {
            "op": "log", "arg": {"op": "sub", "args": [
                {"op": "var", "name": "rho"}, {"op": "param", "name": "wall"}]}}}
    original = copy.deepcopy(definition)

    def invalid_after_accepted(fun, x0, *args, **kwargs):
        x0 = np.array(x0, copy=True)
        fun(x0.copy())
        unaccepted = x0.copy()
        unaccepted[0] -= 0.1
        fun(unaccepted)
        accepted = x0.copy()
        accepted[0] -= 0.25
        fun(accepted.copy())
        kwargs["callback"](accepted.copy())
        invalid = x0.copy()
        invalid[0] -= 1.2 if invalid_trial == "collision" else 0.35
        fun(invalid)
        pytest.fail("Invalid trial must stop without clipping or inventing a new accepted state")

    monkeypatch.setattr(relaxation, "minimize", invalid_after_accepted)
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "expression_domain_error", "not_converged")
    l0, e0 = definition["scales"]["length_m"], definition["scales"]["energy_j"]
    assert partial["final_positions_m"][1][0]/l0 == pytest.approx(0.95, rel=0, abs=1e-14)
    assert partial["iterations"] == 1 and partial["evaluations"] == 4
    expected_energy = (0.95-1)**2 if invalid_trial == "collision" else math.log(0.95-0.9)
    assert partial["energy_j"]/e0 == pytest.approx(expected_energy, rel=1e-10, abs=1e-10)
    assert len(partial["optimization_history"]) == 2
    initial_energy = 0.04 if invalid_trial == "collision" else math.log(0.3)
    assert partial["optimization_history"][0]["energy_j"]/e0 == pytest.approx(initial_energy, rel=1e-10, abs=1e-10)
    assert partial["forces_n"][0][0] != 0
    assert partial["forces_n"][0][0] == -partial["forces_n"][1][0]
    assert definition == original
    assert_fixed_unchanged(partial, original)


def test_abnormal_solver_termination_is_not_stationarity(definition, registry, monkeypatch):
    def line_search_failure(fun, x0, *args, **kwargs):
        energy, gradient = fun(np.array(x0, copy=True))
        return OptimizeResult(x=np.array(x0, copy=True), fun=energy, jac=gradient,
                              success=False, status=2, nit=0, nfev=1, message="ABNORMAL:")

    monkeypatch.setattr(relaxation, "minimize", line_search_failure)
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "line_search_failed", "not_converged")
    assert captured.value.code == "NUM_NOT_CONVERGED"
    assert partial["iterations"] == 0 and partial["evaluations"] == 1
    assert partial["final_positions_m"] == partial["initial_positions_m"]


def test_valid_unaccepted_solver_result_is_not_published_as_final_state(definition, registry, monkeypatch):
    def return_without_accepting(fun, x0, *args, **kwargs):
        trial = np.array(x0, copy=True)
        trial[0] -= 0.2
        energy, gradient = fun(trial)
        # A valid, even stationary, trial does not become accepted merely
        # because solver metadata names it as a successful result.
        return OptimizeResult(x=trial, fun=energy, jac=gradient, success=True,
                              status=0, nit=1, nfev=2, message="CONVERGENCE")

    monkeypatch.setattr(relaxation, "minimize", return_without_accepting)
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "engine_failure", "not_converged")
    assert captured.value.code == "ENGINE_FAILURE"
    assert partial["iterations"] == 0 and partial["evaluations"] == 2
    assert partial["final_positions_m"] == partial["initial_positions_m"]


def registry_with_wall_limit(contract_dir, tmp_path, seconds):
    bundle = tmp_path/"wall-policy"
    shutil.copytree(contract_dir, bundle)
    policy_path = bundle/"resource_policy.json"
    policy = json.loads(policy_path.read_text())
    policy["common_execution"]["wall_seconds_per_step"] = seconds
    policy_path.write_text(json.dumps(policy, indent=2)+"\n")
    sums_path = bundle/"SHA256SUMS.json"
    sums = json.loads(sums_path.read_text())
    sums["resource_policy.json"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    sums_path.write_text(json.dumps(sums, indent=2)+"\n")
    registry = ContractRegistry(bundle)
    assert registry.validate_integrity() == []
    return registry


def test_frozen_wall_policy_stops_before_another_kernel_call(definition, contract_dir, tmp_path, monkeypatch):
    registry = registry_with_wall_limit(contract_dir, tmp_path, 1e-6)
    clock = {"now": 0.0}
    monkeypatch.setattr(relaxation.time, "monotonic", lambda: clock["now"])

    def expire_before_trial(fun, x0, *args, **kwargs):
        clock["now"] = 1.0
        trial = np.array(x0, copy=True)
        trial[0] += 0.1
        fun(trial)
        pytest.fail("The expired registered wall limit must prevent a new calculation")

    monkeypatch.setattr(relaxation, "minimize", expire_before_trial)
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, definition, registry, "wall_time_limit")
    assert captured.value.code == "RESOURCE_LIMIT"
    assert partial["iterations"] == 0 and partial["evaluations"] == 1
    assert partial["initial_positions_m"] == partial["final_positions_m"]


@pytest.mark.parametrize("initially_stationary", [False, True])
def test_wall_expiry_during_success_payload_validation_prevents_success_publication(definition, registry, monkeypatch, initially_stationary):
    if initially_stationary:
        definition["system"]["particles"][1]["position_m"][0] = definition["scales"]["length_m"]
    original_definition = copy.deepcopy(definition)
    clock = {"now": 0.0}
    completed_payloads = []
    monkeypatch.setattr(relaxation.time, "monotonic", lambda: clock["now"])
    original_payload = relaxation._PreparedPair.payload

    def expire_after_validated_success(self, *args, **kwargs):
        result = original_payload(self, *args, **kwargs)
        if kwargs.get("stop_reason") == "gradient_tolerance":
            completed_payloads.append(result)
            clock["now"] = 61.0
        return result

    monkeypatch.setattr(relaxation._PreparedPair, "payload", expire_after_validated_success)
    with pytest.raises(RelaxationError) as captured:
        relax_pair(definition, registry=registry)
    partial = assert_failed(captured.value, original_definition, registry, "wall_time_limit", "pass")
    assert captured.value.code == "RESOURCE_LIMIT"
    assert len(completed_payloads) == 1
    assert partial["free_gradient_inf"] <= definition["numerics"]["gradient_tolerance"]
    gradient_checks = [check for check in partial["diagnostics"]["checks"]
                       if check["id"] == "free_gradient_tolerance"]
    assert len(gradient_checks) == 1
    assert gradient_checks[0]["status"] == "pass"
    assert gradient_checks[0]["value"] == partial["free_gradient_inf"]
    assert gradient_checks[0]["tolerance"] == original_definition["numerics"]["gradient_tolerance"]
    assert_harmonic_result_matches_final_geometry(partial, definition)
    assert partial["final_positions_m"] == completed_payloads[0]["final_positions_m"]
    assert partial["iterations"] == (0 if initially_stationary else 1)
    assert definition == original_definition
    for index, particle in enumerate(original_definition["system"]["particles"]):
        for axis, coordinate in enumerate(particle["position_m"]):
            assert bits(definition["system"]["particles"][index]["position_m"][axis]) == bits(coordinate)
            assert bits(partial["initial_positions_m"][index][axis]) == bits(coordinate)


def test_unrequested_history_is_not_created(definition, registry):
    definition["observables"] = ["energy", "forces", "final_positions"]
    payload = relax_pair(definition, registry=registry)
    assert_payload(payload, definition, registry)
    assert "optimization_history" not in payload and "pair_energies" not in payload
