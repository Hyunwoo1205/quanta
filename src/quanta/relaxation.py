"""Bounded L-BFGS-B search using the shared conservative pair kernel.

Only free coordinates enter the solver, as reduced displacements from their
initial SI positions. A reported success requires the actual accepted free
gradient norm; energy-change termination alone is never sufficient.
"""

from __future__ import annotations

import time
from fractions import Fraction

import numpy as np
from scipy.optimize import minimize

from .autodiff import CalculationError, _fraction_float
from .pair import _PairEvaluation, _PreparedPair
from .registry import ContractRegistry


def _partial_numerical_status(partial_payload: dict | None) -> str:
    if partial_payload is None:
        return "not_checked"
    for check in partial_payload.get("diagnostics", {}).get("checks", []):
        if check.get("id") == "free_gradient_tolerance" and check.get("tolerance") is not None:
            return "pass" if partial_payload["free_gradient_inf"] <= check["tolerance"] else "not_converged"
    return "not_converged"


class RelaxationError(CalculationError):
    """A failed search with an optional, validated last accepted module payload."""

    def __init__(self, message: str, *, code: str = "NUM_NOT_CONVERGED",
                 path: str = "/definition/numerics", details: dict | None = None,
                 partial_payload: dict | None = None, numerical_status: str | None = None):
        super().__init__(message, code=code, path=path, details=details)
        self.partial_payload = partial_payload
        self.numerical_status = numerical_status or _partial_numerical_status(partial_payload)


class _Converged(Exception):
    pass


class _SearchStop(CalculationError):
    def __init__(self, reason: str, message: str, *, path: str, details: dict | None = None):
        super().__init__(message, code="RESOURCE_LIMIT", path=path, details=details)
        self.reason = reason


def relax_pair(definition: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Search for a stationary configuration with fixed SI coordinates intact.

    Counts include the initial evaluation and failed numerical trials. A hard
    evaluation guard is applied before calling the kernel; monotonic wall-time
    guards run before and after evaluations and at every pair. Trial domain
    failures stop immediately. Partial outputs contain accepted states only.
    The authored protocol is not executed by this low-level single-operation API.
    """
    started = time.monotonic()
    try:
        prepared = _PreparedPair(definition, registry=registry, operation="relax")
    except CalculationError as exc:
        raise RelaxationError(str(exc), code=exc.code, path=exc.path, details=exc.details,
                              numerical_status="not_checked") from exc
    numerics = prepared.definition["numerics"]
    max_iterations = int(numerics["max_iterations"])
    max_evaluations = int(numerics["max_evaluations"])
    tolerance = float(numerics["gradient_tolerance"])
    policy = prepared.registry.resource_policy["common_execution"]
    wall_limit = min(60.0, float(policy["wall_seconds_per_step"]), float(policy["wall_seconds_per_run"]))
    nfev = 0
    iterations = 0
    accepted: _PairEvaluation | None = None
    accepted_vector: np.ndarray | None = None
    initial_evaluation: _PairEvaluation | None = None
    initial_vector = np.zeros(len(prepared.free_coordinates), dtype=np.float64)
    recent_key: bytes | None = None
    recent_evaluation: _PairEvaluation | None = None
    history: list[dict] = []
    requested_history = "optimization_history" in prepared.definition["observables"]

    def check_deadline() -> None:
        elapsed = time.monotonic() - started
        if elapsed >= wall_limit:
            raise _SearchStop("wall_time_limit", "Relaxation exceeded the step wall-time limit",
                              path="/definition/numerics", details={"elapsed_seconds": elapsed,
                                                                     "limit_seconds": wall_limit})

    def evaluation_limit() -> _SearchStop:
        return _SearchStop("evaluation_limit", "Relaxation exhausted its evaluation budget",
                           path="/definition/numerics/max_evaluations",
                           details={"evaluations": nfev, "limit": max_evaluations})

    def positions_from_vector(vector: np.ndarray) -> list[list[float]]:
        positions = [row.copy() for row in prepared.initial_positions]
        for displacement, (index, axis) in zip(vector, prepared.free_coordinates):
            # A zero displacement preserves signed zero and the initial bits.
            if displacement != 0.0:
                positions[index][axis] = _fraction_float(
                    Fraction(prepared.initial_positions[index][axis])
                    + Fraction(prepared.length) * Fraction(float(displacement)),
                    f"/definition/system/particles/{index}/position_m/{axis}", "trial SI coordinate")
        return positions

    def trial(vector: object) -> tuple[np.ndarray, _PairEvaluation]:
        nonlocal nfev, recent_key, recent_evaluation
        check_deadline()
        try:
            normalized = np.asarray(vector, dtype=np.float64)
            if normalized.shape != initial_vector.shape or not np.isfinite(normalized).all():
                raise ValueError("Expected a finite free-coordinate vector")
        except (TypeError, ValueError, OverflowError) as exc:
            if nfev >= max_evaluations:
                raise evaluation_limit() from exc
            nfev += 1
            raise CalculationError("The solver supplied an invalid trial vector", code="ENGINE_FAILURE",
                                   path="/definition/system/particles") from exc
        key = normalized.tobytes()
        if initial_evaluation is not None and np.array_equal(normalized, initial_vector):
            return normalized, initial_evaluation
        if accepted is not None and accepted_vector is not None and np.array_equal(normalized, accepted_vector):
            return normalized, accepted
        if recent_key == key and recent_evaluation is not None:
            return normalized, recent_evaluation
        if nfev >= max_evaluations:
            raise evaluation_limit()
        nfev += 1
        evaluation = prepared.evaluate(positions_from_vector(normalized), check_deadline=check_deadline)
        check_deadline()
        recent_key, recent_evaluation = key, evaluation
        return normalized, evaluation

    def record(evaluation: _PairEvaluation, iteration: int) -> dict:
        return {"iteration": iteration, "energy_j": evaluation.energy_j,
                "free_gradient_inf": evaluation.free_gradient_inf}

    def payload(reason: str) -> dict | None:
        if accepted is None:
            return None
        return prepared.payload(accepted, operation="relax", iterations=iterations,
                                evaluations=nfev, stop_reason=reason,
                                history=history if requested_history else None,
                                converged=accepted.free_gradient_inf <= tolerance)

    def finish_success() -> dict:
        result_payload = payload("gradient_tolerance")
        check_deadline()
        return result_payload

    def objective(vector: object) -> tuple[float, np.ndarray]:
        _, evaluation = trial(vector)
        gradient = np.array([-evaluation.reduced_forces[index][axis]
                             for index, axis in prepared.free_coordinates], dtype=np.float64)
        return evaluation.reduced_energy, gradient

    def callback(vector: object) -> None:
        nonlocal accepted, accepted_vector, iterations
        check_deadline()
        vector = getattr(vector, "x", vector)
        normalized, evaluation = trial(vector)
        next_iteration = iterations + 1
        proposed_history = history + [record(evaluation, next_iteration)] if requested_history else None
        # Validate before preserving this as a usable partial state. A line-search
        # trial is promoted only by this accepted-iteration callback.
        prepared.payload(evaluation, operation="relax", iterations=next_iteration,
                         evaluations=nfev, stop_reason="accepted_iteration",
                         history=proposed_history, converged=evaluation.free_gradient_inf <= tolerance)
        check_deadline()
        accepted, accepted_vector = evaluation, normalized.copy()
        iterations = next_iteration
        if requested_history:
            history.append(record(evaluation, iterations))
        if accepted.free_gradient_inf <= tolerance:
            raise _Converged
        if iterations >= max_iterations:
            raise _SearchStop("iteration_limit", "Relaxation exhausted its accepted-iteration budget",
                              path="/definition/numerics/max_iterations",
                              details={"iterations": iterations, "limit": max_iterations})
        if nfev >= max_evaluations:
            raise evaluation_limit()

    try:
        _, initial_evaluation = trial(initial_vector)
        initial_history = [record(initial_evaluation, 0)] if requested_history else None
        prepared.payload(initial_evaluation, operation="relax", iterations=0, evaluations=nfev,
                         stop_reason="initial_evaluation", history=initial_history,
                         converged=initial_evaluation.free_gradient_inf <= tolerance)
        check_deadline()
        accepted, accepted_vector = initial_evaluation, initial_vector.copy()
        if requested_history:
            history.append(record(initial_evaluation, 0))
        if accepted.free_gradient_inf <= tolerance:
            return finish_success()
        if nfev >= max_evaluations:
            raise evaluation_limit()
        try:
            result = minimize(objective, initial_vector.copy(), method="L-BFGS-B", jac=True, callback=callback,
                              options={"gtol": tolerance, "ftol": float(numerics["energy_ftol"]),
                                       "maxiter": max_iterations, "maxfun": max_evaluations})
        except _Converged:
            return finish_success()
        check_deadline()
        # Solver metadata cannot turn an unevaluated or unaccepted trial into a
        # result, and its success flag cannot replace our gradient criterion.
        result_vector = np.asarray(result.x, dtype=np.float64)
        if result_vector.shape != initial_vector.shape or not np.array_equal(result_vector, accepted_vector):
            raise CalculationError("The solver returned a configuration without an accepted callback",
                                   code="ENGINE_FAILURE", path="/definition/system/particles")
        if accepted.free_gradient_inf <= tolerance:
            return finish_success()
        if iterations >= max_iterations:
            raise _SearchStop("iteration_limit", "Relaxation exhausted its accepted-iteration budget",
                              path="/definition/numerics/max_iterations",
                              details={"iterations": iterations, "limit": max_iterations})
        if nfev >= max_evaluations:
            raise evaluation_limit()
        message = str(getattr(result, "message", ""))
        upper = message.upper()
        reason = "energy_tolerance_without_gradient" if bool(getattr(result, "success", False)) or "REL_REDUCTION" in upper or "FTOL" in upper else "line_search_failed"
        raise RelaxationError("The solver stopped before the accepted free gradient met tolerance",
                              details={"solver_message": message[:240], "free_gradient_inf": accepted.free_gradient_inf,
                                       "gradient_tolerance": tolerance}, partial_payload=payload(reason))
    except RelaxationError:
        raise
    except CalculationError as exc:
        if isinstance(exc, _SearchStop):
            reason = exc.reason
        else:
            reason = ("expression_domain_error" if exc.code in {"EXPRESSION_DOMAIN", "INPUT_SEMANTIC"}
                      else "engine_failure")
            if exc.details.get("quantity"):
                reason = "numerical_range_error"
        partial = payload(reason)
        raise RelaxationError(str(exc), code=exc.code, path=exc.path,
                              details={**exc.details, "iterations": iterations, "evaluations": nfev},
                              partial_payload=partial) from exc
    except Exception as exc:
        partial = payload("engine_failure")
        raise RelaxationError("The relaxation engine failed", code="ENGINE_FAILURE",
                              details={"reason": str(exc)[:200], "iterations": iterations, "evaluations": nfev},
                              partial_payload=partial) from exc
