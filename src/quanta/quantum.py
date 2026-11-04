"""Checked low stationary states on a finite uniform one-dimensional grid.

The potential uses xi=(x-a)/L0. The kinetic matrix is the second-order
Dirichlet stencil, and every requested grid is solved without changing the
domain, potential, mass or scales. Discrete solver accuracy and refinement
convergence are independent outcomes.
"""
from __future__ import annotations

import json
import math
import time
from fractions import Fraction
from itertools import islice

import numpy as np
from scipy.linalg import eigh_tridiagonal

from .autodiff import CalculationError, _fraction_float, _number, _product, _ratio, _sum
from .parsing import StrictJSONError, parse_json, pointer
from .registry import ContractRegistry
from .validation import _evaluate, validate_definition


HBAR = 6.62607015e-34 / (2 * math.pi)
NORMALIZATION_TOLERANCE = 1e-10
ORTHOGONALITY_TOLERANCE = 1e-10
RESIDUAL_TOLERANCE = 1e-12
_PATH = "/definition/system"
_OPTIONAL = {"density": "density_per_m", "x_mean": "x_mean_m", "x2_mean": "x2_mean_m2",
             "kinetic_mean": "kinetic_mean_j", "potential_mean": "potential_mean_j"}


def _status(payload: dict | None, name: str) -> str:
    if payload is None:
        return "not_checked"
    checks = payload["diagnostics"]["checks"]
    if name == "resolution":
        return next(check["status"] for check in checks if check["id"] == "grid_energy_convergence")
    return "pass" if all(check["status"] == "pass" for check in checks
                         if check["id"] in {"weighted_normalization", "weighted_orthogonality", "eigen_residual"}) else "not_converged"


class QuantumError(CalculationError):
    """A failed operation with only previously checked complete grids retained."""

    def __init__(self, message: str, *, code: str = "ENGINE_FAILURE", path: str = "/definition/numerics",
                 details: dict | None = None, partial_payload: dict | None = None,
                 numerical_status: str | None = None, resolution_status: str | None = None):
        super().__init__(message, code=code, path=path, details=details)
        self.partial_payload = partial_payload
        self.numerical_status = numerical_status or _status(partial_payload, "numerical")
        self.resolution_status = resolution_status or _status(partial_payload, "resolution")


def _check_payload(payload: dict, *, registry: ContractRegistry, schema_ref: str,
                   definition: dict, completed_grids: int, max_bytes: int) -> None:
    """Validate the registered schema plus actual shape, SI and boundary meaning."""
    errors = list(islice(registry.validator(schema_ref).iter_errors(payload), 1))
    if errors:
        error = errors[0]
        raise CalculationError("Calculated payload violates its registered result schema", code="ENGINE_FAILURE",
                               path="/payload" + pointer(error.absolute_path), details={"reason": error.message[:200]})
    numerics, system = definition["numerics"], definition["system"]
    n = (int(numerics["n_points"]) + 1) * 2 ** (completed_grids - 1) - 1
    count, states = n + 2, int(numerics["states"])
    x, energy = payload["x_m"], payload["energies_j"]
    if (len(x) != count or len(energy) != states or any(not a < b for a, b in zip(x, x[1:]))
            or x[0] != system["domain"]["a_m"] or x[-1] != system["domain"]["b_m"]
            or any(a > b for a, b in zip(energy, energy[1:]))):
        raise CalculationError("Calculated grid or energies have inconsistent dimensions or ordering",
                               code="ENGINE_FAILURE", path="/payload")
    for part in ("real", "imag"):
        values = payload["states"][part]
        if len(values) != states or any(len(row) != count or row[0] != 0.0 or row[-1] != 0.0 for row in values):
            raise CalculationError("Calculated state shape or endpoints are inconsistent", code="ENGINE_FAILURE",
                                   path="/payload/states/" + part)
    if any(value != 0.0 for row in payload["states"]["imag"] for value in row):
        raise CalculationError("This real stationary module requires a zero imaginary carrier",
                               code="ENGINE_FAILURE", path="/payload/states/imag")
    grids = payload["grid_results"]
    if len(grids) != completed_grids:
        raise CalculationError("Grid history is incomplete", code="ENGINE_FAILURE", path="/payload/grid_results")
    for index, result in enumerate(grids):
        expected = (int(numerics["n_points"]) + 1) * 2 ** index - 1
        if (result["n_points"] != expected or len(result["energies_j"]) != states
                or result["atol"] != numerics["grid_energy_atol"] or result["rtol"] != numerics["grid_energy_rtol"]):
            raise CalculationError("Grid history differs from the authored refinement request",
                                   code="ENGINE_FAILURE", path="/payload/grid_results")
    if grids[-1]["energies_j"] != energy:
        raise CalculationError("Final energy differs from its grid history", code="ENGINE_FAILURE", path="/payload/energies_j")
    requested = set(definition["observables"])
    for observable, field in _OPTIONAL.items():
        if (field in payload) != (observable in requested):
            raise CalculationError("An optional output differs from the requested observables",
                                   code="ENGINE_FAILURE", path="/payload/" + field)
        if field in payload:
            values = payload[field]
            if len(values) != states or (observable == "density" and any(len(row) != count for row in values)):
                raise CalculationError("Optional output has an inconsistent shape", code="ENGINE_FAILURE", path="/payload/" + field)
    try:
        encoded = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, OverflowError) as exc:
        raise CalculationError("Calculated payload contains a nonfinite numeric value", code="ENGINE_FAILURE", path="/payload") from exc
    if len(encoded) > max_bytes:
        raise CalculationError("Calculated payload exceeds the artifact byte limit", code="RESOURCE_LIMIT", path="/payload",
                               details={"bytes": len(encoded), "limit": max_bytes})


def eigenstates(definition: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Return the finest completed stationary solution, or raise QuantumError.

    Mandatory states include the two zero endpoints and SI amplitudes. All
    authored grids must finish; the final adjacent pair determines resolution
    convergence. A request with no refinement has resolution not_checked.
    This low-level API validates a definition but does not execute its protocol.
    """
    started = time.monotonic()
    accepted = None
    completed = 0
    try:
        try:
            authored = parse_json(definition)
        except StrictJSONError as exc:
            raise CalculationError(str(exc), code=exc.code, path=exc.path) from exc
        try:
            registry = registry or ContractRegistry()
            module = registry.get_module("quanta.quantum_stationary", "0.1.0")
            if module is None:
                raise ValueError("Exact module registration is unavailable")
            policy = registry.resource_policy["common_execution"]
            wall_limit = min(60.0, float(policy["wall_seconds_per_step"]), float(policy["wall_seconds_per_run"]))
            max_bytes = int(policy["max_artifact_bytes_per_run"])
        except (OSError, KeyError, ValueError, TypeError) as exc:
            raise CalculationError("Frozen quantum registration or policy is unavailable", code="REGISTRY_SNAPSHOT_UNAVAILABLE",
                                   path="/definition", details={"reason": str(exc)[:200]}) from exc

        def check_deadline() -> None:
            elapsed = time.monotonic() - started
            if elapsed >= wall_limit:
                raise CalculationError("Stationary calculation exceeded the step wall-time limit", code="RESOURCE_LIMIT",
                                       path="/definition/numerics", details={"elapsed_seconds": elapsed, "limit_seconds": wall_limit,
                                                                            "stop_reason": "wall_time_limit"})

        check_deadline()
        report = validate_definition(authored, registry=registry)
        if not report["valid"]:
            error = report["errors"][0]
            raise CalculationError(error["message"], code=error["code"], path=error["path"], details=error["details"])
        check_deadline()
        system, numerics = authored["system"], authored["numerics"]
        if (system["module_id"], system["module_version"]) != ("quanta.quantum_stationary", "0.1.0"):
            raise CalculationError("The solver supports quanta.quantum_stationary@0.1.0", code="MODEL_UNSUPPORTED", path=_PATH + "/module_id")
        a = _number(system["domain"]["a_m"], _PATH + "/domain/a_m")
        b = _number(system["domain"]["b_m"], _PATH + "/domain/b_m")
        length = _number(authored["scales"]["length_m"], "/definition/scales/length_m")
        energy_scale = _number(authored["scales"]["energy_j"], "/definition/scales/energy_j")
        mass = _number(system["mass_kg"], _PATH + "/mass_kg")
        alpha = _fraction_float(Fraction(HBAR) ** 2 / (2 * Fraction(mass) * Fraction(length) ** 2 * Fraction(energy_scale)),
                                "/definition/scales", "reduced kinetic coefficient")
        width_m = _fraction_float(Fraction(b) - Fraction(a), _PATH + "/domain", "domain width")
        width = _ratio(width_m, length, _PATH + "/domain", "reduced domain width")
        states, levels = int(numerics["states"]), int(numerics["refinement_levels"])
        atol, rtol = float(numerics["grid_energy_atol"]), float(numerics["grid_energy_rtol"])
        grid_results, previous_energies = [], None
        for level in range(levels + 1):
            check_deadline()
            n = (int(numerics["n_points"]) + 1) * 2 ** level - 1
            dx = _ratio(width, float(n + 1), _PATH + "/domain", "reduced grid spacing")
            dx_m = _ratio(width_m, float(n + 1), _PATH + "/domain", "SI grid spacing")
            kinetic = _fraction_float(Fraction(alpha) / Fraction(dx) ** 2, "/definition/numerics/n_points", "kinetic stencil coefficient")
            xi = [i * dx for i in range(n + 2)]
            xi[-1] = width
            x = [a] + [_fraction_float(Fraction(a) + (Fraction(b) - Fraction(a)) * i / (n + 1), _PATH + "/domain", "SI grid coordinate")
                       for i in range(1, n + 1)] + [b]
            if any(not left < right for left, right in zip(x, x[1:])):
                raise CalculationError("The SI grid collapses at this coordinate offset and resolution", code="INPUT_SEMANTIC", path=_PATH + "/domain")
            values = []
            for index, position in enumerate(xi):
                check_deadline()
                try:
                    values.append(_evaluate(system["potential"]["expression"], system["potential"]["parameters"], position))
                except (ArithmeticError, ValueError) as exc:
                    if isinstance(exc, CalculationError):
                        raise
                    raise CalculationError("Potential is not finite and defined on a requested grid", path=_PATH + "/potential/expression",
                                           details={"level": level, "grid_index": index, "reason": str(exc)[:160]}) from exc
            potential = np.asarray(values[1:-1], dtype=np.float64)
            diagonal = np.array([_sum((kinetic, kinetic, value), _PATH + "/potential", "Hamiltonian diagonal") for value in potential])
            off_diagonal = np.full(n - 1, -kinetic, dtype=np.float64)
            check_deadline()
            try:
                eigenvalues, vectors = eigh_tridiagonal(diagonal, off_diagonal, select="i", select_range=(0, states - 1),
                                                       lapack_driver="stebz", check_finite=True)
            except Exception as exc:
                raise CalculationError("The symmetric tridiagonal eigensolver failed", code="ENGINE_FAILURE",
                                       details={"exception_type": type(exc).__name__, "reason": str(exc)[:160]}) from exc
            check_deadline()
            eigenvalues, vectors = np.asarray(eigenvalues, dtype=np.float64), np.asarray(vectors, dtype=np.float64)
            if (eigenvalues.shape != (states,) or vectors.shape != (n, states) or not np.isfinite(eigenvalues).all()
                    or not np.isfinite(vectors).all() or np.any(np.diff(eigenvalues) < 0)):
                raise CalculationError("The eigensolver returned inconsistent finite states or energies", code="ENGINE_FAILURE")
            vectors = vectors.copy()
            for state in range(states):
                norm = math.hypot(*(float(value) for value in vectors[:, state]))
                if norm == 0.0 or not math.isfinite(norm):
                    raise CalculationError("The eigensolver returned an empty state", code="NUM_NOT_CONVERGED")
                vectors[:, state] /= norm
                pivot = int(np.argmax(np.abs(vectors[:, state])))
                if vectors[pivot, state] < 0:
                    vectors[:, state] *= -1
            gram = vectors.T @ vectors
            normalization = float(np.max(np.abs(np.diag(gram) - 1.0)))
            orthogonality = float(np.max(np.abs(gram - np.diag(np.diag(gram)))))
            # Scale the residual before multiplication so a finite large
            # Hamiltonian cannot overflow an otherwise scale-free diagnostic.
            h_scale = max(float(np.max(np.abs(diagonal))), kinetic, float(np.max(np.abs(eigenvalues))))
            d_scaled, e_scaled = diagonal / h_scale, off_diagonal / h_scale
            hv = d_scaled[:, None] * vectors
            hv[1:] += e_scaled[:, None] * vectors[:-1]
            hv[:-1] += e_scaled[:, None] * vectors[1:]
            scaled_row_sums = np.abs(d_scaled).copy()
            scaled_row_sums[1:] += np.abs(e_scaled)
            scaled_row_sums[:-1] += np.abs(e_scaled)
            h_inf_scaled = float(np.max(scaled_row_sums))
            residual = max(math.hypot(*(float(value) for value in hv[:, state] - (eigenvalues[state] / h_scale) * vectors[:, state]))
                           / (h_inf_scaled + abs(float(eigenvalues[state] / h_scale))) for state in range(states))
            if (normalization > NORMALIZATION_TOLERANCE or orthogonality > ORTHOGONALITY_TOLERANCE or residual > RESIDUAL_TOLERANCE):
                raise QuantumError("The computed discrete states did not meet numerical criteria", code="NUM_NOT_CONVERGED",
                                   details={"level": level, "normalization_error": normalization, "orthogonality_error": orthogonality,
                                            "backward_residual": residual}, partial_payload=accepted,
                                   numerical_status="pass" if accepted is not None else "not_converged")
            check_deadline()
            energies = [_product((float(value), energy_scale), "/payload/energies_j", "SI energy") for value in eigenvalues]
            amplitude_scale = math.sqrt(dx_m)
            real = [[0.0] + [_ratio(float(value), amplitude_scale, "/payload/states/real", "SI state amplitude")
                              for value in vectors[:, state]] + [0.0] for state in range(states)]
            # Reconstruct dimensionless weights from the actual SI carrier, so
            # the published amplitudes are checked as well as solver vectors.
            restored = np.asarray([row[1:-1] for row in real], dtype=np.float64).T * amplitude_scale
            restored_gram = restored.T @ restored
            normalization = max(normalization, float(np.max(np.abs(np.diag(restored_gram) - 1.0))))
            orthogonality = max(orthogonality, float(np.max(np.abs(restored_gram - np.diag(np.diag(restored_gram))))))
            if normalization > NORMALIZATION_TOLERANCE or orthogonality > ORTHOGONALITY_TOLERANCE:
                raise QuantumError("The SI state carrier did not preserve weighted normalization", code="NUM_NOT_CONVERGED",
                                   details={"level": level, "normalization_error": normalization,
                                            "orthogonality_error": orthogonality}, partial_payload=accepted,
                                   numerical_status="pass" if accepted is not None else "not_converged")
            grid_results.append({"n_points": n, "energies_j": energies.copy(), "atol": atol, "rtol": rtol})
            grid_ratio = None
            if previous_energies is not None:
                grid_ratio = max(_fraction_float(abs(Fraction(float(value)) - Fraction(float(previous)))
                                                 / (Fraction(atol) + Fraction(rtol) * abs(Fraction(float(value)))),
                                                 "/definition/numerics", "grid convergence ratio")
                                 for value, previous in zip(eigenvalues, previous_energies))
            resolution = "not_checked" if level < levels or levels == 0 else ("pass" if grid_ratio <= 1.0 else "not_converged")
            payload = {"operation": "eigenstates", "x_m": x, "energies_j": energies,
                       "states": {"real": real, "imag": [[0.0] * (n + 2) for _ in range(states)]},
                       "grid_results": [row.copy() for row in grid_results],
                       "diagnostics": {"method": "second_order_dirichlet_eigh_tridiagonal_stebz", "checks": [
                           {"id": "weighted_normalization", "status": "pass", "value": normalization, "tolerance": NORMALIZATION_TOLERANCE},
                           {"id": "weighted_orthogonality", "status": "pass", "value": orthogonality, "tolerance": ORTHOGONALITY_TOLERANCE},
                           {"id": "eigen_residual", "status": "pass", "value": residual, "tolerance": RESIDUAL_TOLERANCE},
                           {"id": "grid_energy_convergence", "status": resolution, "value": grid_ratio, "tolerance": 1.0},
                           {"id": "boundary_zero", "status": "pass", "value": 0.0, "tolerance": 0.0},
                           {"id": "finite_binary64_output", "status": "pass", "value": None, "tolerance": None}]}}
            observables = set(authored["observables"])
            if "density" in observables:
                payload["density_per_m"] = [[_product((value, value), "/payload/density_per_m", "SI probability density") for value in row] for row in real]
            for name, factors in (("x_mean", 1), ("x2_mean", 2)):
                if name in observables:
                    payload[_OPTIONAL[name]] = [_fraction_float(sum((Fraction(float(q)) ** 2 * Fraction(position) ** factors
                                                                    for q, position in zip(vectors[:, state], x[1:-1])), Fraction()),
                                                               "/payload/" + _OPTIONAL[name], "SI expectation")
                                               for state in range(states)]
            if "kinetic_mean" in observables:
                payload["kinetic_mean_j"] = []
                for state in range(states):
                    q = [0.0, *map(float, vectors[:, state]), 0.0]
                    value = Fraction(kinetic) * Fraction(energy_scale) * sum(
                        ((Fraction(right) - Fraction(left)) ** 2 for left, right in zip(q, q[1:])), Fraction())
                    payload["kinetic_mean_j"].append(_fraction_float(value, "/payload/kinetic_mean_j", "SI kinetic expectation"))
            if "potential_mean" in observables:
                payload["potential_mean_j"] = [_fraction_float(Fraction(energy_scale) * sum(
                    (Fraction(float(q)) ** 2 * Fraction(float(value)) for q, value in zip(vectors[:, state], potential)), Fraction()),
                    "/payload/potential_mean_j", "SI potential expectation") for state in range(states)]
            check_deadline()
            _check_payload(payload, registry=registry, schema_ref=module["payload_schema_ref"], definition=authored,
                           completed_grids=level + 1, max_bytes=max_bytes)
            check_deadline()
            accepted, completed = payload, level + 1
            previous_energies = eigenvalues.copy()
        # Recheck final publication as well as each accepted grid; operational
        # failure never changes a retained grid's actual numerical criteria.
        _check_payload(accepted, registry=registry, schema_ref=module["payload_schema_ref"], definition=authored,
                       completed_grids=completed, max_bytes=max_bytes)
        check_deadline()
        if _status(accepted, "resolution") == "not_converged":
            raise QuantumError("Requested adjacent grids did not meet the energy convergence criterion", code="NUM_NOT_CONVERGED",
                               path="/definition/numerics", details={"completed_grids": completed, "stop_reason": "grid_energy_not_converged"},
                               partial_payload=accepted)
        return accepted
    except QuantumError:
        raise
    except CalculationError as exc:
        raise QuantumError(str(exc), code=exc.code, path=exc.path, details={**exc.details, "completed_grids": completed},
                           partial_payload=accepted) from exc
    except Exception as exc:
        raise QuantumError("The stationary calculation failed", details={"exception_type": type(exc).__name__, "reason": str(exc)[:200],
                                                                          "completed_grids": completed}, partial_payload=accepted) from exc
