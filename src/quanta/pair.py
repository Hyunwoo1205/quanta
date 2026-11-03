"""Single unchanged-configuration energy/force evaluation for the pair module."""

from __future__ import annotations

import math
from fractions import Fraction
from itertools import islice

from .autodiff import (CalculationError, _fraction_float, _number, _product,
                       _ratio, _sum, value_and_derivative)
from .parsing import StrictJSONError, parse_json, pointer
from .registry import ContractRegistry
from .validation import validate_definition


_PARTICLES_PATH = "/definition/system/particles"
_PAYLOAD_PATH = "/payload"
_OBSERVABLES = {"energy", "forces", "pair_energies", "final_positions"}


def _check_payload(payload: dict, positions: list[list[float]], registry: ContractRegistry,
                   schema_ref: str, requested_pairs: bool) -> None:
    """Apply both the registered structure and cross-field numerical contract."""
    errors = list(islice(registry.validator(schema_ref).iter_errors(payload), 1))
    if errors:
        error = errors[0]
        raise CalculationError("Calculated payload violates its registered result schema",
                               code="ENGINE_FAILURE", path=_PAYLOAD_PATH + pointer(error.absolute_path),
                               details={"reason": error.message[:200]})
    count = len(positions)
    if payload["initial_positions_m"] != positions or payload["final_positions_m"] != positions:
        raise CalculationError("A single evaluation changed the configuration", code="ENGINE_FAILURE", path=_PAYLOAD_PATH)
    for field in ("initial_positions_m", "final_positions_m", "forces_n"):
        array = payload[field]
        if len(array) != count or any(len(row) != 3 for row in array):
            raise CalculationError("Calculated array has an inconsistent shape", code="ENGINE_FAILURE", path=f"{_PAYLOAD_PATH}/{field}")
        if any(not math.isfinite(value) for row in array for value in row):
            raise CalculationError("Calculated array contains a nonfinite value", code="ENGINE_FAILURE", path=f"{_PAYLOAD_PATH}/{field}")
    for field in ("energy_j", "free_gradient_inf"):
        if not math.isfinite(payload[field]):
            raise CalculationError("Calculated scalar is nonfinite", code="ENGINE_FAILURE", path=f"{_PAYLOAD_PATH}/{field}")
    if requested_pairs:
        expected = [(i, j) for i in range(count) for j in range(i + 1, count)]
        actual = [(entry["i"], entry["j"]) for entry in payload["pair_energies"]]
        if actual != expected or len(set(actual)) != len(expected):
            raise CalculationError("Pair output indices are incomplete or duplicated", code="ENGINE_FAILURE", path=_PAYLOAD_PATH + "/pair_energies")
        if any(not math.isfinite(entry[field]) for entry in payload["pair_energies"] for field in ("distance_m", "energy_j")):
            raise CalculationError("Pair output contains a nonfinite value", code="ENGINE_FAILURE", path=_PAYLOAD_PATH + "/pair_energies")
    elif "pair_energies" in payload:
        raise CalculationError("Unrequested pair output was produced", code="ENGINE_FAILURE", path=_PAYLOAD_PATH + "/pair_energies")


def evaluate_pair(definition: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Evaluate the initial system once, preserving all authored coordinates.

    This low-level function validates a bare definition but does not execute its
    protocol, apply overrides or expand sweep axes. The experiment wrapper must
    enforce its single-evaluation execution boundary. Forces on fixed coordinates
    are retained. Numerical range failures, including nonzero underflow, raise
    CalculationError; no cutoff, clipping or alternate derivative is introduced.
    """
    try:
        snapshot = parse_json(definition)
    except StrictJSONError as exc:
        raise CalculationError(str(exc), code=exc.code, path=exc.path) from exc
    try:
        registry = registry or ContractRegistry()
    except (OSError, ValueError, TypeError) as exc:
        raise CalculationError("Frozen contract bundle could not be loaded",
                               code="REGISTRY_SNAPSHOT_UNAVAILABLE", path="/definition",
                               details={"reason": str(exc)[:200]}) from exc
    report = validate_definition(snapshot, registry=registry)
    if not report["valid"]:
        error = report["errors"][0]
        raise CalculationError(error["message"], code=error["code"], path=error["path"], details=error["details"])
    system = snapshot["system"]
    if (system["module_id"], system["module_version"]) != ("quanta.pair_static", "0.1.0"):
        raise CalculationError("The evaluator supports quanta.pair_static@0.1.0", code="INPUT_SEMANTIC", path="/definition/system/module_id")
    unsupported = set(snapshot["observables"]) - _OBSERVABLES
    if unsupported:
        raise CalculationError("The single evaluation does not produce the requested observable",
                               code="INPUT_SEMANTIC", path="/definition/observables",
                               details={"unsupported": sorted(unsupported)})
    module = registry.get_module(system["module_id"], system["module_version"])
    if module is None:
        raise CalculationError("Exact module registration is unavailable", code="INPUT_SEMANTIC", path="/definition/system")
    length = _number(snapshot["scales"]["length_m"], "/definition/scales/length_m")
    energy = _number(snapshot["scales"]["energy_j"], "/definition/scales/energy_j")
    force_scale = _ratio(energy, length, "/definition/scales", "force scale")
    particles = system["particles"]
    positions = [[_number(value, f"{_PARTICLES_PATH}/{index}/position_m/{axis}")
                  for axis, value in enumerate(particle["position_m"])]
                 for index, particle in enumerate(particles)]
    minimum = _number(system["min_distance_m"], "/definition/system/min_distance_m")
    expression = system["potential"]["expression"]
    parameters = system["potential"]["parameters"]
    requested_pairs = "pair_energies" in snapshot["observables"]
    count = len(particles)
    energy_terms: list[float] = []
    force_terms: list[list[list[float]]] = [[[] for _ in range(3)] for _ in range(count)]
    pair_energies: list[dict] = []
    for i in range(count):
        for j in range(i + 1, count):
            try:
                displacement = [_sum((positions[i][axis], -positions[j][axis]), _PARTICLES_PATH,
                                     "coordinate difference") for axis in range(3)]
                distance = math.hypot(*displacement)
                if not math.isfinite(distance) or distance <= minimum:
                    raise CalculationError("Every pair distance must exceed the minimum distance",
                                           code="INPUT_SEMANTIC", path=_PARTICLES_PATH)
                rho = _ratio(distance, length, _PARTICLES_PATH, "reduced pair distance")
                value, slope = value_and_derivative(expression, parameters, rho)
                energy_terms.append(value)
                for axis in range(3):
                    # Combining the direction and slope before rounding avoids
                    # losing a small direction component that has a finite force.
                    contribution = _fraction_float(-Fraction(slope) * Fraction(displacement[axis])
                                                   / Fraction(distance), _PARTICLES_PATH,
                                                   "reduced pair force")
                    force_terms[i][axis].append(contribution)
                    force_terms[j][axis].append(-contribution)
                if requested_pairs:
                    pair_energies.append({"i": i, "j": j, "distance_m": distance,
                                          "energy_j": _product((value, energy), _PAYLOAD_PATH + "/pair_energies",
                                                               "SI pair energy")})
            except CalculationError as exc:
                exc.details.setdefault("pair_indices", [i, j])
                raise
    reduced_energy = _sum(energy_terms, _PAYLOAD_PATH + "/energy_j", "total reduced energy")
    reduced_forces = [[_sum(terms, f"{_PAYLOAD_PATH}/forces_n/{index}/{axis}", "total reduced force")
                       for axis, terms in enumerate(axes)] for index, axes in enumerate(force_terms)]
    total_energy = _product((reduced_energy, energy), _PAYLOAD_PATH + "/energy_j", "SI total energy")
    forces = [[_product((component, force_scale), f"{_PAYLOAD_PATH}/forces_n/{index}/{axis}", "SI force")
               for axis, component in enumerate(row)] for index, row in enumerate(reduced_forces)]
    free_gradient = max((abs(reduced_forces[index][axis]) for index, particle in enumerate(particles)
                         for axis, fixed in enumerate(particle["fixed"]) if not fixed), default=0.0)
    pair_count = count * (count - 1) // 2
    if len(energy_terms) != pair_count:
        raise CalculationError("Not all pairs were evaluated", code="ENGINE_FAILURE", path=_PAYLOAD_PATH)
    payload = {
        "operation": "energy_forces",
        "initial_positions_m": [row.copy() for row in positions],
        "final_positions_m": [row.copy() for row in positions],
        "energy_j": total_energy,
        "forces_n": forces,
        "free_gradient_inf": free_gradient,
        "iterations": 0,
        "evaluations": 1,
        "stop_reason": "evaluated",
        "minimum_confirmed": False,
        "diagnostics": {
            "method": "forward_mode_ast_all_pairs_no_cutoff",
            "checks": [
                {"id": "all_pairs_evaluated", "status": "pass", "value": pair_count, "tolerance": 0},
                {"id": "finite_binary64_output", "status": "pass", "value": None, "tolerance": None},
                {"id": "configuration_unchanged", "status": "pass", "value": 0, "tolerance": 0},
                {"id": "optimization_convergence", "status": "not_applicable", "value": None, "tolerance": None},
            ],
        },
    }
    if requested_pairs:
        payload["pair_energies"] = pair_energies
    _check_payload(payload, positions, registry, module["payload_schema_ref"], requested_pairs)
    return payload
