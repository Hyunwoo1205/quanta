"""Single unchanged-configuration energy/force evaluation for the pair module."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from fractions import Fraction
from itertools import islice
from typing import Callable

from .autodiff import (CalculationError, _fraction_float, _number, _product,
                       _ratio, _sum, value_and_derivative)
from .parsing import StrictJSONError, parse_json, pointer
from .registry import ContractRegistry
from .validation import validate_definition


_PARTICLES_PATH = "/definition/system/particles"
_PAYLOAD_PATH = "/payload"
_OBSERVABLES = {"energy", "forces", "pair_energies", "final_positions"}


def _check_payload(payload: dict, positions: list[list[float]], registry: ContractRegistry,
                   schema_ref: str, requested_pairs: bool, fixed: list[list[bool]] | None = None) -> None:
    """Apply both the registered structure and cross-field numerical contract."""
    errors = list(islice(registry.validator(schema_ref).iter_errors(payload), 1))
    if errors:
        error = errors[0]
        raise CalculationError("Calculated payload violates its registered result schema",
                               code="ENGINE_FAILURE", path=_PAYLOAD_PATH + pointer(error.absolute_path),
                               details={"reason": error.message[:200]})
    count = len(positions)
    if payload["initial_positions_m"] != positions:
        raise CalculationError("Initial positions changed", code="ENGINE_FAILURE", path=_PAYLOAD_PATH)
    if payload["operation"] == "energy_forces" and payload["final_positions_m"] != positions:
        raise CalculationError("A single evaluation changed the configuration", code="ENGINE_FAILURE", path=_PAYLOAD_PATH)
    for field in ("initial_positions_m", "final_positions_m", "forces_n"):
        array = payload[field]
        if len(array) != count or any(len(row) != 3 for row in array):
            raise CalculationError("Calculated array has an inconsistent shape", code="ENGINE_FAILURE", path=f"{_PAYLOAD_PATH}/{field}")
        if any(not math.isfinite(value) for row in array for value in row):
            raise CalculationError("Calculated array contains a nonfinite value", code="ENGINE_FAILURE", path=f"{_PAYLOAD_PATH}/{field}")
    if fixed is not None:
        for index, mask in enumerate(fixed):
            for axis, is_fixed in enumerate(mask):
                if is_fixed and struct.pack("!d", positions[index][axis]) != struct.pack("!d", payload["final_positions_m"][index][axis]):
                    raise CalculationError("A fixed coordinate changed", code="ENGINE_FAILURE",
                                           path=f"{_PAYLOAD_PATH}/final_positions_m/{index}/{axis}")
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


@dataclass
class _PairEvaluation:
    positions: list[list[float]]
    reduced_energy: float
    reduced_forces: list[list[float]]
    energy_j: float
    forces_n: list[list[float]]
    free_gradient_inf: float
    pair_energies: list[dict]


class _PreparedPair:
    """Validated immutable input plus the shared, trial-safe pair calculation."""

    def __init__(self, definition: dict, *, registry: ContractRegistry | None = None,
                 operation: str = "energy_forces"):
        try:
            self.definition = parse_json(definition)
        except StrictJSONError as exc:
            raise CalculationError(str(exc), code=exc.code, path=exc.path) from exc
        try:
            self.registry = registry or ContractRegistry()
        except (OSError, ValueError, TypeError) as exc:
            raise CalculationError("Frozen contract bundle could not be loaded",
                                   code="REGISTRY_SNAPSHOT_UNAVAILABLE", path="/definition",
                                   details={"reason": str(exc)[:200]}) from exc
        report = validate_definition(self.definition, registry=self.registry)
        if not report["valid"]:
            error = report["errors"][0]
            raise CalculationError(error["message"], code=error["code"], path=error["path"], details=error["details"])
        system = self.definition["system"]
        if (system["module_id"], system["module_version"]) != ("quanta.pair_static", "0.1.0"):
            raise CalculationError("The evaluator supports quanta.pair_static@0.1.0", code="INPUT_SEMANTIC", path="/definition/system/module_id")
        allowed = _OBSERVABLES | ({"optimization_history"} if operation == "relax" else set())
        unsupported = set(self.definition["observables"]) - allowed
        if unsupported:
            raise CalculationError("The operation does not produce the requested observable",
                                   code="INPUT_SEMANTIC", path="/definition/observables",
                                   details={"unsupported": sorted(unsupported)})
        self.module = self.registry.get_module(system["module_id"], system["module_version"])
        if self.module is None:
            raise CalculationError("Exact module registration is unavailable", code="INPUT_SEMANTIC", path="/definition/system")
        self.length = _number(self.definition["scales"]["length_m"], "/definition/scales/length_m")
        self.energy = _number(self.definition["scales"]["energy_j"], "/definition/scales/energy_j")
        self.force_scale = _ratio(self.energy, self.length, "/definition/scales", "force scale")
        self.initial_positions = [[_number(value, f"{_PARTICLES_PATH}/{index}/position_m/{axis}")
                                   for axis, value in enumerate(particle["position_m"])]
                                  for index, particle in enumerate(system["particles"])]
        self.fixed = [particle["fixed"].copy() for particle in system["particles"]]
        self.free_coordinates = [(index, axis) for index, mask in enumerate(self.fixed)
                                 for axis, fixed in enumerate(mask) if not fixed]
        if operation == "relax" and not self.free_coordinates:
            raise CalculationError("Relaxation requires at least one free coordinate", code="INPUT_SEMANTIC", path=_PARTICLES_PATH)
        self.minimum = _number(system["min_distance_m"], "/definition/system/min_distance_m")
        self.expression = system["potential"]["expression"]
        self.parameters = system["potential"]["parameters"]
        self.requested_pairs = "pair_energies" in self.definition["observables"]
        self.count = len(self.initial_positions)
        self.pair_count = self.count * (self.count - 1) // 2

    def evaluate(self, positions: list[list[float]], *, check_deadline: Callable[[], None] | None = None) -> _PairEvaluation:
        if len(positions) != self.count or any(len(row) != 3 for row in positions):
            raise CalculationError("Trial positions have an inconsistent shape", code="INPUT_SEMANTIC", path=_PARTICLES_PATH)
        positions = [[_number(value, f"{_PARTICLES_PATH}/{i}/position_m/{axis}")
                      for axis, value in enumerate(row)] for i, row in enumerate(positions)]
        for i, mask in enumerate(self.fixed):
            for axis, is_fixed in enumerate(mask):
                if is_fixed and struct.pack("!d", positions[i][axis]) != struct.pack("!d", self.initial_positions[i][axis]):
                    raise CalculationError("A fixed trial coordinate changed", code="INPUT_SEMANTIC", path=f"{_PARTICLES_PATH}/{i}/position_m/{axis}")
                if not math.isfinite(positions[i][axis] / self.length):
                    raise CalculationError("Trial coordinate exceeds the finite reduced domain", path=f"{_PARTICLES_PATH}/{i}/position_m/{axis}")
        energy_terms: list[float] = []
        force_terms: list[list[list[float]]] = [[[] for _ in range(3)] for _ in range(self.count)]
        pair_energies: list[dict] = []
        for i in range(self.count):
            for j in range(i + 1, self.count):
                if check_deadline is not None:
                    check_deadline()
                try:
                    displacement = [_sum((positions[i][axis], -positions[j][axis]), _PARTICLES_PATH,
                                         "coordinate difference") for axis in range(3)]
                    distance = math.hypot(*displacement)
                    if not math.isfinite(distance) or distance <= self.minimum:
                        raise CalculationError("Every pair distance must exceed the minimum distance",
                                               code="INPUT_SEMANTIC", path=_PARTICLES_PATH)
                    rho = _ratio(distance, self.length, _PARTICLES_PATH, "reduced pair distance")
                    value, slope = value_and_derivative(self.expression, self.parameters, rho)
                    energy_terms.append(value)
                    for axis in range(3):
                        contribution = _fraction_float(-Fraction(slope) * Fraction(displacement[axis])
                                                       / Fraction(distance), _PARTICLES_PATH,
                                                       "reduced pair force")
                        force_terms[i][axis].append(contribution)
                        force_terms[j][axis].append(-contribution)
                    if self.requested_pairs:
                        pair_energies.append({"i": i, "j": j, "distance_m": distance,
                                              "energy_j": _product((value, self.energy), _PAYLOAD_PATH + "/pair_energies",
                                                                   "SI pair energy")})
                except CalculationError as exc:
                    exc.details.setdefault("pair_indices", [i, j])
                    raise
        reduced_energy = _sum(energy_terms, _PAYLOAD_PATH + "/energy_j", "total reduced energy")
        reduced_forces = [[_sum(terms, f"{_PAYLOAD_PATH}/forces_n/{index}/{axis}", "total reduced force")
                           for axis, terms in enumerate(axes)] for index, axes in enumerate(force_terms)]
        total_energy = _product((reduced_energy, self.energy), _PAYLOAD_PATH + "/energy_j", "SI total energy")
        forces = [[_product((component, self.force_scale), f"{_PAYLOAD_PATH}/forces_n/{index}/{axis}", "SI force")
                   for axis, component in enumerate(row)] for index, row in enumerate(reduced_forces)]
        free_gradient = max((abs(reduced_forces[i][axis]) for i, axis in self.free_coordinates), default=0.0)
        if len(energy_terms) != self.pair_count:
            raise CalculationError("Not all pairs were evaluated", code="ENGINE_FAILURE", path=_PAYLOAD_PATH)
        if check_deadline is not None:
            check_deadline()
        return _PairEvaluation(positions, reduced_energy, reduced_forces, total_energy, forces, free_gradient, pair_energies)

    def payload(self, evaluation: _PairEvaluation, *, operation: str = "energy_forces", iterations: int = 0,
                evaluations: int = 1, stop_reason: str = "evaluated", history: list[dict] | None = None,
                converged: bool = False) -> dict:
        checks = [
            {"id": "all_pairs_evaluated", "status": "pass", "value": self.pair_count, "tolerance": 0},
            {"id": "finite_binary64_output", "status": "pass", "value": None, "tolerance": None},
        ]
        if operation == "energy_forces":
            checks.extend([
                {"id": "configuration_unchanged", "status": "pass", "value": 0, "tolerance": 0},
                {"id": "optimization_convergence", "status": "not_applicable", "value": None, "tolerance": None},
            ])
        else:
            checks.extend([
                {"id": "fixed_coordinates_unchanged", "status": "pass", "value": 0, "tolerance": 0},
                {"id": "free_gradient_tolerance", "status": "pass" if converged else "not_converged",
                 "value": evaluation.free_gradient_inf, "tolerance": self.definition["numerics"]["gradient_tolerance"]},
            ])
        payload = {
            "operation": operation,
            "initial_positions_m": [row.copy() for row in self.initial_positions],
            "final_positions_m": [row.copy() for row in evaluation.positions],
            "energy_j": evaluation.energy_j,
            "forces_n": [row.copy() for row in evaluation.forces_n],
            "free_gradient_inf": evaluation.free_gradient_inf,
            "iterations": iterations, "evaluations": evaluations,
            "stop_reason": stop_reason, "minimum_confirmed": False,
            "diagnostics": {"method": "lbfgsb_forward_ad_all_pairs_no_cutoff" if operation == "relax"
                            else "forward_mode_ast_all_pairs_no_cutoff", "checks": checks},
        }
        if self.requested_pairs:
            payload["pair_energies"] = [entry.copy() for entry in evaluation.pair_energies]
        if history is not None:
            payload["optimization_history"] = [entry.copy() for entry in history]
        _check_payload(payload, self.initial_positions, self.registry, self.module["payload_schema_ref"],
                       self.requested_pairs, self.fixed)
        if history is not None and ([entry["iteration"] for entry in history] != list(range(iterations + 1))
                                    or history[-1]["energy_j"] != evaluation.energy_j
                                    or history[-1]["free_gradient_inf"] != evaluation.free_gradient_inf):
            raise CalculationError("Accepted history is inconsistent with the output state", code="ENGINE_FAILURE", path=_PAYLOAD_PATH + "/optimization_history")
        return payload


def evaluate_pair(definition: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Evaluate the initial system once, preserving all authored coordinates.

    The bare definition is validated, but its protocol, overrides and sweep axes
    are not executed here. The experiment wrapper enforces the execution scope.
    Domain and numerical range failures, including nonzero underflow, are errors.
    """
    prepared = _PreparedPair(definition, registry=registry)
    return prepared.payload(prepared.evaluate(prepared.initial_positions))
