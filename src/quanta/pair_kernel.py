"""Shared all-pairs conservative energy/force kernel, without module adapters.

Callers select and validate their own module schema, physical state and resource
profile. This kernel consumes explicit scales, a bounded distance AST, minimum
distance and N Cartesian positions. It does not invent masses or velocities,
apply fixed-coordinate masks, integrate time, or claim physical validation.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from fractions import Fraction
import math
from typing import Callable

from .autodiff import (CalculationError, _fraction_float, _number, _product,
                       _ratio, _sum, value_and_derivative)


@dataclass(frozen=True)
class PairForceEvaluation:
    positions: list[list[float]]
    reduced_energy: float
    reduced_forces: list[list[float]]
    energy_j: float
    forces_n: list[list[float]]
    pair_energies: list[dict]


class PairForceKernel:
    """Snapshot a module-independent radial-pair model and evaluate all pairs.

    The numerical loop, summation order and exact local product/range policy
    are shared by static calculations and future dynamics. Public request
    validators remain responsible for structural/resource/physical contracts.
    This class defensively checks its numerical inputs and bounded AST through
    the same AD evaluator; it never falls back to another force law.
    """

    def __init__(self, *, count: int, length_m: float, energy_j: float,
                 min_distance_m: float, expression: dict, parameters: dict,
                 requested_pairs: bool = False,
                 particles_path: str = "/system/particles", payload_path: str = "/payload",
                 scales_path: str = "/scales", potential_path: str = "/system/potential"):
        if isinstance(count, bool) or not isinstance(count, int) or not 2 <= count <= 128:
            raise CalculationError("Pair kernel requires 2 to 128 particles",
                                   code="INPUT_SEMANTIC", path=particles_path)
        if not isinstance(requested_pairs, bool):
            raise CalculationError("Pair output selection must be boolean",
                                   code="INPUT_SEMANTIC", path=payload_path)
        self.count = count
        self.pair_count = count * (count - 1) // 2
        self.particles_path, self.payload_path = particles_path, payload_path
        self.potential_path = potential_path
        self.length = _number(length_m, scales_path + "/length_m")
        self.energy = _number(energy_j, scales_path + "/energy_j")
        self.minimum = _number(min_distance_m, particles_path.rsplit("/", 1)[0] + "/min_distance_m")
        for value, path in ((self.length, scales_path + "/length_m"),
                            (self.energy, scales_path + "/energy_j"),
                            (self.minimum, particles_path.rsplit("/", 1)[0] + "/min_distance_m")):
            if value <= 0.0:
                raise CalculationError("Pair scales and minimum distance must be strictly positive",
                                       code="INPUT_SEMANTIC", path=path)
        self.force_scale = _ratio(self.energy, self.length, scales_path, "force scale")
        self.expression = copy.deepcopy(expression)
        self.parameters = copy.deepcopy(parameters)
        self.requested_pairs = requested_pairs

    def evaluate(self, positions: list[list[float]], *,
                 check_deadline: Callable[[], None] | None = None) -> PairForceEvaluation:
        ppath, opath = self.particles_path, self.payload_path
        try:
            valid_shape = len(positions) == self.count and all(len(row) == 3 for row in positions)
        except TypeError:
            valid_shape = False
        if not valid_shape:
            raise CalculationError("Trial positions have an inconsistent shape",
                                   code="INPUT_SEMANTIC", path=ppath)
        positions = [[_number(value, f"{ppath}/{i}/position_m/{axis}")
                      for axis, value in enumerate(row)] for i, row in enumerate(positions)]
        for i, row in enumerate(positions):
            for axis, value in enumerate(row):
                if not math.isfinite(value / self.length):
                    raise CalculationError("Trial coordinate exceeds the finite reduced domain",
                                           path=f"{ppath}/{i}/position_m/{axis}")
        energy_terms: list[float] = []
        force_terms: list[list[list[float]]] = [[[] for _ in range(3)] for _ in range(self.count)]
        pair_energies: list[dict] = []
        for i in range(self.count):
            for j in range(i + 1, self.count):
                if check_deadline is not None:
                    check_deadline()
                try:
                    displacement = [_sum((positions[i][axis], -positions[j][axis]), ppath,
                                         "coordinate difference") for axis in range(3)]
                    distance = math.hypot(*displacement)
                    if not math.isfinite(distance) or distance <= self.minimum:
                        raise CalculationError("Every pair distance must exceed the minimum distance",
                                               code="INPUT_SEMANTIC", path=ppath)
                    rho = _ratio(distance, self.length, ppath, "reduced pair distance")
                    value, slope = value_and_derivative(self.expression, self.parameters, rho)
                    energy_terms.append(value)
                    for axis in range(3):
                        contribution = _fraction_float(-Fraction(slope) * Fraction(displacement[axis])
                                                       / Fraction(distance), ppath,
                                                       "reduced pair force")
                        force_terms[i][axis].append(contribution)
                        force_terms[j][axis].append(-contribution)
                    if self.requested_pairs:
                        pair_energies.append({"i": i, "j": j, "distance_m": distance,
                                              "energy_j": _product((value, self.energy), opath + "/pair_energies",
                                                                   "SI pair energy")})
                except CalculationError as exc:
                    # The existing AD evaluator owns a fixed expression path.
                    # Preserve it for static callers and map only that prefix
                    # for a differently rooted standalone module request.
                    prefix = "/definition/system/potential"
                    if exc.path == prefix or (isinstance(exc.path, str) and exc.path.startswith(prefix + "/")):
                        exc.path = self.potential_path + exc.path[len(prefix):]
                    exc.details.setdefault("pair_indices", [i, j])
                    raise
        reduced_energy = _sum(energy_terms, opath + "/energy_j", "total reduced energy")
        reduced_forces = [[_sum(terms, f"{opath}/forces_n/{index}/{axis}", "total reduced force")
                           for axis, terms in enumerate(axes)] for index, axes in enumerate(force_terms)]
        total_energy = _product((reduced_energy, self.energy), opath + "/energy_j", "SI total energy")
        forces = [[_product((component, self.force_scale), f"{opath}/forces_n/{index}/{axis}", "SI force")
                   for axis, component in enumerate(row)] for index, row in enumerate(reduced_forces)]
        if len(energy_terms) != self.pair_count:
            raise CalculationError("Not all pairs were evaluated", code="ENGINE_FAILURE", path=opath)
        if check_deadline is not None:
            check_deadline()
        return PairForceEvaluation(positions, reduced_energy, reduced_forces, total_energy, forces, pair_energies)
