"""Apply fixed A04 numerical criteria to one-factor cc-pVQZ comparisons."""

from __future__ import annotations

import json
import math
from fractions import Fraction
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from compare_atomistic_a04_accuracy import _cell_length, _grid_count, _read_plane, _verified_samples
from verify_atomistic_a03 import LOCK_DIR

if TYPE_CHECKING:
    from run_atomistic_a04_resource_ci import Case


FACTOR_SETTINGS = {
    "scf": "eps_scf",
    "radial": "radial_grid",
    "angular": "lebedev_grid",
    "cell": "cell",
    "cutoff": "cutoff",
    "relative": "rel_cutoff",
}
SAME_LATTICE_FIELDS = (
    "grid_counts", "origin_bohr_rounded", "grid_axes_bohr_rounded", "atoms_bohr_rounded",
)


def _native_shell(attempt: dict, cube: Path, cell: Fraction, width: int, bohr_per_angstrom: float) -> dict:
    count = _grid_count(attempt, cell * bohr_per_angstrom)
    # A native half-open cell samples coordinate i * cell / count. Include
    # sample points on the inner shell boundary, without rounding positions.
    lower = width * count // cell + 1
    upper = math.ceil((cell - width) * count / cell)
    volume = (cell * bohr_per_angstrom / count) ** 3
    signed, absolute = [], []
    with _verified_samples(cube, attempt["density"]) as samples:
        for i in range(count):
            plane = _read_plane(samples, count)
            if i < lower or i >= upper:
                shell = (plane,)
            else:
                shell = (
                    plane[:lower, :], plane[upper:, :], plane[lower:upper, :lower], plane[lower:upper, upper:],
                )
            signed.extend(float(region.sum()) for region in shell)
            absolute.extend(float(np.abs(region).sum()) for region in shell)
    return {
        "width_angstrom": width,
        "samples": count ** 3 - max(0, upper - lower) ** 3,
        "voxel_volume_bohr3": volume,
        "signed_integral_electrons": math.fsum(signed) * volume,
        "absolute_integral_electrons": math.fsum(absolute) * volume,
    }


def compare_cell_tails(
    reference: dict, candidate: dict, reference_cube: Path, candidate_cube: Path,
    reference_cell_angstrom: int | float | str, candidate_cell_angstrom: int | float | str,
    spatial_density: dict, *, shell_width_angstrom: int = 1,
    shell_atol: float = 0.001, omitted_atol: float = 0.001,
) -> dict:
    """Check the signed native boundary shells and already-compared omitted domain."""
    reference_cell = _cell_length(reference_cell_angstrom)
    candidate_cell = _cell_length(candidate_cell_angstrom)
    if (
        type(shell_width_angstrom) is not int
        or not 0 < 2 * shell_width_angstrom < candidate_cell <= reference_cell
    ):
        raise ValueError("Expected an ordered cell pair and a positive integer shell width less than half the smaller cell")
    if not all(math.isfinite(tolerance) and tolerance > 0 for tolerance in (shell_atol, omitted_atol)):
        raise ValueError("Expected positive finite-cell electron tolerances")
    units = json.loads((LOCK_DIR / "density-and-units.json").read_bytes())["engine_unit_profile"]
    bohr_per_angstrom = 1e-10 / units["a_bohr_m"]
    reference_shell = _native_shell(
        reference, reference_cube, reference_cell, shell_width_angstrom, bohr_per_angstrom,
    )
    candidate_shell = _native_shell(
        candidate, candidate_cube, candidate_cell, shell_width_angstrom, bohr_per_angstrom,
    )
    omitted_absolute = spatial_density["reference_outer_shell_absolute_integral_electrons"]
    return {
        "reference_native_boundary_shell": reference_shell,
        "candidate_native_boundary_shell": candidate_shell,
        "shell_absolute_atol_electrons": shell_atol,
        "omitted_reference_absolute_integral_electrons": omitted_absolute,
        "omitted_reference_signed_integral_electrons": spatial_density["reference_outer_shell_signed_integral_electrons"],
        "omitted_reference_absolute_atol_electrons": omitted_atol,
        "shell_passed": max(
            reference_shell["absolute_integral_electrons"], candidate_shell["absolute_integral_electrons"],
        ) <= shell_atol,
        "omitted_domain_passed": omitted_absolute <= omitted_atol,
    }


def compare_qz_pair(
    reference_case: Case, candidate_case: Case, reference: dict, candidate: dict,
    reference_cube: Path, candidate_cube: Path, checks: dict, l1_atol: float,
    *, axis: str, shell_width_angstrom: int = 1, shell_atol: float = 0.001,
    omitted_atol: float = 0.001, allow_cell_interpolation: bool = False,
) -> dict:
    """Compare a preregistered candidate and its tighter one-factor endpoint."""
    from run_atomistic_a04_resource_ci import compare_accuracy_pair

    if axis not in FACTOR_SETTINGS:
        raise ValueError(f"Unknown QZ sensitivity axis: {axis}")
    if any(case.basis != "cc-pVQZ" or not case.density for case in (reference_case, candidate_case)):
        raise ValueError("QZ sensitivity requires fixed cc-pVQZ and total density output")
    field = FACTOR_SETTINGS[axis]
    ref_cell = _cell_length(reference_case.cell)
    candidate_cell = _cell_length(candidate_case.cell)
    changed = [key for key in FACTOR_SETTINGS.values()
               if key != "cell" and getattr(reference_case, key) != getattr(candidate_case, key)]
    if ref_cell != candidate_cell:
        changed.append("cell")
    ref_setting = ref_cell if axis == "cell" else getattr(reference_case, field)
    candidate_setting = candidate_cell if axis == "cell" else getattr(candidate_case, field)
    tighter = ref_setting < candidate_setting if axis == "scf" else ref_setting > candidate_setting
    if changed != [field] or not tighter or reference_case.overlap_condition != candidate_case.overlap_condition:
        raise ValueError("QZ sensitivity requires changing only the declared factor toward the tighter endpoint")

    same_lattice = axis not in ("cell", "cutoff")
    if same_lattice and any(
        reference["density"][key] != candidate["density"][key] for key in SAME_LATTICE_FIELDS
    ):
        raise ValueError(f"The QZ {axis} comparison requires the same native lattice and ordered geometry")
    result = compare_accuracy_pair(
        reference_case, candidate_case, reference, candidate, reference_cube, candidate_cube, checks, l1_atol,
    )
    result["sensitivity_axis"] = axis
    result["reference_axis_setting"] = getattr(reference_case, field)
    result["candidate_axis_setting"] = getattr(candidate_case, field)
    density = result["spatial_density"]
    if (same_lattice or (axis == "cell" and not allow_cell_interpolation)) and density["method"] != "native_aligned_crop":
        raise ValueError(f"The QZ {axis} comparison requires direct native samples")

    if axis == "cell":
        tails = compare_cell_tails(
            reference, candidate, reference_cube, candidate_cube, reference_case.cell, candidate_case.cell,
            density, shell_width_angstrom=shell_width_angstrom, shell_atol=shell_atol, omitted_atol=omitted_atol,
        )
        result["finite_cell_tail"] = tails
        result["within_all_endpoint_thresholds"] &= tails["shell_passed"] and tails["omitted_domain_passed"]
    return result
