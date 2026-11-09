"""Compare fixed A04 CP2K total electron-density grids in centered coordinates."""

from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from compare_atomistic_a04_mpi import cube_values
from verify_atomistic_a03 import LOCK_DIR


HEADER_ATOL_BOHR = 5.01e-7
MAX_AXIS_COUNT = 360
TOTAL_ELECTRON_DENSITY = ["-Quickstep-", " TOTAL ELECTRON DENSITY"]


def _cell_length(value: int | float | str) -> Fraction:
    if type(value) not in (int, float, str):
        raise ValueError("Expected a positive authored decimal cell length in Å")
    try:
        decimal = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("Expected a positive authored decimal cell length in Å") from error
    if not decimal.is_finite() or decimal <= 0:
        raise ValueError("Expected a positive authored decimal cell length in Å")
    return Fraction(decimal)


def _grid_count(attempt: dict, cell_bohr: float) -> int:
    density = attempt["density"]
    counts = density["grid_counts"]
    if (
        attempt["status"] != "measured" or density["comments"] != TOTAL_ELECTRON_DENSITY
        or len(counts) != 3 or any(type(n) is not int for n in counts)
        or not 1 <= counts[0] <= MAX_AXIS_COUNT or counts != [counts[0]] * 3
        or density["samples"] != math.prod(counts)
    ):
        raise ValueError("Expected a measured, bounded cubic total electron-density CUBE")
    spacing = cell_bohr / counts[0]
    origin = np.asarray(density["origin_bohr_rounded"], dtype=np.float64)
    axes = np.asarray(density["grid_axes_bohr_rounded"], dtype=np.float64)
    if (
        origin.shape != (3,) or axes.shape != (3, 3)
        or not np.allclose(origin, 0, rtol=0, atol=HEADER_ATOL_BOHR)
        or not np.allclose(axes, np.eye(3) * spacing, rtol=0, atol=HEADER_ATOL_BOHR)
    ):
        raise ValueError("CUBE origin or axes differ from the authored cell beyond header rounding")
    return counts[0]


def _require_aligned_atoms(left: dict, right: dict, shift_bohr: float) -> None:
    left_atoms = np.asarray(left["atoms_bohr_rounded"], dtype=np.float64)
    right_atoms = np.asarray(right["atoms_bohr_rounded"], dtype=np.float64)
    count = left["atom_count"]
    if (
        count <= 0 or right["atom_count"] != count
        or left_atoms.shape != (count, 5) or right_atoms.shape != (count, 5)
        or not np.isfinite(left_atoms).all() or not np.isfinite(right_atoms).all()
        or not np.array_equal(left_atoms[:, :2], right_atoms[:, :2])
        or not np.allclose(
            left_atoms[:, 2:], right_atoms[:, 2:] + shift_bohr, rtol=0, atol=2 * HEADER_ATOL_BOHR
        )
    ):
        raise ValueError("Ordered CUBE atoms do not align after centering the two authored cells")


@contextmanager
def _verified_samples(path: Path, density: dict):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for _ in range(6 + density["atom_count"]):
            line = stream.readline(256)
            if not line.endswith(b"\n"):
                raise ValueError("Invalid native CUBE header line")
            digest.update(line)
        samples = cube_values(stream, digest)
        yield samples
        if next(samples, None) is not None:
            raise ValueError("Native CUBE contains excess samples")
    if digest.hexdigest() != density["sha256"]:
        raise ValueError("Native CUBE digest differs from the measured density record")


def _read_plane(samples, count: int) -> np.ndarray:
    return np.fromiter(samples, dtype=np.float64, count=count * count).reshape(count, count)


def _lagrange_stencil(source_count: int, target_count: int, points: int) -> tuple[np.ndarray, np.ndarray]:
    if source_count < points:
        raise ValueError("Candidate axis is too short for the fixed interpolation stencil")
    positions = np.arange(target_count, dtype=np.float64) * source_count / target_count
    starts = np.floor(positions).astype(np.int64) - (points // 2 - 1)
    # Centered stencils in the interior, one-sided polynomial at the ends.
    # The finer grid can place its final sample up to one coarse step past the
    # last candidate node, within the same half-open cell.
    starts = np.clip(starts, 0, source_count - points)
    offsets = np.arange(points)
    indices = starts[:, None] + offsets
    weights = np.ones_like(indices, dtype=np.float64)
    for i in range(points):
        for j in range(points):
            if i != j:
                weights[:, i] *= (positions - indices[:, j]) / (i - j)
    return indices, weights


def _interpolated_planes(source: np.ndarray, count: int, points: int):
    indices, weights = _lagrange_stencil(source.shape[0], count, points)

    @lru_cache(maxsize=points)
    def resample_yz(source_i: int) -> np.ndarray:
        plane = source[source_i]
        y = np.zeros((count, plane.shape[1]), dtype=np.float64)
        for col in range(points):
            y += weights[:, col, None] * plane[indices[:, col], :]
        yz = np.zeros((count, count), dtype=np.float64)
        for col in range(points):
            yz += weights[None, :, col] * y[:, indices[:, col]]
        return yz

    for i in range(count):
        plane = np.zeros((count, count), dtype=np.float64)
        for j, w in zip(indices[i], weights[i], strict=True):
            plane += w * resample_yz(int(j))
        yield plane


def _slab_difference(candidate: np.ndarray, reference: np.ndarray) -> tuple[float, float, float, float]:
    delta = candidate - reference
    absolute = np.abs(delta)
    return float(absolute.sum()), float(delta.sum()), float(np.square(delta).sum()), float(absolute.max())


def _overlap_metrics(slabs: list[tuple], count: int, dv: float, shell_absolute: float) -> dict:
    absolute = math.fsum(slab[0] for slab in slabs) * dv
    return {
        "overlap_absolute_density_difference_integral_electrons": absolute,
        "overlap_signed_density_difference_integral_electrons": math.fsum(slab[1] for slab in slabs) * dv,
        "overlap_rms_density_difference_electron_per_bohr3": math.sqrt(
            math.fsum(slab[2] for slab in slabs) / count
        ),
        "overlap_maximum_absolute_density_difference_electron_per_bohr3": max(slab[3] for slab in slabs),
        "zero_extended_absolute_density_difference_integral_electrons": absolute + shell_absolute,
    }


def compare_density(
    reference_attempt: dict, candidate_attempt: dict, reference_cube: Path, candidate_cube: Path,
    reference_cell_angstrom: int | float | str, candidate_cell_angstrom: int | float | str,
) -> dict:
    """Report overlap and omitted-domain errors, without assigning a scientific pass."""
    reference_cell = _cell_length(reference_cell_angstrom)
    candidate_cell = _cell_length(candidate_cell_angstrom)
    if candidate_cell > reference_cell:
        raise ValueError("Expected a reference cell no smaller than the candidate cell")
    engine_units = json.loads((LOCK_DIR / "density-and-units.json").read_bytes())["engine_unit_profile"]
    bohr_per_angstrom = 1e-10 / engine_units["a_bohr_m"]
    ref_n = _grid_count(reference_attempt, reference_cell * bohr_per_angstrom)
    cand_n = _grid_count(candidate_attempt, candidate_cell * bohr_per_angstrom)
    if reference_cell == candidate_cell and ref_n < cand_n:
        raise ValueError("Equal-cell comparison requires a reference grid at least as fine as the candidate")
    overlap = ref_n * candidate_cell / reference_cell
    offset = (ref_n - overlap) / 2
    if overlap.denominator != 1 or offset.denominator != 1:
        raise ValueError("Candidate cell boundaries must align to native reference grid indices")
    extent, start = int(overlap), int(offset)
    stop = start + extent
    dv = (reference_cell * bohr_per_angstrom / ref_n) ** 3
    direct = cand_n == extent
    left, right = reference_attempt["density"], candidate_attempt["density"]
    _require_aligned_atoms(left, right, (reference_cell - candidate_cell) * bohr_per_angstrom / 2)

    shell_absolute_sums, shell_signed_sums = [], []
    primary_slabs, sensitivity_slabs, interpolation_delta = [], [], []
    with _verified_samples(reference_cube, left) as ref_samples, _verified_samples(candidate_cube, right) as cand_samples:
        if not direct:
            values = np.fromiter(cand_samples, dtype=np.float64, count=cand_n ** 3).reshape((cand_n,) * 3)
            cubic = _interpolated_planes(values, extent, 4)
            sixth = _interpolated_planes(values, extent, 6)
        for i in range(ref_n):
            reference = _read_plane(ref_samples, ref_n)
            if start <= i < stop:
                inner = reference[start:stop, start:stop]
                candidate = _read_plane(cand_samples, cand_n) if direct else next(cubic)
                primary_slabs.append(_slab_difference(candidate, inner))
                if not direct:
                    alternative = next(sixth)
                    sensitivity_slabs.append(_slab_difference(alternative, inner))
                    interpolation_delta.append(float(np.abs(alternative - candidate).sum()))
                shell = (reference[:start, :], reference[stop:, :],
                         reference[start:stop, :start], reference[start:stop, stop:])
            else:
                shell = (reference,)
            shell_absolute_sums.extend(float(np.abs(region).sum()) for region in shell)
            shell_signed_sums.extend(float(region.sum()) for region in shell)
    shell_absolute = math.fsum(shell_absolute_sums) * dv
    return {
        "method": "native_aligned_crop" if direct else "separable_lagrange_4pt_and_6pt",
        "comparison_grid": "native reference grid with half-open centered cell domain",
        "outside_extension_for_metric": "zero outside candidate cell only; report native reference absolute and signed sums",
        "reference_grid_counts": [ref_n] * 3,
        "candidate_grid_counts": [cand_n] * 3,
        "reference_native_cube_sha256": left["sha256"],
        "candidate_native_cube_sha256": right["sha256"],
        "reference_overlap_start_index": [start] * 3,
        "reference_overlap_grid_counts": [extent] * 3,
        "reference_voxel_volume_bohr3": dv,
        "reference_outer_shell_samples": ref_n ** 3 - extent ** 3,
        "reference_outer_shell_absolute_integral_electrons": shell_absolute,
        "reference_outer_shell_signed_integral_electrons": math.fsum(shell_signed_sums) * dv,
        "primary": _overlap_metrics(primary_slabs, extent ** 3, dv, shell_absolute),
        "sensitivity": None if direct else _overlap_metrics(sensitivity_slabs, extent ** 3, dv, shell_absolute),
        "interpolants_overlap_l1_electrons": None if direct else math.fsum(interpolation_delta) * dv,
        "interpolation_right_extrapolated_planes_per_axis": 0 if direct else (
            extent - 1 - (cand_n - 1) * extent // cand_n
        ),
        "candidate_native_samples_clipped_or_renormalized": False,
    }
