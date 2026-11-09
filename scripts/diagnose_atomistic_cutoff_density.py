"""Separate sampling and reconstruction diagnostics for fixed-cell A04 CUBEs."""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np

from compare_atomistic_a04_accuracy import (
    MAX_HE16_AXIS_COUNT,
    _grid_count,
    _interpolated_planes,
    _require_aligned_atoms,
    _verified_samples,
)
from verify_atomistic_a03 import LOCK_DIR


# Bound the in-memory diagnostics separately from the CP2K container.
MAX_DIAGNOSTIC_AXIS_COUNT = 300
MAX_16_ANGSTROM_DIAGNOSTIC_AXIS_COUNT = MAX_HE16_AXIS_COUNT


def _native_grid(path: Path, attempt: dict, count: int) -> np.ndarray:
    with _verified_samples(path, attempt["density"]) as samples:
        return np.fromiter(samples, dtype=np.float64, count=count ** 3).reshape((count,) * 3)


def _trigonometric_axis(values: np.ndarray, target_count: int, axis: int) -> np.ndarray:
    """Evaluate the real periodic interpolant at a new set of cell nodes."""
    source = np.moveaxis(values, axis, -1)
    source_count = source.shape[-1]
    if source_count == target_count:
        return values
    if source_count % target_count == 0:
        return np.moveaxis(source[..., ::source_count // target_count], -1, axis)

    target = np.empty((*source.shape[:-1], target_count), dtype=np.float64)
    # Bound temporary Fourier arrays to one strip at a time. Forward normalization
    # makes the coefficients independent of source and target sample counts.
    for i, strip in enumerate(source):
        coefficients = np.fft.rfft(strip, axis=-1, norm="forward")
        folded = np.zeros((strip.shape[0], target_count // 2 + 1), dtype=np.complex128)
        if target_count > source_count:
            folded[:, :coefficients.shape[1]] = coefficients
            if source_count % 2 == 0:
                # The source's unpaired Nyquist coefficient becomes one
                # of two conjugate coefficients on the finer lattice.
                folded[:, source_count // 2] *= 0.5
        else:
            folded[:, 0] = coefficients[:, 0]
            for frequency in range(1, coefficients.shape[1]):
                coefficient = coefficients[:, frequency]
                if 2 * frequency == source_count:
                    coefficient = 0.5 * coefficient
                index = frequency % target_count
                if index == 0 or 2 * index == target_count:
                    folded[:, index] += 2.0 * coefficient.real
                elif 2 * index < target_count:
                    folded[:, index] += coefficient
                else:
                    folded[:, target_count - index] += coefficient.conjugate()
        target[i] = np.fft.irfft(folded, n=target_count, axis=-1, norm="forward")
    return np.moveaxis(target, -1, axis)


def _trigonometric_grid(values: np.ndarray, target_count: int) -> np.ndarray:
    for axis in range(3):
        values = _trigonometric_axis(values, target_count, axis)
    return values


def _difference(reference: np.ndarray, candidate, cell_bohr: float) -> dict:
    count = reference.shape[0]
    absolute, signed, squared, maxima = [], [], [], []
    for ref_plane, cand_plane in zip(reference, candidate, strict=True):
        delta = cand_plane - ref_plane
        magnitude = np.abs(delta)
        absolute.append(float(magnitude.sum()))
        signed.append(float(delta.sum()))
        squared.append(float(np.square(delta).sum()))
        maxima.append(float(magnitude.max()))
    dv = (cell_bohr / count) ** 3
    result = {
        "samples": count ** 3,
        "voxel_volume_bohr3": dv,
        "absolute_difference_integral_electrons": math.fsum(absolute) * dv,
        "signed_difference_integral_electrons": math.fsum(signed) * dv,
        "rms_difference_electrons_per_bohr3": math.sqrt(math.fsum(squared) / count ** 3),
        "max_absolute_difference_electrons_per_bohr3": max(maxima),
    }
    if not all(math.isfinite(v) for v in result.values()):
        raise ValueError("Nonfinite cutoff-density diagnostic")
    return result


def diagnose_cutoff_density(
    reference_attempt: dict, candidate_attempt: dict, reference_cube: Path,
    candidate_cube: Path, cell_angstrom: int,
    *, maximum_axis_count: int = MAX_DIAGNOSTIC_AXIS_COUNT,
) -> dict:
    """Report alternative sampling metrics without changing the A04 gate."""
    if type(cell_angstrom) is not int or cell_angstrom <= 0:
        raise ValueError("Expected a positive authored cubic cell in integer Å")
    limits = (MAX_DIAGNOSTIC_AXIS_COUNT,)
    if cell_angstrom == 16:
        limits += (MAX_16_ANGSTROM_DIAGNOSTIC_AXIS_COUNT,)
    if type(maximum_axis_count) is not int or maximum_axis_count not in limits:
        raise ValueError("Unsupported cutoff-density diagnostic axis limit for this cell")
    units = json.loads((LOCK_DIR / "density-and-units.json").read_bytes())["engine_unit_profile"]
    cell_bohr = cell_angstrom * 1e-10 / units["a_bohr_m"]
    fine_count = _grid_count(reference_attempt, cell_bohr, maximum_axis_count=maximum_axis_count)
    coarse_count = _grid_count(candidate_attempt, cell_bohr, maximum_axis_count=maximum_axis_count)
    if not 6 <= coarse_count < fine_count <= maximum_axis_count:
        raise ValueError("Expected distinct bounded CUTOFF density grids, finer reference first")
    _require_aligned_atoms(reference_attempt["density"], candidate_attempt["density"], 0)
    fine = _native_grid(reference_cube, reference_attempt, fine_count)
    coarse = _native_grid(candidate_cube, candidate_attempt, coarse_count)

    shared_count = math.gcd(fine_count, coarse_count)
    fine_stride, coarse_stride = fine_count // shared_count, coarse_count // shared_count
    shared = _difference(fine[::fine_stride, ::fine_stride, ::fine_stride],
                         coarse[::coarse_stride, ::coarse_stride, ::coarse_stride], cell_bohr)
    fourier = _difference(fine, _trigonometric_grid(coarse, fine_count), cell_bohr)
    sampled_reference = _trigonometric_grid(fine, coarse_count)
    coarse_difference = _difference(sampled_reference, coarse, cell_bohr)
    roundtrip = {
        "fourier": _difference(fine, _trigonometric_grid(sampled_reference, fine_count), cell_bohr),
        "lagrange_4pt": _difference(fine, _interpolated_planes(sampled_reference, fine_count, 4), cell_bohr),
        "lagrange_6pt": _difference(fine, _interpolated_planes(sampled_reference, fine_count, 6), cell_bohr),
    }
    return {
        "method": "signed periodic trigonometric diagnostic on a common half-open cell",
        "reference_grid_axis_count": fine_count,
        "candidate_grid_axis_count": coarse_count,
        "shared_native_grid_axis_count": shared_count,
        "shared_native_points": shared,
        "shared_native_scope": "Direct point differences; its integral uses the sparse shared-grid rectangular rule.",
        "candidate_to_reference_fourier": fourier,
        "reference_to_candidate_sampling": (
            "exact native subsampling" if fine_count % coarse_count == 0
            else "periodic trigonometric evaluation with alias folding"
        ),
        "candidate_vs_sampled_reference": coarse_difference,
        "reference_self_roundtrip": roundtrip,
        "interpretation": (
            "Self-roundtrip starts from the same fine output and measures sampling plus reconstruction. "
            "The Fourier estimator assumes periodic extension of the serialized finite-cell data. "
            "These diagnostics do not replace the preregistered two-interpolant gate or provide "
            "an additive separation of error magnitudes."
        ),
    }
