"""Compare same-input CP2K results with bounded memory."""

from __future__ import annotations

import hashlib
from itertools import batched
import json
import math
from pathlib import Path


VALIDATION_PLAN = Path("docs/design/atomistic-a01-v0.1/validation-plan.json")
GEOMETRY_FIELDS = (
    "comments", "atom_count", "atoms_bohr_rounded", "origin_bohr_rounded",
    "grid_counts", "grid_axes_bohr_rounded", "samples", "voxel_volume_bohr3_from_rounded_header",
)
FIELD_L1_ATOL_ELECTRONS = 1e-3


def compare_summaries(reference: dict, distributed: dict) -> dict:
    """Compare measured metadata, including the historical CUBE digest."""
    if (
        reference["status"] != "measured"
        or distributed["status"] != "measured"
        or reference["input_sha256"] != distributed["input_sha256"]
    ):
        raise ValueError("Comparison requires completed calculations with the same input digest")
    checks = {
        check["id"]: check for check in json.loads(
            (Path(__file__).resolve().parents[1] / VALIDATION_PLAN).read_bytes()
        )["checks"]
    }
    av01 = checks["AV01"]
    count_atol = checks["AV06"]["atol"]
    ref_density, new_density = reference["density"], distributed["density"]
    if any(ref_density[key] != new_density[key] for key in GEOMETRY_FIELDS):
        raise ValueError("CUBE grids or ordered atoms differ")
    if ref_density["comments"] != ["-Quickstep-", " TOTAL ELECTRON DENSITY"]:
        raise ValueError("Comparison requires CP2K's total electron density")
    left = reference["engine_forces_hartree_per_bohr"]
    right = distributed["engine_forces_hartree_per_bohr"]
    if len(left) != ref_density["atom_count"] or len(right) != len(left):
        raise ValueError("Native force count differs from the CUBE atom count")
    if any(len(row) != 3 for row in (*left, *right)):
        raise ValueError("Force rows must have three Cartesian components")
    df = max(abs(a - b) for lhs, rhs in zip(left, right) for a, b in zip(lhs, rhs))
    de = abs(reference["engine_energy_hartree"] - distributed["engine_energy_hartree"])
    ref_count, new_count = ref_density["electron_integral"], new_density["electron_integral"]
    if not all(map(math.isfinite, (df, de, ref_count, new_count))) or not all(
        math.isfinite(value) for row in (*left, *right) for value in row
    ):
        raise ValueError("Nonfinite native observable")
    passes = (
        de <= av01["energy_atol_hartree"] and df <= av01["force_atol_hartree_per_bohr"]
        and max(abs(ref_count - 2), abs(new_count - 2)) <= count_atol
    )
    return {
        "scope": "same locked scientific input and engine, different execution layout or swap allowance",
        "tolerance_sources": [f"{VALIDATION_PLAN}#AV01", f"{VALIDATION_PLAN}#AV06"],
        "input_sha256": reference["input_sha256"],
        "grid_counts": ref_density["grid_counts"],
        "reference_energy_hartree": reference["engine_energy_hartree"],
        "distributed_energy_hartree": distributed["engine_energy_hartree"],
        "absolute_energy_difference_hartree": de,
        "absolute_maximum_force_component_difference_hartree_per_bohr": df,
        "energy_atol_hartree": av01["energy_atol_hartree"],
        "force_atol_hartree_per_bohr": av01["force_atol_hartree_per_bohr"],
        "reference_exported_electron_count": ref_count,
        "distributed_exported_electron_count": new_count,
        "absolute_exported_electron_count_difference": abs(new_count - ref_count),
        "exported_electron_count_atol_from_two": count_atol,
        "reference_native_cube_sha256": ref_density["sha256"],
        "distributed_native_cube_sha256": new_density["sha256"],
        "same_native_cube_sha256": ref_density["sha256"] == new_density["sha256"],
        "passes_summary_comparison": passes,
    }


def cube_values(stream, digest):
    # Pinned CP2K E13.5E3, up to six fields per line with no required separator.
    while line := stream.readline(81):
        digest.update(line)
        raw = line.rstrip(b"\r\n")
        if not raw or len(raw) > 78 or len(raw) % 13 or not line.endswith(b"\n"):
            raise ValueError("Unexpected native CUBE row")
        for offset in range(0, len(raw), 13):
            sample = float(raw[offset:offset + 13])
            if not math.isfinite(sample):
                raise ValueError("Nonfinite native CUBE sample")
            yield sample


def compare_attempts(reference: dict, distributed: dict, reference_cube: Path, distributed_cube: Path) -> dict:
    """Compare every original serialized CUBE sample without changing its grid."""
    result = compare_summaries(reference, distributed)
    density = reference["density"]
    hashes = hashlib.sha256(), hashlib.sha256()
    signed, absolute, squares = [], [], []
    max_delta = 0.0
    count = 0
    with reference_cube.open("rb") as left, distributed_cube.open("rb") as right:
        for _ in range(6 + density["atom_count"]):
            a, b = left.readline(256), right.readline(256)
            if a != b or not a.endswith(b"\n"):
                raise ValueError("Native CUBE header mismatch")
            hashes[0].update(a)
            hashes[1].update(b)
        pairs = zip(cube_values(left, hashes[0]), cube_values(right, hashes[1]), strict=True)
        for block in batched((b - a for a, b in pairs), 8192):
            count += len(block)
            if count > density["samples"]:
                raise ValueError("Native CUBE contains excess samples")
            signed.append(math.fsum(block))
            magnitudes = tuple(map(abs, block))
            absolute.append(math.fsum(magnitudes))
            squares.append(math.fsum(value * value for value in block))
            max_delta = max(max_delta, max(magnitudes))
    if count != density["samples"] or count != math.prod(density["grid_counts"]):
        raise ValueError("Native CUBE sample count mismatch")
    if tuple(d.hexdigest() for d in hashes) != (density["sha256"], distributed["density"]["sha256"]):
        raise ValueError("CUBE file digest differs from the measured density record")
    voxel_volume = density["voxel_volume_bohr3_from_rounded_header"]
    l1 = math.fsum(absolute) * voxel_volume
    result.update(
        compared_native_samples=count,
        maximum_absolute_density_difference_electron_per_bohr3=max_delta,
        rms_density_difference_electron_per_bohr3=math.sqrt(math.fsum(squares) / count),
        signed_density_difference_integral_electrons=math.fsum(signed) * voxel_volume,
        absolute_density_difference_integral_electrons=l1,
        density_l1_atol_electrons=FIELD_L1_ATOL_ELECTRONS,
        density_l1_tolerance_origin=(
            "predeclared MPI reproducibility criterion using the AV06 tolerance magnitude; "
            "distinct from AV06 and spatial convergence"
        ),
        passes_comparison=result["passes_summary_comparison"] and l1 <= FIELD_L1_ATOL_ELECTRONS,
    )
    return result
