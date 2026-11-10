"""Measure a checkpoint's direct FE density against a locked A04 pilot CUBE."""

from __future__ import annotations

import argparse
import hashlib
from itertools import chain
import json
import math
from pathlib import Path
import subprocess
import tempfile

import numpy as np

from compare_atomistic_a04_accuracy import (
    HEADER_ATOL_BOHR,
    _grid_count,
    _read_plane,
    _verified_samples,
)
from verify_atomistic_a03 import LOCK_DIR, sha256

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/design/atomistic-a04-v0.1/a04-basis-redesign-v1.json"
PROJECTION_RECEIPT_KEYS = {
    "overlap_electrons", "finite_domain_axial_bohr", "quadrature_32_electrons", "quadrature_64_electrons",
    "cell_omitted_upper_32_electrons", "cell_omitted_upper_64_electrons",
}


def locked_grid(report: dict, cube: Path) -> tuple[dict, int, float, float]:
    """Rebuild exact coordinates from the locked deck, verifying CUBE metadata."""
    starts = json.loads(DESIGN.read_bytes())["fixed_starts"]
    attempt = report["attempt"]
    candidate = report["candidate"]
    case = report["case"]
    metadata = attempt["input_metadata"]
    system = case["system"]
    expected_model = {
        "method": "GAPW", "functional": "PBE", "potential": "ALL",
        "charge_e": 0, "multiplicity": 1, "electron_count": 2,
        "uks": False, "dispersion": False, "periodic": "NONE",
    }
    if (
        candidate["cp2k_source"] != starts["cp2k_source"]
        or candidate["binary_sha256"] != starts["x86_binary_sha256"]
        or metadata["model"] != expected_model
        or metadata["system"] != system
        or metadata["density"]["density_include"] != "TOTAL_DENSITY"
        or metadata["density"]["stride"] != [1, 1, 1]
    ):
        raise ValueError("The CUBE must be from the pinned x86 GAPW/PBE all-electron pilot")
    if system == "he":
        axis, bond_m = starts["he"]["prior_native_axis"], 0.0
        species, positions, cutoff, rel_cutoff = (2,), (0.0,), 1800, 80
        admitted_basis_caps = {("cc-pV5Z", 8), ("cc-pV5Z", 10), ("cc-pV6Z", 10)}
    elif system == "h2-short":
        axis, bond_m = starts["h2"]["prior_pilot_native_axis"], 6e-11
        species, positions, cutoff, rel_cutoff = (1, 1), (-3e-11, 3e-11), 600, 40
        admitted_basis_caps = {("cc-pV5Z", 8), ("cc-pV5Z", 10)}
    else:
        raise ValueError("Only the two R1 pilot geometries are supported")
    numerics = metadata["numerics"]
    if (
        (metadata["basis"], numerics["lmaxn1"]) not in admitted_basis_caps
        or (numerics["cell_angstrom"], numerics["cutoff_ry"], numerics["rel_cutoff_ry"])
        != (12, cutoff, rel_cutoff)
        or [atom["source_position_m"] for atom in metadata["atoms"]]
        != [[x, 0, 0] for x in positions]
    ):
        raise ValueError("Unexpected locked R1 case or Cartesian orientation")
    bohr_m = json.loads((LOCK_DIR / "density-and-units.json").read_bytes())["engine_unit_profile"]["a_bohr_m"]
    cell, bond = 12e-10 / bohr_m, bond_m / bohr_m
    density = attempt["density"]
    atoms = np.asarray(density["atoms_bohr_rounded"], dtype=np.float64)
    center = cell / 2
    exact = [[x / bohr_m + center, center, center] for x in positions]
    if (
        axis != _grid_count(attempt, cell)
        or cube.stat().st_size != density["bytes"]
        or density["atom_count"] != len(species)
        or atoms.shape != (len(species), 5)
        or list(atoms[:, 0]) != list(species)
        or not np.allclose(atoms[:, 2:], exact, atol=HEADER_ATOL_BOHR, rtol=0)
    ):
        raise ValueError("CUBE shape, coordinates or file size differ from the locked case")
    return density, axis, cell, bond


def project(
    executable: Path, checkpoint: Path, destination: Path, axis: int, cell: float, bond: float,
) -> dict:
    input_hash = sha256(checkpoint)
    process = subprocess.run(
        [str(executable.resolve()), str(checkpoint), str(destination), str(axis), repr(cell), repr(bond)],
        text=True, capture_output=True, timeout=1800, check=True,
    )
    numeric_receipt = {}
    for line in process.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if separator and key in PROJECTION_RECEIPT_KEYS:
            if key in numeric_receipt:
                raise ValueError("Duplicate HelFEM projection receipt key")
            numeric_receipt[key] = float(value)
    if (
        numeric_receipt.keys() != PROJECTION_RECEIPT_KEYS
        or not all(map(math.isfinite, numeric_receipt.values()))
        or abs(numeric_receipt["overlap_electrons"] - 2.0) > 1e-8
        or abs(numeric_receipt["quadrature_64_electrons"] - numeric_receipt["overlap_electrons"]) > 1e-8
        or min(numeric_receipt["cell_omitted_upper_32_electrons"],
               numeric_receipt["cell_omitted_upper_64_electrons"]) < 0.0
        or numeric_receipt["finite_domain_axial_bohr"] <= cell / 2
        or destination.stat().st_size != axis**3 * 8
        or input_hash != sha256(checkpoint)
    ):
        raise ValueError("Unqualified or incomplete HelFEM density projection")
    return {
        "checkpoint_sha256": input_hash,
        "projected_field_sha256": sha256(destination),
        **numeric_receipt,
    }


def reference_density_axes(
    executable: Path, plan_path: Path, summary_path: Path, fixture: str,
    axis: int, cell: float, bond: float,
) -> dict:
    """Measure both adjacent FE refinements without using CP2K density values."""
    summary_bytes = summary_path.read_bytes()
    plan_bytes = plan_path.read_bytes()
    summary = json.loads(summary_bytes)
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    if summary["plan_sha256"] != plan_hash or summary["fixture"] != fixture:
        raise ValueError("Reference receipt does not match the locked fixture and plan")
    axes = json.loads(plan_bytes)["axes"][fixture]
    records = summary["records"]
    if records["fine"]["status"] != "admitted":
        raise ValueError("The finest reference checkpoint is not admitted")
    volume = (cell / axis)**3

    def grid(label: str, destination: Path):
        checkpoint = summary_path.parent / label / "checkpoint.h5"
        if sha256(checkpoint) != records[label]["checkpoint_sha256"]:
            raise ValueError(f"Reference checkpoint digest changed for {label}")
        receipt = project(executable, checkpoint, destination, axis, cell, bond)
        return np.memmap(destination, dtype="<f8", mode="r", shape=(axis,) * 3), receipt

    def l1(left, right):
        value = math.fsum(float(np.abs(a - b).sum()) for a, b in zip(left, right, strict=True)) * volume
        if not math.isfinite(value):
            raise ValueError("Nonfinite reference refinement difference")
        return value

    differences, missing = {}, []
    with tempfile.TemporaryDirectory(prefix="a04-helfem-axes-") as scratch:
        fine, fine_receipt = grid("fine", Path(scratch) / "fine.f64")
        for name, levels in axes.items():
            labels = (f"{name}-1", f"{name}-2")
            if any(records.get(label, {}).get("status") != "admitted" for label in labels):
                missing.extend(label for label in labels if records.get(label, {}).get("status") != "admitted")
                continue
            with tempfile.TemporaryDirectory(dir=scratch) as axis_scratch:
                (coarse, c_receipt), (middle, m_receipt) = (
                    grid(label, Path(axis_scratch) / f"{label}.f64") for label in labels
                )
                differences[name] = {
                    "levels": levels,
                    "coarse": c_receipt,
                    "middle": m_receipt,
                    "coarse_to_middle_l1_electrons": l1(coarse, middle),
                    "middle_to_fine_l1_electrons": l1(middle, fine),
                }
    return {
        "scope": "Empirical finite-element axis differences only, on identical Cartesian nodes",
        "reference_plan_sha256": plan_hash,
        "reference_summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
        "exporter_binary_sha256": sha256(executable),
        "reference_density": fine_receipt,
        "axis_differences": differences,
        "missing_or_inadmissible_labels": missing,
        "available_middle_to_fine_l1_sum_electrons": math.fsum(
            item["middle_to_fine_l1_electrons"] for item in differences.values()
        ),
    }


def compare(cube: Path, report_path: Path, executable: Path, checkpoints: list[Path]) -> dict:
    report = json.loads(report_path.read_bytes())
    density, axis, cell, bond = locked_grid(report, cube)
    spacing = cell / axis
    volume = spacing**3
    nodes = (np.arange(axis) - axis // 2) * spacing
    transverse_squared = nodes[:, None]**2 + nodes[None, :]**2
    shell_radii = (0.25, 0.5, 1.0, 2.0, 3.0)
    cumulative_l1s = [[] for _ in shell_radii]
    max_absolute_delta, max_delta, max_indices = -1.0, 0.0, (0, 0, 0)
    limits = json.loads(DESIGN.read_bytes())["thresholds"]["matched_pbe"]
    total = limits["total_limits"]["density_l1_electrons"]
    reserve = limits["reserve"]["density_l1_electrons"]
    with tempfile.TemporaryDirectory(prefix="a04-helfem-density-") as scratch:
        files = [Path(scratch) / f"density-{i}.f64" for i in range(len(checkpoints))]
        projections = [project(executable, checkpoint, output, axis, cell, bond)
                       for checkpoint, output in zip(checkpoints, files, strict=True)]
        grids = [np.memmap(output, dtype="<f8", mode="r", shape=(axis,) * 3) for output in files]
        final, *refinements = grids
        cp2k_integrals, l1s, reference_integrals = [], [], []
        refinement_l1s = [[] for _ in refinements]
        with _verified_samples(cube, density) as samples:
            for i in range(axis):
                cp2k, reference = _read_plane(samples, axis), final[i]
                if not np.isfinite(reference).all():
                    raise ValueError("Nonfinite projected density")
                cp2k_integrals.append(float(cp2k.sum()))
                reference_integrals.append(float(reference.sum()))
                delta = cp2k - reference
                abs_delta = np.abs(delta)
                l1s.append(float(abs_delta.sum()))
                nearest_squared = (abs(nodes[i]) - bond / 2)**2 + transverse_squared
                for radius, shell_l1 in zip(shell_radii, cumulative_l1s, strict=True):
                    shell_l1.append(float(abs_delta[nearest_squared <= radius**2].sum()))
                j, k = np.unravel_index(abs_delta.argmax(), abs_delta.shape)
                if abs_delta[j, k] > max_absolute_delta:
                    max_absolute_delta = float(abs_delta[j, k])
                    max_delta = float(delta[j, k])
                    max_indices = i, int(j), int(k)
                for grid, l1 in zip(refinements, refinement_l1s, strict=True):
                    l1.append(float(np.abs(reference - grid[i]).sum()))
        measured = math.fsum(l1s) * volume
        refinement_l1 = [math.fsum(l1) * volume for l1 in refinement_l1s]
        if not all(map(math.isfinite, chain((measured,), refinement_l1))):
            raise ValueError("Nonfinite density discrepancy")
    ref_count = math.fsum(reference_integrals) * volume
    cp2k_count = math.fsum(cp2k_integrals) * volume
    return {
        "status": "density_screen_measured_reference_admission_pending",
        "physical_validation_status": "unvalidated",
        "m04_passed": None,
        "scope": "Exact authored half-open Cartesian nodes; raw signed CP2K versus direct HelFEM FE samples",
        "fixture": report["case"]["system"],
        "cp2k_report_sha256": sha256(report_path),
        "cp2k_cube_sha256": density["sha256"],
        "exporter_binary_sha256": sha256(executable),
        "reference_density": projections[0],
        "density_refinement_diagnostics": [
            {**projection, "l1_from_reference_electrons": l1}
            for projection, l1 in zip(projections[1:], refinement_l1, strict=True)
        ],
        "exact_grid_count_per_axis": axis,
        "exact_cell_bohr": cell,
        "exact_bond_bohr": bond,
        "exact_origin_bohr": [0.0] * 3,
        "exact_voxel_volume_bohr3": volume,
        "cp2k_cartesian_integral_electrons": cp2k_count,
        "helfem_cartesian_integral_electrons": ref_count,
        "helfem_cartesian_minus_overlap_electrons": ref_count - projections[0]["overlap_electrons"],
        "omitted_mass_scope": "Native FE quadrature outside a sphere (He) or prolate ellipsoid (H2) inscribed in the cube, an upper enclosure within the finite FE domain",
        "signed_cp2k_minus_helfem_integral_electrons": cp2k_count - ref_count,
        "measured_absolute_density_difference_integral_electrons": measured,
        "cumulative_nearest_nucleus_l1": [
            {"radius_bohr": radius, "l1_electrons": math.fsum(shell_l1) * volume}
            for radius, shell_l1 in zip(shell_radii, cumulative_l1s, strict=True)
        ],
        "maximum_absolute_difference_sample": {
            "centered_position_bohr": [float(nodes[index]) for index in max_indices],
            "grid_indices_zero_based": list(max_indices),
            "signed_cp2k_minus_helfem_electrons_per_bohr3": max_delta,
        },
        "full_reference_density_reserve_electrons": reserve,
        "total_density_limit_electrons": total,
        "measured_discrepancy_within_fixed_margin": measured + reserve <= total,
        "reference_uncertainty_status": "Needs FE-axis convergence and Cartesian shape-sampling uncertainty; finite-domain and signed mass diagnostics are reported separately",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cube", type=Path, required=True)
    parser.add_argument("--cp2k-report", type=Path, required=True)
    parser.add_argument("--exporter", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--refinement", type=Path, action="append", default=[])
    parser.add_argument("--axis-plan", type=Path)
    parser.add_argument("--axis-summary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.axis_plan) != bool(args.axis_summary):
        parser.error("Provide both the reference axis plan and its execution summary")
    result = compare(args.cube, args.cp2k_report, args.exporter, [args.reference, *args.refinement])
    if args.axis_plan:
        result["reference_axis_convergence"] = reference_density_axes(
            args.exporter, args.axis_plan, args.axis_summary, {"he": "he", "h2-short": "h2"}[result["fixture"]],
            result["exact_grid_count_per_axis"], result["exact_cell_bohr"], result["exact_bond_bohr"],
        )
        if result["reference_axis_convergence"]["reference_density"] != result["reference_density"]:
            raise ValueError("Comparison reference differs from the finest axis receipt")
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
