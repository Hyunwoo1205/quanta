"""Screen five distinct, centered native grids for the locked A04 He QZ reference."""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
from itertools import combinations
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from atomistic_a04_runner_swap import SWAP_BYTES, bounded_ci_swap
from run_atomistic_a04_final_x86 import deck_bytes
from run_atomistic_a04_resource_ci import (
    Case, DISK_ADMISSION, GIB, REPORT_LIMIT, ROOT, available_memory_bytes, check_grid_attempt,
    load_locked_candidate, refinement_attempt, require_native_ci, sha256, write_report,
)
from run_atomistic_a04_he16 import FINAL_PLAN, FINAL_RECEIPT
from verify_atomistic_a03 import LOCK_DIR, check_density_geometry


MANIFEST = FINAL_PLAN.with_name("he-opt-reference-inputs.json")
CELL_ANGSTROM = 12
CUTOFF_GRID = {1400: 288, 1600: 300, 1800: 320, 2000: 324, 2100: 360}
WALL_SECONDS = 3000
MIN_MEMORY = 11 * GIB
MAX_MEMORY = 12 * GIB
MIN_COMPARISON_MEMORY = 6 * GIB
EVIDENCE_ERRORS = (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError)


def case_for(cutoff: int) -> Case:
    if cutoff not in CUTOFF_GRID:
        raise ValueError("Unsupported He cutoff for the centered grid screen")
    return Case(
        name=f"he-12a-{cutoff}ry", cell=CELL_ANGSTROM, cutoff=cutoff, density=True,
        wall_seconds=WALL_SECONDS, minimum_memory_bytes=MIN_MEMORY, system="he", rel_cutoff=80,
        radial_grid=200, lebedev_grid=194, basis="cc-pVQZ", overlap_condition=True, final_batch=True,
    )


def build_manifest() -> dict:
    prior = json.loads(FINAL_RECEIPT.read_bytes())
    previous = next(row for row in prior["reports"] if row["stage"] == "f1-refine" and row["system"] == "he")
    plan = json.loads(FINAL_PLAN.read_bytes())
    anchor = deck_bytes(case_for(1400))
    if hashlib.sha256(anchor).hexdigest() != previous["cases"]["he1400"]["input_sha256"]:
        raise ValueError("The 1400 Ry deck differs from its archived input")
    cutoff_line = b"      CUTOFF [Ry] 1400\n"
    if anchor.count(cutoff_line) != 1:
        raise ValueError("Expected exactly one finest-grid CUTOFF line in the anchor")
    decks = {}
    for cutoff, count in CUTOFF_GRID.items():
        deck = deck_bytes(case_for(cutoff))
        if deck != anchor.replace(cutoff_line, f"      CUTOFF [Ry] {cutoff}\n".encode("ascii")):
            raise ValueError(f"He {cutoff} Ry deck may change only the CUTOFF line")
        decks[str(cutoff)] = {"input_sha256": hashlib.sha256(deck).hexdigest(), "expected_axis_count": count}
    thresholds = plan["thresholds"]
    return {
        "schema_version": 1,
        "scope": "fixed_native_x86_He_QZ_centered_12_angstrom_cutoff_screen",
        "prior_receipt": str(FINAL_RECEIPT.relative_to(ROOT)),
        "prior_receipt_sha256": sha256(FINAL_RECEIPT),
        "prior_plan_sha256": sha256(FINAL_PLAN),
        "cp2k_source": plan["fixed"]["cp2k_source"],
        "binary_sha256": previous["candidate"]["binary_sha256"],
        "cell_angstrom": CELL_ANGSTROM,
        "fixture": "C01-He",
        "rel_cutoff_ry": 80,
        "basis": "cc-pVQZ",
        "eps_scf": 1e-8,
        "radial_grid": 200,
        "lebedev_grid": 194,
        "lmaxn1": 6,
        "density_include": "TOTAL_DENSITY",
        "cube_stride": [1, 1, 1],
        "decks": decks,
        "checks": {name: thresholds["unchanged_AV03_AV06"][name] for name in ("AV03", "AV05", "AV06")},
        "l1_atol_electrons_each": thresholds["field_l1_electrons"],
        "boundary_shell_width_angstrom": thresholds["boundary_shell_angstrom"],
        "boundary_shell_absolute_atol_electrons": thresholds["absolute_boundary_shell_and_omitted_mass_electrons_each"],
        "maximum_comparison_axis": max(CUTOFF_GRID.values()),
        "wall_seconds_per_deck": WALL_SECONDS,
        "resources": {
            "ram_min_gib": 11, "ram_max_gib": 12, "temporary_runner_swap_gib": 16,
            "host_ram_reserve_gib": 2, "free_disk_before_swap_gib": 26,
            "comparison_available_ram_min_gib": 6, "ranks": 1, "omp_threads": 1,
        },
        "selection": [
            "Check all ten ordered finer-reference comparisons using unchanged AV03/AV05/AV06 and the 0.001 electron limit separately for each of the 4-point, 6-point and Fourier L1 values.",
            "Each measured row must use the prescribed distinct even native lattice, the centered He geometry and a converged SCF. Each passing pair must pass both QZ overlap and 1 Å native boundary shell checks.",
            "An eligible candidate needs at least two distinct finer measured lattices. The candidate must pass against every finer tested lattice, and the two finest references must pass against each other.",
            "Among eligible candidates rank by observed engine wall seconds, peak cgroup RAM, peak cgroup swap and then cutoff. These are individual isolated host observations, not a controlled performance benchmark.",
            "A pair-level pass without the finer-lattice confirmation does not qualify a candidate. This screen does not execute F2 through F4, establish basis convergence, freeze a profile, or qualify public or OCI execution.",
        ],
    }


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_bytes())
    if manifest != build_manifest():
        raise ValueError("He grid screen differs from the fixed input, thresholds or resource manifest")
    return manifest


def report_base(manifest: dict) -> dict:
    identity = {
        "quanta_source": os.environ.get("GITHUB_SHA", ""),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if not re.fullmatch(r"[0-9a-f]{40}", identity["quanta_source"]) or not all(
        value.isdecimal() and value.isascii() and int(value) > 0
        for key, value in identity.items() if key != "quanta_source"
    ):
        raise ValueError("Fixed GitHub workflow run and source identity are required")
    return {
        **identity, "scope": manifest["scope"], "status": "measurement_incomplete",
        "manifest_sha256": sha256(MANIFEST), "resources": manifest["resources"],
    }


def check_measurement(cutoff: int, manifest: dict, attempt: dict, cube: Path) -> dict:
    from compare_atomistic_a04_accuracy import _grid_count

    expected = manifest["decks"][str(cutoff)]
    cap = attempt["granted_memory_bytes"]
    if not MIN_MEMORY <= cap <= MAX_MEMORY:
        raise ValueError("He cutoff measurement lacks the prescribed cgroup memory grant")
    check_grid_attempt(
        attempt, case_for(cutoff), {"fixture": manifest["fixture"]}, expected["input_sha256"], cube,
        cap, manifest["checks"], require_electron_counts=False, expected_swap_bytes=SWAP_BYTES,
    )
    density = attempt["density"]
    geometry = check_density_geometry(density, attempt["input_metadata"])
    units = json.loads((LOCK_DIR / "density-and-units.json").read_bytes())["engine_unit_profile"]
    cell_bohr = CELL_ANGSTROM * 1e-10 / units["a_bohr_m"]
    count = _grid_count(attempt, cell_bohr, maximum_axis_count=manifest["maximum_comparison_axis"])
    if count != expected["expected_axis_count"] or count % 2:
        raise ValueError(f"Unexpected He {cutoff} Ry native grid size or center phase: {count}")
    engine = attempt["engine_resource"]
    wall = engine["engine_wall_seconds"]
    peak_swap = engine["final_cgroup_swap_peak_bytes"]
    if (
        geometry != density["geometry_check"]
        or engine["reported_revision"] != manifest["cp2k_source"]
        or engine["binary_sha256"] != manifest["binary_sha256"]
        or engine["engine_returncode"] != 0
        or engine["final_cgroup_memory_max_bytes"] != cap
        or engine["final_cgroup_swap_max_bytes"] != SWAP_BYTES
        or not math.isfinite(wall) or wall <= 0
        or type(peak_swap) is not int or not 0 <= peak_swap <= SWAP_BYTES
    ):
        raise ValueError("He cutoff geometry, engine identity or measured resource evidence differs from the plan")
    conditioning = attempt["basis_conditioning"]
    if (
        conditioning["basis_reported"] != manifest["basis"]
        or conditioning["element"] != "He" or conditioning["atom_count"] != 1
        or conditioning["effective_density_lmax"] != manifest["lmaxn1"]
    ):
        raise ValueError("He cutoff measurement lacks matching native QZ basis evidence")
    return {
        "cutoff_ry": cutoff,
        "input_sha256": expected["input_sha256"],
        "native_cube_sha256": density["sha256"],
        "native_cube_bytes": density["bytes"],
        "native_grid_axis_count": count,
        "native_spacing_angstrom": CELL_ANGSTROM / count,
        "nuclear_center_index_xyz": [count // 2] * 3,
        "geometry_check": geometry,
        "engine_scf_iterations": attempt["engine_scf_iterations"],
        "engine_energy_hartree": attempt["engine_energy_hartree"],
        "engine_forces_hartree_per_bohr": attempt["engine_forces_hartree_per_bohr"],
        "engine_hard_soft_electron_count": attempt["engine_hard_soft_electron_count"],
        "native_cube_electron_integral": density["electron_integral"],
        "native_cube_negative_integral_electrons": density["negative_integral"],
        "native_cube_minimum_electrons_per_bohr3": density["minimum_electrons_per_bohr3"],
        "native_cube_maximum_electrons_per_bohr3": density["maximum_electrons_per_bohr3"],
        "basis_conditioning": conditioning,
        "engine_wall_seconds": wall,
        "granted_ram_bytes": cap,
        "peak_ram_bytes": attempt["cgroup_memory_peak_bytes"],
        "peak_swap_bytes": peak_swap,
        "minimum_sampled_host_available_ram_bytes": attempt["minimum_sampled_available_memory_bytes"],
    }


def measure(cutoff: int, manifest: dict, candidate_dir: Path, output: Path, scratch_root: Path, report: dict) -> None:
    require_native_ci()
    if shutil.disk_usage(scratch_root).free < SWAP_BYTES + DISK_ADMISSION:
        report.update(status="deferred_disk", free_disk_bytes=shutil.disk_usage(scratch_root).free)
        return
    filesystem = subprocess.check_output(
        ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(scratch_root)], text=True, timeout=10,
    ).strip()
    if filesystem not in {"ext4", "xfs"}:
        raise ValueError("The isolated swap experiment requires a native ext4 or xfs disk")
    candidate = load_locked_candidate(candidate_dir)
    if any(candidate[key] != manifest[key] for key in ("cp2k_source", "binary_sha256")):
        raise ValueError("Unexpected He screen engine identity")
    report["candidate"] = candidate
    expected = manifest["decks"][str(cutoff)]["input_sha256"]
    with tempfile.TemporaryDirectory(prefix="he-opt-", dir=scratch_root) as directory:
        scratch = Path(directory)
        cube = scratch / "density.cube"
        with bounded_ci_swap(scratch_root, minimum_free_bytes=DISK_ADMISSION) as swap:
            attempt = refinement_attempt(
                case_for(cutoff), candidate, scratch, output / "diagnostics", ranks=1, swap=swap,
                expected_input=expected, cube=cube,
            )
            report["attempt"] = attempt
            report["status"] = attempt["status"]
        report["temporary_swap_removed"] = True
        if attempt["status"] != "measured":
            return
        report["status"] = "measurement_incomplete"
        report["measurement"] = check_measurement(cutoff, manifest, attempt, cube)
        shutil.move(cube, output / "density.cube")
        report["status"] = "measured"


def retained_case(cutoff: int, manifest: dict, directory: Path, comparison: dict) -> tuple:
    from compare_atomistic_qz_sensitivity import _native_shell

    path = directory / "report.json"
    cube = directory / "density.cube"
    if directory.is_symlink() or path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= REPORT_LIMIT:
        raise ValueError("Unexpected bounded measurement report artifact")
    receipt = json.loads(path.read_bytes())
    identity = ("scope", "quanta_source", "workflow_run_id", "workflow_run_attempt", "manifest_sha256", "resources")
    if any(receipt[key] != comparison[key] for key in identity):
        raise ValueError("Cross-job He measurement is from a different workflow run attempt or manifest")
    if receipt["status"] != "measured" or receipt["temporary_swap_removed"] is not True or receipt["cutoff_ry"] != cutoff:
        raise ValueError("Expected a measured and cleaned receipt for the requested cutoff")
    if any(receipt["candidate"][key] != manifest[key] for key in ("cp2k_source", "binary_sha256")):
        raise ValueError("Cross-job engine candidate identity mismatch")
    attempt = receipt["attempt"]
    measurement = check_measurement(cutoff, manifest, attempt, cube)
    if measurement != receipt["measurement"]:
        raise ValueError("Cross-job measurement summary differs from the checked receipt")
    units = json.loads((LOCK_DIR / "density-and-units.json").read_bytes())["engine_unit_profile"]
    shell = _native_shell(attempt, cube, Fraction(CELL_ANGSTROM), manifest["boundary_shell_width_angstrom"],
                          1e-10 / units["a_bohr_m"])
    shell_atol = manifest["boundary_shell_absolute_atol_electrons"]
    measurement.update(
        native_boundary_shell=shell, native_boundary_shell_absolute_atol_electrons=shell_atol,
        native_boundary_shell_passed=shell["absolute_integral_electrons"] <= shell_atol,
    )
    comparison["measurements"][str(cutoff)] = measurement | {"measurement_report_sha256": sha256(path)}
    return attempt, cube


def compare_pair(low: int, high: int, measurements: dict, manifest: dict, summaries: dict) -> dict:
    from compare_atomistic_qz_sensitivity import compare_qz_pair
    from diagnose_atomistic_cutoff_density import diagnose_cutoff_density

    a, a_cube = measurements[low]
    b, b_cube = measurements[high]
    maximum_axis = manifest["maximum_comparison_axis"]
    limit = manifest["l1_atol_electrons_each"]
    result = compare_qz_pair(
        case_for(high), case_for(low), b, a, b_cube, a_cube, manifest["checks"], limit,
        axis="cutoff", maximum_axis_count=maximum_axis,
    )
    density = result["spatial_density"]
    if density["method"] != "separable_lagrange_4pt_and_6pt":
        raise ValueError("Expected both Lagrange estimates on distinct native lattices")
    diagnosis = diagnose_cutoff_density(b, a, b_cube, a_cube, CELL_ANGSTROM, maximum_axis_count=maximum_axis)
    l1 = {
        "lagrange_4pt": density["primary"]["zero_extended_absolute_density_difference_integral_electrons"],
        "lagrange_6pt": density["sensitivity"]["zero_extended_absolute_density_difference_integral_electrons"],
        "fourier": diagnosis["candidate_to_reference_fourier"]["absolute_difference_integral_electrons"],
    }
    if not all(math.isfinite(value) and value >= 0 for value in l1.values()):
        raise ValueError("Nonfinite He density comparison")
    basis_passed = all(row["basis_conditioning"]["conditioning_passed"] is True for row in (a, b))
    boundary_passed = all(summaries[str(cutoff)]["native_boundary_shell_passed"] for cutoff in (low, high))
    l1_passed = {method: value <= limit for method, value in l1.items()}
    return {
        "candidate_cutoff_ry": low,
        "reference_cutoff_ry": high,
        "l1_electrons": l1,
        "l1_passed": l1_passed,
        "basis_conditioning_passed": basis_passed,
        "native_boundary_shell_passed": boundary_passed,
        "pair_passed": all((result["within_all_endpoint_thresholds"], basis_passed, boundary_passed, *l1_passed.values())),
        "result": result,
        "resampling": diagnosis,
    }


def choose_candidate(comparisons: dict, measurements: dict) -> dict:
    cutoffs = tuple(CUTOFF_GRID)
    finest_pair = cutoffs[-2:]
    finest_pair_passed = comparisons[finest_pair]["pair_passed"]
    eligible = [
        low for index, low in enumerate(cutoffs[:-2])
        if finest_pair_passed and all(comparisons[low, high]["pair_passed"] for high in cutoffs[index + 1:])
    ]
    ranked = sorted(eligible, key=lambda cutoff: (
        measurements[str(cutoff)]["engine_wall_seconds"], measurements[str(cutoff)]["peak_ram_bytes"],
        measurements[str(cutoff)]["peak_swap_bytes"], cutoff,
    ))
    passing_pairs = [list(pair) for pair, record in comparisons.items() if record["pair_passed"]]
    return {
        "status": "passed_reference_screen" if ranked else "pair_pass_only" if passing_pairs else "criterion_not_met",
        "selected_candidate_cutoff_ry": ranked[0] if ranked else None,
        "eligible_cutoffs_ranked_ry": ranked,
        "passing_pairs_candidate_reference_ry": passing_pairs,
        "two_finest_reference_pair_ry": list(finest_pair),
        "two_finest_reference_pair_passed": finest_pair_passed,
    }


def compare(manifest: dict, references: Path, report: dict) -> None:
    available = available_memory_bytes()
    if available < MIN_COMPARISON_MEMORY:
        report.update(status="deferred_comparison_headroom", available_memory_bytes=available)
        return
    report.update(measurements={}, comparisons=[], missing_measurements={}, comparison_errors={},
                  l1_atol_electrons_each=manifest["l1_atol_electrons_each"])
    measurements = {}
    for cutoff in CUTOFF_GRID:
        try:
            measurements[cutoff] = retained_case(cutoff, manifest, references / str(cutoff), report)
        except EVIDENCE_ERRORS as exc:
            report["missing_measurements"][str(cutoff)] = f"{type(exc).__name__}: {exc}"[:500]
    comparisons = {}
    for low, high in combinations(measurements, 2):
        try:
            pair = compare_pair(low, high, measurements, manifest, report["measurements"])
        except EVIDENCE_ERRORS as exc:
            report["comparison_errors"][f"{low}:{high}"] = f"{type(exc).__name__}: {exc}"[:500]
            continue
        comparisons[low, high] = pair
        report["comparisons"].append(pair)
        print("QUANTA_HE_OPT_PAIR " + json.dumps({
            key: pair[key] for key in ("candidate_cutoff_ry", "reference_cutoff_ry", "l1_electrons", "pair_passed")
        }, allow_nan=False), flush=True)
    if report["missing_measurements"] or report["comparison_errors"]:
        return
    report.update(choose_candidate(comparisons, report["measurements"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("write-manifest")
    run_parser = modes.add_parser("run")
    run_parser.add_argument("--cutoff", type=int, choices=tuple(CUTOFF_GRID), required=True)
    run_parser.add_argument("--candidate-dir", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--scratch-root", type=Path, required=True)
    compare_parser = modes.add_parser("compare")
    compare_parser.add_argument("--references", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "write-manifest":
        MANIFEST.write_text(json.dumps(build_manifest(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0
    manifest = load_manifest()
    report = report_base(manifest)
    output = args.output.resolve()
    if args.mode == "run":
        (output / "diagnostics").mkdir(parents=True, exist_ok=True)
        report_path = output / "report.json"
        report["cutoff_ry"] = args.cutoff
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        report_path = output
    try:
        if args.mode == "run":
            measure(args.cutoff, manifest, args.candidate_dir, output, args.scratch_root.resolve(strict=True), report)
        else:
            compare(manifest, args.references, report)
    except EVIDENCE_ERRORS as exc:
        report.update(status="measurement_incomplete", error=f"{type(exc).__name__}: {exc}"[:500])
    write_report(report_path, report)
    summary = {key: report[key] for key in ("cutoff_ry", "status", "error", "selected_candidate_cutoff_ry")
               if key in report}
    summary["report_sha256"] = sha256(report_path)
    print("QUANTA_HE_OPT_RESULT " + json.dumps(summary, allow_nan=False))
    return 0 if report["status"] in {"measured", "passed_reference_screen"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
