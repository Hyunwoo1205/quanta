"""Measure and compare two locked 16 Å QZ He decks on isolated x86 CI."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

from atomistic_a04_runner_swap import SWAP_BYTES, bounded_ci_swap
from run_atomistic_a04_final_x86 import deck_bytes
from run_atomistic_a04_resource_ci import (
    Case, DISK_ADMISSION, GIB, ROOT, available_memory_bytes, check_grid_attempt,
    load_locked_candidate, refinement_attempt, require_native_ci, sha256, write_report,
)

DESIGN = ROOT / "docs/design/atomistic-a04-v0.1"
MANIFEST = DESIGN / "he16-reference-inputs.json"
FINAL_PLAN = DESIGN / "a04-final-validation-batch.json"
FINAL_RECEIPT = ROOT / "docs/verification/atomistic-a04/final-validation-42538884365.json"
CUTOFFS = (1200, 1400)
MAXIMUM_AXIS = 400
WALL_SECONDS = 3600


def case_for(cutoff: int) -> Case:
    if cutoff not in CUTOFFS:
        raise ValueError("Unsupported He 16 Å cutoff")
    return Case(f"he-16a-{cutoff}ry", 16, cutoff, True, WALL_SECONDS,
                minimum_memory_bytes=11 * GIB, system="he", rel_cutoff=80, radial_grid=200,
                lebedev_grid=194, basis="cc-pVQZ", overlap_condition=True, final_batch=True)


def build_manifest() -> dict:
    prior = json.loads(FINAL_RECEIPT.read_bytes())
    previous = next(x for x in prior["reports"] if x["stage"] == "f1-refine" and x["system"] == "he")
    plan = json.loads(FINAL_PLAN.read_bytes())
    hashes = {}
    for cutoff in CUTOFFS:
        case = case_for(cutoff)
        old = replace(case, cell=12)
        scientific = deck_bytes(case)
        historical = deck_bytes(old)
        if hashlib.sha256(historical).hexdigest() != previous["cases"][f"he{cutoff}"]["input_sha256"]:
            raise ValueError("The 12 Å anchor does not match its archived exact input")
        diffs = [(a, b) for a, b in zip(historical.splitlines(), scientific.splitlines(), strict=True) if a != b]
        if len(diffs) != 2 or not all(a.lstrip().startswith(key) and b.lstrip().startswith(key)
                                      for (a, b), key in zip(diffs, (b"ABC ", b"He "), strict=True)):
            raise ValueError("The 16 Å input may change only the cell and He centering")
        hashes[str(cutoff)] = hashlib.sha256(scientific).hexdigest()
    threshold = plan["thresholds"]
    return {
        "scope": "fixed_native_x86_He_QZ_16_angstrom_reference_pilot",
        "schema_version": 1, "prior_receipt": str(FINAL_RECEIPT.relative_to(ROOT)),
        "prior_receipt_sha256": sha256(FINAL_RECEIPT), "prior_plan_sha256": sha256(FINAL_PLAN),
        "cp2k_source": plan["fixed"]["cp2k_source"], "binary_sha256": previous["candidate"]["binary_sha256"],
        "input_sha256": hashes, "cell_angstrom": 16, "cutoffs_ry": list(CUTOFFS), "rel_cutoff_ry": 80,
        "checks": threshold["unchanged_AV03_AV06"], "l1_atol_electrons_each": threshold["field_l1_electrons"],
        "maximum_comparison_axis": MAXIMUM_AXIS, "wall_seconds_per_deck": WALL_SECONDS,
        "resources": {"ram_min_gib": 11, "ram_max_gib": 12, "temporary_runner_swap_gib": 16,
                      "host_ram_reserve_gib": 2, "free_disk_before_swap_gib": 26, "ranks": 1, "omp_threads": 1},
        "decision": [
            "Compare equal 16 Å cells on distinct native grids at fixed QZ/LMAXN1=6. Require AV03/AV05/AV06 and each original 4-point, 6-point and Fourier L1 <= 0.001 electrons.",
            "Scope is an exploratory He reference screen only. A pass can trigger planning the remaining final validation. It does not reopen or change the prior 12 Å no-go, freeze a profile, or qualify a deployment."
        ],
    }


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_bytes())
    if manifest != build_manifest():
        raise ValueError("He 16 Å experiment input hashes or thresholds changed")
    return manifest


def report_base(manifest: dict) -> dict:
    return {
        "scope": manifest["scope"], "status": "measurement_incomplete",
        "quanta_source": os.environ.get("GITHUB_SHA"), "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "manifest_sha256": sha256(MANIFEST), "resources": manifest["resources"],
    }


def measure(cutoff: int, manifest: dict, candidate_dir: Path, output: Path, report: dict) -> None:
    require_native_ci()
    if shutil.disk_usage(output).free < SWAP_BYTES + DISK_ADMISSION:
        report.update(status="deferred_disk", free_disk_bytes=shutil.disk_usage(output).free)
        return
    filesystem = subprocess.check_output(["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(output)],
                                         text=True, timeout=10).strip()
    if filesystem not in {"ext4", "xfs"}:
        raise ValueError("This isolated swap run requires a native ext4 or xfs disk")
    candidate = load_locked_candidate(candidate_dir)
    if any(candidate[k] != manifest[k] for k in ("cp2k_source", "binary_sha256")):
        raise ValueError("Unexpected He pilot image or binary")
    report["candidate"] = candidate
    case = case_for(cutoff)
    expected = manifest["input_sha256"][str(cutoff)]
    with tempfile.TemporaryDirectory(prefix="he16-", dir=output.parent) as directory:
        scratch = Path(directory)
        cube = scratch / "density.cube"
        with bounded_ci_swap(scratch, minimum_free_bytes=DISK_ADMISSION) as swap:
            attempt = refinement_attempt(case, candidate, scratch, output / "diagnostics", ranks=1, swap=swap,
                                         expected_input=expected, cube=cube)
            report["attempt"] = attempt
            report["status"] = attempt["status"]
        report["temporary_swap_removed"] = True
        if attempt["status"] != "measured":
            return
        report["status"] = "measurement_incomplete"
        check_grid_attempt(attempt, case, {"fixture": "C01-He"}, expected, cube,
                           attempt["granted_memory_bytes"], manifest["checks"],
                           require_electron_counts=False, expected_swap_bytes=SWAP_BYTES)
        if not attempt["basis_conditioning"]["conditioning_passed"]:
            report["status"] = "criterion_not_met"
            return
        cube.rename(output / "density.cube")
        report["status"] = "measured"


def retained_case(cutoff: int, manifest: dict, directory: Path, expected_report: dict) -> tuple:
    path, cube = directory / "report.json", directory / "density.cube"
    if path.is_symlink() or not 0 < path.stat().st_size <= 128 * 1024:
        raise ValueError("Unexpected bounded report artifact")
    report = json.loads(path.read_bytes())
    if any(report[key] != expected_report[key] for key in (
        "scope", "quanta_source", "workflow_run_id", "manifest_sha256", "resources",
    )):
        raise ValueError("Cross-job He pilot receipt is not from this fixed workflow and input manifest")
    if report["status"] != "measured" or not report["temporary_swap_removed"] or report["cutoff_ry"] != cutoff:
        raise ValueError("Missing measured and cleaned He pilot receipt")
    if any(report["candidate"][key] != manifest[key] for key in ("cp2k_source", "binary_sha256")):
        raise ValueError("Cross-job CP2K candidate identity mismatch")
    attempt = report["attempt"]
    cap = attempt["granted_memory_bytes"]
    if not 11 * GIB <= cap <= 12 * GIB or not attempt["basis_conditioning"]["conditioning_passed"]:
        raise ValueError("Cross-job memory or basis evidence mismatch")
    check_grid_attempt(attempt, case_for(cutoff), {"fixture": "C01-He"}, manifest["input_sha256"][str(cutoff)],
                       cube, cap, manifest["checks"], require_electron_counts=False, expected_swap_bytes=SWAP_BYTES)
    return case_for(cutoff), attempt, cube, sha256(path)


def compare(manifest: dict, references: Path, report: dict) -> None:
    from compare_atomistic_qz_sensitivity import compare_qz_pair
    from diagnose_atomistic_cutoff_density import diagnose_cutoff_density

    if available_memory_bytes() < 6 * GIB:
        report.update(status="deferred_comparison_headroom", available_memory_bytes=available_memory_bytes())
        return
    lo, a, a_cube, a_sha = retained_case(1200, manifest, references / "1200", report)
    hi, b, b_cube, b_sha = retained_case(1400, manifest, references / "1400", report)
    report["measurement_reports_sha256"] = {"1200": a_sha, "1400": b_sha}
    limit = manifest["l1_atol_electrons_each"]
    result = compare_qz_pair(hi, lo, b, a, b_cube, a_cube, manifest["checks"], limit, axis="cutoff",
                             maximum_axis_count=MAXIMUM_AXIS)
    report["result"] = result
    diagnosis = diagnose_cutoff_density(b, a, b_cube, a_cube, 16, maximum_axis_count=MAXIMUM_AXIS)
    report["resampling"] = diagnosis
    fourier = diagnosis["candidate_to_reference_fourier"]["absolute_difference_integral_electrons"]
    report["fourier_reference_readiness_passed"] = fourier <= limit
    report["status"] = "passed_reference_pilot" if result["within_all_endpoint_thresholds"] and fourier <= limit else "criterion_not_met"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-manifest", action="store_true")
    mode.add_argument("--cutoff", type=int, choices=CUTOFFS)
    mode.add_argument("--references", type=Path)
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--reference-source")
    parser.add_argument("--reference-run-id")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.write_manifest:
        MANIFEST.write_text(json.dumps(build_manifest(), indent=2) + "\n")
        return 0
    if args.output is None or (args.cutoff and args.candidate_dir is None):
        parser.error("Expected output and candidate directory for measurement")
    replay = args.reference_source is not None or args.reference_run_id is not None
    if replay and (args.references is None or not re.fullmatch(r"[0-9a-f]{40}", args.reference_source or "")
                   or not re.fullmatch(r"[0-9]+", args.reference_run_id or "")):
        parser.error("Artifact replay requires a fixed source SHA and workflow run ID")
    output = args.output.resolve()
    (output / "diagnostics").mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    report = report_base(manifest)
    if replay:
        report.update(quanta_source=args.reference_source, workflow_run_id=args.reference_run_id,
                      comparison_execution="offline replay of independently verified GitHub workflow artifacts")
    try:
        if args.cutoff:
            report["cutoff_ry"] = args.cutoff
            measure(args.cutoff, manifest, args.candidate_dir, output, report)
        else:
            compare(manifest, args.references, report)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report.update(status="measurement_incomplete", error=f"{type(exc).__name__}: {exc}"[:500])
    write_report(output / "report.json", report)
    summary = {key: report[key] for key in ("cutoff_ry", "status", "error", "fourier_reference_readiness_passed")
               if key in report}
    summary["report_sha256"] = sha256(output / "report.json")
    print("QUANTA_HE16_RESULT " + json.dumps(summary, allow_nan=False))
    return 0 if report["status"] in {"measured", "passed_reference_pilot"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
