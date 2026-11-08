"""Measure fixed A04 candidates on an isolated native GitHub-hosted ARM runner."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from atomistic_a03_candidate import load_candidate
from run_atomistic_a04_gapw_ci import approved_candidate
from run_atomistic_a04_resource_ci import (
    DISK_ADMISSION, DISK_GUARD, GIB, MEMORY_RESERVE_BYTES, REFINEMENT_RECEIPTS, ROOT,
    VALIDATION_PLAN, WORK_LIMIT, Case, accuracy_scalars, available_memory_bytes,
    require_native_ci, run_attempt, sha256, write_report,
)


PLAN = ROOT / "docs/design/atomistic-a04-v0.1/native-arm-qualification.json"
ARM_ARCHIVE = 13573889644


def x86_references(plan: dict) -> dict:
    receipts = {}
    for name, digest in plan["x86_receipt_sha256"].items():
        path = REFINEMENT_RECEIPTS / name
        if sha256(path) != digest:
            raise ValueError(f"x86 receipt digest mismatch: {name}")
        receipt = json.loads(path.read_bytes())
        if (receipt["workflow_conclusion"] != "success"
                or receipt["candidate"]["cp2k_source"] != plan["cp2k_source_sha"]):
            raise ValueError("x86 reference source or workflow outcome differs")
        receipts[name] = receipt
    references = {}
    for spec in plan["cases"]:
        receipt = receipts[spec["receipt"]]
        if spec["case_role"] is None:
            group, = (x for x in receipt["tracks"] if x["track"] == spec["group"])
        else:
            group, = (x for x in receipt["fixtures"] if x["system"] == spec["group"])
        row, = (
            x for x in group["cases"]
            if x["settings"] == spec["settings"] and x.get("role") == spec["case_role"]
        )
        attempt = row["attempt"]
        expected_atoms = 1 if spec["system"] == "he" else 2
        if (attempt["status"] != "measured" or attempt["input_sha256"] != attempt["submitted_input_sha256"]
                or len(attempt["engine_forces_hartree_per_bohr"]) != expected_atoms):
            raise ValueError("Unexpected x86 reference evidence")
        references[spec["system"]] = {
            "workflow_run_id": receipt["workflow_run_id"],
            "receipt": spec["receipt"],
            "attempt": {**attempt, "density": {**attempt["density"], "atom_count": expected_atoms}},
        }
    return references


def arm_image(directory: Path, plan: dict) -> dict:
    artifact, approved, expected_proof = approved_candidate()
    if artifact["id"] != ARM_ARCHIVE or approved["source_sha"] != plan["arm_source_sha"]:
        raise ValueError("ARM image provenance differs from the fixed plan")
    metadata, proof = load_candidate(directory, plan["arm_source_sha"], architecture="arm64")
    if metadata != approved or any(
        proof.get(k) != v for k, v in expected_proof.items()
        if k not in ("daemon_image_id", "already_loaded_identical_image")
    ):
        raise ValueError("Loaded ARM candidate differs from the native A03 image")
    return {
        "platform": "linux/arm64", "archive_artifact_id": ARM_ARCHIVE, "source_sha": metadata["source_sha"],
        "cp2k_source": plan["cp2k_source_sha"], "binary_sha256": metadata["binary_sha256"],
        "image_id": proof["daemon_image_id"], "metadata": metadata, "image_proof": proof,
    }


def compare_same_input(reference: dict, attempt: dict, checks: dict) -> dict:
    x86 = reference["attempt"]
    if x86["input_sha256"] != attempt["input_sha256"] or attempt["input_sha256"] != attempt["submitted_input_sha256"]:
        raise ValueError("Cross-build comparison requires the exact same submitted input")
    result = accuracy_scalars(x86, attempt, checks, energy_force_check="AV01")
    result["native_grid_matches"] = x86["density"]["grid_counts"] == attempt["density"]["grid_counts"]
    result["arm_geometry_matches_input"] = attempt["density"]["geometry_check"]["atoms_and_composition_match"]
    result["passed"] = all(result[k] for k in (
        "energy_passed", "force_passed", "engine_electron_counts_passed", "exported_electron_counts_passed",
        "native_grid_matches", "arm_geometry_matches_input",
    ))
    result["x86_reference_run_id"] = reference["workflow_run_id"]
    result["x86_reference_receipt"] = reference["receipt"]
    result["x86_native_cube_sha256"] = x86["density"]["sha256"]
    result["arm_native_cube_sha256"] = attempt["density"]["sha256"]
    return result


def compact_attempt(attempt: dict) -> dict:
    keys = (
        "status", "error", "input_sha256", "submitted_input_sha256", "observed_mpi_ranks", "observed_omp_threads",
        "granted_memory_bytes", "available_memory_at_admission_bytes", "minimum_sampled_available_memory_bytes",
        "minimum_sampled_free_disk_bytes", "cgroup_memory_peak_bytes", "cgroup_memory_events_max",
        "container_controls", "container_removed", "engine_resource", "engine_energy_hartree",
        "engine_forces_hartree_per_bohr", "engine_hard_soft_electron_count", "density",
        "output_bytes", "sampled_work_peak_logical_bytes", "work_directory_removed",
    )
    result = {k: attempt[k] for k in keys if k in attempt}
    if "input_metadata" in attempt:
        result["fixture"] = attempt["input_metadata"]["source_fixture"]
        result["atoms"] = attempt["input_metadata"]["atoms"]
    return result


def run_cases(plan: dict, references: dict, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> None:
    checks = {c["id"]: c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    report["tolerances"] = {
        "energy_hartree": checks["AV01"]["energy_atol_hartree"],
        "max_force_component_hartree_per_bohr": checks["AV01"]["force_atol_hartree_per_bohr"],
        "engine_electron_count": checks["AV05"]["atol"], "cube_electron_count": checks["AV06"]["atol"],
    }
    for spec in plan["cases"]:
        system, budget = spec["system"], spec["cap_gib"] * GIB
        reference = references[system]
        row = {"system": system, "fixture": spec["fixture"], "settings": spec["settings"], "cap_bytes": budget}
        report["cases"].append(row)
        available = available_memory_bytes()
        free = shutil.disk_usage(scratch).free
        if available < budget + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
            row.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
            continue
        cell, cutoff, rel = spec["settings"]
        case = Case(f"arm-{system}-{cell}a-{cutoff}ry-rel{rel}", cell, cutoff, True,
                    spec["deadline_seconds"], rel_cutoff=rel, system=system)
        attempt: dict = {}
        run_attempt(case, 1, budget, available, candidate, scratch, diagnostics, attempt, architecture="arm64",
                    expected_input=reference["attempt"]["input_sha256"])
        row.update(status=attempt["status"], attempt=compact_attempt(attempt))
        if attempt["status"] != "measured":
            continue
        if attempt["input_metadata"]["source_fixture"] != spec["fixture"]:
            raise ValueError("Measured ARM case does not match its locked fixture")
        row["comparison"] = compare_same_input(reference, attempt, checks)
    if all(row["status"] == "measured" for row in report["cases"]):
        report["status"] = "measured"
        report["all_cross_build_checks_passed"] = all(row["comparison"]["passed"] for row in report["cases"])
    else:
        report["status"] = "measurement_incomplete"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    diagnostics = output / "diagnostics"
    diagnostics.mkdir()
    report = {
        "schema_version": 1, "scope": "isolated_native_arm_A04_same_input_qualification",
        "status": "controller_error", "quanta_source": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"), "plan_sha256": sha256(PLAN), "cases": [],
        "resource_controls": {"ranks": 1, "threads": 1, "swap_bytes": 0,
                              "host_memory_reserve_bytes": MEMORY_RESERVE_BYTES,
                              "disk_admission_bytes": DISK_ADMISSION, "disk_guard_bytes": DISK_GUARD,
                              "sampled_per_case_work_bytes": WORK_LIMIT},
        "verification_scope": {"production_oci_measured": False, "public_execution_support": False,
                               "spatial_density_cross_build": "not_executed", "physical_validation": "unvalidated"},
    }
    try:
        require_native_ci("arm64")
        plan = json.loads(PLAN.read_bytes())
        references = x86_references(plan)
        filesystem = subprocess.check_output(
            ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(output)],
            text=True, timeout=10,
        ).strip()
        if filesystem not in {"ext4", "xfs", "btrfs"} or shutil.disk_usage(output).free < DISK_ADMISSION:
            raise ValueError("A native disk filesystem with adequate headroom is required")
        if output.stat().st_dev != output.parent.stat().st_dev:
            raise ValueError("Work scratch and evidence must share the measured filesystem")
        report["candidate"] = arm_image(args.candidate_dir, plan)
        with tempfile.TemporaryDirectory(prefix="quanta-a04-native-arm-", dir=output.parent) as directory:
            run_cases(plan, references, report["candidate"], Path(directory), diagnostics, report)
        report["scratch_removed"] = True
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
        report["status"] = "controller_error"
    finally:
        write_report(output / "report.json", report)
    print(f"A04 native ARM qualification: {report['status']}; report.json")
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
