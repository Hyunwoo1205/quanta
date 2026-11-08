"""Measure fixed A04 candidates on a native ARM CI runner or under the isolated OCI gate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile

# The fixed OCI controller runs the archived script with Python's isolated mode.
if sys.flags.isolated:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from atomistic_a03_candidate import load_candidate, read_metadata
from run_atomistic_a04_gapw_ci import approved_candidate
from run_atomistic_a04_resource_ci import (
    DISK_ADMISSION, DISK_GUARD, GIB, MEMORY_RESERVE_BYTES, REFINEMENT_RECEIPTS, ROOT,
    VALIDATION_PLAN, WORK_LIMIT, Case, accuracy_scalars, available_memory_bytes,
    require_native_ci, run_attempt, run_docker, sha256, write_report,
)


PLAN = ROOT / "docs/design/atomistic-a04-v0.1/native-arm-qualification.json"
ARM_ARCHIVE = 13573889644
OCI_CASE_ADMISSION = 6 * GIB
LOCAL_DOCKER = "unix:///var/run/docker.sock"


class GuardInterruption(BaseException):
    """Unwind work and Docker cleanup before reporting a stop by the outer gate."""


def stop_measurement(signum: int, _frame) -> None:
    for watched in (signal.SIGTERM, signal.SIGINT):
        signal.signal(watched, signal.SIG_IGN)
    raise GuardInterruption(signal.Signals(signum).name)


def require_oci_arm(source_sha: str | None) -> None:
    if (not sys.flags.isolated or os.getuid() == 0 or os.geteuid() == 0
            or platform.system() != "Linux" or platform.machine() != "aarch64"
            or os.environ.get("GITHUB_ACTIONS") == "true" or Path.cwd() != ROOT
            or not source_sha or not re.fullmatch(r"[0-9a-f]{40}", source_sha)):
        raise ValueError("The fixed OCI gate requires isolated Python on native nonroot Linux ARM")
    if os.environ.get("DOCKER_HOST") != LOCAL_DOCKER:
        raise ValueError("The fixed OCI gate requires the explicit local Docker socket")
    endpoint = run_docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}").stdout.strip()
    if endpoint != LOCAL_DOCKER:
        raise ValueError("The fixed OCI gate does not permit a remote Docker context")
    info = run_docker(
        "info", "--format", "{{.OSType}} {{.Architecture}} {{.CgroupVersion}} {{.DockerRootDir}}",
    ).stdout.split(maxsplit=3)
    if (len(info) != 4 or info[0] != "linux" or info[1] not in {"aarch64", "arm64"}
            or info[2] != "2" or not Path(info[3].strip()).is_absolute()):
        raise ValueError("The fixed OCI gate requires native ARM Docker with cgroup v2")


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
    if read_metadata(directory, plan["arm_source_sha"], architecture="arm64") != approved:
        raise ValueError("ARM candidate metadata differs from the native A03 image")
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
        "container_elapsed_seconds", "output_analysis_seconds", "total_attempt_seconds",
    )
    result = {k: attempt[k] for k in keys if k in attempt}
    if "input_metadata" in attempt:
        result["fixture"] = attempt["input_metadata"]["source_fixture"]
        result["atoms"] = attempt["input_metadata"]["atoms"]
    return result


def run_cases(plan: dict, references: dict, candidate: dict, scratch: Path, diagnostics: Path, report: dict,
              *, oci_probe_output: Path | None = None) -> None:
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
        required = budget + MEMORY_RESERVE_BYTES
        if oci_probe_output is not None:
            required = max(required, OCI_CASE_ADMISSION)
            row["minimum_admission_memory_bytes"] = required
        if available < required or free < DISK_ADMISSION:
            row.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
            if oci_probe_output is not None:
                break
            continue
        cell, cutoff, rel = spec["settings"]
        case = Case(f"arm-{system}-{cell}a-{cutoff}ry-rel{rel}", cell, cutoff, True,
                    spec["deadline_seconds"], rel_cutoff=rel, system=system)
        attempt: dict = {}
        options = {} if oci_probe_output is None else {"oci_probe_output": oci_probe_output}
        try:
            run_attempt(case, 1, budget, available, candidate, scratch, diagnostics, attempt, architecture="arm64",
                        expected_input=reference["attempt"]["input_sha256"], **options)
        except GuardInterruption:
            row.update(status="guard_interrupted", attempt=compact_attempt(attempt))
            raise
        row.update(status=attempt["status"], attempt=compact_attempt(attempt))
        if attempt["status"] != "measured":
            if oci_probe_output is not None:
                break
            continue
        if attempt["input_metadata"]["source_fixture"] != spec["fixture"]:
            raise ValueError("Measured ARM case does not match its locked fixture")
        row["comparison"] = compare_same_input(reference, attempt, checks)
    if (len(report["cases"]) == len(plan["cases"])
            and all(row["status"] == "measured" for row in report["cases"])):
        report["status"] = "measured"
        report["all_cross_build_checks_passed"] = all(row["comparison"]["passed"] for row in report["cases"])
    else:
        report["status"] = "measurement_incomplete"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed-oci-a04", action="store_true")
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=not args.fixed_oci_a04)
    diagnostics = output / "diagnostics"
    diagnostics.mkdir()
    source_sha = os.environ.get("QUANTA_A04_SOURCE_SHA" if args.fixed_oci_a04 else "GITHUB_SHA")
    scope = "isolated_oci_arm" if args.fixed_oci_a04 else "isolated_native_arm"
    report = {
        "schema_version": 1, "scope": f"{scope}_A04_same_input_qualification",
        "status": "controller_error", "quanta_source": source_sha,
        "workflow_run_id": None if args.fixed_oci_a04 else os.environ.get("GITHUB_RUN_ID"),
        "plan_sha256": sha256(PLAN), "cases": [],
        "resource_controls": {"ranks": 1, "threads": 1, "swap_bytes": 0,
                              "host_memory_reserve_bytes": MEMORY_RESERVE_BYTES,
                              "disk_admission_bytes": DISK_ADMISSION, "disk_guard_bytes": DISK_GUARD,
                              "sampled_per_case_work_bytes": WORK_LIMIT},
        "verification_scope": {"production_oci_measured": False, "public_execution_support": False,
                               "spatial_density_cross_build": "not_executed", "physical_validation": "unvalidated"},
    }
    if args.fixed_oci_a04:
        report["verification_scope"]["execution_lane"] = "isolated_oci_host_probe"
    handlers = {}
    try:
        if args.fixed_oci_a04:
            for watched in (signal.SIGTERM, signal.SIGINT):
                handlers[watched] = signal.signal(watched, stop_measurement)
            require_oci_arm(source_sha)
        else:
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
        scratch = tempfile.TemporaryDirectory(prefix="quanta-a04-native-arm-", dir=output.parent)
        try:
            with scratch as directory:
                run_cases(plan, references, report["candidate"], Path(directory), diagnostics, report,
                          oci_probe_output=output if args.fixed_oci_a04 else None)
        finally:
            report["scratch_removed"] = not Path(scratch.name).exists()
    except GuardInterruption as exc:
        report.update(status="guard_interrupted", error=str(exc))
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
        report["status"] = "controller_error"
    finally:
        try:
            write_report(output / "report.json", report)
        finally:
            for watched, handler in handlers.items():
                signal.signal(watched, handler)
    print(f"A04 native ARM qualification: {report['status']}; report.json")
    return 0 if (report["status"] == "measured"
                 and (not args.fixed_oci_a04 or report["all_cross_build_checks_passed"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
