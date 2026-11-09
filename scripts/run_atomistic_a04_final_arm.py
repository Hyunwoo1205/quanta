"""Replay a locked A04 final fixture on an isolated native ARM CI runner."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import Request, urlopen

from run_atomistic_a04_gapw_ci import (
    A03_EVIDENCE, ARTIFACT_ID, NATIVE_RUN, REPO, SOURCE_SHA, approved_candidate,
)
from run_atomistic_a04_native_arm import PLAN as ARM_PLAN, arm_image, compact_attempt
from run_atomistic_a04_resource_ci import (
    DISK_ADMISSION, DISK_GUARD, GIB, MEMORY_RESERVE_BYTES, VALIDATION_PLAN, WORK_LIMIT,
    accuracy_scalars, available_memory_bytes, check_grid_attempt, compare_accuracy_pair,
    require_native_ci, run_attempt, sha256, write_report,
)


FIXTURES = ("h2-short", "h2-reference", "h2", "h2-long", "he")


def authorize_arm(output: Path) -> None:
    """Resolve only the live, previously qualified native ARM archive."""
    native_artifact, metadata, image = approved_candidate()
    recorded = json.loads(A03_EVIDENCE.read_bytes())["successful_retry"]
    runs = (
        (42370042984, "cp2k-armv8a-build.yml", 128396088619),
        (NATIVE_RUN, "atomistic-a03.yml", 128396088895),
        (42370042969, "ci.yml", 128396088737),
    )
    if (recorded["source_build_run_id"], recorded["native_run_id"], recorded["full_ci_run_id"], ARTIFACT_ID) != (
        runs[0][0], runs[1][0], runs[2][0], 13573889644,
    ):
        raise ValueError("ARM source-build, probe and contract CI identities changed")
    headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json"}

    def get(path: str) -> dict:
        request = Request(f"https://api.github.com/repos/{REPO}/actions/{path}", headers=headers)
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    for run_id, workflow, job_id in runs:
        run, job = get(f"runs/{run_id}"), get(f"jobs/{job_id}")
        if (run["id"], run["head_sha"], run["head_branch"], run["path"], run["status"], run["conclusion"]) != (
            run_id, SOURCE_SHA, "main", f".github/workflows/{workflow}", "completed", "success",
        ) or (job["id"], job["run_id"], job["head_sha"], job["status"], job["conclusion"]) != (
            job_id, run_id, SOURCE_SHA, "completed", "success",
        ):
            raise ValueError(f"ARM provenance run {run_id} does not match the successful evidence")
    source_artifact = next(item for item in recorded["source_build_artifacts"] if item["id"] == 13574357276)
    artifacts = []
    for run_id, lock in ((runs[0][0], source_artifact), (NATIVE_RUN, native_artifact)):
        artifact = get(f'artifacts/{lock["id"]}')
        observed = (artifact["id"], artifact["name"], artifact["digest"], artifact["size_in_bytes"],
                    artifact["expired"], artifact["workflow_run"]["id"], artifact["workflow_run"]["head_sha"])
        expected = (lock["id"], lock["name"], lock["digest"], lock["zip_bytes"], False, run_id, SOURCE_SHA)
        if observed != expected:
            raise ValueError(f'ARM image artifact {lock["id"]} differs from the lock or has expired')
        artifacts.append({key: artifact[key] for key in ("id", "name", "digest", "size_in_bytes", "expires_at")})
    output.parent.mkdir(parents=True, exist_ok=True)
    write_report(output, {
        "source_sha": SOURCE_SHA, "runs": [run[0] for run in runs], "artifacts": artifacts,
        "candidate": metadata, "image": image,
    })
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(f"run-id={NATIVE_RUN}\nartifact-id={ARTIFACT_ID}\n")


def checked_file(path: Path, maximum_bytes: int) -> None:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum_bytes:
        raise ValueError(f"Missing or invalid reference file: {path.name}")


def reference_attempt(directory: Path, case, spec: dict, manifest_path: Path, plan_path: Path) -> tuple[dict, Path]:
    reference_path = directory / "selected.json"
    cube = directory / "selected.cube"
    checked_file(reference_path, 128 * 1024)
    checked_file(cube, GIB)
    reference = json.loads(reference_path.read_bytes())
    expected = (os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"], case.system, spec["fixture"],
                sha256(manifest_path), sha256(plan_path), asdict(case))
    observed = (reference["quanta_source"], str(reference["workflow_run_id"]), reference["system"],
                reference["fixture"], reference["manifest_sha256"], reference["plan_sha256"], reference["case"])
    if observed != expected:
        raise ValueError("x86 selected reference does not match the same-run locked fixture and case")
    attempt = reference["attempt"]
    digest = spec["decks"]["qz8"]["input_sha256"]
    if (attempt["status"] != "measured"
            or attempt["input_sha256"] != digest
            or attempt["submitted_input_sha256"] != digest
            or attempt["observed_mpi_ranks"] != 1 or attempt["observed_omp_threads"] != 1
            or attempt["granted_swap_extra_bytes"] != 0
            or attempt["container_removed"] is not True
            or not 1 <= attempt.get("engine_scf_iterations", 0) <= 80
            or any(attempt["cgroup_memory_events_max"].get(k, 0) for k in ("oom", "oom_kill", "oom_group_kill"))
            or attempt["basis_conditioning"]["conditioning_passed"] is not True
            or attempt["density"]["geometry_check"]["atoms_and_composition_match"] is not True
            or cube.stat().st_size != attempt["density"]["bytes"] or sha256(cube) != attempt["density"]["sha256"]):
        raise ValueError("Same-run x86 evidence, controls, or retained CUBE do not match the final fixture")
    return attempt, cube


def compare_cross_build(case, reference: dict, attempt: dict, reference_cube: Path, arm_cube: Path,
                        checks: dict, l1_atol: float) -> dict:
    from compare_atomistic_qz_sensitivity import SAME_LATTICE_FIELDS

    native_grid_matches = all(reference["density"][k] == attempt["density"][k] for k in SAME_LATTICE_FIELDS)
    if native_grid_matches:
        result = compare_accuracy_pair(
            case, case, reference, attempt, reference_cube, arm_cube, checks, l1_atol, energy_force_check="AV01",
        )
        if result["spatial_density"]["method"] != "native_aligned_crop":
            raise ValueError("Final cross-build density comparison requires native pointwise samples")
    else:
        result = accuracy_scalars(reference, attempt, checks, energy_force_check="AV01")
        result.update(spatial_density=None, spatial_l1_screen_passed=False, within_all_endpoint_thresholds=False)
    result["native_lattice_matches"] = native_grid_matches
    result["raw_cube_digest_matches"] = reference["density"]["sha256"] == attempt["density"]["sha256"]
    result["x86_cube_sha256"] = reference["density"]["sha256"]
    result["arm_cube_sha256"] = attempt["density"]["sha256"]
    result["arm_basis_conditioning_passed"] = attempt["basis_conditioning"]["conditioning_passed"] is True
    result["arm_geometry_matches_input"] = attempt["density"]["geometry_check"]["atoms_and_composition_match"] is True
    result["passed"] = all(result[k] for k in (
        "within_all_endpoint_thresholds", "native_lattice_matches",
        "arm_basis_conditioning_passed", "arm_geometry_matches_input",
    ))
    return result


def run_final_arm(system: str, candidate_dir: Path, reference_dir: Path, output: Path) -> int:
    from run_atomistic_a04_final_x86 import MANIFEST, load_manifest, make_case

    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    diagnostics = output / "diagnostics"
    diagnostics.mkdir()
    plan_path = MANIFEST.parent / "a04-final-validation-batch.json"
    report = {
        "schema_version": 1, "stage": "F4", "scope": "isolated_native_arm_A04_final_same_input",
        "status": "controller_error", "system": system, "gate_failures": [],
        "quanta_source": os.environ.get("GITHUB_SHA"), "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "plan_sha256": sha256(plan_path), "manifest_sha256": sha256(MANIFEST),
        "resource_controls": {
            "ranks": 1, "threads": 1, "swap_bytes": 0, "host_memory_reserve_bytes": MEMORY_RESERVE_BYTES,
            "disk_admission_bytes": DISK_ADMISSION, "disk_guard_bytes": DISK_GUARD,
            "sampled_per_case_work_bytes": WORK_LIMIT,
        },
        "physical_validation": "unvalidated", "production_oci_measured": False,
    }
    try:
        require_native_ci("arm64")
        filesystem = subprocess.check_output(
            ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(output)],
            text=True, timeout=10,
        ).strip()
        if filesystem not in {"ext4", "xfs", "btrfs"} or output.stat().st_dev != output.parent.stat().st_dev:
            raise ValueError("A native disk filesystem shared by evidence and work scratch is required")
        manifest = load_manifest()
        spec = manifest["fixtures"][system]
        case = make_case(system, "qz8", manifest)
        x86_attempt, x86_cube = reference_attempt(reference_dir, case, spec, MANIFEST, plan_path)
        checks = {c["id"]: c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
        plan = json.loads(plan_path.read_bytes())
        limits = plan["thresholds"]
        if (checks["AV01"]["energy_atol_hartree"] != limits["arm_same_input_energy_hartree"]
                or checks["AV01"]["force_atol_hartree_per_bohr"] != limits["arm_same_input_force_hartree_per_bohr"]):
            raise ValueError("The final ARM tolerances differ from the locked same-input values")
        budget = spec["decks"]["qz8"]["cap_gib"] * GIB
        available = available_memory_bytes()
        free = shutil.disk_usage(output).free
        report.update(case=asdict(case), cap_bytes=budget, available_memory_bytes=available, free_disk_bytes=free)
        if available < budget + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
            report["status"] = "deferred_headroom"
        else:
            report["candidate"] = arm_image(candidate_dir, json.loads(ARM_PLAN.read_bytes()))
            if report["candidate"]["cp2k_source"] != plan["fixed"]["cp2k_source"]:
                raise ValueError("The pinned ARM CP2K source differs from the final-plan source")
            attempt: dict = {}
            with tempfile.TemporaryDirectory(prefix="quanta-a04-final-arm-", dir=output.parent) as directory:
                scratch = Path(directory)
                cube = scratch / "arm.cube"
                run_attempt(
                    case, 1, budget, available, report["candidate"], scratch, diagnostics, attempt,
                    architecture="arm64", expected_input=x86_attempt["input_sha256"], retained_cube=cube,
                )
                report["attempt"] = compact_attempt(attempt)
                if attempt["status"] == "measured":
                    check_grid_attempt(
                        attempt, case, spec, x86_attempt["input_sha256"], cube, budget, checks,
                        require_electron_counts=False,
                    )
                    report["comparison"] = compare_cross_build(
                        case, x86_attempt, attempt, x86_cube, cube, checks, limits["field_l1_electrons"],
                    )
                    report["status"] = "passed" if report["comparison"]["passed"] else "criterion_not_met"
                    report["gate_failures"] = [
                        key for key in (
                            "energy_passed", "force_passed", "engine_electron_counts_passed",
                            "exported_electron_counts_passed", "spatial_l1_screen_passed",
                            "native_lattice_matches", "arm_basis_conditioning_passed", "arm_geometry_matches_input",
                        ) if not report["comparison"][key]
                    ]
                else:
                    report["status"] = "measurement_incomplete"
            report["scratch_removed"] = not Path(directory).exists()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report.update(status="controller_error", error=f"{type(exc).__name__}: {exc}"[:500])
    finally:
        write_report(output / "report.json", report)
    print(f"A04 final ARM {system}: {report['status']}; report.json")
    return 0 if report["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-candidate", type=Path)
    parser.add_argument("--system", choices=FIXTURES)
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--reference-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.authorize_candidate is not None:
        if any(v is not None for v in (args.system, args.candidate_dir, args.reference_dir, args.output_dir)):
            parser.error("Candidate authorization is a separate mode")
        authorize_arm(args.authorize_candidate)
        return 0
    if any(v is None for v in (args.system, args.candidate_dir, args.reference_dir, args.output_dir)):
        parser.error("Replay requires --system, --candidate-dir, --reference-dir and --output-dir")
    return run_final_arm(args.system, args.candidate_dir, args.reference_dir, args.output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
