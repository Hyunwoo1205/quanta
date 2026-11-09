"""Admit the byte-exact historical A04 F1 inputs and locked engine archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from urllib.error import URLError
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/design/atomistic-a04-v0.1"
HISTORICAL_PLAN = DESIGN / "a04-final-validation-batch.json"
SUCCESSOR_PLAN = DESIGN / "a04-final-validation-he-even-grid-plan.json"
SUCCESSOR_MANIFEST = DESIGN / "a04-even-grid-final-inputs.json"
RECEIPTS = ROOT / "docs/verification/atomistic-a04"
HE_RECEIPT = RECEIPTS / "he-even-grid-42563236250.json"
H2_RECEIPT = RECEIPTS / "final-validation-42538884365.json"
X86_RECEIPT = RECEIPTS / "x86-a03-gapw-42389732936.json"
ARM_RECEIPT = ROOT / "docs/verification/atomistic-a03/armv8a-retry-20261107.json"
API = "https://api.github.com/repos/Hyunwoo1205/quanta/actions"
CHUNK = 1024 * 1024
JSON_LIMIT = 128 * 1024
HE_GRID = {1800: 320, 2000: 324, 2100: 360}
HE_PAIRS = [[1800, 2000], [1800, 2100], [2000, 2100]]
H2_RAW = {
    "id": 13640881058, "name": "final-f1-joint-h2-short-1", "size_in_bytes": 19049498,
    "digest": "sha256:a99667c8e0b7f0f4407bfda23522fe407c6ac3ce593caa9aee61a8619f5b1ffa",
}


def require(condition, detail: str) -> None:
    if not condition:
        raise ValueError(detail)


def sha_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def locked_json(path: Path, digest: str) -> dict:
    raw = path.read_bytes()
    require(sha_bytes(raw) == digest, f"{path.name}: locked SHA-256 differs")
    return json.loads(raw)


def stream_verified(source, destination, byte_count: int, digest: str) -> None:
    observed = hashlib.sha256()
    count = 0
    while chunk := source.read(CHUNK):
        count += len(chunk)
        require(count <= byte_count, "Artifact member exceeds the locked byte count")
        observed.update(chunk)
        if destination is not None:
            destination.write(chunk)
    require(count == byte_count and observed.hexdigest() == digest, "Locked member size or SHA-256 differs")


class GitHubEvidence:
    def __init__(self, token: str):
        self.token = token

    def open(self, route: str):
        request = Request(f"{API}/{route}", headers={"Accept": "application/vnd.github+json"})
        # Artifact downloads redirect to a temporary blob URL. Keep the repository token on GitHub.
        request.add_unredirected_header("Authorization", f"Bearer {self.token}")
        return urlopen(request, timeout=60)

    def metadata(self, route: str) -> dict:
        with self.open(route) as response:
            raw = response.read(2 * CHUNK + 1)
        require(len(raw) <= 2 * CHUNK, "Unexpectedly large GitHub metadata response")
        return json.loads(raw)

    def download(self, artifact: dict, path: Path) -> None:
        with self.open(f"artifacts/{artifact['id']}/zip") as source, path.open("xb") as destination:
            stream_verified(source, destination, artifact["size_in_bytes"], artifact["digest"].removeprefix("sha256:"))


def workflow(github: GitHubEvidence, run: int, source: str, name: str, conclusion: str) -> dict:
    item = github.metadata(f"runs/{run}/attempts/1")
    require(
        (item["id"], item["head_sha"], item["head_branch"], item["path"], item["run_attempt"],
         item["status"], item["conclusion"])
        == (run, source, "main", f".github/workflows/{name}", 1, "completed", conclusion),
        f"Historical workflow {run} differs from the recorded attempt",
    )
    return item


def artifact(github: GitHubEvidence, run: int, source: str, lock: dict) -> dict:
    # Resolve by run, then ID, never by the newest same-named artifact.
    items = github.metadata(f"runs/{run}/artifacts?per_page=100")["artifacts"]
    item = next((entry for entry in items if entry["id"] == lock["id"]), None)
    require(item is not None, f"Historical artifact {lock['id']} is missing from run {run}")
    require(
        item["expired"] is False and item["workflow_run"]["id"] == run
        and item["workflow_run"]["head_sha"] == source
        and all(item[key] == value for key, value in lock.items()),
        f"Historical artifact {lock['id']} expired or differs from its identity, size or digest",
    )
    return {key: item[key] for key in ("id", "name", "size_in_bytes", "digest", "expires_at")}


def read_member(archive: ZipFile, name: str, digest: str | None = None) -> tuple[bytes, dict]:
    info = archive.getinfo(name)
    require(0 < info.file_size <= JSON_LIMIT and not info.is_dir(), f"{name}: unexpected report size")
    raw = archive.read(info)
    if digest is not None:
        require(sha_bytes(raw) == digest, f"{name}: historical report SHA-256 differs")
    return raw, json.loads(raw)


def verify_cube(archive: ZipFile, name: str, row: dict, axis: int, destination: Path | None) -> None:
    info = archive.getinfo(name)
    require(info.file_size == row["bytes"] and 0 < info.file_size <= 1024 * CHUNK, "Unexpected CUBE size")
    with archive.open(info) as source:
        header = [source.readline(8192) for _ in range(6)]
        require(all(line.endswith(b"\n") for line in header), "Invalid CUBE header")
        require([int(line.split()[0]) for line in header[3:6]] == [axis] * 3, "CUBE native lattice differs")
    with archive.open(info) as source:
        if destination is None:
            stream_verified(source, None, info.file_size, row["sha256"])
        else:
            with destination.open("xb") as out:
                stream_verified(source, out, info.file_size, row["sha256"])


def engine_availability(github: GitHubEvidence, plan: dict) -> dict:
    x86 = locked_json(X86_RECEIPT, plan["baseline"]["input_evidence_sha256"][X86_RECEIPT.relative_to(ROOT).as_posix()])
    arm = locked_json(ARM_RECEIPT, "f295fee219b25ec06cab7e70877c6ef77c17b19529686b590d446a9bcbe1f750")["successful_retry"]
    cp2k = plan["fixed"]["cp2k_source"]
    require(x86["cp2k_source"] == arm["source_revision"] == cp2k
            and x86["native_build_and_a03"]["a03_passed"]
            and x86["upstream_gapw"]["passed"] == 5 and arm["native_arm"]["passed"],
            "The archived engine qualification or common CP2K source differs")
    x86_source = x86["quanta_candidate_source"]
    x86_build = x86["native_build_and_a03"]["run_id"]
    workflow(github, x86_build, x86_source, "atomistic-a04-x86.yml", "failure")
    workflow(github, x86["upstream_gapw"]["run_id"], x86["quanta_regression_source"],
             "atomistic-a04-x86-gapw-replay.yml", "success")
    x86_image = next(item for item in x86["artifacts"] if item["kind"] == "candidate_image")
    images = {"x86_64": artifact(github, x86_build, x86_source, {
        "id": x86_image["id"], "name": f"atomistic-a04-x86-image-{x86_source}",
        "size_in_bytes": x86_image["zip_bytes"], "digest": "sha256:" + x86_image["zip_sha256"],
    }) | {"run_id": x86_build, "source_sha": x86_source, "binary_sha256": x86["candidate"]["binary_sha256"]}}
    arm_source = arm["source_sha"]
    workflow(github, arm["full_ci_run_id"], arm_source, "ci.yml", "success")
    for name, run_key, rows_key, image_id, workflow_name in (
        ("arm_source_build", "source_build_run_id", "source_build_artifacts", 13574357276, "cp2k-armv8a-build.yml"),
        ("arm_native", "native_run_id", "native_artifacts", 13573889644, "atomistic-a03.yml"),
    ):
        run = arm[run_key]
        workflow(github, run, arm_source, workflow_name, "success")
        row = next(item for item in arm[rows_key] if item["id"] == image_id)
        lock = {key: row[key] for key in ("id", "name", "digest")} | {"size_in_bytes": row["zip_bytes"]}
        images[name] = artifact(github, run, arm_source, lock) | {
            "run_id": run, "source_sha": arm_source, "binary_sha256": arm["source_binary_sha256"],
        }
    return images


def verify_he(github: GitHubEvidence, receipt: dict, scratch: Path, output: Path) -> dict:
    run = receipt["workflow"]["id"]
    source = receipt["workflow"]["head_sha"]
    workflow(github, run, source, "atomistic-a04-he-opt.yml", "success")
    local_manifest = ROOT / receipt["manifest"]
    manifest = locked_json(local_manifest, receipt["manifest_sha256"])
    verdict = receipt["verdict"]
    require(verdict["status"] == "passed_reference_screen" and verdict["selected_candidate_cutoff_ry"] == 1800
            and verdict["passing_pairs_candidate_reference_ry"] == HE_PAIRS
            and verdict["two_finest_reference_pair_passed"] is True, "He reference screen did not pass the locked selection")
    comparison_lock = receipt["comparison_artifact"]
    comparison_artifact = artifact(github, run, source, {
        key: comparison_lock[key] for key in ("id", "name", "size_in_bytes", "digest")
    })
    comparison_zip = scratch / "he-comparison.zip"
    github.download(comparison_artifact, comparison_zip)
    with ZipFile(comparison_zip) as archive:
        require(archive.namelist() == ["he-opt-report.json"], "Unexpected He comparison ZIP layout")
        _, comparison = read_member(archive, "he-opt-report.json", comparison_lock["report_sha256"])
    require(
        (comparison["quanta_source"], int(comparison["workflow_run_id"]), comparison["workflow_run_attempt"],
         comparison["manifest_sha256"], comparison["l1_atol_electrons_each"])
        == (source, run, "1", receipt["manifest_sha256"], receipt["density_shape_l1_atol_electrons"])
        and all(comparison[key] == value for key, value in verdict.items()),
        "He comparison report no longer matches the selected three-grid receipt",
    )

    proof = {}
    for cutoff, axis in HE_GRID.items():
        evidence = next(item for item in receipt["measurements"] if item["cutoff_ry"] == cutoff)
        measured = comparison["measurements"][str(cutoff)]
        require(all(evidence[key] == value for key, value in measured.items()), "He comparison report measurement differs")
        require(
            evidence["native_grid_axis_count"] == axis
            and evidence["nuclear_center_index_xyz"] == [axis // 2] * 3
            and evidence["native_boundary_shell_passed"] is True
            and evidence["native_boundary_shell"]["width_angstrom"] == receipt["native_boundary_shell_width_angstrom"] == 1
            and evidence["native_boundary_shell"]["absolute_integral_electrons"] <= receipt["native_boundary_shell_atol_electrons"]
            and evidence["input_sha256"] == manifest["decks"][str(cutoff)]["input_sha256"],
            f"He {cutoff}: lattice, input or boundary evidence differs",
        )
        raw = artifact(github, run, source, evidence["raw_evidence"])
        path = scratch / f"he-{cutoff}.zip"
        github.download(raw, path)
        with ZipFile(path) as archive:
            require(sorted(archive.namelist()) == ["density.cube", "report.json"], "Unexpected He raw ZIP layout")
            _, report = read_member(archive, "report.json", evidence["measurement_report_sha256"])
            attempt = report["attempt"]
            cube = attempt["density"]
            require(
                (report["quanta_source"], int(report["workflow_run_id"]), report["workflow_run_attempt"],
                 report["manifest_sha256"], report["status"], report["cutoff_ry"], report["temporary_swap_removed"])
                == (source, run, "1", receipt["manifest_sha256"], "measured", cutoff, True)
                and report["candidate"]["binary_sha256"] == receipt["cp2k_binary_sha256"]
                and report["candidate"]["cp2k_source"] == receipt["cp2k_source"]
                and attempt["input_sha256"] == attempt["submitted_input_sha256"] == evidence["input_sha256"]
                and attempt["basis_conditioning"]["conditioning_passed"] is True
                and attempt["basis_conditioning"]["effective_density_lmax"] == 6
                and attempt["container_removed"] is True
                and cube["grid_counts"] == [axis] * 3
                and cube["sha256"] == evidence["native_cube_sha256"]
                and cube["bytes"] == evidence["native_cube_bytes"],
                f"He {cutoff}: archived attempt does not match the receipt",
            )
            retained = output / "he/qz6.cube" if cutoff == 1800 else None
            verify_cube(archive, "density.cube", cube, axis, retained)
            if retained is not None:
                selected = {
                    "quanta_source": source, "workflow_run_id": str(run), "system": "he", "fixture": "C01-He",
                    "manifest_sha256": receipt["manifest_sha256"], "historical": True, "attempt": attempt,
                }
                (output / "he/qz6.json").write_text(json.dumps(selected, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        proof[str(cutoff)] = {
            "artifact": raw, "input_sha256": evidence["input_sha256"], "cube_sha256": evidence["native_cube_sha256"],
            "report_sha256": evidence["measurement_report_sha256"], "grid_axis_count": axis,
        }
        path.unlink()
    return {"run_id": run, "source_sha": source, "comparison": comparison_artifact | {"report_sha256": comparison_lock["report_sha256"]}, "measurements": proof}


def verify_h2(github: GitHubEvidence, scratch: Path, output: Path) -> dict:
    receipt = locked_json(H2_RECEIPT, "d055e1f5abdf890bb458102873b105fdb45e4179d845c451ef8e885b155cc213")
    run = receipt["workflow"]["id"]
    source = receipt["workflow"]["head_sha"]
    workflow(github, run, source, "atomistic-a04-final.yml", "failure")
    saved = next(row for row in receipt["reports"] if row["stage"] == "f1-joint" and row["system"] == "h2-short")
    raw = artifact(github, run, source, H2_RAW)
    path = scratch / "h2.zip"
    github.download(raw, path)
    with ZipFile(path) as archive:
        require(sorted(archive.namelist()) == ["qz6.cube", "qz6.json", "report.json"], "Unexpected H2 raw ZIP layout")
        _, report = read_member(archive, "report.json", saved["artifact"]["report_sha256"])
        qz_raw, qz = read_member(archive, "qz6.json", "7fcee12f544aba291981569e91cb8e03773e8ef579432d01bc277ad6e49222e2")
        require(all(report[key] == saved[key] for key in report), "Archived H2 report differs from the compact receipt")
        require(
            (report["quanta_source"], int(report["workflow_run_id"]), report["status"],
             report["manifest_sha256"], report["plan_sha256"])
            == (source, run, "measured", receipt["manifest_sha256"], receipt["plan_sha256"])
            and not report["gate_failures"] and report["scratch_removed"] is True
            and all(qz[key] == report[key] for key in ("quanta_source", "workflow_run_id", "manifest_sha256", "plan_sha256"))
            and qz["system"] == "h2-short" and qz["fixture"] == "A04-H2-short"
            and qz["attempt"] == report["cases"]["qz6"]
            and qz["attempt"]["input_sha256"] == "5d899325be7ff80f883157e83cd23978809f3120d3a9c9ca6e5ed2f2335c32ed",
            "H2 F1 result, deck or normalized attempt differs",
        )
        joint = report["comparisons"]["pilot_joint"]
        require(joint["result"]["within_all_endpoint_thresholds"] is True
                and joint["boundary"]["shell_passed"] is True and joint["boundary"]["omitted_domain_passed"] is True,
                "H2 F1 comparison did not pass the exact historical gates")
        verify_cube(archive, "qz6.cube", qz["attempt"]["density"], 180, output / "h2-short/qz6.cube")
        (output / "h2-short/qz6.json").write_bytes(qz_raw)
    return {
        "run_id": run, "source_sha": source, "artifact": raw, "report_sha256": saved["artifact"]["report_sha256"],
        "candidate_input_sha256": qz["attempt"]["input_sha256"],
        "candidate_cube_sha256": qz["attempt"]["density"]["sha256"],
        "joint_reference_input_sha256": report["cases"]["joint6"]["input_sha256"],
        "joint_reference_cube_sha256_in_locked_report": report["cases"]["joint6"]["density"]["sha256"],
        "joint_reference_raw_export_retained": False,
    }


def verify(github: GitHubEvidence, output: Path, report: dict) -> None:
    successor = json.loads(SUCCESSOR_PLAN.read_bytes())
    history = locked_json(HISTORICAL_PLAN, successor["inherits"]["sha256"])
    receipt = locked_json(HE_RECEIPT, successor["admission"]["receipt_sha256"])
    require(receipt["workflow"]["id"] == successor["admission"]["workflow_run_id"], "He run ID differs from plan")
    require(shutil.disk_usage(output).free >= 3 * 1024**3, "Insufficient disk for historical evidence validation")
    plan_sha256 = sha_file(SUCCESSOR_PLAN)
    manifest = json.loads(SUCCESSOR_MANIFEST.read_bytes())
    require(manifest["plan_sha256"] == plan_sha256
            and manifest["previous_plan_sha256"] == successor["inherits"]["sha256"]
            and manifest["he_receipt_sha256"] == successor["admission"]["receipt_sha256"],
            "The successor deck manifest differs from its locked plan and receipt")
    report.update(plan_sha256=plan_sha256, manifest_sha256=sha_file(SUCCESSOR_MANIFEST))
    report["engine_artifact_metadata"] = engine_availability(github, history)
    (output / "he").mkdir()
    (output / "h2-short").mkdir()
    with tempfile.TemporaryDirectory(prefix="a04-f1-", dir=output.parent) as directory:
        scratch = Path(directory)
        report["he_f1"] = verify_he(github, receipt, scratch, output)
        report["h2_short_f1"] = verify_h2(github, scratch, output)
    retained = {}
    for system in ("he", "h2-short"):
        directory = output / system
        qz6 = directory / "qz6.json"
        attempt = json.loads(qz6.read_bytes())["attempt"]
        expected = manifest["fixtures"][system]["decks"]["qz6"]["input_sha256"]
        require(attempt["input_sha256"] == attempt["submitted_input_sha256"] == expected,
                f"{system}: admitted raw result differs from the successor qz6 deck")
        retained[system] = {
            "input_sha256": expected, "cube_sha256": attempt["density"]["sha256"],
            "qz6_json_sha256": sha_file(qz6),
        }
    report.update(f1_status="verified_historical_evidence", status="verified_historical_evidence", historical=retained)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1, "quanta_source": os.environ.get("GITHUB_SHA"), "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"), "f1_status": "incomplete", "status": "incomplete",
        "new_cp2k_calculations": False, "independent_physical_validation_status": "unvalidated",
    }
    try:
        verify(GitHubEvidence(os.environ["GH_TOKEN"]), output, report)
    except (OSError, URLError, KeyError, StopIteration, TypeError, ValueError, BadZipFile) as exc:
        report["error_type"] = type(exc).__name__
        report["error"] = ("GitHub evidence retrieval failed" if isinstance(exc, URLError) else str(exc)[:500])
    finally:
        (output / "preflight.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"f1_status": report["f1_status"], "error": report.get("error")}, allow_nan=False))
    return int(report["f1_status"] != "verified_historical_evidence")


if __name__ == "__main__":
    raise SystemExit(main())