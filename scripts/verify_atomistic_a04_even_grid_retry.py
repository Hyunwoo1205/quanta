"""Stage the original F0/F1 and H2 F2 evidence for one exact He-only admission retry."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.error import URLError
from zipfile import BadZipFile, ZipFile

from verify_atomistic_a04_even_grid_preflight import (
    DESIGN, GitHubEvidence, SUCCESSOR_MANIFEST, SUCCESSOR_PLAN, artifact, require, sha_file,
    stream_verified, workflow,
)


LOCK = DESIGN / "a04-even-grid-f2-retry.json"
IDENTITY = ("quanta_source", "workflow_run_id", "workflow_run_attempt", "manifest_sha256")
RETAINED = {
    "historical": {
        "preflight.json", "he/qz6.json", "he/qz6.cube", "h2-short/qz6.json", "h2-short/qz6.cube",
    },
    "h2-short-qz8": {"report.json", "density.cube"},
    "h2-short-5z8": {"report.json", "density.cube"},
}
BLOCKED = ("he-qz8", "he-5z8")


def check_jobs(github: GitHubEvidence, lock: dict) -> None:
    prior = lock["prior"]
    run_id = int(prior["workflow_run_id"])
    jobs = github.metadata(f"runs/{run_id}/attempts/1/jobs?per_page=100")["jobs"]
    observed = {str(job["id"]): job for job in jobs}
    require(set(observed) == set(lock["jobs"]), "Original F2 jobs do not match the fixed attempt")
    for job_id, expected in lock["jobs"].items():
        job = observed[job_id]
        require(
            job["run_id"] == run_id and job["head_sha"] == prior["quanta_source"]
            and job["status"] == "completed" and all(job[key] == value for key, value in expected.items()),
            f"Original F2 job {job_id} differs from the recorded result",
        )


def restore(github: GitHubEvidence, label: str, lock: dict, work: Path) -> dict:
    prior = lock["prior"]
    spec = lock["artifacts"][label]
    zip_meta = artifact(github, int(prior["workflow_run_id"]), prior["quanta_source"], {
        key: spec[key] for key in ("id", "name", "size_in_bytes", "digest")
    })
    path = work / f"{label}.zip"
    github.download(zip_meta, path)
    expected = RETAINED.get(label, {"report.json"})
    with ZipFile(path) as archive:
        require(set(spec["members"]) == expected and sorted(archive.namelist()) == sorted(expected),
                f"{label}: original ZIP contents differ from the lock")
        for name, member in spec["members"].items():
            info = archive.getinfo(name)
            require(info.file_size == member["size_in_bytes"], f"{label}: member size changed")
            destination = work / label / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("xb") as target:
                stream_verified(source, target, info.file_size, member["sha256"])
    path.unlink()
    return zip_meta


def check_identity(report: dict, prior: dict) -> None:
    require(all(report[key] == prior[key] for key in IDENTITY), "Retained F2 report identity changed")


def check_input(record: dict, manifest: dict, system: str, label: str, cube_sha256: str) -> None:
    attempt = record["attempt"]
    expected = manifest["fixtures"][system]["decks"][label]["input_sha256"]
    require(
        attempt["status"] == "measured" and attempt["input_sha256"] == attempt["submitted_input_sha256"] == expected
        and attempt["density"]["sha256"] == cube_sha256
        and attempt["engine_resource"]["binary_sha256"] == manifest["x86_binary_sha256"]
        and attempt["engine_resource"]["reported_revision"] == manifest["cp2k_source"],
        f"{system}/{label}: input, engine or native CUBE identity changed",
    )


def verify_prior_science(work: Path, manifest: dict, lock: dict) -> dict:
    prior = lock["prior"]
    proof = json.loads((work / "historical/preflight.json").read_bytes())
    check_identity(proof, prior)
    require(proof["status"] == "verified_historical_evidence" and proof["plan_sha256"] == prior["plan_sha256"]
            and set(proof["historical"]) == {"he", "h2-short"}, "Original F0/F1 did not verify both endpoints")
    members = lock["artifacts"]["historical"]["members"]
    for system, expected in proof["historical"].items():
        require(
            members[f"{system}/qz6.json"]["sha256"] == expected["qz6_json_sha256"]
            and members[f"{system}/qz6.cube"]["sha256"] == expected["cube_sha256"]
            and expected["input_sha256"] == manifest["fixtures"][system]["decks"]["qz6"]["input_sha256"],
            f"{system}: historical endpoint differs from original F0/F1",
        )
        historical = json.loads((work / "historical" / system / "qz6.json").read_bytes())
        check_input(historical, manifest, system, "qz6", expected["cube_sha256"])
    for label in ("qz8", "5z8"):
        row = f"h2-short-{label}"
        report = json.loads((work / row / "report.json").read_bytes())
        check_identity(report, prior)
        require((report["status"], report["system"], report["label"]) == ("measured", "h2-short", label),
                "An original H2 basis row is not a completed measurement")
        check_input(report, manifest, "h2-short", label, lock["artifacts"][row]["members"]["density.cube"]["sha256"])
    for row in BLOCKED:
        report = json.loads((work / f"{row}-blocked/report.json").read_bytes())
        check_identity(report, prior)
        require(
            report["system"] == "he" and report["label"] == row.removeprefix("he-")
            and report["status"] == "measurement_incomplete" and not report["attempt"]
            and report["error"] == lock["prior_he_error"]
            and report["candidate"]["binary_sha256"] == manifest["x86_binary_sha256"],
            f"{row}: failure before CP2K is not established",
        )
    report = json.loads((work / "comparison/report.json").read_bytes())
    check_identity(report, prior)
    basis = report["pilots"]["h2-short"]["comparisons"]["qz_vs_5z"]
    require(report["status"] == lock["prior_h2_status"] == "criterion_not_met"
            and basis["within_all_endpoint_thresholds"] is False and basis["energy_passed"] is False
            and basis["force_passed"] is False and basis["spatial_l1_screen_passed"] is False,
            "Original scientific H2 failure differs from the retry lock")
    return {
        "status": "criterion_not_met",
        "energy_hartree": basis["absolute_energy_difference_hartree"],
        "force_hartree_per_bohr": basis["absolute_maximum_force_component_difference_hartree_per_bohr"],
        "signed_native_l1_electrons": basis["spatial_density"]["primary"]["zero_extended_absolute_density_difference_integral_electrons"],
        "conditioning_and_gate_failures": report["pilots"]["h2-short"]["gate_failures"],
        "report_sha256": lock["artifacts"]["comparison"]["members"]["report.json"]["sha256"],
    }


def stage(github: GitHubEvidence, output: Path, receipt: dict) -> None:
    lock = json.loads(LOCK.read_bytes())
    prior = lock["prior"]
    require(
        lock["schema_version"] == 1 and lock["allowed_rerun_rows"] == list(BLOCKED)
        and sha_file(SUCCESSOR_MANIFEST) == prior["manifest_sha256"] and sha_file(SUCCESSOR_PLAN) == prior["plan_sha256"],
        "Retry changes the original locked decks or allows different measurement rows",
    )
    manifest = json.loads(SUCCESSOR_MANIFEST.read_bytes())
    require(shutil.disk_usage(output).free >= 2 * 1024**3, "Insufficient disk for the retained CUBEs")
    require(all(not (output / label).exists() and not (output / label).is_symlink() for label in RETAINED),
            "Refusing to replace previously staged F2 evidence")
    workflow(github, int(prior["workflow_run_id"]), prior["quanta_source"], prior["workflow"], "failure")
    check_jobs(github, lock)
    with tempfile.TemporaryDirectory(prefix="a04-even-grid-retry-", dir=output.parent) as directory:
        work = Path(directory)
        receipt["artifacts"] = {label: restore(github, label, lock, work) for label in lock["artifacts"]}
        receipt["original_h2_scientific_result"] = verify_prior_science(work, manifest, lock)
        for label in RETAINED:
            shutil.move(work / label, output / label)
    receipt.update(status="verified_exact_retry_evidence", retry_lock_sha256=sha_file(LOCK), prior=prior,
                   allowed_rerun_rows=lock["allowed_rerun_rows"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=True)
    receipt = {"schema_version": 1, "status": "incomplete", **{key: os.environ.get(variable) for key, variable in (
        ("quanta_source", "GITHUB_SHA"), ("workflow_run_id", "GITHUB_RUN_ID"), ("workflow_run_attempt", "GITHUB_RUN_ATTEMPT"),
    )}}
    try:
        require(os.environ.get("GITHUB_WORKFLOW_REF") ==
                "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-even-grid-final-retry.yml@refs/heads/main"
                and receipt["workflow_run_attempt"] == "1"
                and bool(re.fullmatch(r"[0-9a-f]{40}", receipt["quanta_source"] or ""))
                and (receipt["workflow_run_id"] or "").isdigit()
                and int(receipt["workflow_run_id"]) > 42645481557,
                "Retry evidence staging requires the fixed first-attempt GitHub workflow on main")
        stage(GitHubEvidence(os.environ["GH_TOKEN"]), output, receipt)
    except (OSError, URLError, ValueError, KeyError, TypeError, BadZipFile) as exc:
        receipt["error"] = ("GitHub evidence retrieval failed" if isinstance(exc, URLError) else str(exc)[:500])
    (output / "retry.json").write_text(json.dumps(receipt, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "error": receipt.get("error")}, allow_nan=False))
    return int(receipt["status"] != "verified_exact_retry_evidence")


if __name__ == "__main__":
    raise SystemExit(main())