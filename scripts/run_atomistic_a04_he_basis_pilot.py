"""Lock and execute the He-only A04 LMAXN1 bridge and 5Z/6Z comparison."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from zipfile import BadZipFile, ZipFile

from atomistic_a03_inputs import A04_FINE_BASIS_ASSETS
from atomistic_a04_basis_output import MAX_PRINTED_CONDITION_NUMBER, MIN_PRINTED_EIGENVALUE
from run_atomistic_a04_even_grid_final import (
    DESIGN, ERRORS, MANIFEST as OLD_MANIFEST, RUN_IDENTITY, make_case, measure, read_json, read_row,
)
from run_atomistic_a04_final_x86 import deck_bytes
from run_atomistic_a04_resource_ci import (
    GIB, MEMORY_RESERVE_BYTES, ROOT, available_memory_bytes, check_grid_attempt, compare_accuracy_pair,
    require_native_ci, sha256, write_report,
)
from verify_atomistic_a04_even_grid_preflight import (
    GitHubEvidence, artifact, read_member, require, verify_cube, workflow,
)

MANIFEST = DESIGN / "a04-he-basis-pilot-inputs.json"
REDESIGN = DESIGN / "a04-basis-redesign-v1.json"
PREDECESSOR = ROOT / "docs/verification/atomistic-a04/even-grid-final-42646711532.json"
WORKFLOW = "atomistic-a04-he-basis-pilot.yml"
NEW_LABELS = ("5z10", "6z10")
GATES = (("lmax_bridge", "5z8", "5z10", "AV03"), ("five_z_vs_six_z", "5z10", "6z10", "AV04"))
ANCHOR_ZIP = {
    "id": 13689135930, "name": "a04-even-grid-he-5z8-1", "size_in_bytes": 31335856,
    "digest": "sha256:a66eefe3cdd2bdfda449ce04211d85a05d29b8d065a146baa5bfe11e8582154b",
}
ANCHOR_REPORT_SHA256 = "b8bc1575621730cab1588ba18b09dfd7e43cf466c2b09c59f7ad9ec91cf51e41"
ANCHOR_JOB = 129261799967
DRIVE_ARCHIVE_SHA256 = "d30227db33fcd9d55ac0a02bc572afc558ccfe8a1deeb8adc299c71933d83233"


def build_manifest() -> dict:
    redesign = read_json(REDESIGN)
    previous = read_json(PREDECESSOR)
    old = read_json(OLD_MANIFEST)
    starts = redesign["fixed_starts"]
    candidates = redesign["candidates"]
    limits = redesign["thresholds"]
    thresholds = old["thresholds"]["unchanged_AV03_AV06"]
    anchor = old["fixtures"]["he"]["decks"]["5z8"]
    past = previous["pilots"]["he"]["cases"]["5z8"]
    expected_basis = {
        "cc-pV5Z": candidates["five_z"]["asset_sha256"],
        "cc-pV6Z": candidates["six_z"]["converted"]["identity"]["sha256"],
    }
    require(
        sha256(PREDECESSOR) == redesign["predecessor"]["sha256"]
        and sha256(OLD_MANIFEST) == previous["manifest_sha256"]
        and starts["cp2k_source"] == old["cp2k_source"] == past["cp2k_source"]
        and starts["x86_binary_sha256"] == old["x86_binary_sha256"] == past["cp2k_binary_sha256"]
        and starts["image_artifact_id"] == previous["engine_asset_availability"]["x86_64"]["id"]
        and anchor["input_sha256"] == past["input_sha256"]
        and old["fixtures"]["he"]["fixture"] == starts["he"]["fixture"] == "C01-He"
        and past["grid_counts"] == [starts["he"]["prior_native_axis"]] * 3 == [320] * 3
        and expected_basis == {basis: sha256(path) for basis, path in A04_FINE_BASIS_ASSETS.items()}
        and expected_basis["cc-pV5Z"] == old["basis_5z_sha256"]
        and limits["overlap"]["min_printed_eigenvalue"] == MIN_PRINTED_EIGENVALUE
        and limits["overlap"]["max_printed_condition_2"] == MAX_PRINTED_CONDITION_NUMBER,
        "The redesign, prior He measurement, basis assets or overlap guards do not match",
    )
    density_limit = old["thresholds"]["field_l1_electrons"]
    for gate in ("AV03", "AV04"):
        require(
            limits[gate]["energy_hartree"] == thresholds[gate]["energy_atol_hartree"]
            and limits[gate]["max_force_hartree_per_bohr"] == thresholds[gate]["force_atol_hartree_per_bohr"]
            and limits[gate]["density_l1_electrons"] == density_limit,
            f"{gate} differs from the locked limits",
        )
    require(
        limits["AV05"]["engine_count_absolute_electrons"] == thresholds["AV05"]["atol"]
        and limits["AV06"]["native_cube_count_absolute_electrons"] == thresholds["AV06"]["atol"],
        "Electron-count tolerances differ from the prior gates",
    )
    retry = previous["retry"]
    decks = {"5z8": anchor}
    for label, basis in zip(NEW_LABELS, ("cc-pV5Z", "cc-pV6Z"), strict=True):
        decks[label] = {**anchor, "options": anchor["options"] | {"basis": basis, "lmaxn1": 10}}
    manifest = {
        "schema_version": 1, "scope": "isolated_native_x86_A04_He_basis_pilot",
        "redesign_sha256": sha256(REDESIGN), "predecessor_sha256": sha256(PREDECESSOR),
        "cp2k_source": starts["cp2k_source"], "x86_binary_sha256": starts["x86_binary_sha256"],
        "x86_image": previous["engine_asset_availability"]["x86_64"], "basis_sha256": expected_basis,
        "anchor": {
            "workflow_run_id": str(retry["run_id"]), "workflow_run_attempt": "1",
            "quanta_source": retry["source_sha"], "manifest_sha256": previous["manifest_sha256"],
            "workflow": "atomistic-a04-even-grid-final-retry.yml", "job_id": ANCHOR_JOB,
            "artifact": ANCHOR_ZIP, "report_sha256": ANCHOR_REPORT_SHA256,
            "cube_sha256": past["cube_sha256"], "cube_bytes": past["cube_bytes"],
            "drive_archive_sha256": DRIVE_ARCHIVE_SHA256,
        },
        "fixtures": {"he": {"fixture": "C01-He", "decks": decks}},
        "native_lattice": [320] * 3,
        "one_center_product_upper_bound": {"5z8": 8, "5z10": 8, "6z10": 10},
        "thresholds": {"unchanged_AV03_AV06": thresholds, "field_l1_electrons": density_limit},
    }
    anchor_deck, bridge_deck, reference_deck = (deck_bytes(make_case("he", label, manifest)) for label in decks)
    require(
        hashlib.sha256(anchor_deck).hexdigest() == anchor["input_sha256"]
        and anchor_deck.count(b"      LMAXN1 8\n") == 1
        and bridge_deck == anchor_deck.replace(b"      LMAXN1 8\n", b"      LMAXN1 10\n")
        and bridge_deck.count(b"cc-pV5Z") == 2
        and reference_deck == bridge_deck.replace(b"cc-pV5Z", b"cc-pV6Z"),
        "He decks must differ only by the explicit cap and the two basis references",
    )
    for label, deck in zip(NEW_LABELS, (bridge_deck, reference_deck), strict=True):
        decks[label]["input_sha256"] = hashlib.sha256(deck).hexdigest()
    return manifest


def restore_anchor(zip_path: Path, output: Path, manifest: dict) -> None:
    lock = manifest["anchor"]
    require(not zip_path.is_symlink() and zip_path.stat().st_size == ANCHOR_ZIP["size_in_bytes"]
            and sha256(zip_path) == ANCHOR_ZIP["digest"].removeprefix("sha256:"),
            "Historical raw He 5Z8 ZIP differs from the exact archived artifact")
    with ZipFile(zip_path) as archive:
        require(sorted(archive.namelist()) == ["density.cube", "report.json"], "Unexpected raw He 5Z8 members")
        raw, record = read_member(archive, "report.json", lock["report_sha256"])
        expected = {"bytes": lock["cube_bytes"], "sha256": lock["cube_sha256"]}
        verify_cube(archive, "density.cube", expected, 320, output / "density.cube")
    (output / "report.json").write_bytes(raw)
    require(all(record[key] == lock[key] for key in RUN_IDENTITY), "Historical raw He 5Z8 report identity differs")
    checked_row("5z8", output.parent, manifest, lock)


def checked_row(label: str, evidence: Path, manifest: dict, identity: dict) -> tuple:
    case, attempt, cube = read_row("he", label, manifest, evidence, identity)
    fixture = manifest["fixtures"]["he"]
    spec = fixture["decks"][label]
    cap = attempt["granted_memory_bytes"]
    require(
        spec["min_cap_gib"] * GIB <= cap <= spec["cap_gib"] * GIB
        and attempt["available_memory_at_admission_bytes"] - cap >= MEMORY_RESERVE_BYTES
        and attempt["minimum_sampled_available_memory_bytes"] >= MEMORY_RESERVE_BYTES
        and attempt["docker_oom_killed"] is False
        and attempt["engine_resource"]["final_cgroup_memory_max_bytes"] == cap
        and attempt["engine_resource"]["final_cgroup_swap_max_bytes"] == spec["swap_gib"] * GIB
        and 0 <= attempt["engine_resource"]["final_cgroup_swap_peak_bytes"] <= spec["swap_gib"] * GIB
        and attempt["density"]["grid_counts"] == manifest["native_lattice"],
        f"{label}: native lattice or bounded-run evidence differs",
    )
    check_grid_attempt(
        attempt, case, fixture, spec["input_sha256"], cube, cap, manifest["thresholds"]["unchanged_AV03_AV06"],
        require_electron_counts=False, expected_swap_bytes=spec["swap_gib"] * GIB,
    )
    return case, attempt, cube


def stage_anchor(github: GitHubEvidence, output: Path, manifest: dict, report: dict) -> None:
    lock = manifest["anchor"]
    run = int(lock["workflow_run_id"])
    source = lock["quanta_source"]
    workflow(github, run, source, lock["workflow"], "failure")
    jobs = github.metadata(f"runs/{run}/attempts/1/jobs?per_page=100")["jobs"]
    job = next(item for item in jobs if item["id"] == lock["job_id"])
    require(
        (job["run_id"], job["head_sha"], job["name"], job["status"], job["conclusion"])
        == (run, source, "measure / measure (he-5z8)", "completed", "success"),
        "The archived He 5Z8 job does not match the successful native measurement",
    )
    report["anchor_artifact"] = artifact(github, run, source, lock["artifact"])
    image = manifest["x86_image"]
    report["image_artifact"] = artifact(github, image["run_id"], image["source_sha"], {
        key: image[key] for key in ("id", "name", "size_in_bytes", "digest")
    })
    with tempfile.TemporaryDirectory(prefix="a04-he-anchor-", dir=output) as temporary:
        path = Path(temporary) / "anchor.zip"
        github.download(report["anchor_artifact"], path)
        shutil.move(path, output / "anchor.zip")
    report["status"] = "exact_anchor_ready"


def compare(evidence: Path, manifest: dict, report: dict) -> None:
    from compare_atomistic_qz_sensitivity import SAME_LATTICE_FIELDS

    require(available_memory_bytes() >= 6 * GIB, "Insufficient same-lattice comparison headroom")
    anchor_path = evidence / "he-5z8"
    anchor_path.mkdir(exist_ok=False)
    restore_anchor(evidence / "anchor.zip", anchor_path, manifest)
    rows = {"5z8": checked_row("5z8", evidence, manifest, manifest["anchor"])}
    for label in NEW_LABELS:
        try:
            rows[label] = checked_row(label, evidence, manifest, report)
        except ERRORS as exc:
            report["errors"][label] = f"{type(exc).__name__}: {exc}"[:400]
    for label, (case, attempt, _) in rows.items():
        report["cases"][label] = {
            "case": asdict(case), "one_center_product_upper_bound": manifest["one_center_product_upper_bound"][label],
            **{key: attempt[key] for key in (
                "input_sha256", "density", "basis_conditioning", "engine_scf_iterations", "engine_resource",
                "engine_energy_hartree", "engine_forces_hartree_per_bohr", "engine_hard_soft_electron_count",
                "cgroup_memory_peak_bytes", "cgroup_memory_events_max",
            )},
        }
        if attempt["basis_conditioning"]["conditioning_passed"] is not True:
            report["gate_failures"].append(f"{label}: AO overlap or angular conditioning")
    for name, low, high, gate in GATES:
        if low not in rows or high not in rows:
            continue
        try:
            lo, a, a_cube = rows[low]
            hi, b, b_cube = rows[high]
            require(all(a["density"][field] == b["density"][field] for field in SAME_LATTICE_FIELDS),
                    "He native density lattice differs")
            thresholds = manifest["thresholds"]
            result = compare_accuracy_pair(
                hi, lo, b, a, b_cube, a_cube, thresholds["unchanged_AV03_AV06"],
                thresholds["field_l1_electrons"], energy_force_check=gate,
            )
            report["comparisons"][name] = result
            if not result["within_all_endpoint_thresholds"]:
                report["gate_failures"].append(f"{name}: {gate}/AV05/AV06/signed density")
        except ERRORS as exc:
            report["errors"][name] = f"{type(exc).__name__}: {exc}"[:400]
    if report["gate_failures"]:
        report["status"] = "criterion_not_met"
    elif not report["errors"] and len(report["comparisons"]) == len(GATES):
        report["status"] = "he_basis_pilot_passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write-manifest", action="store_true")
    action.add_argument("--check-manifest", action="store_true")
    action.add_argument("--stage", choices=("anchor", "measure", "compare"))
    action.add_argument("--restore-archive", type=Path)
    parser.add_argument("--label", choices=NEW_LABELS)
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    generated = build_manifest()
    if args.write_manifest:
        write_report(MANIFEST, generated)
        return 0
    manifest = read_json(MANIFEST)
    require(manifest == generated, "He basis pilot manifest differs from the locked inputs and evidence")
    if args.check_manifest:
        print(f"QUANTA_A04_HE_BASIS_MANIFEST {sha256(MANIFEST)}")
        return 0
    if not args.output_dir or (args.stage == "measure" and not (args.label and args.candidate_dir)) or (
        args.stage == "compare" and not args.evidence_dir
    ):
        parser.error("Missing fixed inputs or output")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if args.restore_archive:
        require(sha256(args.restore_archive) == DRIVE_ARCHIVE_SHA256, "Drive archive differs from the exact backup")
        with ZipFile(args.restore_archive) as archive:
            member = archive.getinfo("he-5z8-retry-raw.zip")
            require(member.file_size == ANCHOR_ZIP["size_in_bytes"], "Unexpected inner He 5Z8 ZIP size")
            with archive.open(member) as source, (output / "anchor.zip").open("xb") as target:
                shutil.copyfileobj(source, target)
        extracted = output / "he-5z8"
        extracted.mkdir()
        restore_anchor(output / "anchor.zip", extracted, manifest)
        print(f"QUANTA_A04_HE_BASIS_ARCHIVE_RESTORED {sha256(output / 'anchor.zip')}")
        return 0
    report = {
        "scope": manifest["scope"], "stage": args.stage, "status": "measurement_incomplete",
        "quanta_source": os.environ["GITHUB_SHA"], "workflow_run_id": os.environ["GITHUB_RUN_ID"],
        "workflow_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "manifest_sha256": sha256(MANIFEST),
        "physical_validation_status": "unvalidated",
    }
    try:
        require_native_ci()
        require(
            os.environ.get("GITHUB_WORKFLOW_REF") == f"Hyunwoo1205/quanta/.github/workflows/{WORKFLOW}@refs/heads/main"
            and report["workflow_run_attempt"] == "1"
            and re.fullmatch(r"[0-9a-f]{40}", report["quanta_source"])
            and report["workflow_run_id"].isdigit() and int(report["workflow_run_id"]) > int(manifest["anchor"]["workflow_run_id"]),
            "He basis pilot requires the first attempt of the fixed main workflow",
        )
        if args.stage == "anchor":
            stage_anchor(GitHubEvidence(os.environ["GH_TOKEN"]), output, manifest, report)
        elif args.stage == "measure":
            (output / "diagnostics").mkdir()
            measure("he", args.label, manifest, args.candidate_dir, output, report)
        else:
            report.update(cases={}, comparisons={}, gate_failures=[], errors={})
            compare(args.evidence_dir, manifest, report)
    except (*ERRORS, BadZipFile, StopIteration, TypeError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
    write_report(output / "report.json", report)
    print("QUANTA_A04_HE_BASIS_RESULT " + json.dumps({
        "status": report["status"], "report_sha256": sha256(output / "report.json"),
    }))
    return 0 if report["status"] in {"exact_anchor_ready", "measured", "he_basis_pilot_passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
