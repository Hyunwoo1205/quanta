"""Freeze successor inputs and run the A04 He/H2 basis admission gate."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from atomistic_a03_inputs import A04_5Z_ASSET, SYSTEM_FIXTURES
from atomistic_a04_runner_swap import SWAP_BYTES, bounded_ci_swap
from run_atomistic_a04_final_x86 import DESIGN, MANIFEST as OLD_INPUTS, deck_bytes, deck_options
from run_atomistic_a04_resource_ci import (
    Case, DISK_ADMISSION, GIB, MEMORY_RESERVE_BYTES, REPORT_LIMIT, ROOT,
    available_memory_bytes, check_grid_attempt, compare_accuracy_pair,
    load_locked_candidate, require_native_ci, run_attempt, sha256, write_report,
)


PLAN = DESIGN / "a04-final-validation-he-even-grid-plan.json"
MANIFEST = DESIGN / "a04-even-grid-final-inputs.json"
RETRY_LOCK = DESIGN / "a04-even-grid-f2-retry.json"
PILOTS = ("h2-short", "he")
BASIS_LABELS = ("qz8", "5z8")
ERRORS = (OSError, KeyError, RuntimeError, ValueError, subprocess.SubprocessError)
RUN_IDENTITY = ("quanta_source", "workflow_run_id", "workflow_run_attempt", "manifest_sha256")


def read_json(path: Path) -> dict:
    if path.is_symlink() or not 0 < path.stat().st_size <= REPORT_LIMIT:
        raise ValueError(f"Invalid bounded evidence file: {path.name}")
    return json.loads(path.read_bytes())


def he_options(plan: dict) -> dict:
    tuples = plan["tuples"]
    keys = ("cell", "cutoff", "rel_cutoff", "eps_scf", "radial_grid", "lebedev_grid", "lmaxn1")
    def options(name):
        settings = dict(zip(keys, tuples[name], strict=True), basis="cc-pVQZ")
        if settings["cell"].isdecimal():
            settings["cell"] = int(settings["cell"])
        return settings
    base = options("He_candidate")
    finer = options("He_joint_finer_grid_reference")
    enlarged = options("He_joint_enlarged_cell_reference")
    _, middle, highest = tuples["He_cutoff_axis"]
    _, cell_mid, cell_high = tuples["He_cell_axis_angstrom"]
    return {
        "qz6": base | {"lmaxn1": 6}, "qz8": base, "5z8": base | {"basis": "cc-pV5Z"},
        "scf9": base | {"eps_scf": 1e-9}, "scf10": base | {"eps_scf": finer["eps_scf"]},
        "radial": base | {"radial_grid": finer["radial_grid"]},
        "angular": base | {"lebedev_grid": finer["lebedev_grid"]},
        "relative": base | {"rel_cutoff": finer["rel_cutoff"]},
        "cutoff_mid": base | {"cutoff": middle}, "cutoff": base | {"cutoff": highest},
        "cell_mid": base | {"cell": cell_mid}, "cell_high": base | {"cell": cell_high},
        "joint": finer, "joint5z": finer | {"basis": "cc-pV5Z"},
        "joint_cell": enlarged, "joint_cell5z": enlarged | {"basis": "cc-pV5Z"},
    }


def make_case(system: str, label: str, manifest: dict) -> Case:
    spec = manifest["fixtures"][system]["decks"][label]
    return Case(name=f"{system}-{label}", system=system, density=True, overlap_condition=True,
                final_batch=True, wall_seconds=spec["wall_seconds"], **spec["options"])


def build_manifest() -> dict:
    plan = read_json(PLAN)
    prior_path = ROOT / plan["inherits"]["path"]
    receipt_path = ROOT / plan["admission"]["receipt"]
    if sha256(prior_path) != plan["inherits"]["sha256"] or sha256(receipt_path) != plan["admission"]["receipt_sha256"]:
        raise ValueError("Successor historical plan or He receipt identity differs")
    prior = read_json(prior_path)
    receipt = read_json(receipt_path)
    old_inputs = read_json(OLD_INPUTS)
    for path, digest in prior["baseline"]["input_evidence_sha256"].items():
        if sha256(ROOT / path) != digest:
            raise ValueError(f"Historical prerequisite evidence differs: {path}")
    he = he_options(plan)
    if receipt["verdict"]["selected_candidate_cutoff_ry"] != he["qz6"]["cutoff"]:
        raise ValueError("He deck differs from selected historical receipt")
    counts = plan["tuples"]["He_cell_axis_expected_grids"]
    cells = list(map(Fraction, plan["tuples"]["He_cell_axis_angstrom"]))
    crop = [counts[-1] * cell / cells[-1] for cell in cells[:-1]]
    if crop != [320, 336] or any((counts[-1] - span) % 2 for span in crop):
        raise ValueError("He finite cells do not have exact centered reference crops")
    manifest = {
        "schema_version": 1, "plan_sha256": sha256(PLAN), "previous_plan_sha256": sha256(prior_path),
        "he_receipt_sha256": sha256(receipt_path), "cp2k_source": prior["fixed"]["cp2k_source"],
        "x86_binary_sha256": receipt["cp2k_binary_sha256"], "basis_5z_sha256": sha256(A04_5Z_ASSET),
        "thresholds": prior["thresholds"], "he_cell_expected_axes": counts,
        "he_cell_crop_points": [int(span) for span in crop], "fixtures": {},
    }
    for system in prior["fixed"]["fixtures"]:
        decks = {}
        manifest["fixtures"][system] = {"fixture": SYSTEM_FIXTURES[system], "decks": decks}
        opts = he if system == "he" else deck_options(prior, system)
        for label, values in opts.items():
            if label == "joint6":
                continue
            if system == "he":
                spec = {"options": values, "cap_gib": 12, "min_cap_gib": 11,
                        "wall_seconds": 3000, "swap_gib": 16}
            else:
                historical = old_inputs["fixtures"][system]["decks"][label]
                spec = {"options": values, "cap_gib": historical["cap_gib"],
                        "min_cap_gib": historical["cap_gib"], "wall_seconds": old_inputs["wall_seconds"], "swap_gib": 0}
            decks[label] = spec
            content = deck_bytes(make_case(system, label, manifest))
            spec["input_sha256"] = hashlib.sha256(content).hexdigest()
            if system != "he" and spec["input_sha256"] != historical["input_sha256"]:
                raise ValueError(f"H2 successor deck differs from the historical plan: {system}/{label}")
        qz6, qz8, five = (deck_bytes(make_case(system, label, manifest)) for label in ("qz6", "qz8", "5z8"))
        if qz6.count(b"      LMAXN1 6\n") != 1 or qz8 != qz6.replace(b"      LMAXN1 6\n", b"      LMAXN1 8\n"):
            raise ValueError(f"Only LMAXN1 may change across the QZ bridge: {system}")
        qz_path = b"BASIS_SET_FILE_NAME /quanta-data/cc-pVQZ.cp2k"
        five_path = b"BASIS_SET_FILE_NAME /quanta-input/cc-pV5Z.cp2k"
        if qz8.count(qz_path) != 1 or five != qz8.replace(qz_path, five_path).replace(
            b"BASIS_SET cc-pVQZ", b"BASIS_SET cc-pV5Z",
        ):
            raise ValueError(f"Only basis file and KIND labels may change across QZ/5Z: {system}")
    historical_he = next(row for row in receipt["measurements"] if row["cutoff_ry"] == he["qz6"]["cutoff"])
    if manifest["fixtures"]["he"]["decks"]["qz6"]["input_sha256"] != historical_he["input_sha256"]:
        raise ValueError("Selected He input bytes differ from the reusable x86 measurement")
    return manifest


def load_manifest() -> dict:
    manifest = read_json(MANIFEST)
    if manifest != build_manifest():
        raise ValueError("Successor A04 manifest differs from fixed inputs and evidence")
    return manifest


def measure(system: str, label: str, manifest: dict, candidate_dir: Path, output: Path, report: dict) -> None:
    require_native_ci()
    candidate = load_locked_candidate(candidate_dir)
    if (candidate["cp2k_source"], candidate["binary_sha256"]) != (manifest["cp2k_source"], manifest["x86_binary_sha256"]):
        raise ValueError("Unexpected x86 CP2K image or binary")
    case = make_case(system, label, manifest)
    fixture = manifest["fixtures"][system]
    spec = fixture["decks"][label]
    minimum = spec["min_cap_gib"] * GIB
    swap_bytes = spec["swap_gib"] * GIB
    if (available_memory_bytes() < minimum + MEMORY_RESERVE_BYTES
            or shutil.disk_usage(output).free < DISK_ADMISSION + swap_bytes):
        raise RuntimeError("Insufficient hosted runner headroom for the fixed row")
    if swap_bytes:
        filesystem = subprocess.check_output(
            ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(output)], text=True, timeout=10,
        ).strip()
        if filesystem not in {"ext4", "xfs"} or swap_bytes != SWAP_BYTES:
            raise ValueError("He swap requires the fixed size and native ext4 or xfs disk")
    report.update(system=system, label=label, case=asdict(case), candidate=candidate, attempt={})
    with tempfile.TemporaryDirectory(prefix="a04-even-grid-", dir=output.parent) as directory:
        scratch = Path(directory)
        cube = scratch / "density.cube"
        guard = bounded_ci_swap(scratch, minimum_free_bytes=DISK_ADMISSION) if swap_bytes else nullcontext(0)
        with guard as swap:
            available = available_memory_bytes()
            cap = min(spec["cap_gib"] * GIB, available - MEMORY_RESERVE_BYTES)
            cap -= cap % os.sysconf("SC_PAGE_SIZE")
            if cap < minimum:
                raise RuntimeError("Host memory reserve unavailable before CP2K start")
            attempt = report["attempt"]
            run_attempt(case, 1, cap, available, candidate, scratch, output / "diagnostics", attempt,
                        swap_extra_bytes=swap, expected_input=spec["input_sha256"], retained_cube=cube)
        report["temporary_swap_removed"] = True
        if attempt["status"] != "measured":
            raise RuntimeError(f"{label}: {attempt['status']}")
        check_grid_attempt(attempt, case, fixture, spec["input_sha256"], cube, cap,
                           manifest["thresholds"]["unchanged_AV03_AV06"], require_electron_counts=False,
                           expected_swap_bytes=swap_bytes)
        if system == "he" and attempt["density"]["grid_counts"] != [320] * 3:
            raise ValueError("He basis pilot must retain the selected 320-axis lattice")
        shutil.move(cube, output / "density.cube")
    report["scratch_removed"] = True
    report["status"] = "measured"


def read_row(system: str, label: str, manifest: dict, evidence: Path, report: dict) -> tuple:
    case = make_case(system, label, manifest)
    spec = manifest["fixtures"][system]["decks"][label]
    if label == "qz6":
        root = evidence / "historical" / system
        path = root / "qz6.json"
        record = read_json(path)
        cube = root / "qz6.cube"
        lock = report["historical"][system]
        if (sha256(path) != lock["qz6_json_sha256"] or spec["input_sha256"] != lock["input_sha256"]
                or record["attempt"]["density"]["sha256"] != lock["cube_sha256"]):
            raise ValueError("Archived F1 endpoint differs from the verified preflight")
    else:
        root = evidence / f"{system}-{label}"
        record = read_json(root / "report.json")
        cube = root / "density.cube"
        source = report["retry"]["prior"] if system == "h2-short" and "retry" in report else report
        if (any(record[key] != source[key] for key in RUN_IDENTITY)
                or record["status"] != "measured" or record["system"] != system or record["label"] != label
                or record["case"] != asdict(case) or record["temporary_swap_removed"] is not True
                or record["scratch_removed"] is not True):
            raise ValueError("Unverified same-workflow basis result")
    attempt = record["attempt"]
    if (attempt["status"] != "measured" or attempt["input_sha256"] != spec["input_sha256"]
            or attempt["submitted_input_sha256"] != spec["input_sha256"]
            or attempt["engine_resource"]["binary_sha256"] != manifest["x86_binary_sha256"]
            or attempt["engine_resource"]["reported_revision"] != manifest["cp2k_source"]
            or cube.is_symlink() or cube.stat().st_size != attempt["density"]["bytes"]
            or not 0 < cube.stat().st_size <= GIB or sha256(cube) != attempt["density"]["sha256"]):
        raise ValueError("Basis endpoint is not the planned, measured signed CUBE")
    return case, attempt, cube


def compare(evidence: Path, manifest: dict, report: dict) -> None:
    from compare_atomistic_qz_sensitivity import SAME_LATTICE_FIELDS

    proof_path = evidence / "historical" / "preflight.json"
    proof = read_json(proof_path)
    source = report["retry"]["prior"] if "retry" in report else report
    if (any(proof[key] != source[key] for key in RUN_IDENTITY) or proof["status"] != "verified_historical_evidence"
            or proof["plan_sha256"] != manifest["plan_sha256"] or set(proof["historical"]) != set(PILOTS)):
        raise ValueError("Historical F1 proof is from a different successor run or plan")
    report.update(preflight_sha256=sha256(proof_path), historical=proof["historical"])
    if available_memory_bytes() < 6 * GIB:
        raise RuntimeError("Insufficient comparison headroom")
    checks = manifest["thresholds"]["unchanged_AV03_AV06"]
    limit = manifest["thresholds"]["field_l1_electrons"]
    for system in PILOTS:
        pilot = {"comparisons": {}, "errors": {}, "gate_failures": [], "cases": {}}
        report["pilots"][system] = pilot
        rows = {}
        for label in ("qz6", *BASIS_LABELS):
            try:
                row = read_row(system, label, manifest, evidence, report)
                rows[label] = row
                attempt = row[1]
                pilot["cases"][label] = {key: attempt[key] for key in (
                    "input_sha256", "density", "basis_conditioning", "engine_scf_iterations",
                    "engine_resource", "engine_energy_hartree", "engine_forces_hartree_per_bohr",
                    "engine_hard_soft_electron_count", "cgroup_memory_peak_bytes",
                )}
                if attempt["basis_conditioning"]["conditioning_passed"] is not True:
                    pilot["gate_failures"].append(f"{label}: overlap or angular conditioning")
            except ERRORS as exc:
                pilot["errors"][label] = f"{type(exc).__name__}: {exc}"[:400]
        for name, low, high, gate in (("lmax_bridge", "qz6", "qz8", "AV03"),
                                      ("qz_vs_5z", "qz8", "5z8", "AV04")):
            if low not in rows or high not in rows:
                continue
            try:
                lo, a, a_cube = rows[low]
                hi, b, b_cube = rows[high]
                if any(a["density"][key] != b["density"][key] for key in SAME_LATTICE_FIELDS):
                    raise ValueError("Expected identical native lattices for the basis comparison")
                result = compare_accuracy_pair(hi, lo, b, a, b_cube, a_cube, checks, limit, energy_force_check=gate)
                pilot["comparisons"][name] = result
                if not result["within_all_endpoint_thresholds"]:
                    pilot["gate_failures"].append(f"{name}: {gate}/AV05/AV06/signed density")
            except ERRORS as exc:
                pilot["errors"][name] = f"{type(exc).__name__}: {exc}"[:400]
    if any(pilot["gate_failures"] for pilot in report["pilots"].values()):
        report["status"] = "criterion_not_met"
    elif all(not pilot["errors"] and len(pilot["comparisons"]) == 2 for pilot in report["pilots"].values()):
        report["status"] = "basis_gate_passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write-manifest", action="store_true")
    action.add_argument("--check-manifest", action="store_true")
    action.add_argument("--stage", choices=("measure", "compare"))
    parser.add_argument("--system", choices=PILOTS)
    parser.add_argument("--label", choices=BASIS_LABELS)
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--retry-lock", action="store_true")
    args = parser.parse_args()
    if args.write_manifest:
        MANIFEST.write_bytes((json.dumps(build_manifest(), indent=2) + "\n").encode())
        return 0
    manifest = load_manifest()
    if args.check_manifest:
        print(f"QUANTA_A04_SUCCESSOR_MANIFEST {sha256(MANIFEST)}")
        return 0
    if not args.output_dir or (args.stage == "measure" and not all((args.system, args.label, args.candidate_dir))) or (
        args.stage == "compare" and not args.evidence_dir
    ):
        parser.error("Missing the bounded inputs or output for this phase")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "diagnostics").mkdir()
    report = {
        "stage": args.stage, "status": "measurement_incomplete", "quanta_source": os.environ["GITHUB_SHA"],
        "workflow_run_id": os.environ["GITHUB_RUN_ID"], "workflow_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "manifest_sha256": sha256(MANIFEST),
    }
    try:
        if args.stage == "measure":
            measure(args.system, args.label, manifest, args.candidate_dir, output, report)
        else:
            report["pilots"] = {}
            if args.retry_lock:
                lock = read_json(RETRY_LOCK)
                prior = lock["prior"]
                if (prior["manifest_sha256"] != report["manifest_sha256"]
                        or prior["plan_sha256"] != manifest["plan_sha256"]
                        or prior["workflow_run_id"] == report["workflow_run_id"]):
                    raise ValueError("Retry must reuse the exact locked prior manifest in a new run")
                retry_path = args.evidence_dir / "retry.json"
                staged = read_json(retry_path)
                lock_sha = sha256(RETRY_LOCK)
                if (staged["status"] != "verified_exact_retry_evidence" or staged["prior"] != prior
                        or staged["retry_lock_sha256"] != lock_sha
                        or any(staged[key] != report[key] for key in RUN_IDENTITY[:3])):
                    raise ValueError("Retry staging receipt does not authorize the imported results")
                report["retry"] = {"prior": prior, "lock_sha256": lock_sha,
                                   "staging_receipt_sha256": sha256(retry_path)}
            compare(args.evidence_dir, manifest, report)
    except ERRORS as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
    write_report(output / "report.json", report)
    print("QUANTA_A04_SUCCESSOR_RESULT " + json.dumps({
        "status": report["status"], "report_sha256": sha256(output / "report.json"),
    }))
    return 0 if report["status"] in {"measured", "basis_gate_passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
