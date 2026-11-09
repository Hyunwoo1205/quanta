"""Execute the fixed A04 final validation DAG using the isolated CP2K controller."""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import tempfile

from atomistic_a03_inputs import SYSTEM_FIXTURES, generate_input
from run_atomistic_a04_resource_ci import (
    Case, DISK_ADMISSION, GIB, MEMORY_RESERVE_BYTES, PROJECT, ROOT,
    available_memory_bytes, check_grid_attempt, compare_accuracy_pair,
    load_locked_candidate, require_native_ci, run_attempt, sha256, write_report,
)

DESIGN = ROOT / "docs/design/atomistic-a04-v0.1"
PLAN = DESIGN / "a04-final-validation-batch.json"
MANIFEST = DESIGN / "a04-final-validation-inputs.json"


def make_case(system: str, label: str, manifest: dict) -> Case:
    spec = manifest["fixtures"][system]["decks"][label]
    return Case(name=f"{system}-{label}", system=system, density=True,
                wall_seconds=manifest["wall_seconds"], final_batch=True, overlap_condition=True,
                **spec["options"])


def deck_bytes(case: Case) -> bytes:
    return generate_input(
        system=case.system, basis=case.basis, project=PROJECT,
        cell_angstrom=case.cell, cutoff_ry=case.cutoff, rel_cutoff_ry=case.rel_cutoff,
        density=case.density, eps_scf=case.eps_scf, radial_grid=case.radial_grid,
        lebedev_grid=case.lebedev_grid, overlap_condition=case.overlap_condition,
        lmaxn1=case.lmaxn1, final_batch=True,
    ).encode("ascii")


def deck_options(plan: dict, system: str) -> dict:
    species = "He" if system == "he" else "H2"
    tuples = plan["tuples"]
    keys = ("cell", "cutoff", "rel_cutoff", "eps_scf", "radial_grid", "lebedev_grid", "lmaxn1")
    base = dict(zip(keys, tuples[f"{species}_candidate"], strict=True), basis="cc-pVQZ")
    joint = dict(zip(keys, tuples[f"{species}_joint_reference"], strict=True), basis="cc-pVQZ")
    for settings in (base, joint):
        if settings["cell"].isdecimal():
            settings["cell"] = int(settings["cell"])
    cells = tuples[f"{species}_cell_axis"]
    options = {
        "qz8": base, "qz6": base | {"lmaxn1": 6}, "5z8": base | {"basis": "cc-pV5Z"},
        "scf9": base | {"eps_scf": 1e-9}, "scf10": base | {"eps_scf": joint["eps_scf"]},
        "radial": base | {"radial_grid": joint["radial_grid"]},
        "angular": base | {"lebedev_grid": joint["lebedev_grid"]},
        "relative": base | {"rel_cutoff": joint["rel_cutoff"]},
        "cutoff": base | {"cutoff": joint["cutoff"]},
        "cell_mid": base | {"cell": cells[1]},
        "cell_high": base | {"cell": int(cells[2]) if cells[2].isdecimal() else cells[2]},
        "joint": joint, "joint5z": joint | {"basis": "cc-pV5Z"},
    }
    if system in plan["fixed"]["pilot_fixtures"]:
        options["joint6"] = joint | {"lmaxn1": 6}
    if system == "he":
        for cutoff in (1100, 1200, 1400):
            options[f"he{cutoff}"] = base | {"cutoff": cutoff, "lmaxn1": 6}
    return options


def build_manifest() -> dict:
    import hashlib

    plan = json.loads(PLAN.read_bytes())
    base = {
        "schema_version": 1, "plan_sha256": sha256(PLAN), "cp2k_source": plan["fixed"]["cp2k_source"],
        "wall_seconds": plan["limits"]["wall_seconds_per_science_deck"], "fixtures": {},
    }
    for system in plan["fixed"]["fixtures"]:
        decks = {}
        base["fixtures"][system] = {"fixture": SYSTEM_FIXTURES[system], "decks": decks}
        for label, options in deck_options(plan, system).items():
            heavy = label in {"cell_mid", "cell_high", "joint", "joint6", "joint5z", "he1400"}
            cap = 12 if heavy else (10 if system == "he" else 6)
            decks[label] = {"options": options, "cap_gib": cap}
            decks[label]["input_sha256"] = hashlib.sha256(deck_bytes(make_case(system, label, base))).hexdigest()
    return base


def load_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_bytes())
    if manifest != build_manifest():
        raise ValueError("Final A04 input manifest differs from the planned byte-exact decks")
    plan = json.loads(PLAN.read_bytes())
    for path, digest in plan["baseline"]["input_evidence_sha256"].items():
        if sha256(ROOT / path) != digest:
            raise ValueError(f"Final A04 prerequisite evidence changed: {path}")
    prior = json.loads((ROOT / "docs/verification/atomistic-a04/qz-cutoff-refinement-42533166322.json").read_bytes())
    labels = {"h2-short": {600: "qz6"}, "he": {1000: "qz6", 1200: "he1200"}}
    for row in prior["fixtures"]:
        system = row["system"]
        for case in row["cases"]:
            label = labels[system].get(case["cutoff_ry"])
            if label and case["input_sha256"] != manifest["fixtures"][system]["decks"][label]["input_sha256"]:
                raise ValueError(f"Historical anchor {system}/{label} differs from the measured input")
    return manifest


class MissingEvidence(RuntimeError):
    """A required scientific result was not admitted or could not be measured."""


def selected_evidence(system: str, row: tuple, manifest: dict) -> dict:
    case, attempt, cube = row
    return {
        "quanta_source": os.environ.get("GITHUB_SHA"), "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "system": system, "fixture": manifest["fixtures"][system]["fixture"],
        "manifest_sha256": sha256(MANIFEST), "plan_sha256": sha256(PLAN),
        "case": asdict(case), "attempt": attempt,
    }


def retained_row(directory: Path, system: str, label: str, manifest: dict) -> tuple:
    evidence = json.loads((directory / f"{label}.json").read_bytes())
    case = make_case(system, label, manifest)
    cube = directory / f"{label}.cube"
    attempt = evidence["attempt"]
    if (selected_evidence(system, (case, attempt, cube), manifest) != evidence
            or attempt["status"] != "measured"
            or attempt["input_sha256"] != manifest["fixtures"][system]["decks"][label]["input_sha256"]
            or not attempt["basis_conditioning"]["conditioning_passed"]
            or sha256(cube) != attempt["density"]["sha256"]):
        raise MissingEvidence(f"Unverified same-workflow evidence for {label}")
    return case, attempt, cube


def evaluate(stage: str, system: str, manifest: dict, candidate: dict, scratch: Path,
             output: Path, imports: dict, report: dict) -> str:
    from compare_atomistic_qz_sensitivity import SAME_LATTICE_FIELDS, compare_cell_tails
    from diagnose_atomistic_cutoff_density import diagnose_cutoff_density

    plan = json.loads(PLAN.read_bytes())
    checks = plan["thresholds"]["unchanged_AV03_AV06"]
    limit = plan["thresholds"]["field_l1_electrons"]
    spec = manifest["fixtures"][system]
    rows = {}

    def measure(label):
        if label in rows:
            return rows[label]
        if label in imports:
            rows[label] = retained_row(imports[label], system, label, manifest)
            report["reused"].append(label)
            return rows[label]
        case = make_case(system, label, manifest)
        deck = spec["decks"][label]
        cap, expected = deck["cap_gib"] * GIB, deck["input_sha256"]
        available = available_memory_bytes()
        cube = scratch / f"{label}.cube"
        record = {}
        report["cases"][label] = record
        if available < cap + MEMORY_RESERVE_BYTES or shutil.disk_usage(scratch).free < DISK_ADMISSION:
            record.update(status="deferred_headroom", available_memory_at_admission_bytes=available)
            raise MissingEvidence(f"{label}: insufficient runner resources")
        attempt = {}
        run_attempt(case, 1, cap, available, candidate, scratch, output / "diagnostics", attempt,
                    expected_input=expected, retained_cube=cube)
        record.update({k: attempt[k] for k in (
            "status", "error", "input_sha256", "submitted_input_sha256", "granted_memory_bytes",
            "available_memory_at_admission_bytes", "granted_swap_extra_bytes", "cgroup_memory_peak_bytes",
            "cgroup_memory_events_max", "engine_scf_iterations", "engine_energy_hartree",
            "engine_forces_hartree_per_bohr", "engine_hard_soft_electron_count", "basis_conditioning",
            "basis_diagnostic_excerpt", "engine_resource", "density", "container_removed",
            "observed_mpi_ranks", "observed_omp_threads",
        ) if k in attempt})
        if attempt["status"] != "measured":
            raise MissingEvidence(f"{label}: {attempt['status']}")
        check_grid_attempt(attempt, case, spec, expected, cube, cap, checks, require_electron_counts=False)
        if not attempt["basis_conditioning"]["conditioning_passed"]:
            report["gate_failures"].append(f"{label}: overlap or angular conditioning")
        rows[label] = case, record, cube
        return rows[label]

    def compare(label, low, high, *, check="AV03", same_grid=False, tails=False, diagnostic=False):
        lo, a, a_cube = measure(low)
        hi, b, b_cube = measure(high)
        if same_grid and any(a["density"][key] != b["density"][key] for key in SAME_LATTICE_FIELDS):
            raise MissingEvidence(f"{label}: expected identical native lattices")
        result = compare_accuracy_pair(hi, lo, b, a, b_cube, a_cube, checks, limit, energy_force_check=check)
        row = {"candidate": low, "reference": high, "result": result}
        report["comparisons"][label] = row
        if tails:
            tail = compare_cell_tails(b, a, b_cube, a_cube, hi.cell, lo.cell, result["spatial_density"])
            row["boundary"] = tail
            if not (tail["shell_passed"] and tail["omitted_domain_passed"]):
                report["gate_failures"].append(f"{label}: finite cell tail")
        if diagnostic:
            info = diagnose_cutoff_density(b, a, b_cube, a_cube, hi.cell)
            row["resampling"] = info
            if info["candidate_to_reference_fourier"]["absolute_difference_integral_electrons"] > limit:
                report["gate_failures"].append(f"{label}: Fourier reference readiness")
        if not result["within_all_endpoint_thresholds"]:
            report["gate_failures"].append(f"{label}: {check}/AV05/AV06/density")

    def basis():
        compare("lmax_bridge", "qz6", "qz8", same_grid=True)
        if not report["gate_failures"]:
            compare("qz_vs_5z", "qz8", "5z8", same_grid=True, check="AV04")

    if stage == "f1-refine":
        compare("he_reference", "he1200", "he1400", diagnostic=True)
    elif stage == "f1-joint":
        if system == "he":
            compare("he_plateau", "qz6", "he1100", same_grid=True)
        compare("pilot_joint", "qz6", "joint6", tails=True)
    elif stage == "f2":
        basis()
    elif stage == "f3":
        basis()
        if not report["gate_failures"]:
            compare("scf_finest", "scf9", "scf10", same_grid=True)
            compare("scf_candidate", "qz8", "scf10", same_grid=True)
            for axis in ("radial", "angular", "relative", "cutoff"):
                compare(axis, "qz8", axis, same_grid=(axis != "cutoff"))
            compare("cell_finest", "cell_mid", "cell_high", tails=True)
            compare("cell_candidate", "qz8", "cell_high", tails=True)
            compare("joint", "qz8", "joint", tails=True)
            compare("joint_basis", "joint", "joint5z", same_grid=True, check="AV04")
    else:
        raise ValueError("Unknown final validation stage")

    if report["gate_failures"]:
        return "criterion_not_met"
    exports = {"f1-joint": ("qz6",), "f2": ("qz6", "qz8", "5z8"), "f3": ("qz8",)}.get(stage, ())
    for label in exports:
        row = rows[label]
        filename = "selected" if stage == "f3" else label
        shutil.copyfile(row[2], output / f"{filename}.cube")
        write_report(output / f"{filename}.json", selected_evidence(system, row, manifest))
    return "measured"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--check-manifest", action="store_true")
    parser.add_argument("--stage", choices=("f1-refine", "f1-joint", "f2", "f3"))
    parser.add_argument("--system", choices=tuple(SYSTEM_FIXTURES))
    parser.add_argument("--candidate-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--previous-dir", type=Path)
    args = parser.parse_args()
    if args.write_manifest:
        MANIFEST.write_text(json.dumps(build_manifest(), indent=2) + "\n")
        return 0
    manifest = load_manifest()
    if args.check_manifest:
        return 0
    if not all((args.stage, args.system, args.output_dir, args.candidate_dir)):
        parser.error("A measurement requires stage, system, candidate and output directories")
    output = args.output_dir.resolve()
    (output / "diagnostics").mkdir(parents=True, exist_ok=True)
    report = {
        "stage": args.stage, "system": args.system, "status": "measurement_incomplete",
        "quanta_source": os.environ.get("GITHUB_SHA"), "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "manifest_sha256": sha256(MANIFEST), "plan_sha256": sha256(PLAN),
        "cases": {}, "comparisons": {}, "reused": [], "gate_failures": [],
    }
    try:
        require_native_ci()
        candidate = load_locked_candidate(args.candidate_dir)
        if candidate["cp2k_source"] != manifest["cp2k_source"]:
            raise MissingEvidence("CP2K source does not match the final plan")
        report["candidate"] = candidate
        imports = {}
        if args.previous_dir is not None:
            labels = ("qz6",) if args.stage == "f2" else ("qz6", "qz8", "5z8")
            imports = dict.fromkeys(labels, args.previous_dir)
        with tempfile.TemporaryDirectory(prefix="a04-final-", dir=output.parent) as scratch:
            report["status"] = evaluate(args.stage, args.system, manifest, candidate, Path(scratch),
                                        output, imports, report)
        report["scratch_removed"] = True
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
    write_report(output / "report.json", report)
    summary = {k: report[k] for k in ("stage", "system", "status", "gate_failures", "error") if k in report}
    summary["report_sha256"] = sha256(output / "report.json")
    print("QUANTA_A04_FINAL_RESULT " + json.dumps(summary, allow_nan=False))
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
