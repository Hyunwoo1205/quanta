#!/usr/bin/env python3
"""Execute the prospectively locked independent He / H2 pilot locally on Linux."""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PLAN_DIR = ROOT / "deploy/helfem-a04"
DEFAULT_LIBXC_SHA256 = "04357dfb756fbc45c311fdd59fb4817f8fc8854908312fea9609de98edebd08e"
SCF = re.compile(r"^QUANTA_SCF (\S+) (\S+) ([01])$", re.MULTILINE)
CHARGE = re.compile(r"^QUANTA_ELECTRONS (\S+)$", re.MULTILINE)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pilot_cases(axes: dict) -> list[tuple[str, dict]]:
    fine = {axis: levels[2] for axis, levels in axes.items()}
    cases = [("fine", fine)]
    for axis, levels in axes.items():
        for index, value in enumerate(levels[:2], start=1):
            cases.append((f"{axis}-{index}", {**fine, axis: value}))
    return cases


def available_bytes() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("Host memory availability is missing")


def launch(
    command: list[str], output: Path, policy: dict, residual_limit: float, charge_limit: float,
) -> dict:
    if len(Path("/proc/swaps").read_text().splitlines()) != 1:
        raise RuntimeError("Reference pilot requires a host without active swap")
    available = available_bytes()
    allowance = min(available - policy["min_host_available_reserve_bytes"],
                    policy["max_address_space_bytes"])
    if allowance <= 0:
        raise RuntimeError("Insufficient host memory reserve")
    core = min(os.sched_getaffinity(0))

    def set_limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (allowance, allowance))
        os.sched_setaffinity(0, {core})

    start = time.monotonic()
    environment = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1",
                       MKL_NUM_THREADS="1", LC_ALL="C")
    returncode = None
    status = "timed_out"
    try:
        with output.open("wb") as stream:
            completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                       cwd=output.parent, env=environment, preexec_fn=set_limits,
                                       timeout=policy["timeout_seconds_per_case"], check=False)
        returncode = completed.returncode
        status = "missing_evidence" if returncode == 0 else "process_failed"
    except subprocess.TimeoutExpired:
        pass
    log = output.read_text(errors="replace")
    scf = SCF.findall(log)
    charge = CHARGE.findall(log)
    record = {
        "status": status,
        "returncode": returncode,
        "required_scf_residual_limit": residual_limit,
        "wall_seconds": time.monotonic() - start,
        "host_available_before_bytes": available,
        "address_space_limit_bytes": allowance,
        "log_sha256": sha256(output),
    }
    if len(scf) == 1:
        energy, residual = map(float, scf[0][:2])
        record.update(
            energy_hartree=energy if math.isfinite(energy) else None,
            scf_residual=residual if math.isfinite(residual) else None,
            scf_solver_reported_converged=scf[0][2] == "1",
        )
    if len(charge) == 1:
        count = float(charge[0])
        record["overlap_electrons"] = count if math.isfinite(count) else None
    if returncode == 0 and len(scf) == len(charge) == 1:
        admitted = (record["scf_solver_reported_converged"] and
                    all(map(math.isfinite, (energy, residual, count))) and
                    0 <= residual <= residual_limit and abs(count - 2) <= charge_limit)
        record["status"] = "admitted" if admitted else "scf_or_charge_rejected"
    return record



def summarize(records: dict, axes: dict) -> dict:
    def energy(case: str) -> float:
        return records[case]["energy_hartree"]

    center = energy("fine")
    energy_axes = {}
    for axis in axes:
        coarse, middle = energy(f"{axis}-1"), energy(f"{axis}-2")
        energy_axes[axis] = [abs(coarse - middle), abs(middle - center)]
    return {
        "center_energy_hartree": center,
        "energy_adjacent_differences_hartree": energy_axes,
        "energy_finest_axis_differences_sum_hartree": sum(v[1] for v in energy_axes.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", choices=("he", "h2"))
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--revision", choices=(1, 2, 3, 4), type=int, default=4)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--center-only", action="store_true")
    modes.add_argument("--h2-center-refinement", action="store_true",
                       help="run only the locked H2 domain, mesh, angular and polynomial center axes")
    parser.add_argument("--reuse-v3", "--reuse-he-v3", dest="reuse_v3", type=Path,
                        help="reuse verified, identical admitted rows from the v3 pilot")
    args = parser.parse_args()
    plan_path = PLAN_DIR / f"pilot-v{args.revision}.json"
    plan = json.loads(plan_path.read_text(), parse_float=Decimal)
    if args.revision == 1 and not args.center_only:
        parser.error("Initial SCF-clamp diagnostic is confined to the center")

    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    axes = plan["axes"][args.fixture]
    h2 = args.fixture == "h2"
    if h2 and not (args.center_only or args.h2_center_refinement):
        parser.error("H2 force displacement is blocked by the R1 center density result")
    if args.h2_center_refinement and (not h2 or args.revision != 3):
        parser.error("The H2 center refinement screen uses only the locked v3 deck")
    bond = plan["h2_bond_angstrom"] * Decimal("1e-10") / plan["codata2006_bohr_m"] if h2 else None
    records: dict[str, dict] = {}
    resolved_libraries = subprocess.run(["ldd", str(binary)], check=True, text=True, capture_output=True).stdout
    linked = re.findall(r"^\s*libxc\.so\.15 => (\S+) \(", resolved_libraries, re.MULTILINE)
    if len(linked) != 1:
        raise RuntimeError("Exactly one resolved LibXC 7 shared library is required")
    libxc_sha256 = sha256(Path(linked[0]))
    if libxc_sha256 != plan.get("libxc_binary_sha256", DEFAULT_LIBXC_SHA256):
        raise RuntimeError("Resolved LibXC library does not match the locked pilot revision")
    prior_path = None
    prior_rows = {}
    if args.reuse_v3:
        if not (args.h2_center_refinement or (args.fixture == "he" and args.revision == 4)):
            parser.error("v3 reuse is limited to the corrected He or H2 center-only axis screen")
        prior_path = args.reuse_v3.resolve(strict=True)
        prior = json.loads((prior_path / "summary.json").read_text())
        if (prior["fixture"] != args.fixture or prior["plan_sha256"] != sha256(PLAN_DIR / "pilot-v3.json")
                or prior["libxc_binary_sha256"] != libxc_sha256 or prior["binary_sha256"] != sha256(binary)):
            raise RuntimeError("Prior rows have a different plan, executable, or LibXC library")
        prior_rows = prior["records"]
    report = {"fixture": args.fixture, "revision": args.revision, "center_only": args.center_only,
              "h2_center_refinement": args.h2_center_refinement,
              "plan_sha256": sha256(plan_path), "binary_sha256": sha256(binary),
              "libxc_binary_sha256": libxc_sha256, "records": records, "status": "running"}


    output.mkdir(parents=True)

    def save() -> None:
        temporary = output / "summary.tmp"
        temporary.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
        temporary.replace(output / "summary.json")

    cases = pilot_cases(axes)
    if args.center_only:
        cases = cases[:1]
    elif args.h2_center_refinement:
        axes = {axis: axes[axis] for axis in ("Rmax", "nelem", "lmax", "nnodes")}
        cases = [entry for entry in cases if entry[0] == "fine" or
                 entry[0].rsplit("-", 1)[0] in axes]
        report["center_refinement_budget_seconds"] = 240
        report["h2_force_status"] = "not_measured_center_density_exceeds_total_limit"
    report["planned_cases"] = [name for name, _ in cases]
    save()
    deadline = time.monotonic() + 240 if args.h2_center_refinement else None
    for case, settings in cases:
        case_path = output / case
        case_path.mkdir()
        options = dict(plan["shared_options"], method=plan["method"], **settings)
        if h2:
            options.update(plan["h2_fixed_options"], Z1=1, Z2=1, Rbond=format(float(bond), ".17g"))
        else:
            options["Z"] = 2
        options["save"] = "checkpoint.h5"
        command = [str(binary), *(f"--{key}={value}" for key, value in options.items())]
        (case_path / "args.json").write_text(json.dumps(command[1:], indent=2) + "\n")
        previous = next(
            ((name, row) for name, row in prior_rows.items()
             if row["status"] == "admitted" and row["arguments"] == command[1:]), None
        )
        if previous:
            previous_case, record = previous
            for name, digest in (("run.log", record["log_sha256"]),
                                 (options["save"], record["checkpoint_sha256"])):
                source = prior_path / previous_case / name
                if sha256(source) != digest:
                    raise RuntimeError(f"Prior row {previous_case} has a different {name} digest")
                shutil.copyfile(source, case_path / name)
            record = {**record, "reused_v3_case": previous_case,
                      "reused_receipt_sha256": sha256(prior_path / "summary.json")}
        else:
            try:
                record = launch(command, case_path / "run.log", plan["resource"],
                                float(settings["quanta-scf-threshold"]),
                                float(plan["native_electron_count_limit"]))
            except (OSError, RuntimeError) as error:
                record = {"status": "launch_failed", "error": str(error)}
        checkpoint = case_path / options["save"]
        if checkpoint.is_file():
            record["checkpoint_sha256"] = sha256(checkpoint)
        elif record["status"] == "admitted":
            record["status"] = "missing_checkpoint"
        record["arguments"] = command[1:]
        records[case] = record
        if record["status"] != "admitted":
            report["status"] = "incomplete"
            report["batch_peak_child_rss_kib"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            save()
            raise SystemExit(f"Reference row {case} failed with {record['status']}; retained in {output}")
        save()
    if not args.center_only:
        report.update(summarize(records, axes))
    if args.fixture == "he":
        report["force_by_centered_atom_symmetry_hartree_per_bohr"] = [0.0, 0.0, 0.0]
    report["status"] = "rows_completed"
    report["batch_peak_child_rss_kib"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    save()


if __name__ == "__main__":
    main()
