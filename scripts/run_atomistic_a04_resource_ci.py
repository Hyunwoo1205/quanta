#!/usr/bin/env python3
"""Measure the pinned native x86 CP2K candidate in isolated GitHub Actions."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time
from uuid import uuid4

from atomistic_a03_candidate import load_candidate
from atomistic_a03_inputs import A04_FINE_BASIS_ASSETS, generate_input, probe_metadata
from atomistic_a04_resources import (
    GIB, MEMORY_RESERVE_BYTES, MEMORY_TIERS_BYTES, available_memory_bytes, memory_budget,
)
from verify_atomistic_a03 import (
    LOCK_DIR, check_density_geometry, parse_cube, parse_force_artifact, parse_output, sha256,
)


ROOT = Path(__file__).resolve().parents[1]
REPO = "Hyunwoo1205/quanta"
RECEIPT = ROOT / "docs/verification/atomistic-a04/x86-a03-gapw-42389732936.json"
VALIDATION_PLAN = ROOT / "docs/design/atomistic-a01-v0.1/validation-plan.json"
PROJECT = "a04_resource_h2"
CUBE = f"{PROJECT}-TOTAL_ELECTRON_DENSITY-1_0.cube"
REPORT_LIMIT = 128 * 1024
LOG_LIMIT = 1024 * 1024
DIAGNOSTIC_EDGE = 32 * 1024
WORK_LIMIT = 2 * GIB
TMPFS_LIMIT = 256 * 1024**2
DISK_ADMISSION = 10 * GIB
DISK_GUARD = 6 * GIB
MEMORY_GUARD = MEMORY_RESERVE_BYTES
OCI_PROBE_LABEL = "org.quanta.atomistic-a04"
SHM_LIMIT = 64 * 1024**2
HEARTBEAT = 1.0
EXPECTED_FILES = {"cp2k.out", "forces.xyz", "engine-resource.json", CUBE}
SMALL_FILES = {"cp2k.out": LOG_LIMIT, "forces.xyz": 64 * 1024, "engine-resource.json": 8 * 1024}
TRANSIENT_FILES = {"engine-resource.tmp": 8 * 1024, "release": 1}
BASELINE_CASE_IDS = ("h2-12a-400ry-density-off", "h2-12a-400ry-density-on")


@dataclass(frozen=True)
class Case:
    name: str
    cell: int | str
    cutoff: int
    density: bool
    wall_seconds: int
    minimum_memory_bytes: int = 2 * GIB
    rel_cutoff: int = 40
    system: str = "h2"
    eps_scf: float = 1e-8
    radial_grid: int = 100
    lebedev_grid: int = 110
    basis: str = "cc-pVDZ"
    overlap_condition: bool = False
    lmaxn1: int = 6
    final_batch: bool = False


CASES = (
    Case(BASELINE_CASE_IDS[0], 12, 400, False, 240),
    Case(BASELINE_CASE_IDS[1], 12, 400, True, 240),
    Case("h2-16a-800ry-density-on", 16, 800, True, 900, 4 * GIB, rel_cutoff=80),
)

MPI_CASES = (
    Case("h2-20a-800ry-density-on", 20, 800, True, 1800, 4 * GIB, rel_cutoff=80),
    CASES[-1],
    CASES[1],
)
REFINEMENT_RECEIPTS = RECEIPT.parent
ACCURACY_REFERENCE = REFINEMENT_RECEIPTS / "memory-recovery-42438533750.json"
ACCURACY_PLAN = ROOT / "docs/design/atomistic-a04-v0.1/h2-cross-grid-comparison.json"
ONE_FACTOR_PLAN = ACCURACY_PLAN.with_name("h2-one-factor-refinement.json")
ENDPOINT_RECEIPT = ACCURACY_REFERENCE.with_name("cross-grid-accuracy-42443582121.json")
ONE_FACTOR_AXES = ("cell", "cutoff", "relative")
FIXTURE_PLAN = ACCURACY_PLAN.with_name("fixed-fixture-refinement.json")
FIXTURE_PREDECESSOR = ACCURACY_REFERENCE.with_name("one-factor-refinement-42447627356.json")
BOUNDARY_PLAN = FIXTURE_PLAN.with_name("h2-boundary-refinement.json")
BOUNDARY_PREDECESSOR = ACCURACY_REFERENCE.with_name("fixed-fixture-accuracy-42448653582.json")
BOUNDARY_SYSTEMS = ("h2-short", "h2-long")
FIXTURE_SYSTEMS = ("he", "h2-reference", *BOUNDARY_SYSTEMS)
SCF_SYSTEMS = (*FIXTURE_SYSTEMS, "h2")
SCF_PLAN = FIXTURE_PLAN.with_name("scf-refinement.json")
GRID_PLAN = FIXTURE_PLAN.with_name("remaining-numerical-validation.json")
GRID_INPUTS = FIXTURE_PLAN.with_name("atomic-grid-inputs.json")
BASIS_INPUTS = FIXTURE_PLAN.with_name("basis-refinement-inputs.json")
QZ_INPUTS = FIXTURE_PLAN.with_name("qz-sensitivity-inputs.json")
QZ_G2_RECEIPT = REFINEMENT_RECEIPTS / "basis-refinement-42499460058.json"
QZ_TRACKS = ("h2-short", "he-local", "he-mgrid", "he-cell")
QZ_CUTOFF_INPUTS = FIXTURE_PLAN.with_name("qz-cutoff-refinement-inputs.json")
QZ_SENSITIVITY_RECEIPT = REFINEMENT_RECEIPTS / "qz-sensitivity-42501071977.json"


ENGINE_WRAPPER = r"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback

root = Path('/work')
start = time.monotonic()
log = root / 'cp2k.out'
def log_uncaught(exc_type, value, trace):
    with log.open('a', encoding='utf-8') as stream:
        traceback.print_exception(exc_type, value, trace, file=stream)

sys.excepthook = log_uncaught
binary, revision, ranks_arg = sys.argv[1:]
mpi_ranks = int(ranks_arg)
if mpi_ranks not in (1, 2):
    raise ValueError('Only the fixed one- and two-rank layouts are supported')
with log.open('wb') as output:
    exe = shutil.which('cp2k')
    if exe is None:
        raise RuntimeError('Pinned CP2K binary is absent')
    with open(exe, 'rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != binary:
        raise RuntimeError('CP2K binary hash mismatch')
    version = subprocess.check_output([exe, '--version'], stderr=subprocess.STDOUT, timeout=30)
    if not re.search(rb'^\s*CP2K version 2026\.2\s*$', version, re.M) or not re.search(
        rb'^\s*Source code revision ' + revision.encode('ascii') + rb'\s*$', version, re.M
    ):
        raise RuntimeError('CP2K source revision or version mismatch')
    command = [exe, '-i', '/quanta-input/input.inp']
    if mpi_ranks == 2:
        mpi = shutil.which('mpiexec')
        if mpi is None:
            raise RuntimeError('The pinned candidate has no MPICH launcher')
        command = [mpi, '-launcher', 'fork', '-hosts', 'localhost', '-iface', 'lo', '-n', ranks_arg, *command]
    engine_started = time.monotonic()
    child = subprocess.Popen(command, stdout=output, stderr=output)
    _, status, usage = os.wait4(child.pid, 0)
    engine_wall_seconds = time.monotonic() - engine_started
    child.returncode = os.waitstatus_to_exitcode(status)

cgroup = Path('/sys/fs/cgroup')
def metric(name):
    try:
        return int((cgroup / name).read_text())
    except (OSError, ValueError):
        return None

def event_counts():
    try:
        return {name: int(value) for name, value in
                (line.split() for line in (cgroup / 'memory.events').read_text().splitlines())}
    except (OSError, ValueError):
        return {}

tmp = os.statvfs('/tmp')
row = {
    'binary_sha256': actual,
    'reported_revision': revision,
    'requested_mpi_ranks': mpi_ranks,
    'engine_returncode': child.returncode,
    'engine_wall_seconds': engine_wall_seconds,
    'engine_wall_seconds_with_inventory': time.monotonic() - start,
    'engine_children_peak_rss_kib': usage.ru_maxrss,
    'engine_user_cpu_seconds': usage.ru_utime,
    'engine_system_cpu_seconds': usage.ru_stime,
    'final_cgroup_memory_max_bytes': metric('memory.max'),
    'final_cgroup_swap_max_bytes': metric('memory.swap.max'),
    'final_cgroup_swap_current_bytes': metric('memory.swap.current'),
    'final_cgroup_swap_peak_bytes': metric('memory.swap.peak'),
    'final_cgroup_memory_peak_bytes': metric('memory.peak'),
    'final_cgroup_memory_events': event_counts(),
    'final_tmpfs_used_bytes': (tmp.f_blocks - tmp.f_bfree) * tmp.f_frsize,
}
(root / 'engine-resource.tmp').write_text(json.dumps(row, allow_nan=False), encoding='ascii')
os.replace(root / 'engine-resource.tmp', root / 'engine-resource.json')
# Hold the cgroup briefly so the controller can sample terminal counters. A
# parent-side watchdog always removes the container, including on interruption.
until = time.monotonic() + 35
while not (root / 'release').is_file() and time.monotonic() < until:
    time.sleep(0.2)
sys.exit(child.returncode if child.returncode >= 0 else 128 - child.returncode)
"""


def run_docker(*args: str, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=check)


def inspect_container(name: str) -> dict:
    return json.loads(run_docker("inspect", name).stdout)[0]


def docker_disk_free(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except PermissionError:
        # Hosted runner DockerRootDir is sometimes not traversable by the job
        # user. This only reads filesystem capacity and never changes privileges
        # for the actual controller or container.
        result = subprocess.check_output(
            ["sudo", "-n", "df", "--block-size=1", "--output=avail", "--", str(path)],
            text=True, timeout=10,
        ).splitlines()
        if len(result) != 2 or not result[1].strip().isdigit():
            raise ValueError("Docker storage capacity could not be read")
        return int(result[1].strip())


def require_native_ci(architecture: str = "amd64") -> None:
    machine, runner, docker_architectures = {
        "amd64": ("x86_64", "X64", {"x86_64"}),
        "arm64": ("aarch64", "ARM64", {"aarch64", "arm64"}),
    }[architecture]
    expected_env = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPO,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_ARCH": runner,
    }
    if (
        os.geteuid() == 0
        or platform.system() != "Linux"
        or platform.machine() != machine
        or any(os.environ.get(key) != value for key, value in expected_env.items())
        or not shutil.which("docker")
    ):
        raise ValueError(f"Only the nonroot native {machine} GitHub-hosted Quanta runner is permitted")
    # The process and the container must share the native local host/cgroup view.
    if os.environ.get("DOCKER_HOST") not in (None, "", "unix:///var/run/docker.sock"):
        raise ValueError("A remote Docker daemon is unsupported")
    endpoint = run_docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}").stdout.strip()
    if endpoint != "unix:///var/run/docker.sock":
        raise ValueError("The default native GitHub runner Docker socket is required")
    info = run_docker("info", "--format", "{{.OSType}} {{.Architecture}} {{.CgroupVersion}} {{.DockerRootDir}}").stdout.strip()
    parts = info.split(maxsplit=3)
    if len(parts) != 4 or parts[0] != "linux" or parts[1] not in docker_architectures or parts[2] != "2":
        raise ValueError(f"Native Linux {architecture} Docker with cgroup v2 is required")
    if not parts[3].startswith("/") or docker_disk_free(Path(parts[3])) < DISK_ADMISSION:
        raise ValueError("Docker storage has insufficient disk headroom before image load")


def safe_bind(path: Path, target: str, *, readonly: bool = False) -> str:
    resolved = path.resolve(strict=True)
    if any(c in str(resolved) for c in ',\r\n'):
        raise ValueError("Unsupported bind path")
    return f"type=bind,source={resolved},target={target}" + (",readonly" if readonly else "")


def container_args(name: str, image_id: str, budget: int, work: Path, inputs: Path, candidate: dict,
                   *, mpi_ranks: int = 1, swap_extra_bytes: int = 0, architecture: str = "amd64",
                   oci_probe_output: Path | None = None) -> list[str]:
    if type(mpi_ranks) is not int or mpi_ranks not in (1, 2):
        raise ValueError("Only the fixed one- and two-rank layouts are supported")
    if type(swap_extra_bytes) is not int or swap_extra_bytes < 0:
        raise ValueError("Swap allowance must be a nonnegative byte count")
    if architecture not in ("amd64", "arm64"):
        raise ValueError("Unsupported native architecture")
    label = []
    if oci_probe_output is not None:
        if architecture != "arm64" or not oci_probe_output.is_absolute():
            raise ValueError("The OCI cleanup label requires native ARM and an absolute output path")
        label = ["--label", f"{OCI_PROBE_LABEL}={oci_probe_output}"]
    return [
        "create", "--name", name, "--pull=never", "--platform", f"linux/{architecture}",
        *label,
        "--read-only", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}", "--group-add", "0",
        "--cpus", str(mpi_ranks), "--memory", str(budget), "--memory-swap", str(budget + swap_extra_bytes),
        "--pids-limit", "128", "--cgroupns", "private", "--log-driver", "none", "--shm-size", str(SHM_LIMIT),
        "--ulimit", "core=0:0", "--ulimit", f"fsize={GIB}:{GIB}",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={TMPFS_LIMIT},mode=1777", "--workdir", "/work",
        "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp", "--env", "LC_ALL=C", "--env", "OMP_NUM_THREADS=1",
        "--env", "OPENBLAS_NUM_THREADS=1", "--env", "MKL_NUM_THREADS=1", "--env", "NUMEXPR_NUM_THREADS=1",
        "--mount", safe_bind(work, "/work"), "--mount", safe_bind(inputs, "/quanta-input", readonly=True),
        "--mount", safe_bind(LOCK_DIR / "assets", "/quanta-data", readonly=True),
        "--entrypoint", "python3", image_id, "-I", "-B", "-c", ENGINE_WRAPPER,
        candidate["binary_sha256"], candidate["cp2k_source"], str(mpi_ranks),
    ]


def checked_controls(inspected: dict, budget: int, *, mpi_ranks: int = 1, swap_extra_bytes: int = 0,
                     oci_probe_output: Path | None = None) -> dict:
    host = inspected["HostConfig"]
    for key, expected in {
        "Memory": budget, "MemorySwap": budget + swap_extra_bytes, "NanoCpus": mpi_ranks * 10**9,
        "PidsLimit": 128, "NetworkMode": "none", "ReadonlyRootfs": True,
        "CgroupnsMode": "private", "ShmSize": SHM_LIMIT,
    }.items():
        if host.get(key) != expected:
            raise ValueError(f"Docker did not enforce {key}")
    if host["LogConfig"]["Type"] != "none":
        raise ValueError("Docker did not disable unbounded daemon logs")
    ulimits = {row["Name"]: (row["Soft"], row["Hard"]) for row in host["Ulimits"]}
    if ulimits.get("fsize") != (GIB, GIB) or ulimits.get("core") != (0, 0):
        raise ValueError("Docker did not enforce the file and core-dump limits")
    if host.get("Tmpfs") != {"/tmp": f"rw,nosuid,nodev,noexec,size={TMPFS_LIMIT},mode=1777"}:
        raise ValueError("Docker did not enforce the bounded /tmp mount")
    if "ALL" not in host.get("CapDrop", []) or "no-new-privileges" not in host.get("SecurityOpt", []):
        raise ValueError("Docker did not enforce the process capability controls")
    mounts = {row["Destination"]: (row["Type"], row["RW"]) for row in inspected["Mounts"] if row["Type"] == "bind"}
    if mounts != {"/work": ("bind", True), "/quanta-input": ("bind", False), "/quanta-data": ("bind", False)}:
        raise ValueError("Docker did not enforce the expected bind controls")
    if oci_probe_output is not None:
        labels = inspected["Config"]["Labels"] or {}
        if labels.get(OCI_PROBE_LABEL) != str(oci_probe_output):
            raise ValueError("Docker did not attach the exact OCI cleanup label")
    return {
        "memory_bytes": budget, "memory_swap_bytes": budget + swap_extra_bytes, "cpus": mpi_ranks, "pids": 128,
        "work": "disk-backed bind", "network": "none", "tmpfs_max_bytes": TMPFS_LIMIT,
        "readonly_rootfs": True, "log_driver": "none", "fsize_bytes": GIB, "shm_limit_bytes": SHM_LIMIT,
    }


def read_cgroup(pid: int, budget: int, record: dict) -> None:
    if not pid:
        return
    try:
        row = next(x for x in Path(f"/proc/{pid}/cgroup").read_text().splitlines() if x.startswith("0::/"))
        mount = Path("/sys/fs/cgroup")
        scope = (mount / row[4:]).resolve(strict=True)
        if scope == mount or not scope.is_relative_to(mount):
            raise ValueError("Container cgroup is outside the expected v2 mount")
        if int((scope / "memory.max").read_text()) != budget:
            raise ValueError("Container cgroup memory.max differs from the granted hard cap")
        current = int((scope / "memory.current").read_text())
        peak = int((scope / "memory.peak").read_text())
        stats = dict(line.split() for line in (scope / "memory.stat").read_text().splitlines())
        events = dict(line.split() for line in (scope / "memory.events").read_text().splitlines())
    except (FileNotFoundError, ProcessLookupError, StopIteration, PermissionError):
        return  # Container can exit concurrently; terminal state is inspected separately.
    record["samples"] += 1
    record["cgroup_memory_peak_bytes"] = max(record["cgroup_memory_peak_bytes"] or 0, peak)
    record["cgroup_sampled_current_peak_bytes"] = max(record["cgroup_sampled_current_peak_bytes"] or 0, current)
    for key in ("anon", "file", "shmem"):
        if key in stats:
            record["cgroup_sampled_stat_peak_bytes"][key] = max(
                record["cgroup_sampled_stat_peak_bytes"].get(key, 0), int(stats[key])
            )
    for key in ("max", "oom", "oom_kill", "oom_group_kill"):
        if key in events:
            record["cgroup_memory_events_max"][key] = max(
                record["cgroup_memory_events_max"].get(key, 0), int(events[key])
            )


def checked_work_files(work: Path, *, successful: bool = False) -> tuple[dict[str, os.stat_result], int, int]:
    files: dict[str, os.stat_result] = {}
    logical = allocated = 0
    with os.scandir(work) as entries:
        for entry in entries:
            if len(files) >= 12:
                raise ValueError("Scratch file count exceeded the fixed measurement envelope")
            try:
                item = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                if successful:
                    raise
                continue  # Atomic replacement by the wrapper.
            if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                raise ValueError("Scratch contains a symlink, special file or hard link")
            limit = SMALL_FILES.get(entry.name, TRANSIENT_FILES.get(entry.name, GIB))
            if item.st_size > limit:
                raise ValueError(f"Scratch file exceeded its output budget: {entry.name}")
            if successful and entry.name not in EXPECTED_FILES | {"release"}:
                raise ValueError(f"Unexpected completed measurement output: {entry.name}")
            logical += item.st_size
            allocated += item.st_blocks * 512
            files[entry.name] = item
            if max(logical, allocated) > WORK_LIMIT:
                raise ValueError("Aggregate scratch exceeded the sampled 2 GiB work budget")
    return files, logical, allocated


def sample_scratch(work: Path, record: dict) -> None:
    _, logical, allocated = checked_work_files(work)
    record["sampled_work_peak_logical_bytes"] = max(record["sampled_work_peak_logical_bytes"], logical)
    record["sampled_work_peak_allocated_bytes"] = max(record["sampled_work_peak_allocated_bytes"], allocated)


def log_excerpt(work: Path, out: Path) -> None:
    path = work / "cp2k.out"
    if not path.exists():
        return
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
        return
    with path.open("rb") as f:
        content = f.read(DIAGNOSTIC_EDGE * 2)
        if item.st_size > len(content):
            f.seek(-DIAGNOSTIC_EDGE, os.SEEK_END)
            content = content[:DIAGNOSTIC_EDGE] + b"\n[bounded log excerpt]\n" + f.read(DIAGNOSTIC_EDGE)
    out.write_bytes(content)


def clean_container(name: str) -> None:
    # An already-absent container can produce different errors by Docker version.
    run_docker("rm", "--force", name, check=False)
    remaining = run_docker("container", "ls", "--all", "--filter", f"name=^/{re.escape(name)}$",
                           "--format", "{{.Names}}", check=False)
    if remaining.returncode or remaining.stdout:
        raise RuntimeError("Could not verify isolated container removal")


def run_attempt(case: Case, attempt: int, budget: int, available: int, candidate: dict,
                scratch: Path, diagnostics: Path, record: dict, *, mpi_ranks: int = 1,
                swap_extra_bytes: int = 0, expected_input: str | None = None,
                retained_cube: Path | None = None, distribute_real_space: bool = False,
                architecture: str = "amd64", oci_probe_output: Path | None = None) -> None:
    name = f"quanta-a04-resource-{uuid4().hex}"
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"{case.name}-{attempt}-", dir=scratch) as path:
        work = Path(path) / "work"
        inputs = Path(path) / "input"
        work.mkdir(mode=0o700)
        inputs.mkdir(mode=0o700)
        options = {
            "system": case.system, "basis": case.basis, "project": PROJECT,
            "cell_angstrom": case.cell, "cutoff_ry": case.cutoff,
            "rel_cutoff_ry": case.rel_cutoff, "density": case.density, "eps_scf": case.eps_scf,
            "radial_grid": case.radial_grid, "lebedev_grid": case.lebedev_grid,
            "overlap_condition": case.overlap_condition,
        }
        if case.final_batch:
            options.update(lmaxn1=case.lmaxn1, final_batch=True)
            if case.basis in A04_FINE_BASIS_ASSETS:
                shutil.copyfile(A04_FINE_BASIS_ASSETS[case.basis], inputs / f"{case.basis}.cp2k")
        base_input = generate_input(**options).encode("ascii")
        submitted_input = base_input
        if distribute_real_space:
            mgrid_end = b"    &END MGRID\n"
            if base_input.count(mgrid_end) != 1:
                raise ValueError("The fixed input must contain exactly one MGRID section")
            submitted_input = base_input.replace(
                mgrid_end, b"      &RS_GRID\n        DISTRIBUTION_TYPE DISTRIBUTED\n      &END RS_GRID\n" + mgrid_end,
            )
        (inputs / "input.inp").write_bytes(submitted_input)
        metadata = probe_metadata(**options)
        record.update({
            "attempt": attempt, "status": "controller_error", "granted_memory_bytes": budget,
            "requested_mpi_ranks": mpi_ranks, "granted_swap_extra_bytes": swap_extra_bytes,
            "available_memory_at_admission_bytes": available, "minimum_sampled_available_memory_bytes": available,
            "minimum_sampled_free_disk_bytes": shutil.disk_usage(work).free, "samples": 0,
            "sampled_work_peak_logical_bytes": 0, "sampled_work_peak_allocated_bytes": 0,
            "cgroup_memory_peak_bytes": None, "cgroup_sampled_current_peak_bytes": None,
            "cgroup_sampled_stat_peak_bytes": {}, "cgroup_memory_events_max": {},
            "input_sha256": hashlib.sha256(base_input).hexdigest(),
            "submitted_input_sha256": sha256(inputs / "input.inp"), "input_metadata": metadata,
            "real_space_distribution_request": "DISTRIBUTED" if distribute_real_space else "AUTOMATIC",
        })
        state: dict = {}
        engine: dict = {}
        try:
            if expected_input is not None and record["input_sha256"] != expected_input:
                raise ValueError("Scientific input differs from the recorded serial input")
            layout = {"mpi_ranks": mpi_ranks, "swap_extra_bytes": swap_extra_bytes}
            if oci_probe_output is not None:
                layout["oci_probe_output"] = oci_probe_output
            run_docker(*container_args(
                name, candidate["image_id"], budget, work, inputs, candidate, architecture=architecture, **layout,
            ))
            record["container_controls"] = checked_controls(inspect_container(name), budget, **layout)
            run_docker("start", name)
            until = time.monotonic() + case.wall_seconds
            while True:
                inspected = inspect_container(name)
                state = inspected["State"]
                read_cgroup(state.get("Pid", 0), budget, record)
                try:
                    sample_scratch(work, record)
                except ValueError as exc:
                    record.update(status="scratch_guard", error=str(exc))
                    break
                host_memory = available_memory_bytes()
                free_disk = shutil.disk_usage(work).free
                record["minimum_sampled_available_memory_bytes"] = min(
                    record["minimum_sampled_available_memory_bytes"], host_memory
                )
                record["minimum_sampled_free_disk_bytes"] = min(record["minimum_sampled_free_disk_bytes"], free_disk)
                if host_memory < MEMORY_GUARD:
                    record["status"] = "host_memory_guard"
                    break
                if free_disk < DISK_GUARD:
                    record["status"] = "host_disk_guard"
                    break
                if (work / "engine-resource.json").is_file():
                    (work / "release").touch()
                if not state["Running"]:
                    break
                if time.monotonic() >= until:
                    record["status"] = "case_timeout"
                    break
                time.sleep(HEARTBEAT)
            record["container_elapsed_seconds"] = time.monotonic() - started
            record["container_exit_code"] = state.get("ExitCode") if not state.get("Running") else None
            record["docker_oom_killed"] = state.get("OOMKilled") is True
            if record["status"] != "controller_error":
                return
            resource = work / "engine-resource.json"
            if resource.is_file():
                engine = json.loads(resource.read_bytes())
                record["engine_resource"] = engine
                final_peak = engine["final_cgroup_memory_peak_bytes"]
                if final_peak is not None:
                    record["cgroup_memory_peak_bytes"] = max(record["cgroup_memory_peak_bytes"] or 0, final_peak)
                for key, value in engine["final_cgroup_memory_events"].items():
                    record["cgroup_memory_events_max"][key] = max(
                        record["cgroup_memory_events_max"].get(key, 0), value
                    )
            # Docker and cgroup counters describe only this new container. An
            # exit code of 137 (including a guard kill) is not OOM evidence.
            if record["docker_oom_killed"] or record["cgroup_memory_events_max"].get("oom_kill", 0) > 0:
                record["status"] = "container_oom"
                return
            if record["container_exit_code"] != 0:
                record["status"] = "engine_exit"
                return
            record["status"] = "invalid_output"
            if (
                engine.get("engine_returncode") != 0
                or engine.get("binary_sha256") != candidate["binary_sha256"]
                or engine.get("reported_revision") != candidate["cp2k_source"]
                or engine.get("final_cgroup_memory_max_bytes") != budget
                or engine.get("final_cgroup_swap_max_bytes") != swap_extra_bytes
                or engine.get("requested_mpi_ranks") != mpi_ranks
                or not record["cgroup_memory_peak_bytes"]
                or not engine.get("engine_children_peak_rss_kib")
            ):
                raise ValueError("Required engine identity and native cgroup/RSS evidence are incomplete")
            files, total, allocated = checked_work_files(work, successful=True)
            expected = EXPECTED_FILES if case.density else EXPECTED_FILES - {CUBE}
            if set(files) - {"release"} != expected or any(files[k].st_size <= 0 for k in expected):
                raise ValueError("Completed engine output did not match the fixed artifact set")
            record["output_bytes"] = total
            record["output_allocated_bytes"] = allocated
            text = (work / "cp2k.out").read_text(encoding="utf-8")
            counts = re.findall(r"(?m)^\s*GLOBAL\| Total number of message passing processes\s+(\d+)\s*$", text)
            threads = re.findall(r"(?m)^\s*GLOBAL\| Number of threads for this process\s+(\d+)\s*$", text)
            if counts != [str(mpi_ranks)] or threads != ["1"]:
                raise ValueError("CP2K output did not confirm the requested rank/thread layout")
            record["observed_mpi_ranks"] = mpi_ranks
            record["observed_omp_threads"] = 1
            if (case.radial_grid, case.lebedev_grid) != (100, 110) and (
                "the lebedev grid is built for angular momentum" in text.lower()
            ):
                raise ValueError("CP2K reported insufficient angular integration order")
            cp2k = parse_output(text)
            forces = parse_force_artifact(work / "forces.xyz")
            if (
                not cp2k["program_ended"] or not cp2k["scf_converged"]
                or cp2k["energy_hartree"] is None or not math.isfinite(cp2k["energy_hartree"])
                or len(forces) != len(metadata["atoms"])
                or not all(keyword in text for keyword in ("GAPW", "PBE", f"{case.basis}.cp2k", "ALL_POTENTIALS"))
            ):
                raise ValueError("Converged CP2K fixture energy, native forces or locked model evidence is missing")
            iterations = re.findall(r"SCF run converged in\s+(\d+)\s+steps", text)
            if len(iterations) == 1:
                record["engine_scf_iterations"] = int(iterations[0])
            if case.overlap_condition:
                from atomistic_a04_basis_output import parse_basis_conditioning

                try:
                    record["basis_conditioning"] = parse_basis_conditioning(
                        text, basis=case.basis, element=metadata["atoms"][0]["element"], atom_count=len(forces),
                        expected_atom_grid_max_l=case.lmaxn1 if case.final_batch else None,
                    )
                except ValueError:
                    labels = ("Atomic kind:", "Orbital Basis Set", "Number of orbital", "Number of independent",
                              "Number of spherical", "Number of primitive", "Number of Cartesian",
                              "OVERLAP MATRIX CONDITION NUMBER", "Condition Numbers using", "CN :")
                    record["basis_diagnostic_excerpt"] = [
                        line.strip() for line in text.splitlines() if any(label in line for label in labels)
                    ][:25]
                    raise
            record["engine_energy_hartree"] = cp2k["energy_hartree"]
            record["engine_forces_hartree_per_bohr"] = forces
            hard_soft_charge = re.findall(
                r"(?m)^[ \t]*Total Rho_soft \+ Rho1_hard - Rho1_soft[ \t]+(-\d+\.\d+)[ \t]*$", text
            )
            if len(hard_soft_charge) == 1:
                record["engine_hard_soft_electron_count"] = -float(hard_soft_charge[0])
            parsing_start = time.monotonic()
            if case.density:
                density = parse_cube(work / CUBE)
                density["geometry_check"] = check_density_geometry(density, metadata)
                if density["comments"] != ["-Quickstep-", " TOTAL ELECTRON DENSITY"]:
                    raise ValueError("Unexpected native CP2K density-field identity")
                record["density"] = density
            record["files"] = [
                {"file": key, "bytes": files[key].st_size,
                 "sha256": record["density"]["sha256"] if key == CUBE else sha256(work / key)}
                for key in sorted(expected)
            ]
            if retained_cube is not None:
                if not case.density or retained_cube.exists():
                    raise ValueError("Invalid retained density destination")
                (work / CUBE).rename(retained_cube)
            record["output_analysis_seconds"] = time.monotonic() - parsing_start
            record["status"] = "measured"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            try:
                clean_container(name)
                record["container_removed"] = True
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                record["status"] = "cleanup_error"
                record["container_removed"] = False
                record["error"] = f"{type(exc).__name__}: {exc}"[:500]
            try:
                sample_scratch(work, record)
                if (work / "cp2k.out").is_file():
                    with (work / "cp2k.out").open(encoding="utf-8", errors="replace") as stream:
                        layout_log = stream.read(LOG_LIMIT)
                    record["replicated_real_space_grid_count"] = layout_log.count("RS_GRID| Real space fully replicated")
                    record["distributed_real_space_grid_count"] = layout_log.count("RS_GRID| Real space distribution over")
                suffix = f"-mpi-{mpi_ranks}-swap-{swap_extra_bytes}" if retained_cube or mpi_ranks != 1 or swap_extra_bytes else ""
                log_excerpt(work, diagnostics / f"{case.name}{suffix}-attempt-{attempt}.log")
            except (OSError, ValueError) as exc:
                if record["status"] in {"container_oom", "measured"}:
                    record["status"] = "scratch_guard"
                record["scratch_error"] = f"{type(exc).__name__}: {exc}"[:500]
            record["total_attempt_seconds"] = time.monotonic() - started


def run_case(case: Case, candidate: dict, scratch: Path, diagnostics: Path, result: dict) -> None:
    result.update({
        "case": case.name, "attempts": [], "status": "not_measured", "case_timeout_seconds": case.wall_seconds,
        "minimum_memory_bytes": case.minimum_memory_bytes,
    })
    prior_grant = 0
    for number, tier in enumerate((0, len(MEMORY_TIERS_BYTES) - 1), start=1):
        available = available_memory_bytes()
        free = shutil.disk_usage(scratch).free
        budget = memory_budget(available, tier)
        if budget is not None and prior_grant:
            budget = min(budget, prior_grant + 2 * GIB)
        reason = None
        if free < DISK_ADMISSION:
            reason = "insufficient_disk_headroom"
        elif budget is None or budget < case.minimum_memory_bytes:
            reason = "insufficient_memory_for_case_minimum"
        elif budget <= prior_grant:
            reason = "no_safe_increased_memory_grant"
        if reason:
            result.update(
                status="deferred",
                admission={
                    "attempt": number, "available_memory_bytes": available, "free_disk_bytes": free,
                    "safe_grant_bytes": budget, "prior_grant_bytes": prior_grant or None,
                    "reason": reason,
                },
            )
            return
        assert budget is not None
        attempt: dict = {}
        result["attempts"].append(attempt)
        run_attempt(case, number, budget, available, candidate, scratch, diagnostics, attempt)
        result["status"] = attempt["status"]
        if attempt["status"] != "container_oom":
            return
        prior_grant = budget


def baseline_comparison(off: dict, on: dict) -> dict:
    av01 = next(c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"] if c["id"] == "AV01")
    a, b = (r["attempts"][-1] for r in (off, on))
    f0, f1 = (r["engine_forces_hartree_per_bohr"] for r in (a, b))
    de = abs(a["engine_energy_hartree"] - b["engine_energy_hartree"])
    df = max(abs(x-y) for v, w in zip(f0, f1, strict=True) for x, y in zip(v, w, strict=True))
    return {
        "scope": "same-engine baseline print off/on; borrows AV01 tolerances; does not execute AV01",
        "tolerance_source": str(VALIDATION_PLAN.relative_to(ROOT)) + "#AV01",
        "absolute_energy_difference_hartree": de,
        "absolute_maximum_force_component_difference_hartree_per_bohr": df,
        "energy_atol_hartree": av01["energy_atol_hartree"],
        "force_atol_hartree_per_bohr": av01["force_atol_hartree_per_bohr"],
        "passes_baseline_observational_comparison": (
            de <= av01["energy_atol_hartree"] and df <= av01["force_atol_hartree_per_bohr"]
        ),
        "density_cube_bytes": b["density"]["bytes"],
        "total_output_bytes_delta": b["output_bytes"] - a["output_bytes"],
        "observed_cgroup_peak_bytes_delta": b["cgroup_memory_peak_bytes"] - a["cgroup_memory_peak_bytes"],
        "wall_seconds_delta": (
            b["engine_resource"]["engine_wall_seconds"] - a["engine_resource"]["engine_wall_seconds"]
        ),
    }


def load_locked_candidate(directory: Path) -> dict:
    if RECEIPT.stat().st_size > REPORT_LIMIT:
        raise ValueError("Oversized x86 predecessor receipt")
    receipt = json.loads(RECEIPT.read_bytes())
    if (
        receipt["platform"] != "linux/amd64"
        or receipt["native_build_and_a03"]["a03_passed"] is not True
        or receipt["upstream_gapw"]["conclusion"] != "success"
        or receipt["upstream_gapw"]["passed"] != 5
    ):
        raise ValueError("x86 predecessor receipt does not authorize the fixed native candidate")
    source = receipt["quanta_candidate_source"]
    metadata, image_proof = load_candidate(directory, source, architecture="amd64")
    if metadata != receipt["candidate"]:
        raise ValueError("Candidate archive metadata differs from the pinned A03/GAPW receipt")
    for key, value in receipt["image_identity"].items():
        if key not in {"already_loaded_identical_image", "daemon_image_id"} and image_proof.get(key) != value:
            raise ValueError(f"Loaded candidate differs from pinned A03/GAPW image identity: {key}")
    return {
        "predecessor_receipt": str(RECEIPT.relative_to(ROOT)), "predecessor_receipt_sha256": sha256(RECEIPT),
        "source_sha": source, "cp2k_source": receipt["cp2k_source"],
        "binary_sha256": metadata["binary_sha256"], "image_id": image_proof["daemon_image_id"],
        "metadata": metadata, "image_proof": image_proof,
    }


def write_report(path: Path, report: dict) -> None:
    raw = (json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    if len(raw) > REPORT_LIMIT:
        raise ValueError("Resource report exceeded its fixed evidence budget")
    target = path.with_suffix(".tmp")
    target.write_bytes(raw)
    target.replace(path)


def refinement_attempt(case: Case, candidate: dict, scratch: Path, diagnostics: Path,
                       *, ranks: int, swap: int, attempt: int = 1,
                       expected_input: str | None = None, cube: Path | None = None) -> dict:
    available = available_memory_bytes()
    budget = memory_budget(available, len(MEMORY_TIERS_BYTES) - 1)
    free = shutil.disk_usage(scratch).free
    if budget is None or budget < case.minimum_memory_bytes or free < DISK_ADMISSION:
        return {
            "attempt": attempt, "status": "deferred", "requested_mpi_ranks": ranks,
            "available_memory_bytes": available, "safe_grant_bytes": budget, "free_disk_bytes": free,
        }
    record: dict = {}
    run_attempt(case, attempt, budget, available, candidate, scratch, diagnostics, record,
                mpi_ranks=ranks, swap_extra_bytes=swap, expected_input=expected_input, retained_cube=cube,
                distribute_real_space=ranks == 2)
    return record


def run_refinement(candidate: dict, scratch: Path, diagnostics: Path,
                   serial_report: Path, report: dict) -> str:
    from atomistic_a04_runner_swap import bounded_ci_swap
    from compare_atomistic_a04_mpi import compare_attempts, compare_summaries

    if len(os.sched_getaffinity(0)) < 2:
        raise ValueError("This runner does not expose two CPUs for the MPI comparison")
    failed = json.loads((REFINEMENT_RECEIPTS / "resource-42392008763.json").read_bytes())
    failed_mpi = json.loads((REFINEMENT_RECEIPTS / "mpi-resource-42438115255.json").read_bytes())
    historical = json.loads((REFINEMENT_RECEIPTS / "resource-42392583423.json").read_bytes())
    if serial_report.stat().st_size > REPORT_LIMIT or sha256(serial_report) != historical["raw_artifact"]["report_sha256"]:
        raise ValueError("Historical serial report does not match the recorded artifact")
    previous = json.loads(serial_report.read_bytes())
    if any(
        receipt["candidate_source"] != candidate["source_sha"]
        or receipt["binary_sha256"] != candidate["binary_sha256"]
        for receipt in (failed, historical)
    ) or any(previous["candidate"][key] != candidate[key] for key in ("binary_sha256", "image_id")):
        raise ValueError("Historical attempts and the new experiment must use the same image and binary")
    large, middle, small = MPI_CASES
    failed_large = next(row for row in failed["cases"] if row["case"] == large.name)["attempts"][-1]
    prior_mpi = failed_mpi["attempts"][-1]
    if (
        failed_mpi["binary_sha256"] != candidate["binary_sha256"] or failed_mpi["image_id"] != candidate["image_id"]
        or prior_mpi["input_sha256"] != failed_large["input_sha256"]
        or prior_mpi["status"] != "container_oom" or prior_mpi["swap_peak_bytes"] != 16 * GIB
        or prior_mpi["observed_mpi_ranks"] != 2 or not prior_mpi["distributed_real_space_grid_count"]
    ):
        raise ValueError("The larger swap experiment requires the verified two-rank OOM with exhausted swap")
    references = {row["case"]: row["attempts"][-1] for row in previous["cases"]}
    if failed_large["status"] != "container_oom" or any(
        references[case.name]["status"] != "measured" for case in (middle, small)
    ):
        raise ValueError("Unexpected historical A04 evidence")
    report["prior_runs"] = {
        "20a_serial_oom": failed["workflow_run_id"],
        "20a_distributed_oom": failed_mpi["workflow_run_id"],
        "16a_serial_reference": historical["workflow_run_id"],
        "12a_400ry_serial_reference": historical["workflow_run_id"],
    }
    cases = report["cases"]
    large_row = {"case": large.name, "attempts": []}
    cases.append(large_row)
    recovery_ranks = 1
    with bounded_ci_swap(scratch.parent, minimum_free_bytes=DISK_ADMISSION) as swap:
        recovered = refinement_attempt(large, candidate, scratch, diagnostics, ranks=recovery_ranks, swap=swap, attempt=4,
                                       expected_input=failed_large["input_sha256"])
        large_row["attempts"].append(recovered)
        large_row["status"] = recovered["status"]
        if recovered.get("submitted_input_sha256") not in (None, failed_large["input_sha256"]):
            raise ValueError("The one-rank recovery must use the original unmodified deck")
        if large_row["status"] != "measured":
            return large_row["status"]
        report["comparison_layout"] = {
            "mpi_ranks": recovery_ranks, "omp_threads": 1, "swap_allowance_bytes": swap,
            "real_space_distribution_request": "AUTOMATIC",
        }
        comparisons_passed = True
        for case in (middle, small):
            row = {"case": case.name, "attempts": []}
            cases.append(row)
            distributed_cube = scratch / f"{case.name}-mpi.cube"
            reference_cube = scratch / f"{case.name}-serial.cube"
            reference = references[case.name]
            distributed = refinement_attempt(case, candidate, scratch, diagnostics, ranks=recovery_ranks, swap=swap,
                                             expected_input=reference["input_sha256"], cube=distributed_cube)
            row["attempts"].append(distributed)
            row["status"] = distributed["status"]
            if distributed["status"] != "measured":
                comparisons_passed = False
                continue
            try:
                comparison = compare_summaries(reference, distributed)
                row["historical_serial_comparison"] = comparison
                passed = comparison["passes_summary_comparison"]
                if not comparison["same_native_cube_sha256"]:
                    serial = refinement_attempt(case, candidate, scratch, diagnostics, ranks=1, swap=0,
                                                expected_input=distributed["input_sha256"], cube=reference_cube)
                    row["attempts"].append(serial)
                    if serial["status"] != "measured":
                        row["comparison_status"] = "serial_reference_incomplete"
                        comparisons_passed = False
                        continue
                    pointwise = compare_attempts(serial, distributed, reference_cube, distributed_cube)
                    row["pointwise_comparison"] = pointwise
                    row["recreated_serial_comparison"] = compare_summaries(reference, serial)
                    passed &= (
                        pointwise["passes_comparison"]
                        and row["recreated_serial_comparison"]["passes_summary_comparison"]
                    )
                row["comparison_status"] = "passed" if passed else "difference_outside_tolerance"
                comparisons_passed &= passed
            except (KeyError, ValueError) as exc:
                row["comparison_status"] = "invalid_comparison"
                row["comparison_error"] = f"{type(exc).__name__}: {exc}"[:500]
                comparisons_passed = False
            finally:
                for cube in (distributed_cube, reference_cube):
                    cube.unlink(missing_ok=True)
        return "measured" if comparisons_passed else "comparison_incomplete_or_failed"


def accuracy_scalars(reference: dict, candidate: dict, checks: dict, *, energy_force_check: str = "AV03") -> dict:
    left = reference["engine_forces_hartree_per_bohr"]
    right = candidate["engine_forces_hartree_per_bohr"]
    atom_count = reference["density"]["atom_count"]
    if (atom_count not in (1, 2) or candidate["density"]["atom_count"] != atom_count
            or len(left) != atom_count or len(right) != atom_count or any(len(row) != 3 for row in (*left, *right))):
        raise ValueError("Expected ordered Cartesian force rows matching the fixture")
    energy = abs(candidate["engine_energy_hartree"] - reference["engine_energy_hartree"])
    force = max(abs(a - b) for lrow, rrow in zip(left, right) for a, b in zip(lrow, rrow))
    ref_count = reference["density"]["electron_integral"]
    count = candidate["density"]["electron_integral"]
    ref_engine_count = reference["engine_hard_soft_electron_count"]
    engine_count = candidate["engine_hard_soft_electron_count"]
    if not all(math.isfinite(x) for x in (energy, force, ref_count, count, ref_engine_count, engine_count)) or not all(
        math.isfinite(value) for row in (*left, *right) for value in row
    ):
        raise ValueError("Nonfinite scalar comparison")
    return {
        "absolute_energy_difference_hartree": energy,
        "absolute_maximum_force_component_difference_hartree_per_bohr": force,
        "reference_exported_electron_count": ref_count,
        "candidate_exported_electron_count": count,
        "absolute_exported_electron_count_difference": abs(count - ref_count),
        "reference_engine_hard_soft_electron_count": ref_engine_count,
        "candidate_engine_hard_soft_electron_count": engine_count,
        "engine_electron_counts_passed": max(abs(engine_count - 2), abs(ref_engine_count - 2)) <= checks["AV05"]["atol"],
        "energy_passed": energy <= checks[energy_force_check]["energy_atol_hartree"],
        "force_passed": force <= checks[energy_force_check]["force_atol_hartree_per_bohr"],
        "exported_electron_counts_passed": max(abs(count - 2), abs(ref_count - 2)) <= checks["AV06"]["atol"],
    }


def compare_accuracy_pair(reference_case: Case, case: Case, reference: dict, attempt: dict,
                          reference_path: Path, path: Path, checks: dict, l1_atol: float,
                          *, energy_force_check: str = "AV03", maximum_axis_count: int | None = None) -> dict:
    from compare_atomistic_a04_accuracy import compare_density

    if reference_case.system != case.system:
        raise ValueError("Energy and density comparisons require identical fixtures")
    result = accuracy_scalars(reference, attempt, checks, energy_force_check=energy_force_check)
    result.update(
        case=case.name, reference_case=reference_case.name,
        candidate_cell_angstrom=case.cell, candidate_cutoff_ry=case.cutoff,
        candidate_rel_cutoff_ry=case.rel_cutoff,
    )
    limits = {} if maximum_axis_count is None else {"maximum_axis_count": maximum_axis_count}
    density = compare_density(reference, attempt, reference_path, path, reference_case.cell, case.cell, **limits)
    result["spatial_density"] = density
    result["spatial_l1_screen_passed"] = all(
        method["zero_extended_absolute_density_difference_integral_electrons"] <= l1_atol
        for method in (density["primary"], density["sensitivity"]) if method is not None
    )
    result["within_all_endpoint_thresholds"] = all(
        result[key] for key in (
            "energy_passed", "force_passed", "engine_electron_counts_passed",
            "exported_electron_counts_passed", "spatial_l1_screen_passed",
        )
    )
    return result


def run_accuracy(candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    from atomistic_a04_runner_swap import bounded_ci_swap

    previous = json.loads(ACCURACY_REFERENCE.read_bytes())
    plan = json.loads(ACCURACY_PLAN.read_bytes())
    checks = {check["id"]: check for check in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    for case, planned in zip(MPI_CASES, [plan["reference"], *plan["candidates"]], strict=True):
        if (case.cell, case.cutoff, case.rel_cutoff) != (
            planned["cell_angstrom"], planned["cutoff_ry"], planned["rel_cutoff_ry"]
        ):
            raise ValueError("Fixed execution cases differ from the preregistered comparison")
    if any(previous[key] != candidate[key] for key in ("binary_sha256", "image_id")):
        raise ValueError("Accuracy run requires the same CP2K image and binary as the recorded reference")
    prior = {row["case"]: row["attempts"][0] for row in previous["cases"]}
    if any(prior[case.name]["status"] != "measured" for case in MPI_CASES):
        raise ValueError("A completed prior observation is required for every fixed input")
    report["reference_workflow_run_id"] = previous["workflow_run_id"]
    report["comparison_plan_sha256"] = sha256(ACCURACY_PLAN)
    report["thresholds"] = {
        "energy_hartree": checks["AV03"]["energy_atol_hartree"],
        "maximum_force_component_hartree_per_bohr": checks["AV03"]["force_atol_hartree_per_bohr"],
        "engine_hard_soft_count_from_two_electrons": checks["AV05"]["atol"],
        "exported_count_from_two_electrons": checks["AV06"]["atol"],
        "exploratory_spatial_l1_electrons": plan["spatial_l1_atol_electrons"],
    }
    reference_case = MPI_CASES[0]
    reference_path = scratch / "reference.cube"
    report["comparisons"] = []
    with bounded_ci_swap(scratch.parent, minimum_free_bytes=DISK_ADMISSION) as swap:
        reference = refinement_attempt(
            reference_case, candidate, scratch, diagnostics, ranks=1, swap=swap,
            expected_input=prior[reference_case.name]["input_sha256"], cube=reference_path,
        )
        report["cases"].append({"case": reference_case.name, "attempts": [reference]})
        if reference["status"] != "measured":
            return reference["status"]
        for case in MPI_CASES[1:]:
            path = scratch / f"{case.name}.cube"
            attempt = refinement_attempt(
                case, candidate, scratch, diagnostics, ranks=1, swap=0,
                expected_input=prior[case.name]["input_sha256"], cube=path,
            )
            row = {"case": case.name, "attempts": [attempt]}
            report["cases"].append(row)
            if attempt["status"] != "measured":
                continue
            try:
                report["comparisons"].append(compare_accuracy_pair(
                    reference_case, case, reference, attempt, reference_path, path, checks,
                    plan["spatial_l1_atol_electrons"],
                ))
            except (OSError, ValueError, KeyError) as exc:
                row["comparison_error"] = f"{type(exc).__name__}: {exc}"[:500]
            finally:
                path.unlink(missing_ok=True)
    complete = len(report["comparisons"]) == len(MPI_CASES) - 1
    report["verification_scope"]["cross_grid_endpoint_screen"] = "measured" if complete else "incomplete"
    return "measured" if complete else "comparison_incomplete"


def run_one_factor(track: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    plan = json.loads(ONE_FACTOR_PLAN.read_bytes())
    prior = json.loads(ENDPOINT_RECEIPT.read_bytes())
    if (
        sha256(ENDPOINT_RECEIPT) != plan["reference_receipt_sha256"]
        or prior["workflow_conclusion"] != "success"
        or any(prior["candidate"][key] != candidate[key] for key in ("binary_sha256", "image_id"))
    ):
        raise ValueError("One-factor refinement requires the verified prior image and endpoint receipt")
    checks = {check["id"]: check for check in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    l1_atol = plan["spatial_l1_atol_electrons"]
    levels = [tuple(settings) for settings in plan["tracks"][track]]
    pairs = list(zip(levels, levels[1:]))
    if track == "cutoff":
        bridge = [tuple(settings) for settings in plan["operating_bridge"]]
        pairs.insert(0, tuple(bridge))
    settings = list(dict.fromkeys(value for pair in pairs for value in pair))
    expected_inputs = {
        (12, 400, 40): prior["cases"][2]["attempt"]["input_sha256"],
        (16, 800, 80): prior["cases"][1]["attempt"]["input_sha256"],
    }
    report.update(
        track=track, comparison_plan_sha256=sha256(ONE_FACTOR_PLAN),
        comparison_thresholds=prior["thresholds"], comparisons=[],
    )
    if prior["thresholds"] != {
        "energy_hartree": checks["AV03"]["energy_atol_hartree"],
        "maximum_force_component_hartree_per_bohr": checks["AV03"]["force_atol_hartree_per_bohr"],
        "engine_hard_soft_count_from_two_electrons": checks["AV05"]["atol"],
        "exported_count_from_two_electrons": checks["AV06"]["atol"],
        "exploratory_spatial_l1_electrons": l1_atol,
    }:
        raise ValueError("The new and prior comparison thresholds must agree")
    cases = {}
    for key in settings:
        if key == (20, 800, 80):
            continue
        cell, cutoff, relative = key
        case = Case(f"h2-{cell}a-{cutoff}ry-rel{relative}-density-on", cell, cutoff, True, 900,
                    rel_cutoff=relative)
        cube = scratch / f"{case.name}.cube"
        attempt = refinement_attempt(case, candidate, scratch, diagnostics, ranks=1, swap=0,
                                     expected_input=expected_inputs.get(key), cube=cube)
        cases[key] = (case, attempt, cube)
        report["cases"].append({"case": case.name, "settings": key, "attempts": [attempt]})
    for coarse, fine in pairs:
        changed = [i for i, (a, b) in enumerate(zip(coarse, fine, strict=True)) if a != b]
        if len(changed) != 1 or coarse[changed[0]] >= fine[changed[0]]:
            raise ValueError("Every comparison must increase exactly one setting")
        row = {"candidate_settings": coarse, "reference_settings": fine,
               "factor": plan["setting_order"][changed[0]]}
        report["comparisons"].append(row)
        coarse_case, coarse_attempt, coarse_cube = cases[coarse]
        if coarse_attempt["status"] != "measured":
            row["status"] = "case_incomplete"
            continue
        if fine == (20, 800, 80) and coarse == (16, 800, 80):
            row.update(status="measured", reused_workflow_run_id=prior["workflow_run_id"],
                       result=prior["comparisons"][0])
            continue
        fine_case, fine_attempt, fine_cube = cases[fine]
        if fine_attempt["status"] != "measured":
            row["status"] = "case_incomplete"
            continue
        try:
            row["result"] = compare_accuracy_pair(
                fine_case, coarse_case, fine_attempt, coarse_attempt, fine_cube, coarse_cube, checks, l1_atol,
            )
            row["status"] = "measured"
        except (OSError, ValueError, KeyError) as exc:
            row.update(status="comparison_error", error=f"{type(exc).__name__}: {exc}"[:500])
    complete = all(row["status"] == "measured" for row in report["comparisons"])
    report["verification_scope"]["fixed_h2_one_factor_screen"] = "measured" if complete else "incomplete"
    return "measured" if complete else "comparison_incomplete"


def run_fixed_fixture(system: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    boundary = system in BOUNDARY_SYSTEMS
    plan_path = BOUNDARY_PLAN if boundary else FIXTURE_PLAN
    prior_path = BOUNDARY_PREDECESSOR if boundary else FIXTURE_PREDECESSOR
    source = BOUNDARY_PLAN.with_name("boundary-fixtures.json") if boundary else VALIDATION_PLAN.with_name("fixtures.json")
    plan = json.loads(plan_path.read_bytes())
    prior = json.loads(prior_path.read_bytes())
    prior_digest = plan["prior_fixed_fixture_receipt_sha256" if boundary else "prior_h2_refinement_receipt_sha256"]
    if (
        sha256(source) != plan["fixtures_sha256"]
        or sha256(prior_path) != prior_digest
        or prior["workflow_conclusion"] != "success"
        or any(prior["candidate"][k] != candidate[k] for k in ("binary_sha256", "image_id"))
    ):
        raise ValueError("Fixed fixture inputs or the verified image do not match the plan")
    fixture = plan["fixtures"][system]
    checks = {c["id"]: c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    l1 = plan["spatial_l1_atol_electrons"]
    report.update(
        system=system, fixture_id=fixture, comparison_plan_sha256=sha256(plan_path),
        comparison_thresholds={
            "energy_hartree": checks["AV03"]["energy_atol_hartree"],
            "maximum_force_component_hartree_per_bohr": checks["AV03"]["force_atol_hartree_per_bohr"],
            "engine_hard_soft_count_from_two_electrons": checks["AV05"]["atol"],
            "exported_count_from_two_electrons": checks["AV06"]["atol"],
            "exploratory_spatial_l1_electrons": l1,
        },
        comparisons=[],
    )
    if report["comparison_thresholds"] != prior["comparison_thresholds"]:
        raise ValueError("Comparison thresholds must match the previous refinement")
    rows = {}
    labels = ("lightweight", "intermediate", "matched_cutoff_cell_check", "reference")
    for label in labels:
        cell, cutoff, rel = plan[label]
        case = Case(f"{system}-{cell}a-{cutoff}ry-rel{rel}-density-on",
                    cell, cutoff, True, 900, rel_cutoff=rel, system=system)
        cube = scratch / f"{case.name}.cube"
        attempt = refinement_attempt(case, candidate, scratch, diagnostics, ranks=1, swap=0, cube=cube)
        if attempt["status"] == "measured" and attempt["input_metadata"]["source_fixture"] != fixture:
            raise ValueError("Measured case does not match the locked fixture")
        rows[label] = (case, attempt, cube)
        report["cases"].append({"role": label, "case": case.name, "settings": plan[label], "attempts": [attempt]})
    ref_case, reference, ref_cube = rows["reference"]
    for label in labels[:-1]:
        row = {"candidate_role": label, "candidate_settings": plan[label], "reference_settings": plan["reference"]}
        report["comparisons"].append(row)
        case, attempt, cube = rows[label]
        if attempt["status"] != "measured" or reference["status"] != "measured":
            row["status"] = "case_incomplete"
            continue
        try:
            row["result"] = compare_accuracy_pair(ref_case, case, reference, attempt, ref_cube, cube, checks, l1)
            row["status"] = "measured"
        except (OSError, ValueError, KeyError) as exc:
            row.update(status="comparison_error", error=f"{type(exc).__name__}: {exc}"[:500])
    complete = all(row["status"] == "measured" for row in report["comparisons"])
    screen = "h2_boundary_accuracy_screen" if boundary else "fixed_fixture_accuracy_screen"
    report["verification_scope"][screen] = "measured" if complete else "incomplete"
    return "measured" if complete else "comparison_incomplete"


def run_scf_screen(system: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    plan = json.loads(SCF_PLAN.read_bytes())
    profile = json.loads(SCF_PLAN.with_name("profile.json").read_bytes())
    levels = plan["eps_scf"]
    sweep = profile["validation"]["proposal_unexecuted"]["sweeps"]["eps_scf"]
    if levels != sweep or levels != [1e-8, 1e-9, 1e-10]:
        raise ValueError("Unexpected preregistered SCF sweep")
    specs = {row["system"]: row for row in plan["cases"]}
    if len(plan["cases"]) != len(SCF_SYSTEMS) or set(specs) != set(SCF_SYSTEMS):
        raise ValueError("SCF plan must contain all five qualified fixtures exactly once")
    spec = specs[system]
    cell, cutoff, relative = spec["settings"]
    cap = spec["cap_gib"] * GIB
    checks = {c["id"]: c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    tolerances = plan["comparison"]
    if (
        tolerances["energy_hartree"] != checks["AV03"]["energy_atol_hartree"]
        or tolerances["max_force_component_hartree_per_bohr"] != checks["AV03"]["force_atol_hartree_per_bohr"]
        or tolerances["engine_count_from_two_electrons"] != checks["AV05"]["atol"]
        or tolerances["cube_count_from_two_electrons"] != checks["AV06"]["atol"]
        or tolerances["same_grid_cube_l1_electrons"] != json.loads(FIXTURE_PLAN.read_bytes())["spatial_l1_atol_electrons"]
        or plan["admission"]["host_reserve_gib"] * GIB != MEMORY_RESERVE_BYTES
        or plan["admission"]["disk_free_gib"] * GIB != DISK_ADMISSION
    ):
        raise ValueError("SCF plan differs from the predeclared numerical or resource limits")
    report.update(
        system=system, fixture_id=spec["fixture"], settings=spec["settings"], eps_scf_levels=levels,
        comparison_plan_sha256=sha256(SCF_PLAN), thresholds=tolerances, comparisons=[],
        baseline_input_sha256=spec["baseline_input_sha256"],
    )
    report["resource_policy"].update(normal_memory_cap_bytes=cap, retry_memory_cap_bytes=cap)
    options = dict(system=system, basis="cc-pVDZ", project=PROJECT, cell_angstrom=cell,
                   cutoff_ry=cutoff, rel_cutoff_ry=relative, density=True)
    baseline = generate_input(**options, eps_scf=levels[0])
    if hashlib.sha256(baseline.encode("ascii")).hexdigest() != spec["baseline_input_sha256"]:
        raise ValueError("SCF baseline deck does not match the qualified input")
    expected_hashes = {}
    for level in levels:
        deck = generate_input(**options, eps_scf=level)
        old_line = f"      EPS_SCF {levels[0]:.12E}\n"
        new_line = f"      EPS_SCF {level:.12E}\n"
        if baseline.count(old_line) != 1 or deck != baseline.replace(old_line, new_line, 1):
            raise ValueError("SCF refinement may change only the EPS_SCF line")
        expected_hashes[level] = hashlib.sha256(deck.encode("ascii")).hexdigest()

    rows = {}
    for level in levels:
        case = Case(f"{system}-scf-{level:.0e}", cell, cutoff, True, spec["deadline_seconds"],
                    rel_cutoff=relative, system=system, eps_scf=level)
        cube = scratch / f"{case.name}.cube"
        attempt: dict = {}
        available = available_memory_bytes()
        free = shutil.disk_usage(scratch).free
        if available < cap + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
            attempt.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
        else:
            run_attempt(case, 1, cap, available, candidate, scratch, diagnostics, attempt,
                        expected_input=expected_hashes[level], retained_cube=cube)
        report["cases"].append({"case": case.name, "eps_scf": level, "attempt": attempt})
        if attempt["status"] != "measured":
            return "measurement_incomplete"
        if (
            attempt["input_metadata"]["source_fixture"] != spec["fixture"]
            or attempt["submitted_input_sha256"] != expected_hashes[level]
            or not 1 <= attempt.get("engine_scf_iterations", 0) <= 80
        ):
            raise ValueError("The completed SCF measurement lacks matching input or convergence evidence")
        rows[level] = (case, attempt, cube)

    reference_case, reference, reference_cube = rows[levels[-1]]
    for level in levels[:-1]:
        case, attempt, cube = rows[level]
        left, right = reference["density"], attempt["density"]
        if any(left[key] != right[key] for key in ("grid_counts", "origin_bohr_rounded", "grid_axes_bohr_rounded", "atoms_bohr_rounded")):
            raise ValueError("The SCF sweep requires the same native CUBE lattice and atom order")
        result = compare_accuracy_pair(
            reference_case, case, reference, attempt, reference_cube, cube, checks,
            tolerances["same_grid_cube_l1_electrons"],
        )
        if result["spatial_density"]["method"] != "native_aligned_crop":
            raise ValueError("The SCF sweep must compare native CUBE samples directly")
        report["comparisons"].append({"eps_scf": level, "reference_eps_scf": levels[-1], "result": result})
    looser, finer = (row["result"]["within_all_endpoint_thresholds"] for row in report["comparisons"])
    report["scf_screen"] = {
        "two_finest_passed": finer,
        "baseline_vs_finest_passed": looser,
        "candidate_eps_scf": (levels[0] if looser else levels[1]) if finer else None,
    }
    report["verification_scope"]["fixed_fixture_scf_screen"] = "measured"
    return "measured"


def check_grid_attempt(attempt: dict, case: Case, spec: dict, expected: str, cube: Path, cap: int,
                       checks: dict, *, require_electron_counts: bool = True, expected_swap_bytes: int = 0) -> None:
    if attempt["status"] != "measured":
        raise ValueError("Missing completed atomic-grid attempt")
    meta = attempt["input_metadata"]
    numerics = meta["numerics"]
    if (
        meta["source_fixture"] != spec["fixture"]
        or meta["basis"] != case.basis
        or (numerics["radial_grid"], numerics["lebedev_grid"]) != (case.radial_grid, case.lebedev_grid)
        or numerics["eps_scf"] != case.eps_scf
        or attempt["input_sha256"] != expected
        or attempt["submitted_input_sha256"] != expected
        or attempt["granted_memory_bytes"] != cap
        or attempt["granted_swap_extra_bytes"] != expected_swap_bytes
        or attempt["observed_mpi_ranks"] != 1
        or attempt["observed_omp_threads"] != 1
        or not 1 <= attempt.get("engine_scf_iterations", 0) <= 80
        or attempt.get("container_removed") is not True
        or not 0 < attempt["cgroup_memory_peak_bytes"] <= cap
        or any(attempt["cgroup_memory_events_max"].get(k, 0) for k in ("oom", "oom_kill", "oom_group_kill"))
    ):
        raise ValueError("Input identity, explicit SCF convergence or resource evidence differs from the plan")
    density = attempt["density"]
    if cube.is_symlink() or not cube.is_file() or not 0 < density["bytes"] <= GIB or cube.stat().st_size != density["bytes"]:
        raise ValueError("Invalid retained CUBE path or byte size")
    if sha256(cube) != density["sha256"]:
        raise ValueError("Retained CUBE SHA-256 differs from measured evidence")
    if not require_electron_counts:
        return
    for value, gate in ((attempt["engine_hard_soft_electron_count"], "AV05"), (density["electron_integral"], "AV06")):
        if not math.isfinite(value) or abs(value - 2) > checks[gate]["atol"]:
            raise ValueError(f"{gate} electron count exceeds the predeclared tolerance")


def run_atomic_grid(system: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict,
                    *, pilot: bool, pilot_dir: Path | None) -> str:
    plan = json.loads(GRID_PLAN.read_bytes())
    locked = json.loads(GRID_INPUTS.read_bytes())
    stage = next(row for row in plan["stages"] if row["id"] == "G1")
    specs = {row["system"]: row for row in plan["fixtures"]}
    pilots = set(plan["resource_admission"]["first_pilots"])
    pairs = [tuple(x) for x in stage["grid_pairs_radial_then_lebedev"]]
    baseline, reference = (100, 110), tuple(stage["common_reference"])
    if (
        len(specs) != 5 or set(specs) != set(SCF_SYSTEMS)
        or set(pairs) != {(100, 110), (100, 194), (150, 194), (200, 194), (200, 110), (200, 146)}
        or len(pairs) != 6 or reference != (200, 194) or pilots != {"he", "h2-short"}
        or locked["development_plan_sha256"] != sha256(GRID_PLAN)
        or locked["baseline_scf_receipt_sha256"] != sha256(ROOT / plan["start_from"]["scf_receipt"])
        or locked["basis"] != "cc-pVDZ"
        or locked["cp2k_source"] != candidate["cp2k_source"]
        or locked["binary_sha256"] != candidate["binary_sha256"]
    ):
        raise ValueError("Atomic-grid matrix or candidate differs from the fixed plan")
    if (pilot and system not in pilots) or (system in pilots) != (pilot_dir is not None):
        raise ValueError("Only the two registered pilots use the retained pilot directory")
    spec = specs[system]
    caps = plan["resource_admission"]["pilot_caps"]["he" if system == "he" else "h2"]
    cap, deadline = caps["gib"] * GIB, caps["wall_seconds"]
    policy = plan["resource_admission"]
    if policy["retain_host_available_gib"] * GIB != MEMORY_RESERVE_BYTES or policy["admission_disk_gib"] * GIB != DISK_ADMISSION:
        raise ValueError("Atomic-grid resource admission differs from the fixed plan")
    checks = {c["id"]: c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    limit = plan["thresholds"]["separate_field_shape_screen"]["absolute_density_l1_electrons"]
    if limit != json.loads(FIXTURE_PLAN.read_bytes())["spatial_l1_atol_electrons"]:
        raise ValueError("Atomic-grid field limit differs from the predeclared threshold")
    report.update(system=system, fixture_id=spec["fixture"], comparison_plan_sha256=sha256(GRID_PLAN),
                  input_manifest_sha256=sha256(GRID_INPUTS), comparisons=[])
    report["resource_policy"].update(normal_memory_cap_bytes=cap, retry_memory_cap_bytes=cap)
    cell, cutoff, relative = spec["baseline_cell_cutoff_relative"]
    by_pair = {tuple(x["grid"]): x["input_sha256"] for x in locked["fixtures"][system]}
    if len(by_pair) != len(pairs) or set(by_pair) != set(pairs) or by_pair[baseline] != spec["baseline_deck_sha256"]:
        raise ValueError("Atomic-grid input manifest differs from the historical baseline or fixed matrix")

    pilot_rows = {}
    if pilot_dir is not None:
        if pilot:
            pilot_dir.mkdir(exist_ok=False)
        else:
            pilot_report = pilot_dir / "report.json"
            if pilot_report.is_symlink() or not pilot_report.is_file() or pilot_report.stat().st_size > REPORT_LIMIT:
                raise ValueError("Missing bounded pilot report")
            prior = json.loads(pilot_report.read_bytes())
            if (
                prior["status"] != "measured" or prior["scope"] != "isolated_native_x86_A04_atomic_grid_pilot"
                or prior["system"] != system or prior["quanta_source"] != report["quanta_source"]
                or prior["workflow_run_id"] != report["workflow_run_id"]
                or prior["input_manifest_sha256"] != report["input_manifest_sha256"]
                or prior["candidate"]["binary_sha256"] != candidate["binary_sha256"]
                or prior["candidate"]["image_id"] != candidate["image_id"]
            ):
                raise ValueError("Pilot report does not match this workflow, candidate or matrix")
            pilot_rows = {tuple(x["grid"]): x["attempt"] for x in prior["cases"]}
            if set(pilot_rows) != {baseline, reference} or len(prior["cases"]) != 2:
                raise ValueError("Expected exactly the baseline and fine pilot cases")
            report["reused_pilot_report_sha256"] = sha256(pilot_report)

    order = [reference, baseline]
    if not pilot:
        order += [pair for pair in pairs if pair not in order]
    rows = {}
    for radial, lebedev in order:
        pair = (radial, lebedev)
        case = Case(f"{system}-r{radial}-l{lebedev}", cell, cutoff, True, deadline,
                    rel_cutoff=relative, system=system, radial_grid=radial, lebedev_grid=lebedev)
        reused = pair in pilot_rows
        cube = (pilot_dir if pilot or reused else scratch) / f"{case.name}.cube"
        attempt = pilot_rows.get(pair, {})
        row = {"grid": list(pair), "case": case.name, "reused_pilot": reused, "attempt": attempt}
        report["cases"].append(row)
        if not reused:
            available = available_memory_bytes()
            free = shutil.disk_usage(scratch).free
            if available < cap + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
                attempt.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
                return "measurement_incomplete"
            run_attempt(case, 1, cap, available, candidate, scratch, diagnostics, attempt,
                        expected_input=by_pair[pair], retained_cube=cube)
        if attempt["status"] != "measured":
            return "measurement_incomplete"
        check_grid_attempt(attempt, case, spec, by_pair[pair], cube, cap, checks)
        rows[pair] = (case, attempt, cube)
    if pilot:
        return "measured"

    ref_case, ref_attempt, ref_cube = rows[reference]
    for pair in pairs:
        if pair == reference:
            continue
        case, attempt, cube = rows[pair]
        keys = ("grid_counts", "origin_bohr_rounded", "grid_axes_bohr_rounded", "atoms_bohr_rounded")
        if any(ref_attempt["density"][k] != attempt["density"][k] for k in keys):
            raise ValueError("Atomic-grid screen requires identical native CUBE lattice and geometry")
        result = compare_accuracy_pair(ref_case, case, ref_attempt, attempt, ref_cube, cube, checks, limit)
        if result["spatial_density"]["method"] != "native_aligned_crop":
            raise ValueError("Atomic-grid comparison must use the exact native lattice")
        required = pair in {(150, 194), (200, 146)}
        report["comparisons"].append({"grid": list(pair), "reference_grid": list(reference),
                                      "required_finest_pair": required, "result": result})
    passed = all(x["result"]["within_all_endpoint_thresholds"] for x in report["comparisons"] if x["required_finest_pair"])
    report["verification_scope"]["fixed_fixture_atomic_grid_screen"] = "measured"
    report["finest_pairs_passed"] = passed
    return "measured"


def run_basis_ladder(system: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    from atomistic_a04_basis_output import MAX_PRINTED_CONDITION_NUMBER, MIN_PRINTED_EIGENVALUE

    plan = json.loads(GRID_PLAN.read_bytes())
    locked = json.loads(BASIS_INPUTS.read_bytes())
    stage = next(row for row in plan["stages"] if row["id"] == "G2")
    specs = {row["system"]: row for row in plan["fixtures"]}
    spec = specs[system]
    gate_path = ROOT / locked["prerequisite_g1_receipt"]
    gate = json.loads(gate_path.read_bytes())
    if (
        locked["development_plan_sha256"] != sha256(GRID_PLAN)
        or locked["g1_receipt_sha256"] != sha256(gate_path)
        or gate["status"] != "passed_fixed_fixture_atomic_grid_screen"
        or gate["totals"]["finest_pairs_passed"] != 10
        or locked["cp2k_source"] != candidate["cp2k_source"]
        or locked["binary_sha256"] != candidate["binary_sha256"]
        or locked["printed_conditioning_guard"] != [MIN_PRINTED_EIGENVALUE, MAX_PRINTED_CONDITION_NUMBER]
        or stage["basis_levels"] != ["cc-pVDZ", "cc-pVTZ", "cc-pVQZ"]
        or stage["grid_pair"] != [200, 194]
    ):
        raise ValueError("Basis execution requires the exact passed G1 evidence and preregistered reference")
    limits = plan["resource_admission"]["pilot_caps"]["he" if system == "he" else "h2"]
    cap, deadline = limits["gib"] * GIB, limits["wall_seconds"]
    checks = {c["id"]: c for c in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    limit = plan["thresholds"]["separate_field_shape_screen"]["absolute_density_l1_electrons"]
    if checks["AV04"] != locked["av04"] or limit != locked["spatial_l1_atol_electrons"]:
        raise ValueError("Basis criteria differ from the fixed plan")
    report.update(system=system, fixture_id=spec["fixture"], comparison_plan_sha256=sha256(GRID_PLAN),
                  input_manifest_sha256=sha256(BASIS_INPUTS), comparisons=[])
    report["resource_policy"].update(normal_memory_cap_bytes=cap, retry_memory_cap_bytes=cap)
    cell, cutoff, relative = spec["baseline_cell_cutoff_relative"]
    rows = {}
    for basis in reversed(stage["basis_levels"]):
        case = Case(f"{system}-{basis}-r200-l194", cell, cutoff, True, deadline, rel_cutoff=relative,
                    system=system, radial_grid=200, lebedev_grid=194, basis=basis, overlap_condition=True)
        expected = locked["fixtures"][system][basis]
        cube = scratch / f"{case.name}.cube"
        attempt: dict = {}
        row = {"grid": [200, 194], "basis": basis, "case": case.name, "reused_pilot": False, "attempt": attempt}
        report["cases"].append(row)
        available = available_memory_bytes()
        free = shutil.disk_usage(scratch).free
        if available < cap + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
            attempt.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
            return "measurement_incomplete"
        run_attempt(case, 1, cap, available, candidate, scratch, diagnostics, attempt,
                    expected_input=expected, retained_cube=cube)
        if attempt["status"] != "measured":
            return "measurement_incomplete"
        check_grid_attempt(attempt, case, spec, expected, cube, cap, checks)
        rows[basis] = (case, attempt, cube)

    ref_case, ref_attempt, ref_cube = rows[stage["reference"]]
    for basis in stage["basis_levels"][:-1]:
        case, attempt, cube = rows[basis]
        keys = ("grid_counts", "origin_bohr_rounded", "grid_axes_bohr_rounded", "atoms_bohr_rounded")
        if any(ref_attempt["density"][k] != attempt["density"][k] for k in keys):
            raise ValueError("Basis screen requires the same native lattice and ordered geometry")
        result = compare_accuracy_pair(ref_case, case, ref_attempt, attempt, ref_cube, cube, checks, limit,
                                       energy_force_check="AV04")
        if result["spatial_density"]["method"] != "native_aligned_crop":
            raise ValueError("Basis comparison must use the exact native lattice")
        report["comparisons"].append({"grid": [200, 194], "reference_grid": [200, 194],
                                      "basis": basis, "reference_basis": stage["reference"],
                                      "required_finest_pair": basis == stage["target"], "result": result})
    passing_basis = all(x[1]["basis_conditioning"]["conditioning_passed"] for x in rows.values())
    finest_passed = next(x["result"]["within_all_endpoint_thresholds"] for x in report["comparisons"]
                         if x["required_finest_pair"])
    report["finest_pairs_passed"] = finest_passed and passing_basis
    report["verification_scope"]["fixed_fixture_basis_screen"] = "measured"
    return "measured" if report["finest_pairs_passed"] else "criterion_not_met"


def run_qz_sensitivity(track: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    from compare_atomistic_qz_sensitivity import compare_qz_pair

    locked = json.loads(QZ_INPUTS.read_bytes())
    receipt = json.loads(QZ_G2_RECEIPT.read_bytes())
    checks = {item["id"]: item for item in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    if (
        locked["g2_receipt_sha256"] != sha256(QZ_G2_RECEIPT)
        or receipt["status"] != "no_go_fixed_fixture_basis_pilots"
        or any(locked[key] != candidate[key] or locked[key] != receipt[key]
               for key in ("cp2k_source", "binary_sha256"))
        or any(locked["checks"][key] != checks[key] for key in ("AV03", "AV05", "AV06"))
    ):
        raise ValueError("QZ sensitivity requires its locked G2 evidence, candidate and comparison criteria")

    system = locked["tracks"][track]["system"]
    spec = locked["fixtures"][system]
    prior = next(row for row in receipt["pilots"] if row["system"] == system)
    prior_qz = next(row for row in prior["cases"] if row["basis"] == "cc-pVQZ")
    cell, cutoff, relative = spec["baseline_cell_cutoff_relative"]
    base = Case(f"{system}-qz-anchor", cell, cutoff, True, locked["wall_seconds"], rel_cutoff=relative,
                system=system, radial_grid=200, lebedev_grid=194, basis="cc-pVQZ", overlap_condition=True)
    if spec["anchor"]["input_sha256"] != prior_qz["input_sha256"] or not prior_qz["conditioning"]["conditioning_passed"]:
        raise ValueError("QZ anchor does not match the conditioned G2 input")
    report.update(track=track, system=system, fixture_id=spec["fixture"], comparisons=[],
                  input_manifest_sha256=sha256(QZ_INPUTS), prior_qz_cube_sha256=prior_qz["cube_sha256"])
    report["resource_policy"].update(normal_memory_cap_bytes="per case, locked", retry_memory_cap_bytes=None)
    fields = {"scf": "eps_scf", "radial": "radial_grid", "angular": "lebedev_grid",
              "cutoff": "cutoff", "relative": "rel_cutoff", "cell": "cell"}
    incomplete = False
    conditioning_passed = True
    anchor = None
    for axis in ("anchor", *locked["tracks"][track]["axes"]):
        row_spec = spec[axis]
        case = base if axis == "anchor" else replace(base, name=f"{system}-qz-{axis}",
                                                      **{fields[axis]: row_spec["value"]})
        cap, expected = row_spec["cap_gib"] * GIB, row_spec["input_sha256"]
        if not 0 < cap <= MEMORY_TIERS_BYTES[-1]:
            raise ValueError("QZ cap exceeds the fixed development runner envelope")
        cube = scratch / f"{case.name}.cube"
        attempt: dict = {}
        report["cases"].append({"axis": axis, "case": case.name, "attempt": attempt})
        available = available_memory_bytes()
        free = shutil.disk_usage(scratch).free
        if available < cap + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
            attempt.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
        else:
            run_attempt(case, 1, cap, available, candidate, scratch, diagnostics, attempt,
                        expected_input=expected, retained_cube=cube)
        if attempt["status"] != "measured":
            if axis == "anchor":
                return "measurement_incomplete"
            incomplete = True
            continue
        check_grid_attempt(attempt, case, spec, expected, cube, cap, checks, require_electron_counts=False)
        conditioning_passed &= attempt["basis_conditioning"]["conditioning_passed"]
        if axis == "anchor":
            if attempt["density"]["grid_counts"] != prior_qz["cube_grid"]:
                raise ValueError("QZ anchor native grid counts differ from G2")
            report["anchor_cube_matches_g2"] = attempt["density"]["sha256"] == prior_qz["cube_sha256"]
            anchor = attempt, cube
            continue
        base_attempt, base_cube = anchor
        result = compare_qz_pair(case, base, attempt, base_attempt, cube, base_cube, checks,
                                 locked["density_l1_atol_electrons"], axis=axis,
                                 shell_width_angstrom=locked["shell_width_angstrom"],
                                 shell_atol=locked["shell_atol_electrons"],
                                 omitted_atol=locked["omitted_atol_electrons"],
                                 allow_cell_interpolation=locked["allow_cell_interpolation"])
        report["comparisons"].append({"axis": axis, "result": result})
        cube.unlink()
    report["verification_scope"]["fixed_fixture_qz_sensitivity"] = "partial" if incomplete else "measured"
    if incomplete:
        return "measurement_incomplete"
    passed = conditioning_passed and all(row["result"]["within_all_endpoint_thresholds"]
                                        for row in report["comparisons"])
    return "measured" if passed else "criterion_not_met"


def run_qz_cutoff(system: str, candidate: dict, scratch: Path, diagnostics: Path, report: dict) -> str:
    from compare_atomistic_qz_sensitivity import compare_qz_pair
    from diagnose_atomistic_cutoff_density import diagnose_cutoff_density

    locked = json.loads(QZ_CUTOFF_INPUTS.read_bytes())
    prior = json.loads(QZ_SENSITIVITY_RECEIPT.read_bytes())
    checks = {item["id"]: item for item in json.loads(VALIDATION_PLAN.read_bytes())["checks"]}
    if (
        locked["prior_receipt_sha256"] != sha256(QZ_SENSITIVITY_RECEIPT)
        or prior["status"] != "no_go_fixed_fixture_qz_cutoff_density"
        or any(locked[key] != candidate[key] or locked[key] != prior[key]
               for key in ("cp2k_source", "binary_sha256"))
        or any(locked["checks"][key] != checks[key] or locked["checks"][key] != prior["checks"][key]
               for key in ("AV03", "AV05", "AV06"))
        or locked["density_l1_atol_electrons"] != prior["density_l1_atol_electrons"]
    ):
        raise ValueError("QZ CUTOFF refinement requires the locked prior evidence and unchanged criteria")

    spec = locked["fixtures"][system]
    previous = next(row for row in prior["tracks"] if row["track"] == spec["prior_track"])
    prior_cases = {row["axis"]: row for row in previous["cases"]}
    levels = spec["levels"]
    if previous["system"] != system or [row["prior_axis"] for row in levels] != ["anchor", "cutoff", None]:
        raise ValueError("CUTOFF levels do not match the preregistered prior pair and extension")
    report.update(system=system, track=system, fixture_id=spec["fixture"], comparisons=[],
                  input_manifest_sha256=sha256(QZ_CUTOFF_INPUTS))
    report["resource_policy"].update(normal_memory_cap_bytes="per case, locked", retry_memory_cap_bytes=None)
    conditioning_passed = True
    last = None
    for level in levels:
        cutoff = level["cutoff_ry"]
        case = Case(f"{system}-qz-{cutoff}ry", 12, cutoff, True, locked["wall_seconds"],
                    rel_cutoff=spec["rel_cutoff_ry"], system=system, radial_grid=200,
                    lebedev_grid=194, basis="cc-pVQZ", overlap_condition=True)
        cap, expected = level["cap_gib"] * GIB, level["input_sha256"]
        if not 0 < cap <= MEMORY_TIERS_BYTES[-1]:
            raise ValueError("CUTOFF cap exceeds the fixed runner envelope")
        historical = prior_cases[level["prior_axis"]] if level["prior_axis"] is not None else None
        if historical is not None and historical["input_sha256"] != expected:
            raise ValueError("Prior CUTOFF input does not match the historical deck")
        cube = scratch / f"{case.name}.cube"
        attempt: dict = {}
        report["cases"].append({"axis": cutoff, "case": case.name, "attempt": attempt})
        available = available_memory_bytes()
        free = shutil.disk_usage(scratch).free
        if available < cap + MEMORY_RESERVE_BYTES or free < DISK_ADMISSION:
            attempt.update(status="deferred_headroom", available_memory_bytes=available, free_disk_bytes=free)
            return "measurement_incomplete"
        run_attempt(case, 1, cap, available, candidate, scratch, diagnostics, attempt,
                    expected_input=expected, retained_cube=cube)
        if attempt["status"] != "measured":
            return "measurement_incomplete"
        check_grid_attempt(attempt, case, spec, expected, cube, cap, checks, require_electron_counts=False)
        conditioning_passed &= attempt["basis_conditioning"]["conditioning_passed"]
        if historical is not None:
            attempt["historical_cube_sha256_match"] = attempt["density"]["sha256"] == historical["cube"]["sha256"]
        if last is not None:
            low_case, low_attempt, low_cube = last
            result = compare_qz_pair(case, low_case, attempt, low_attempt, cube, low_cube, checks,
                                     locked["density_l1_atol_electrons"], axis="cutoff")
            row = {"low_cutoff_ry": low_case.cutoff, "high_cutoff_ry": cutoff,
                   "required": historical is None, "result": result}
            report["comparisons"].append(row)
            row["resampling_diagnostic"] = diagnose_cutoff_density(attempt, low_attempt, cube, low_cube, case.cell)
            low_cube.unlink()
        last = case, attempt, cube
    report["verification_scope"]["fixed_fixture_qz_cutoff_refinement"] = "measured"
    return "measured" if conditioning_passed and report["comparisons"][-1]["result"]["within_all_endpoint_thresholds"] else "criterion_not_met"


def summarize_qz_sensitivity(report: dict, output: Path) -> None:
    summary = {key: report[key] for key in (
        "scope", "track", "system", "status", "input_manifest_sha256", "anchor_cube_matches_g2", "error",
    ) if key in report}
    summary["report_sha256"] = sha256(output / "report.json")
    summary["cases"] = [
        {
            "axis": row["axis"], **{key: row["attempt"].get(key) for key in (
                "status", "error", "input_sha256", "granted_memory_bytes", "available_memory_at_admission_bytes",
                "granted_swap_extra_bytes", "cgroup_memory_peak_bytes", "cgroup_memory_events_max",
                "historical_cube_sha256_match", "engine_scf_iterations", "engine_energy_hartree", "engine_forces_hartree_per_bohr",
                "engine_hard_soft_electron_count", "basis_conditioning",
            )},
            "engine_seconds": row["attempt"].get("engine_resource", {}).get("engine_wall_seconds"),
            "density": {key: row["attempt"].get("density", {}).get(key)
                        for key in ("sha256", "grid_counts", "electron_integral")},
        }
        for row in report["cases"]
    ]
    summary["comparisons"] = report["comparisons"]
    print("QUANTA_QZ_RESULT " + json.dumps(summary, allow_nan=False, separators=(",", ":")))


def summarize_atomic_grid(report: dict, output: Path) -> None:
    summary = {key: report[key] for key in (
        "system", "scope", "status", "comparison_plan_sha256", "input_manifest_sha256",
        "finest_pairs_passed", "reused_pilot_report_sha256", "error",
    ) if key in report}
    summary["report_sha256"] = sha256(output / "report.json")
    summary["cases"] = [
        {
            "grid": row["grid"], "reused_pilot": row["reused_pilot"], "status": row["attempt"].get("status", "controller_error"),
            "error": row["attempt"].get("error"), "input_sha256": row["attempt"].get("input_sha256"),
            "iterations": row["attempt"].get("engine_scf_iterations"),
            "engine_seconds": row["attempt"].get("engine_resource", {}).get("engine_wall_seconds"),
            "peak_bytes": row["attempt"].get("cgroup_memory_peak_bytes"),
            "engine_count": row["attempt"].get("engine_hard_soft_electron_count"),
            "cube_count": row["attempt"].get("density", {}).get("electron_integral"),
            "cube_sha256": row["attempt"].get("density", {}).get("sha256"),
            "cube_grid": row["attempt"].get("density", {}).get("grid_counts"),
            **({"basis": row["basis"], "conditioning": row["attempt"].get("basis_conditioning"),
                "diagnostic_excerpt": row["attempt"].get("basis_diagnostic_excerpt")} if "basis" in row else {}),
        }
        for row in report["cases"]
    ]
    summary["comparisons"] = [
        {
            "grid": row["grid"], "reference_grid": row["reference_grid"], "required": row["required_finest_pair"],
            **({"basis": row["basis"], "reference_basis": row["reference_basis"]} if "basis" in row else {}),
            "passed": row["result"]["within_all_endpoint_thresholds"],
            "energy_delta_hartree": row["result"]["absolute_energy_difference_hartree"],
            "force_delta_hartree_per_bohr": row["result"]["absolute_maximum_force_component_difference_hartree_per_bohr"],
            "density_l1_electrons": row["result"]["spatial_density"]["primary"][
                "zero_extended_absolute_density_difference_integral_electrons"
            ],
        }
        for row in report.get("comparisons", [])
    ]
    print("QUANTA_ATOMIC_GRID_RESULT " + json.dumps(summary, allow_nan=False, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--mpi-refinement-serial-report", type=Path)
    mode.add_argument("--cross-grid-accuracy", action="store_true")
    mode.add_argument("--one-factor", choices=ONE_FACTOR_AXES)
    mode.add_argument("--fixture-accuracy", choices=FIXTURE_SYSTEMS)
    mode.add_argument("--scf-refinement", choices=SCF_SYSTEMS)
    mode.add_argument("--grid-pilot", choices=("h2-short", "he"))
    mode.add_argument("--atomic-grid", choices=SCF_SYSTEMS)
    mode.add_argument("--basis-refinement", choices=SCF_SYSTEMS)
    mode.add_argument("--qz-sensitivity", choices=QZ_TRACKS)
    mode.add_argument("--qz-cutoff", choices=("h2-short", "he"))
    parser.add_argument("--grid-pilot-dir", type=Path)
    args = parser.parse_args()
    if args.grid_pilot_dir is not None and not (args.grid_pilot or args.atomic_grid):
        parser.error("--grid-pilot-dir requires an atomic-grid mode")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    diagnostics = output / "diagnostics"
    diagnostics.mkdir()
    report: dict = {
        "schema_version": 1, "scope": "isolated_native_x86_A04_resource_measurement",
        "status": "controller_error", "cases": [],
        "known_unadmitted_cases": {
            "h2-20a-800ry-density-on": {
                "reason": "Measured OOM at both 10 GiB and 12 GiB; needs a separately qualified envelope",
                "receipt": "docs/verification/atomistic-a04/resource-42392008763.json",
            },
        },
        "quanta_source": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "resource_policy": {
            "case_concurrency": 1, "cpus": 1, "omp_threads": 1, "swap_extra_bytes": 0,
            "normal_memory_cap_bytes": MEMORY_TIERS_BYTES[0],
            "retry_memory_cap_bytes": MEMORY_TIERS_BYTES[-1],
            "retry_maximum_increase_bytes": 2 * GIB,
            "admission_memory_reserve_bytes": MEMORY_RESERVE_BYTES,
            "work_logical_and_allocated_bytes_sampled_limit": WORK_LIMIT,
            "work_filesystem": "disk-backed; sampled aggregate, hard 1 GiB per-file rlimit",
            "work_sample_interval_seconds": HEARTBEAT, "per_file_rlimit_fsize_bytes": GIB,
            "tmpfs_limit_bytes": TMPFS_LIMIT, "admission_free_disk_bytes": DISK_ADMISSION,
            "guard_free_disk_bytes": DISK_GUARD, "guard_available_memory_bytes": MEMORY_GUARD,
            "oom_retry": "one fresh attempt per case, verified container OOM and strictly larger safe grant only",
            "raw_cube": "streamed, hashed and measured as written; temporary disk scratch discarded",
            "engine_rss": "Linux wait4 ru_maxrss, KiB, distinct from cgroup memory",
        },
        "verification_scope": {
            "production_oci_measured": False, "public_execution_support": False, "runtime_contract_frozen": False,
            "AV01_adapter": "not_executed", "AV03_AV04_convergence": "not_executed",
            "AV05_AV06_density_acceptance": "not_executed", "density_spatial_convergence": "not_tested",
            "physical_validation": "unvalidated",
        },
    }
    if args.qz_cutoff or args.qz_sensitivity:
        qz_scope = "cutoff_refinement" if args.qz_cutoff else "sensitivity"
        report["scope"] = f"isolated_native_x86_A04_fixed_fixture_qz_{qz_scope}"
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update(
            retry_maximum_increase_bytes=0, oom_retry="none; fixed per-case caps",
            raw_cube="signed original samples compared on runner disk and removed",
        )
        report["verification_scope"][f"fixed_fixture_qz_{qz_scope}"] = "incomplete"
    elif args.basis_refinement:
        report["scope"] = "isolated_native_x86_A04_fixed_fixture_basis_refinement"
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update(
            retry_maximum_increase_bytes=0, oom_retry="none; fixed sequential one-rank cases",
            raw_cube="original same-lattice samples compared on runner disk then removed",
        )
        report["verification_scope"]["fixed_fixture_basis_screen"] = "incomplete"
    elif args.grid_pilot or args.atomic_grid:
        report["scope"] = "isolated_native_x86_A04_atomic_grid_" + ("pilot" if args.grid_pilot else "screen")
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update(
            retry_maximum_increase_bytes=0, oom_retry="none; fixed sequential one-rank cases",
            raw_cube="compared on runner disk; exact pilot CUBEs transferred in a short-lived artifact",
        )
        report["verification_scope"]["fixed_fixture_atomic_grid_screen"] = "incomplete"
    elif args.scf_refinement:
        report["scope"] = "isolated_native_x86_A04_fixed_fixture_scf_refinement"
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update(
            retry_maximum_increase_bytes=0, oom_retry="none; fixed sequential one-rank cases",
            raw_cube="original samples compared on runner disk and removed with scratch",
        )
        report["verification_scope"]["fixed_fixture_scf_screen"] = "incomplete"
    elif args.one_factor or args.fixture_accuracy:
        screen = (
            "h2_boundary_accuracy" if args.fixture_accuracy in BOUNDARY_SYSTEMS
            else "fixed_fixture_accuracy" if args.fixture_accuracy else "fixed_h2_one_factor"
        )
        report["scope"] = "isolated_native_x86_A04_" + (
            screen if args.fixture_accuracy else "one_factor_refinement"
        )
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update({
            "normal_memory_cap_bytes": MEMORY_TIERS_BYTES[-1],
            "retry_maximum_increase_bytes": 0,
            "oom_retry": "none; fixed sequential one-rank cases on this runner",
            "raw_cube": "original samples compared on runner disk and removed with scratch",
        })
        report["verification_scope"][f"{screen}_screen"] = "incomplete"
    elif args.cross_grid_accuracy:
        report["scope"] = "isolated_native_x86_A04_cross_grid_endpoint_accuracy"
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update({
            "normal_memory_cap_bytes": MEMORY_TIERS_BYTES[-1],
            "retry_maximum_increase_bytes": 0,
            "swap_extra_bytes": "16 GiB for the reference only; zero for candidates",
            "oom_retry": "none; sequential fixed one-rank inputs",
            "raw_cube": "original samples compared on runner disk and removed with scratch",
        })
        report["verification_scope"]["cross_grid_endpoint_screen"] = "incomplete"
    elif args.mpi_refinement_serial_report:
        report["scope"] = "isolated_native_x86_A04_same_input_memory_refinement"
        report.pop("known_unadmitted_cases")
        report["resource_policy"].update({
            "cpus": "one CPU per MPI rank, maximum two", "swap_extra_bytes": "16 GiB bounded recovery",
            "input_hash_scope": "input_sha256 is the base deck; submitted_input_sha256 includes the RS_GRID execution directive",
            "normal_memory_cap_bytes": MEMORY_TIERS_BYTES[-1],
            "retry_maximum_increase_bytes": 0,
            "oom_retry": "one isolated one-rank follow-up of the recorded two-rank OOM with exhausted swap",
            "raw_cube": "streamed, compared on the runner if necessary, and discarded with temporary scratch",
        })
    try:
        require_native_ci()
        if shutil.disk_usage(output).free < DISK_ADMISSION:
            raise ValueError("Work filesystem has insufficient disk headroom before image load")
        filesystem = subprocess.check_output(
            ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(output)],
            text=True, timeout=10,
        ).strip()
        if filesystem not in {"ext4", "xfs", "btrfs"}:
            raise ValueError(f"Work scratch must be on the native runner's disk filesystem, got {filesystem}")
        report["resource_policy"]["observed_work_filesystem_type"] = filesystem
        if memory_budget(available_memory_bytes(), 0) is None:
            raise ValueError("Insufficient available memory before image load")
        candidate = load_locked_candidate(args.candidate_dir)
        report["candidate"] = candidate
        # Keep raw scratch outside the evidence path even if the job is killed
        # before normal cleanup or the artifact step runs after a cancellation.
        if output.stat().st_dev != output.parent.stat().st_dev:
            raise ValueError("Work scratch and evidence path must use the same measured disk filesystem")
        with tempfile.TemporaryDirectory(prefix="quanta-a04-resource-", dir=output.parent) as directory:
            if args.qz_cutoff:
                report["status"] = run_qz_cutoff(args.qz_cutoff, candidate, Path(directory), diagnostics, report)
            elif args.qz_sensitivity:
                report["status"] = run_qz_sensitivity(args.qz_sensitivity, candidate, Path(directory), diagnostics, report)
            elif args.basis_refinement:
                report["status"] = run_basis_ladder(args.basis_refinement, candidate, Path(directory), diagnostics, report)
            elif args.grid_pilot or args.atomic_grid:
                report["status"] = run_atomic_grid(
                    args.grid_pilot or args.atomic_grid, candidate, Path(directory), diagnostics, report,
                    pilot=bool(args.grid_pilot), pilot_dir=args.grid_pilot_dir,
                )
            elif args.scf_refinement:
                report["status"] = run_scf_screen(args.scf_refinement, candidate, Path(directory), diagnostics, report)
            elif args.fixture_accuracy:
                report["status"] = run_fixed_fixture(args.fixture_accuracy, candidate, Path(directory), diagnostics, report)
            elif args.one_factor:
                report["status"] = run_one_factor(args.one_factor, candidate, Path(directory), diagnostics, report)
            elif args.cross_grid_accuracy:
                report["status"] = run_accuracy(candidate, Path(directory), diagnostics, report)
            elif args.mpi_refinement_serial_report:
                report["status"] = run_refinement(candidate, Path(directory), diagnostics,
                                                  args.mpi_refinement_serial_report, report)
            else:
                for case in CASES:
                    row: dict = {}
                    report["cases"].append(row)
                    run_case(case, candidate, Path(directory), diagnostics, row)
                    if row["status"] != "measured":
                        report["status"] = row["status"]
                        break
                    if case.name == BASELINE_CASE_IDS[-1]:
                        comparison = baseline_comparison(*report["cases"][:2])
                        report["baseline_comparison"] = comparison
                        if not comparison["passes_baseline_observational_comparison"]:
                            report["status"] = "baseline_difference"
                            break
                else:
                    report["status"] = "measured"
        report["scratch_removed"] = True
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"[:500]
    finally:
        write_report(output / "report.json", report)
    print(f"A04 native resource measurement: {report['status']}; report.json")
    if args.qz_cutoff or args.qz_sensitivity:
        summarize_qz_sensitivity(report, output)
    elif args.grid_pilot or args.atomic_grid or args.basis_refinement:
        if args.grid_pilot and report["status"] == "measured":
            shutil.copyfile(output / "report.json", args.grid_pilot_dir / "report.json")
        summarize_atomic_grid(report, output)
    if args.scf_refinement:
        summary = {key: report[key] for key in (
            "system", "status", "comparison_plan_sha256", "scf_screen", "error",
        ) if key in report}
        summary["report_sha256"] = sha256(output / "report.json")
        summary["levels"] = [
            {
                "eps_scf": row["eps_scf"], "status": row["attempt"]["status"],
                "input_sha256": row["attempt"].get("input_sha256"),
                "iterations": row["attempt"].get("engine_scf_iterations"),
                "engine_seconds": row["attempt"].get("engine_resource", {}).get("engine_wall_seconds"),
                "cgroup_peak_bytes": row["attempt"].get("cgroup_memory_peak_bytes"),
                "cgroup_memory_events_max": row["attempt"].get("cgroup_memory_events_max"),
                "engine_count": row["attempt"].get("engine_hard_soft_electron_count"),
                "cube_electron_count": row["attempt"].get("density", {}).get("electron_integral"),
                "cube_sha256": row["attempt"].get("density", {}).get("sha256"),
            }
            for row in report["cases"]
        ]
        summary["comparisons"] = [
            {
                "eps_scf": row["eps_scf"], "reference_eps_scf": row["reference_eps_scf"],
                "passed": row["result"]["within_all_endpoint_thresholds"],
                "energy_delta_hartree": row["result"]["absolute_energy_difference_hartree"],
                "force_delta_hartree_per_bohr": row["result"]["absolute_maximum_force_component_difference_hartree_per_bohr"],
                "density_l1_electrons": row["result"]["spatial_density"]["primary"][
                    "zero_extended_absolute_density_difference_integral_electrons"
                ],
            }
            for row in report.get("comparisons", [])
        ]
        print("QUANTA_SCF_RESULT " + json.dumps(summary, allow_nan=False, separators=(",", ":")))
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
