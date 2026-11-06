#!/usr/bin/env python3
"""Bounded, native Docker-only A03 engine probe; not a Quanta runtime adapter.

The fixed image and data come from the A02 lock.  All engine writes live in
size-limited container tmpfs.  A completed process waits for evidence collection
before releasing tmpfs; no production volume, secret or arbitrary command is used.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import select
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))  # Trusted checkout; also works under python -I.
LOCK_DIR = ROOT / "docs/design/atomistic-a02-v0.1"
LIMITS = {"cpus": 1, "memory_bytes": 2 * 1024**3,
          "memory_swap_bytes": 2 * 1024**3, "pids": 128,
          "work_tmpfs_bytes": 256 * 1024**2, "tmp_tmpfs_bytes": 128 * 1024**2,
          "native_only": True, "network": "none", "rootfs_read_only": True,
          "cap_drop": ["ALL"], "no_new_privileges": True,
          "supplementary_groups": [0]}
HEARTBEAT = 0.5
NUMBER = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[EeDd][-+]?\d+)?"
ARCHIVE_MAX_BYTES = LIMITS["work_tmpfs_bytes"] + 8 * 1024**2
OUTPUT_LOG_MAX_BYTES = 512 * 1024


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_work_archive(archive: Path, destination: Path) -> dict:
    """Extract only bounded ordinary files from the fixed engine-work tar stream."""
    if archive.stat().st_size > ARCHIVE_MAX_BYTES:
        raise ValueError("Engine archive exceeds transport byte limit")
    destination.mkdir(mode=0o700, exist_ok=False)
    total = 0; count = 0; seen = set()
    with tarfile.open(archive, mode="r:") as tf:
        for member in tf:
            if tf.pax_headers or member.pax_headers:
                raise ValueError("PAX metadata is not accepted in engine artifacts")
            if not (member.isdir() or member.isfile()):
                raise ValueError("Engine archive contains a link or special entry")
            name = member.name
            if not name or name.startswith("/") or "\\" in name or ".." in name.split("/"):
                raise ValueError("Unsafe engine archive path")
            relative = Path(name)
            if str(relative) == ".":
                if not member.isdir():
                    raise ValueError("Invalid archive root entry")
                continue
            if str(relative) in seen:
                raise ValueError("Duplicate engine archive path")
            seen.add(str(relative)); count += 1
            if count > 256:
                raise ValueError("Engine archive contains too many entries")
            target = destination / relative
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("Engine archive escapes destination")
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if member.size < 0 or member.size > LIMITS["work_tmpfs_bytes"]:
                raise ValueError("Engine artifact file exceeds byte limit")
            total += member.size
            if total > LIMITS["work_tmpfs_bytes"]:
                raise ValueError("Engine artifact total exceeds work tmpfs limit")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise ValueError("Engine archive omitted regular-file data")
            with source, target.open("xb") as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024*1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated engine artifact")
                    output.write(chunk); remaining -= len(chunk)
    return {"transport": "fixed docker exec tar from live tmpfs",
            "archive_bytes": archive.stat().st_size, "archive_sha256": sha256(archive),
            "regular_file_bytes": total, "entries": count,
            "links_special_files_pax_and_escaping_paths_allowed": False}


def stream_work_archive(name: str, archive: Path, timeout: float = 60) -> None:
    """Bound stdout on disk while reading a live container tmpfs through exec."""
    args = ["docker", "exec", name, "tar", "-C", "/work", "-cf", "-", "."]
    with tempfile.TemporaryFile() as err, archive.open("xb") as target:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err)
        deadline = time.monotonic()+timeout; size = 0
        try:
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Engine artifact transport deadline exceeded")
                ready, _, _ = select.select([process.stdout], [], [], min(1, deadline-time.monotonic()))
                if not ready:
                    continue
                data = os.read(process.stdout.fileno(), 1024*1024)
                if not data:
                    break
                size += len(data)
                if size > ARCHIVE_MAX_BYTES:
                    raise ValueError("Engine archive exceeds transport byte limit")
                target.write(data)
            code = process.wait(timeout=max(0.1, deadline-time.monotonic()))
            if code:
                err.seek(0)
                raise RuntimeError("Engine tar transport failed: "+err.read(3000).decode(errors="replace"))
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
            process.stdout.close()


def run(args: list[str], timeout: float = 30, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0:3]}: {result.stderr[-3000:]}")
    return result


def native_platform(machine: str | None = None) -> str:
    mapping = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}
    try:
        return mapping[machine or platform.machine()]
    except KeyError as exc:
        raise ValueError("Only native Linux x86_64/aarch64 probes are supported") from exc


def image_selection(lock: dict, architecture: str) -> dict:
    matches = [x for x in lock["architecture_images"] if x["platform"] == architecture]
    if len(matches) != 1:
        raise ValueError("No unique pinned image for native architecture")
    image = matches[0]
    if image["immutable_reference"] != image["registry_repository"] + "@" + image["digest"]:
        raise ValueError("Image reference is not its locked immutable digest")
    return image


def assert_image_identity(inspected: dict, selected: dict) -> None:
    arch = selected["platform"].split("/")[1]
    if inspected.get("Architecture") != arch or inspected.get("Os") != "linux":
        raise ValueError("Pulled image has wrong native architecture")
    if inspected.get("Id") != selected["config_digest"]:
        raise ValueError("Pulled image config digest differs from A02 lock")
    if selected["immutable_reference"] not in inspected.get("RepoDigests", []):
        # Docker normalizes docker.io away in RepoDigests.
        normalized = selected["immutable_reference"].removeprefix("docker.io/")
        if normalized not in inspected.get("RepoDigests", []):
            raise ValueError("Pulled image lacks the requested immutable repository digest")


def parse_version(text: str, release_commit: str) -> dict:
    version = re.search(r"CP2K\s+version\s+([^\r\n]+)", text, re.I)
    revision = re.search(r"(?:source code revision|git\s+(?:revision|commit))\s*[:=]?\s*([^\s]+)", text, re.I)
    if not revision:
        revision = re.search(r"\b(?:git:|git-sha:)\s*([0-9a-f]{7,40})\b", text, re.I)
    rev = revision.group(1).strip() if revision else None
    if rev:
        rev = re.sub(r"^(?:git:|git-sha:)", "", rev, flags=re.I)
    return {"reported_version": version.group(1).strip() if version else None,
            "reported_revision": rev,
            "release_source_prefix_matches": bool(rev and re.fullmatch(r"[0-9a-f]{7,40}", rev)
                                                  and release_commit.startswith(rev)),
            "source_identity_attested": False,
            "attestation_note": "Binary self-report is evidence, not a reproducible-build/source attestation."}


def parse_cube(path: Path) -> dict:
    """Stream an ordinary single-field positive-atom CP2K CUBE, without edits."""
    def values(line: str) -> list[float]:
        return [float(s.replace("D", "E").replace("d", "e")) for s in line.split()]

    with path.open(encoding="ascii") as f:
        comments = [f.readline().rstrip(), f.readline().rstrip()]
        head = values(f.readline())
        if len(head) not in (4, 5) or head[0] != int(head[0]) or head[0] <= 0:
            raise ValueError("Unsupported CUBE atom/header format")
        if len(head) == 5 and head[4] != 1:
            raise ValueError("Multi-field CUBE is unsupported")
        atom_count = int(head[0])
        origin = head[1:4]
        axes, counts = [], []
        for _ in range(3):
            row = values(f.readline())
            if len(row) != 4 or row[0] != int(row[0]) or row[0] <= 0:
                raise ValueError("Only positive-count bohr-axis CUBE is supported")
            counts.append(int(row[0])); axes.append(row[1:])
        atoms = []
        for _ in range(atom_count):
            row = values(f.readline())
            if len(row) != 5:
                raise ValueError("Invalid CUBE atom row")
            atoms.append(row)
        a, b, c = axes
        determinant = a[0]*(b[1]*c[2]-b[2]*c[1])-a[1]*(b[0]*c[2]-b[2]*c[0])+a[2]*(b[0]*c[1]-b[1]*c[0])
        if not math.isfinite(determinant) or determinant == 0:
            raise ValueError("Singular/nonfinite CUBE grid")
        n = 0; negative = 0; minimum = math.inf; maximum = -math.inf
        # Compensated summation avoids retaining a multi-million point grid.
        total = correction = negative_sum = 0.0
        expected = math.prod(counts)
        for line in f:
            for v in values(line):
                if not math.isfinite(v):
                    raise ValueError("Nonfinite CUBE sample")
                n += 1
                if n > expected:
                    raise ValueError("CUBE contains excess samples")
                y = v - correction; t = total + y; correction = (t-total)-y; total = t
                if v < 0:
                    negative += 1; negative_sum += v
                minimum = min(minimum, v); maximum = max(maximum, v)
        if n != expected:
            raise ValueError("CUBE sample count does not match dimensions")
    density_units = json.loads((LOCK_DIR / "density-and-units.json").read_text())["engine_unit_profile"]
    bohr_m = density_units["a_bohr_m"]
    return {"file": path.name, "bytes": path.stat().st_size, "sha256": sha256(path),
            "comments": comments, "atom_count": atom_count, "atoms_bohr_rounded": atoms,
            "origin_bohr_rounded": origin, "grid_counts": counts, "grid_axes_bohr_rounded": axes,
            "origin_m_rounded": [v*bohr_m for v in origin],
            "grid_axes_m_rounded": [[v*bohr_m for v in row] for row in axes],
            "samples": n, "voxel_volume_bohr3_from_rounded_header": abs(determinant),
            "electron_integral": total*abs(determinant),
            "electron_count_error_from_2": total*abs(determinant)-2,
            "minimum_electrons_per_bohr3": minimum, "maximum_electrons_per_bohr3": maximum,
            "negative_samples": negative, "negative_integral": negative_sum*abs(determinant),
            "density_multiplier_per_m3": bohr_m**-3,
            "engine_constants_edition_candidate": 2006,
            "header_rounding_bound_bohr": 5e-7, "field_significant_digits": 6,
            "clipped_smoothed_or_renormalized": False,
            "physical_validation_status": "unvalidated", "convergence_status": "not_tested"}


def parse_output(text: str) -> dict:
    energies = re.findall(r"ENERGY\|\s+Total FORCE_EVAL.*?:\s*("+NUMBER+r")", text)
    force_blocks = re.findall(r"ATOMIC FORCES in \[a\.u\.\](.*?)(?:SUM OF ATOMIC FORCES|\n\s*ENERGY\||\Z)", text, re.S)
    forces = []
    if force_blocks:
        for row in force_blocks[-1].splitlines():
            m = re.match(r"\s*\d+\s+\d+\s+\S+\s+("+NUMBER+r")\s+("+NUMBER+r")\s+("+NUMBER+r")\s*$", row)
            if m:
                forces.append([float(v.replace("D", "E")) for v in m.groups()])
    units = json.loads((LOCK_DIR / "density-and-units.json").read_text())["engine_unit_profile"]
    hartree_j = 2*units["rydberg_per_m"]*units["h_planck_j_s"]*units["speed_of_light_m_per_s"]
    energy = float(energies[-1].replace("D", "E")) if energies else None
    return {"program_ended": "PROGRAM ENDED AT" in text,
            "scf_converged": bool(re.search(r"SCF run converged in", text)),
            "energy_hartree": energy, "energy_j_candidate_engine2006": energy*hartree_j if energy is not None else None,
            "forces_hartree_per_bohr": forces,
            "forces_n_candidate_engine2006": [[v*hartree_j/units["a_bohr_m"] for v in row] for row in forces],
            "source_claims_from_output": parse_version(text, json.loads((LOCK_DIR / "engine-lock.json").read_text())["source_commit"]),
            "physical_validation_status": "unvalidated"}


def parse_force_artifact(path: Path) -> list[list[float]]:
    """CP2K FORCE_EVAL PRINT FORCES native default, no numeric correction."""
    text = path.read_text(errors="strict")
    rows = []
    for line in text.splitlines():
        m = re.match(r"\s*\d+\s+\d+\s+[A-Za-z]+\s+("+NUMBER+r")\s+("+NUMBER+r")\s+("+NUMBER+r")\s*$", line)
        if not m:
            m = re.match(r"\s*[A-Za-z]+\s+("+NUMBER+r")\s+("+NUMBER+r")\s+("+NUMBER+r")\s*$", line)
        if m:
            row = [float(v.replace("D", "E").replace("d", "e")) for v in m.groups()]
            if not all(math.isfinite(v) for v in row):
                raise ValueError("Nonfinite force artifact")
            rows.append(row)
    return rows


def check_density_geometry(density: dict, metadata: dict) -> dict:
    atoms = metadata["atoms"]
    if density["atom_count"] != len(atoms):
        raise ValueError("CUBE atom count differs from authored input")
    bohr_m = json.loads((LOCK_DIR / "density-and-units.json").read_text())["engine_unit_profile"]["a_bohr_m"]
    differences = []
    for row, atom in zip(density["atoms_bohr_rounded"], atoms):
        if int(row[0]) != {"H": 1, "He": 2}[atom["element"]]:
            raise ValueError("CUBE composition differs from authored input")
        expected = [float(x)*1e-10/bohr_m for x in atom["engine_position_angstrom"]]
        differences.extend(abs(a-b) for a, b in zip(row[2:], expected))
    maximum = max(differences, default=0)
    if maximum > 5.01e-7:
        raise ValueError("CUBE coordinates differ beyond recorded header rounding budget")
    return {"atoms_and_composition_match": True, "maximum_coordinate_difference_bohr": maximum,
            "absolute_budget_bohr": 5.01e-7, "unit_constants_candidate": "CP2K source CODATA2006"}


def validate_web_origin(origin: str | None) -> str | None:
    if origin is None:
        return None
    u = urlparse(origin)
    if u.scheme != "http" or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("Web probe requires a credential-free HTTP loopback origin")
    try:
        if not ipaddress.ip_address(u.hostname or "").is_loopback:
            raise ValueError("Web probe target is not loopback")
    except ValueError as exc:
        raise ValueError("Web probe requires a numeric loopback address") from exc
    if not u.port:
        raise ValueError("Web probe requires an explicit controlled loopback port")
    return origin.rstrip("/")


class WebSampler:
    def __init__(self, origin: str | None, production_boundary: bool = False):
        self.origin = validate_web_origin(origin)
        if production_boundary and self.origin != "http://127.0.0.1:8765":
            raise ValueError("Production boundary headers require the fixed OCI loopback origin")
        self.headers = {"Host": "quanta.kro.kr", "Origin": "https://quanta.kro.kr"} if production_boundary else {}
        self.phase = "baseline"; self.samples: list[dict] = []
        self.stop = threading.Event(); self.thread: threading.Thread | None = None

    def sample(self) -> None:
        if not self.origin:
            return
        for path, expected in [("/", 200), ("/v1/capabilities", 401)]:
            t = time.monotonic(); code = None; error = None
            try:
                from urllib.request import Request
                with urlopen(Request(self.origin+path, headers=self.headers), timeout=2) as r:
                    code = r.status; r.read(1)
            except HTTPError as exc:
                code = exc.code
            except Exception as exc:
                error = type(exc).__name__
            self.samples.append({"phase": self.phase, "path": path, "status": code,
                                 "expected_status": expected, "wall_seconds": time.monotonic()-t, "error": error})

    def start(self) -> None:
        self.sample()
        def work() -> None:
            while not self.stop.wait(1):
                self.sample()
        if self.origin:
            self.thread = threading.Thread(target=work, daemon=True); self.thread.start()

    def finish(self) -> dict:
        self.phase = "after"; self.sample(); self.stop.set()
        if self.thread:
            self.thread.join(timeout=8)
        groups = {}
        for phase in ("baseline", "during", "after"):
            rows = [s for s in self.samples if s["phase"] == phase]
            groups[phase] = {"samples": len(rows), "max_latency_seconds": max((s["wall_seconds"] for s in rows), default=None),
                             "unexpected_statuses": sum(s["status"] != s["expected_status"] for s in rows)}
        return {"configured": bool(self.origin), "origin": self.origin, "fixed_production_boundary_headers": bool(self.headers),
                "authentication": "anonymous only; no key read or sent", "summary": groups, "samples": self.samples}


INVENTORY = r'''set -eu
echo QUANTA_BINARY_PATH
command -v cp2k
echo QUANTA_BINARY_SHA256
sha256sum "$(command -v cp2k)"
echo QUANTA_REAL_BINARY_PATH
readlink -f "$(command -v cp2k)"
echo QUANTA_VERSION
cp2k --version
echo QUANTA_LDD
ldd "$(command -v cp2k)" || true
echo QUANTA_PACKAGES
dpkg-query -W -f='${Package}\t${Version}\n' | LC_ALL=C sort
'''
PROBE_WRAPPER = r'''python3 -c 'import json,os,subprocess,sys,time
t=time.monotonic()
p=subprocess.Popen(["cp2k","-i","/quanta-input/input.inp"])
_,status,usage=os.wait4(p.pid,0)
rc=os.waitstatus_to_exitcode(status)
p.returncode=rc
json.dump({"engine_returncode":rc,"engine_wall_seconds":time.monotonic()-t,"engine_children_peak_rss_kib":usage.ru_maxrss,"user_cpu_seconds":usage.ru_utime,"system_cpu_seconds":usage.ru_stime,"rss_semantics":"Linux wait4 ru_maxrss; maximum resident set of completed direct engine child and its reaped descendants, not simultaneous aggregate RSS or cgroup memory."},open("/work/engine-resource.json","w"))
sys.exit(rc)' > /work/cp2k.out 2>&1
quanta_rc=$?
printf '%s\n' "$quanta_rc" > /work/quanta_exit_code
while [ ! -f /work/quanta_release ]; do sleep 0.2; done
exit "$quanta_rc"
'''


class DockerProbe:
    def __init__(self, image: str, out: Path, timeout: int):
        self.image = image; self.out = out; self.timeout = timeout
        self.names: set[str] = set()

    def create_args(self, name: str, input_dir: Path | None = None) -> list[str]:
        args = ["docker", "create", "--name", name, "--platform", native_platform(),
                "--label", "org.quanta.atomistic-a03="+str(self.out),
                "--user", f"{os.getuid()}:{os.getgid()}", "--group-add", "0",
                "--read-only", "--network", "none", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--cpus", "1", "--memory", "2g",
                "--memory-swap", "2g", "--pids-limit", "128", "--ulimit", "core=0",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=134217728,mode=1777",
                "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=268435456,mode=1777",
                "--workdir", "/work", "--env", "OMP_NUM_THREADS=1", "--env", "OPENBLAS_NUM_THREADS=1",
                "--env", "MKL_NUM_THREADS=1", "--env", "NUMEXPR_NUM_THREADS=1",
                "--env", "HOME=/tmp", "--mount", f"type=bind,source={LOCK_DIR / 'assets'},target=/quanta-data,readonly"]
        if input_dir:
            args += ["--mount", f"type=bind,source={input_dir},target=/quanta-input,readonly"]
        return args

    def inspect(self, name: str) -> dict:
        return json.loads(run(["docker", "inspect", name]).stdout)[0]

    def remove(self, name: str) -> None:
        run(["docker", "rm", "--force", name], check=False)
        self.names.discard(name)

    def inventory(self) -> dict:
        name = "quanta-a03-inventory-"+uuid.uuid4().hex
        run(self.create_args(name)+[self.image, "/bin/sh", "-c", INVENTORY]); self.names.add(name)
        try:
            r = run(["docker", "start", "--attach", name], timeout=60, check=False)
            (self.out / "inventory.txt").write_text(r.stdout+r.stderr)
            if r.returncode:
                raise RuntimeError("Pinned image nonroot inventory/version command failed: "+(r.stdout+r.stderr)[-2500:])
            version = parse_version(r.stdout, json.loads((LOCK_DIR / "engine-lock.json").read_text())["source_commit"])
            m = re.search(r"QUANTA_BINARY_SHA256\s+([0-9a-f]{64})\s+([^\r\n]+)", r.stdout)
            version.update({"binary_sha256": m.group(1) if m else None, "binary_path": m.group(2) if m else None,
                            "inventory_file": "inventory.txt", "inventory_sha256": sha256(self.out / "inventory.txt")})
            if not version["reported_version"] or not version["binary_sha256"]:
                raise RuntimeError("Engine binary identity/version could not be parsed")
            return version
        finally:
            self.remove(name)

    def sample(self, name: str, metrics: dict) -> list[dict]:
        rows = []
        top = run(["docker", "top", name, "-eo", "pid,rss,comm"], check=False)
        if top.returncode == 0:
            for line in top.stdout.splitlines()[1:]:
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                    pid = int(parts[0]); start = None
                    try:
                        stat = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
                        start = stat[19]
                    except OSError:
                        pass
                    rows.append({"pid": pid, "rss_kib": int(parts[1]), "comm": parts[2], "start_ticks": start})
            metrics["sampled_process_rss_sum_peak_kib"] = max(metrics["sampled_process_rss_sum_peak_kib"], sum(x["rss_kib"] for x in rows))
            metrics["samples"] += 1
        state = self.inspect(name)["State"]
        pid = state.get("Pid")
        if pid:
            try:
                line = next(s for s in Path(f"/proc/{pid}/cgroup").read_text().splitlines() if s.startswith("0::"))
                cg = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
                peak = int((cg / "memory.peak").read_text())
                metrics["observed_cgroup_memory_peak_bytes"] = max(metrics.get("observed_cgroup_memory_peak_bytes") or 0, peak)
                metrics["cgroup_path"] = str(cg)
            except (OSError, ValueError, StopIteration):
                pass
        return rows

    def read_output(self, name: str, target: Path) -> str:
        # docker cp may omit live tmpfs contents; exec observes the actual mount.
        r = run(["docker", "exec", name, "head", "-c", str(OUTPUT_LOG_MAX_BYTES+1), "/work/cp2k.out"], check=False)
        if r.returncode:
            return ""
        raw = r.stdout.encode()
        target.write_bytes(raw[:OUTPUT_LOG_MAX_BYTES])
        return r.stdout if len(raw) <= OUTPUT_LOG_MAX_BYTES else ""

    def copy_work(self, name: str, destination: Path) -> dict:
        archive = destination.parent / "engine-artifacts.tar"
        try:
            stream_work_archive(name, archive)
            return extract_work_archive(archive, destination)
        finally:
            archive.unlink(missing_ok=True)

    @staticmethod
    def remaining_pids(rows: list[dict]) -> list[int]:
        alive = []
        for row in rows:
            try:
                stat = Path(f"/proc/{row['pid']}/stat").read_text().split(") ", 1)[1].split()
                if stat[19] == row["start_ticks"] and stat[0] != "Z":
                    alive.append(row["pid"])
            except OSError:
                pass
        return alive

    def execute(self, case: str, inp: str, metadata: dict, cancel: bool = False) -> dict:
        target = self.out / case; target.mkdir()
        (target / "input.inp").write_text(inp)
        name = "quanta-a03-"+uuid.uuid4().hex
        run(self.create_args(name, target)+[self.image, "/bin/sh", "-c", PROBE_WRAPPER]); self.names.add(name)
        record = {"case": case, "input_sha256": sha256(target / "input.inp"), "input_metadata": metadata,
                  "limits": dict(LIMITS, case_timeout_seconds=self.timeout), "cancel_requested": cancel,
                  "metrics": {"sampled_process_rss_sum_peak_kib": 0, "samples": 0,
                              "observed_cgroup_memory_peak_bytes": None,
                              "rss_metric": "Sampled sum of docker-top per-process resident pages; shared pages may be counted more than once; not exact peak RSS."}}
        start = time.monotonic(); tracked = []; cancellation = None
        try:
            run(["docker", "start", name]); record["container_controls"] = self.inspect(name)["HostConfig"]
            record["container_user"] = self.inspect(name)["Config"]["User"]
            # Keep this report small: select only declared isolation/resource fields.
            record["container_controls"] = {k: record["container_controls"].get(k) for k in
                ["NetworkMode", "ReadonlyRootfs", "CapDrop", "SecurityOpt", "NanoCpus", "Memory", "MemorySwap", "PidsLimit", "Tmpfs", "GroupAdd"]}
            while True:
                state = self.inspect(name)["State"]
                if not state["Running"]:
                    record["container_exit"] = state
                    raise RuntimeError("Engine container exited before completion handshake")
                tracked = self.sample(name, record["metrics"])
                done = run(["docker", "exec", name, "/bin/sh", "-c", "test -f /work/quanta_exit_code && cat /work/quanta_exit_code"], check=False)
                if done.returncode == 0:
                    if cancel:
                        raise RuntimeError("Cancellation probe completed before an active engine could be cancelled")
                    record["engine_returncode"] = int(done.stdout.strip())
                    record["artifact_transport"] = self.copy_work(name, target / "raw")
                    run(["docker", "exec", name, "touch", "/work/quanta_release"])
                    wait = run(["docker", "wait", name], timeout=15)
                    record["container_returncode"] = int(wait.stdout.strip())
                    break
                if cancel and any("cp2k" in r["comm"].lower() for r in tracked):
                    text = self.read_output(name, target / "partial-cp2k.out")
                    if "CP2K|" in text and "PROGRAM ENDED AT" not in text:
                        active_rows = [r for r in tracked if "cp2k" in r["comm"].lower()]
                        t = time.monotonic()
                        stop = run(["docker", "stop", "--time", "1", name], timeout=10, check=False)
                        if stop.returncode:
                            run(["docker", "kill", name], check=False)
                        run(["docker", "wait", name], timeout=10, check=False)
                        state = self.inspect(name)["State"]
                        alive = self.remaining_pids(tracked)
                        cancellation = {"active_cp2k_processes_before_stop": active_rows,
                                        "partial_output_contains_cp2k_banner": True,
                                        "program_had_ended_before_cancel": False,
                                        "interruption_phase": "scf" if "SCF WAVEFUNCTION OPTIMIZATION" in text else "initialization_before_scf",
                                        "cancel_to_exit_seconds": time.monotonic()-t,
                                        "container_running_after": state["Running"], "container_pid_after": state["Pid"],
                                        "tracked_processes_remaining": alive,
                                        "cleaned": not state["Running"] and state["Pid"] == 0 and not alive}
                        record["cancellation"] = cancellation
                        if not cancellation["cleaned"]:
                            raise RuntimeError("Cancellation did not clean engine/container descendants")
                        break
                if time.monotonic()-start > self.timeout:
                    self.read_output(name, target / "timeout-cp2k.out")
                    raise TimeoutError("Declared engine case deadline exceeded")
                time.sleep(HEARTBEAT)
            record["wall_seconds"] = time.monotonic()-start
            if not cancel:
                raw = target / "raw"
                text = (raw / "cp2k.out").read_text(errors="replace")
                record["output"] = parse_output(text)
                if not record["output"]["forces_hartree_per_bohr"] and (raw / "forces.xyz").exists():
                    record["output"]["forces_hartree_per_bohr"] = parse_force_artifact(raw / "forces.xyz")
                    units = json.loads((LOCK_DIR / "density-and-units.json").read_text())["engine_unit_profile"]
                    factor = 2*units["rydberg_per_m"]*units["h_planck_j_s"]*units["speed_of_light_m_per_s"]/units["a_bohr_m"]
                    record["output"]["forces_n_candidate_engine2006"] = [[v*factor for v in row] for row in record["output"]["forces_hartree_per_bohr"]]
                    record["output"]["force_artifact"] = "forces.xyz"
                    record["output"]["force_units_policy"] = "CP2K native PRINT FORCES default atomic units; A04 actual-source binding remains required."
                record["files"] = [{"file": str(p.relative_to(target)), "bytes": p.stat().st_size, "sha256": sha256(p)} for p in sorted(raw.rglob("*")) if p.is_file()]
                record["output_bytes"] = sum(f["bytes"] for f in record["files"])
                cubes = sorted(raw.glob("*TOTAL_ELECTRON_DENSITY*.cube"))
                record["density"] = [parse_cube(p) for p in cubes]
                resource_file = raw / "engine-resource.json"
                if resource_file.exists():
                    record["engine_resource"] = json.loads(resource_file.read_text())
                if record["engine_returncode"] != 0 or not record["output"]["program_ended"] or not record["output"]["scf_converged"]:
                    raise RuntimeError("Engine probe did not finish with a converged SCF")
                energy = record["output"]["energy_hartree"]; forces = record["output"]["forces_hartree_per_bohr"]
                if energy is None or not math.isfinite(energy) or len(forces) != len(metadata["atoms"]) or not all(math.isfinite(v) for row in forces for v in row) or len(cubes) != 1:
                    raise RuntimeError("Expected finite energy, atom forces and one full-density cube were not observed")
                record["density"][0]["geometry_check"] = check_density_geometry(record["density"][0], metadata)
                record["observed_feature_lines"] = [line.strip() for line in text.splitlines() if any(s in line for s in ["GAPW", "PBE", "Basis set file", "Potential file", "PERIODIC", "Poisson solver"])][:30]
                if "GAPW" not in text or "PBE" not in text or metadata["basis"]+".cp2k" not in text or "ALL_POTENTIALS" not in text:
                    raise RuntimeError("Actual GAPW/PBE and supplied locked data use could not be observed")
                if not record.get("engine_resource", {}).get("engine_children_peak_rss_kib"):
                    raise RuntimeError("Actual completed engine peak RSS was not recorded")
            record["passed_execution_gate"] = True
        except Exception as exc:
            record["error"] = type(exc).__name__+": "+str(exc)
            record["passed_execution_gate"] = False
            record["wall_seconds"] = time.monotonic()-start
            self.read_output(name, target / "failed-cp2k.out")
        finally:
            self.remove(name)
            record["container_removed"] = run(["docker", "inspect", name], check=False).returncode != 0
            record["tracked_processes_remaining_after_remove"] = self.remaining_pids(tracked)
            if record["tracked_processes_remaining_after_remove"]:
                record["passed_execution_gate"] = False
        (target / "evidence.json").write_text(json.dumps(record, indent=2)+"\n")
        return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--case-timeout", type=int, default=180)
    parser.add_argument("--web-origin")
    parser.add_argument("--production-web-boundary", action="store_true")
    args = parser.parse_args()
    if not 30 <= args.case_timeout <= 180:
        parser.error("case timeout must be 30..180 seconds")
    if os.getuid() == 0:
        parser.error("Run the controller as a nonroot user with Docker access")
    if platform.system() != "Linux" or not shutil.which("docker"):
        parser.error("Native Linux Docker is required; no emulation or local fallback")
    validate_web_origin(args.web_origin)
    out = args.output_dir.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema_version": 1, "probe": "quanta.atomistic-a03", "started_at": datetime.now(timezone.utc).isoformat(),
              "host": {"machine": platform.machine(), "platform": platform.platform(), "uid": os.getuid(), "gid": os.getgid()},
              "limits": dict(LIMITS, case_timeout_seconds=args.case_timeout), "physical_validation_status": "unvalidated",
              "runtime_contract_implemented": False, "production_deployment_changed": False, "cases": []}
    report["source_sha"] = os.environ.get("QUANTA_A03_SOURCE_SHA")
    sampler = WebSampler(args.web_origin, args.production_web_boundary); sampler.start(); probe = None
    try:
        if shutil.disk_usage(out).free < 8*1024**3:
            raise RuntimeError("Require at least 8 GiB free scratch disk before image pull")
        from check_atomistic_a02 import verify
        report["a02_lock_check"] = verify()
        lock = json.loads((LOCK_DIR / "engine-lock.json").read_text())
        selected = image_selection(lock, native_platform()); report["image_candidate"] = selected
        pull_start = time.monotonic()
        pull = run(["docker", "pull", "--platform", native_platform(), selected["immutable_reference"]], timeout=300)
        (out / "pull.txt").write_text(pull.stdout+pull.stderr)
        report["pull_wall_seconds"] = time.monotonic()-pull_start
        inspected = json.loads(run(["docker", "image", "inspect", selected["immutable_reference"]]).stdout)[0]
        assert_image_identity(inspected, selected)
        report["image_observed"] = {k: inspected.get(k) for k in ["Id", "RepoDigests", "Architecture", "Os", "Size", "RootFS"]}
        probe = DockerProbe(selected["immutable_reference"], out, args.case_timeout)
        report["binary"] = probe.inventory()
        report["locked_data"] = [{"file": p.name, "sha256": sha256(p), "bytes": p.stat().st_size} for p in sorted((LOCK_DIR / "assets").iterdir()) if p.is_file()]
        from atomistic_a03_inputs import generate_input, probe_metadata
        sampler.phase = "during"
        for case, system, basis in [("he-dz", "he", "cc-pVDZ"), ("h2-dz", "h2", "cc-pVDZ"), ("h2-tz", "h2", "cc-pVTZ")]:
            kwargs = dict(system=system, basis=basis, project=case.replace("-", "_"), data_dir="/quanta-data")
            row = probe.execute(case, generate_input(**kwargs), probe_metadata(**kwargs)); report["cases"].append(row)
            if not row["passed_execution_gate"]:
                raise RuntimeError("A03 case failed: "+case)
        kwargs = dict(system="h2", basis="cc-pVQZ", project="h2_cancel", data_dir="/quanta-data", cell_angstrom=20, cutoff_ry=800, rel_cutoff_ry=80)
        row = probe.execute("h2-cancel", generate_input(**kwargs), probe_metadata(**kwargs), cancel=True); report["cases"].append(row)
        if not row["passed_execution_gate"]:
            raise RuntimeError("Active engine cancellation failed")
        kwargs = dict(system="h2", basis="cc-pVDZ", project="h2_after_cancel", data_dir="/quanta-data")
        row = probe.execute("h2-after-cancel", generate_input(**kwargs), probe_metadata(**kwargs)); report["cases"].append(row)
        if not row["passed_execution_gate"]:
            raise RuntimeError("Fresh engine execution after cancellation failed")
        report["passed_execution_gates"] = True
    except Exception as exc:
        report["error"] = type(exc).__name__+": "+str(exc); report["passed_execution_gates"] = False
    finally:
        if probe:
            for name in list(probe.names):
                probe.remove(name)
        report["web_responsiveness"] = sampler.finish()
        web = report["web_responsiveness"]
        if web["configured"] and (any(s["status"] != s["expected_status"] or s["wall_seconds"] > 2 for s in web["samples"]) or not web["summary"]["during"]["samples"]):
            report["passed_execution_gates"] = False
            report["web_gate_error"] = "Unexpected web status/timeout or missing during-compute samples"
        (out / "web-samples.json").write_text(json.dumps(web["samples"], indent=2)+"\n")
        web["raw_samples_file"] = "web-samples.json"
        web["raw_samples_sha256"] = sha256(out / "web-samples.json")
        web["samples"] = web["samples"][:4]+web["samples"][-4:] if len(web["samples"]) > 8 else web["samples"]
        web["report_samples_are_excerpt"] = True
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        (out / "report.json").write_text(json.dumps(report, indent=2)+"\n")
        print(json.dumps({"report": str(out / "report.json"), "passed_execution_gates": report.get("passed_execution_gates", False), "error": report.get("error")}))
    return 0 if report.get("passed_execution_gates") else 2


if __name__ == "__main__":
    raise SystemExit(main())
