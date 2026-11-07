"""Run one pinned CP2K upstream GAPW batch against a verified A03 image."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from urllib.request import Request, urlopen
from uuid import uuid4

from atomistic_a03_candidate import load_candidate, read_metadata


REPO = "Hyunwoo1205/quanta"
SOURCE_SHA = "5dd1e90c8332366c1f95f5b58b260ce966af5e84"
CP2K_SHA = "67b5da876dd6a76b8b021d5a04d1c81ba79a4c50"
CP2K_TREE = "2e4405ec65578a3d8205bc23adf69249798d98d3"
TESTS_TREE = "ac08d96878acbb2f92fa9f71b7eca3088863e443"
NATIVE_RUN = 42370042995
ARTIFACT_ID = 13573889644
BATCH = "QS/regtest-gapw-2"
CASES = (
    "Li-ROKS.inp",
    "NO2-ROKS.inp",
    "C-levelshift.inp",
    "H2-pbe-restart-run.inp",
    "H2-pbe-restart-rerun.inp",
)
BASE = Path(".cache/atomistic-a04")
EVIDENCE = BASE / "evidence"
A03_EVIDENCE = Path("docs/verification/atomistic-a03/armv8a-retry-20261107.json")
CASE_LOG_LIMIT = 8 * 1024**2
CONTAINER_TIMEOUT = 20 * 60


def approved_candidate():
    evidence = json.loads(A03_EVIDENCE.read_text(encoding="utf-8"))["successful_retry"]
    if (evidence["source_sha"], evidence["source_revision"], evidence["native_run_id"]) != (
        SOURCE_SHA, CP2K_SHA, NATIVE_RUN
    ):
        raise ValueError("A03 evidence does not match the pinned A04 predecessor")
    artifact = next(item for item in evidence["native_artifacts"] if item["id"] == ARTIFACT_ID)
    arm = evidence["native_arm"]
    if not arm["passed"] or arm["candidate"]["binary_sha256"] != evidence["source_binary_sha256"]:
        raise ValueError("A03 native ARM result does not establish a passing candidate")
    return artifact, arm["candidate"], arm["image_identity"]


def approved_amd64_candidate(source_sha):
    a03 = json.loads((BASE / "a03" / "report.json").read_text(encoding="utf-8"))
    required_cases = ("he-dz", "h2-dz", "h2-tz", "h2-cancel", "h2-after-cancel")
    cases = a03["cases"]
    candidate = a03["image_candidate"]
    binary = a03["binary"]
    if (a03["source_sha"] != source_sha or a03["host"]["machine"] != "x86_64"
            or a03["passed_execution_gates"] is not True
            or a03["engine_execution_gates_passed"] is not True
            or a03["web_responsiveness"]["observer_scope"] != "independent_native_ci_parent"
            or a03["web_responsiveness"]["observer_complete"] is not True
            or tuple(case["case"] for case in cases) != required_cases
            or any(case["passed_execution_gate"] is not True for case in cases)
            or binary["reported_revision"] != CP2K_SHA or binary["reported_version"] != "2026.2"
            or binary["binary_sha256"] != candidate["binary_sha256"]):
        raise ValueError("AMD64 GAPW requires the exact same-source passing isolated A03 candidate")
    return candidate, a03["image_identity"]


def write_evidence(name, content):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / name).write_text(json.dumps(content, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def authorize():
    artifact, _, _ = approved_candidate()
    headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json"}

    def get(path):
        request = Request(f"https://api.github.com/repos/{REPO}{path}", headers=headers)
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    run = get(f"/actions/runs/{NATIVE_RUN}")
    expected = {
        "id": NATIVE_RUN,
        "head_sha": SOURCE_SHA,
        "head_branch": "main",
        "path": ".github/workflows/atomistic-a03.yml",
        "status": "completed",
        "conclusion": "success",
    }
    if any(run.get(key) != value for key, value in expected.items()):
        raise ValueError("Pinned A03 native run is not the expected successful main workflow")
    result = get(f"/actions/artifacts/{ARTIFACT_ID}")
    if (
        result["id"] != ARTIFACT_ID or result["expired"] or result["name"] != artifact["name"]
        or result["digest"] != artifact["digest"] or result["size_in_bytes"] != artifact["zip_bytes"]
        or result["workflow_run"]["id"] != NATIVE_RUN or result["workflow_run"]["head_sha"] != SOURCE_SHA
    ):
        raise ValueError("Pinned A03 native image artifact is missing, expired, or does not match its digest")
    write_evidence("artifact-lock.json", {"run": expected, "artifact": artifact, "expires_at": result["expires_at"]})
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"run-id={NATIVE_RUN}\nartifact-id={ARTIFACT_ID}\n")


def check_upstream(upstream):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(upstream), *args], text=True, timeout=30).strip()

    if (git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}"), git("rev-parse", "HEAD:tests")) != (
        CP2K_SHA, CP2K_TREE, TESTS_TREE
    ) or git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("CP2K checkout or tests tree differs from the pinned upstream Git tree")
    test_file = upstream / "tests" / BATCH / "TEST_FILES.toml"
    specs = tomllib.loads(test_file.read_text(encoding="utf-8"), parse_float=Decimal)
    if tuple(specs) != CASES or any(
        len(rows) != 1 or set(rows[0]) != {"matcher", "tol", "ref"} or rows[0]["matcher"] != "E_total"
        for rows in specs.values()
    ):
        raise ValueError("Pinned GAPW batch must contain exactly five original E_total tests in order")
    return specs, hashlib.sha256(test_file.read_bytes()).hexdigest()


CONTAINER_SCRIPT = r"""
set -eu
prefix=/opt/quanta-cp2k
cd "$prefix"
printf '%s  bin/cp2k.psmp\n' "$1" | sha256sum -c -
test "$(sed -n '1p' evidence/cp2k-git.txt)" = "$2"
test "$(sed -n '2p' evidence/cp2k-git.txt)" = "$3"
"$prefix/bin/cp2k.psmp" --version > /work/cp2k-version.txt
grep -Fx " Source code revision $2" /work/cp2k-version.txt
grep -Fx ' CP2K version 2026.2' /work/cp2k-version.txt
sha256sum --quiet -c evidence/installed-files.sha256
ldd bin/cp2k.psmp > /work/runtime-ldd.txt
if grep -Fq 'not found' /work/runtime-ldd.txt; then
    cat /work/runtime-ldd.txt
    exit 1
fi
normalize_ldd() {
    sed -E 's/ \(0x[[:xdigit:]]+\)//' "$1" | sort
}
normalize_ldd /work/runtime-ldd.txt > /tmp/actual-ldd.txt
normalize_ldd evidence/runtime-ldd.txt > /tmp/build-ldd.txt
cmp /tmp/actual-ldd.txt /tmp/build-ldd.txt
sha256sum evidence/cp2k-build-info.h evidence/runtime-dpkg.tsv \
    evidence/source-archives.sha256 evidence/installed-files.sha256 > /work/build-evidence.sha256
mpiexec --version > /work/mpi-version.txt
cd /work
exec python3 -u -B /cp2k-source/tests/do_regtest.py --restrictdir QS/regtest-gapw-2 \
    --skip_unittests --mpiranks 1 --ompthreads 1 --maxtasks 1 --timeout 180 \
    --mpiexec 'mpiexec -launcher fork -hosts localhost -iface lo -n {N}' \
    --workbasedir /work --cp2kdatadir "$prefix/share/cp2k/data" "$prefix/bin" psmp
"""


def run_container(image, test_root, work, binary_sha, *, architecture="arm64"):
    name = f"quanta-a04-gapw-{uuid4().hex}"
    command = [
        "docker", "run", "--rm", "--name", name, "--pull=never", "--platform", f"linux/{architecture}",
        "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--cpus", "1", "--memory", "4g", "--memory-swap", "4g",
        "--pids-limit", "128", "--ulimit", "fsize=67108864:67108864",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--env", "HOME=/work", "--env", "LC_ALL=C", "--env", "OMP_NUM_THREADS=1",
        "--env", "OPENBLAS_NUM_THREADS=1", "--env", "BLIS_NUM_THREADS=1", "--env", "MKL_NUM_THREADS=1",
        "--mount", f"type=bind,src={test_root},dst=/cp2k-source/tests,readonly",
        "--mount", f"type=bind,src={work},dst=/work", "--entrypoint", "/bin/sh", image,
        "-c", CONTAINER_SCRIPT, "quanta-a04", binary_sha, CP2K_SHA, CP2K_TREE,
    ]
    with (EVIDENCE / "regtest.log").open("wb") as log:
        try:
            return subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=CONTAINER_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)
            return 124


def capture_case_logs(work, specs):
    generated = list(work.glob("TEST-*"))
    case_dir = generated[0] / BATCH if len(generated) == 1 else None
    results = []
    for case, (spec,) in specs.items():
        result = {"case": case, "matcher": spec["matcher"], "reference_hartree": str(spec["ref"]),
                  "upstream_relative_tolerance": str(spec["tol"])}
        path = case_dir / (case + ".out") if case_dir else None
        if path and path.is_file() and not path.is_symlink() and path.stat().st_size <= CASE_LOG_LIMIT:
            raw = path.read_bytes()
            (EVIDENCE / path.name).write_bytes(raw)
            result["output_sha256"] = hashlib.sha256(raw).hexdigest()
            tokens = re.findall(r"(?m)^\s*Total energy:\s+(\S+)", raw.decode("utf-8", errors="replace"))
            if tokens:
                try:
                    value = Decimal(tokens[-1].replace("D", "E").replace("d", "e"))
                    if value.is_finite():
                        result["reported_hartree"] = str(value)
                        result["absolute_difference_hartree"] = str(abs(value - spec["ref"]))
                        # Match upstream GenericMatcher's binary64 relative comparison.
                        reference = float(spec["ref"])
                        difference = float(value) - reference
                        relative_error = abs(difference / reference if reference != 0.0 else difference)
                        if math.isfinite(relative_error):
                            result["upstream_relative_error_binary64"] = relative_error
                except InvalidOperation:
                    pass
        results.append(result)
    return results


def verify_result(log, return_code, cases):
    status = re.findall(r"(?m)^Status: (\w+)$", log)
    counts = re.findall(r"(?m)^Summary: correct: (\d+) / (\d+)(.*)$", log)
    statuses = re.findall(
        r"(?m)^\s*(\S+\.inp)\s+\S+\s+(OK|WRONG RESULT|RUNTIME FAIL|TIMED OUT|HUGE OUTPUT|N/A)\s+\(",
        log,
    )
    for row, (case, outcome) in zip(cases, statuses, strict=False):
        if row["case"] == case:
            row["upstream_status"] = outcome
    return (
        return_code == 0 and status == ["OK"] and len(counts) == 1 and counts[0][:2] == ("5", "5")
        and not any(word in counts[0][2] for word in ("wrong:", "failed:", "n/a:"))
        and statuses == [(case, "OK") for case in CASES]
        and all("upstream_relative_error_binary64" in row
                and row["upstream_relative_error_binary64"] <= float(row["upstream_relative_tolerance"])
                for row in cases)
    )


def run(architecture="arm64"):
    is_amd64 = architecture == "amd64"
    source_sha = os.environ.get("GITHUB_SHA") if is_amd64 else SOURCE_SHA
    report = {
        "scope": ("pinned_upstream_gapw_regression_on_a03_amd64_candidate" if is_amd64 else
                  "pinned_upstream_gapw_regression_on_a03_arm_candidate"),
        "status": "failure",
        "physical_validation_status": "unvalidated",
        "quanta_candidate_source": source_sha,
        "quanta_regression_source": os.environ.get("GITHUB_SHA"),
        "cp2k_source": CP2K_SHA,
        "cp2k_source_tree": CP2K_TREE,
        "cp2k_tests_tree": TESTS_TREE,
        "batch": BATCH,
        "mpi_ranks": 1,
        "omp_threads": 1,
        "workers": 1,
        "container_cpus": 1,
        "container_memory_bytes": 4 * 1024**3,
    }
    try:
        expected_machine = "x86_64" if is_amd64 else "aarch64"
        if platform.system() != "Linux" or platform.machine() != expected_machine:
            raise ValueError(f"Native Linux {expected_machine} CI is required")
        if is_amd64:
            if not source_sha or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
                raise ValueError("AMD64 GAPW requires the exact Quanta workflow source SHA")
            approved, identity = approved_amd64_candidate(source_sha)
        else:
            _, approved, identity = approved_candidate()
        upstream = (BASE / "upstream").resolve()
        specs, report["test_files_toml_sha256"] = check_upstream(upstream)
        directory = BASE / "candidate"
        if read_metadata(directory, source_sha, architecture=architecture) != approved:
            raise ValueError("Candidate metadata differs from the A03 receipt")
        metadata, proof = load_candidate(directory, source_sha, architecture=architecture)
        for key in ("locked_platform_manifest_digest", "locked_platform_manifest_bytes", "locked_config_digest"):
            if proof[key] != identity[key]:
                raise ValueError("A04 Docker image identity differs from the A03 execution")
        report["candidate"], report["image_identity"] = metadata, proof
        work = (BASE / "work").resolve()
        work.mkdir(mode=0o777)
        work.chmod(0o1777)
        report["return_code"] = run_container(proof["daemon_image_id"], upstream / "tests", work,
                                              approved["binary_sha256"], architecture=architecture)
        for name in ("cp2k-version.txt", "runtime-ldd.txt", "build-evidence.sha256", "mpi-version.txt"):
            path = work / name
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= CASE_LOG_LIMIT:
                shutil.copyfile(path, EVIDENCE / name)
        report["cases"] = capture_case_logs(work, specs)
        log = (EVIDENCE / "regtest.log").read_text(encoding="utf-8", errors="replace")
        print(log[-20000:])
        if not verify_result(log, report["return_code"], report["cases"]):
            raise ValueError("Pinned GAPW regression requires exit 0, Status: OK and all five original tests")
        report["status"] = "success"
    except (KeyError, TypeError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        report["error"] = str(error)
    finally:
        write_evidence("report.json", report)
    return 0 if report["status"] == "success" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("authorize", "run", "run-amd64"))
    operation = parser.parse_args().operation
    if operation == "authorize":
        authorize()
        return 0
    return run("amd64") if operation == "run-amd64" else run()


if __name__ == "__main__":
    raise SystemExit(main())
