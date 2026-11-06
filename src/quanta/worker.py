"""One durable numerical queue, with one bounded child process per execution."""
from __future__ import annotations

import argparse
from copy import deepcopy
import fcntl
import hashlib
import math
import os
from pathlib import Path
import resource
import subprocess
import sys
import threading
import time

from .job_store import JobStore, ServiceError, TERMINAL


def _execution_policy(job: dict) -> dict:
    """Bound a child by its selected contract and captured admitted policy.

    Current operational protection may become stricter than admission, but a
    changed installation cannot widen the frozen limits of a queued execution.
    The legacy default constructor remains explicit for existing 0.2 jobs.
    """
    from .parsing import parse_json
    from .registry import ContractRegistry, experiment_registry

    try:
        version = job["revision"]["schema_version"]
        if version == "0.2.0":
            registry = ContractRegistry()
        elif version == "0.4.0":
            registry = experiment_registry(job["revision"])
            if registry.validate_integrity():
                raise ValueError("Selected experiment registry failed integrity")
        else:
            raise ValueError("Unsupported accepted experiment version")
        current = registry.resource_policy["common_execution"]
        plan = job["plan"]
        ref = plan["execution_manifests"]["effective_resource_profile_sha256"]
        raw = plan["captured_artifacts"][ref].encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != ref:
            raise ValueError("Captured execution policy failed its admitted digest")
        captured = parse_json(raw)["common_execution"]
        result = deepcopy(current)
        for key, ceiling in (("wall_seconds_per_run", 120), ("memory_mib_per_run", 1024)):
            values = (current[key], captured[key])
            if any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(value) or value <= 0 for value in values):
                raise ValueError("Invalid child execution ceiling")
            result[key] = min(ceiling, *values)
        return result
    except (KeyError, TypeError, ValueError, OverflowError, OSError, AttributeError) as exc:
        raise ServiceError(409, "REGISTRY_SNAPSHOT_UNAVAILABLE",
                           "The accepted child resource policy is unavailable") from exc


def _cancelled_report(report: dict) -> dict:
    """Cancellation won the publication transaction after the kernel returned."""
    value = deepcopy(report)
    result = value["result"]
    result.update(execution_status="CANCELLED", partial=True)
    if not any(e["code"] == "CANCELLED" for e in result["errors"]):
        result["errors"].append({"code": "CANCELLED", "category": "runtime",
            "message": "Cancellation committed before result publication", "path": None,
            "step_id": None, "branch_index": None, "retryable": False, "details": {}})
    return value


def execute_job(directory: str | Path, run_id: str) -> None:
    """Trusted child entry point; never executes source strings from the database."""
    from .planning import plan_experiment
    from .run_store import validate_run_report
    from .service import same_plan
    from .workflow import run_experiment, WorkflowCancelled

    store = JobStore(directory)
    job = store.get_job(run_id)
    if job["execution_status"] not in {"RUNNING", "CANCEL_REQUESTED"}:
        return
    current = plan_experiment(job["revision"])
    if not current["valid"] or not same_plan(job["plan"], current):
        store.fail(run_id, "REGISTRY_SNAPSHOT_UNAVAILABLE", "The accepted frozen implementation is unavailable")
        return

    def control():
        if store.cancellation_requested(run_id):
            raise WorkflowCancelled("Cancellation was requested by the authenticated owner")

    report = run_experiment(job["revision"], replay_of=job["replay_of"], run_id=run_id,
        control_check=control, progress_callback=lambda progress: store.update_progress(run_id, progress))
    if report["result"] is None:
        error = next(iter(report["errors"]), {"code": "ENGINE_FAILURE", "message": "The engine refused execution"})
        store.fail(run_id, error["code"], error["message"])
        return
    if not same_plan(job["plan"], report["plan"]):
        store.fail(run_id, "REGISTRY_SNAPSHOT_UNAVAILABLE", "The executed plan differs from the accepted plan")
        return
    checked = validate_run_report(report)
    if not checked["valid"]:
        store.fail(run_id, "ENGINE_FAILURE", "Computed execution evidence failed integrity verification")
        return
    status = store.finish(run_id, report)
    if status["execution_status"] == "CANCEL_REQUESTED":
        cancelled = _cancelled_report(report)
        if not validate_run_report(cancelled)["valid"]:
            store.fail(run_id, "ENGINE_FAILURE", "Cancellation evidence failed integrity verification")
        else:
            store.finish(run_id, cancelled)


class JobWorker:
    """Exclusive supervisor; subprocess isolation does not imply checkpoint resume."""
    def __init__(self, directory: str | Path, *, poll_seconds: float = 0.05, cancellation_grace: float = 5):
        self.directory = Path(directory).resolve()
        self.store = JobStore(self.directory)
        self.poll_seconds = poll_seconds
        self.cancellation_grace = cancellation_grace
        self._stop = threading.Event()
        self._thread = None
        self._lock = None
        self._child = None
        self.error = None

    @property
    def healthy(self):
        return (self._thread is not None and self._thread.is_alive() and self.error is None
                and not self._stop.is_set() and self._lock is not None)

    def start(self):
        if self._thread is not None:
            raise RuntimeError("This worker has already been started")
        self._lock = (self.directory / "worker.lock").open("a+b")
        os.chmod(self.directory / "worker.lock", 0o600)
        try:
            fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._lock.close()
            self._lock = None
            raise ServiceError(409, "WORKER_ACTIVE", "Another numerical worker owns this store") from exc
        try:
            self.store.recover_interrupted()
            self._thread = threading.Thread(target=self._loop, name="quanta-worker", daemon=True)
            self._thread.start()
        except BaseException:
            self._lock.close()
            self._lock = None
            raise
        return self

    def _loop(self):
        try:
            while not self._stop.is_set():
                job = self.store.claim_next()
                if job is None:
                    self._stop.wait(self.poll_seconds)
                    continue
                self._run_child(job)
        except Exception as exc:
            # Make failure inspectable to the service process without exposing inputs.
            self.error = type(exc).__name__

    def _run_child(self, job):
        try:
            policy = _execution_policy(job)
        except ServiceError as exc:
            self.store.fail(job["run_id"], exc.code, str(exc))
            return
        wall_limit = float(policy["wall_seconds_per_run"])
        environment = os.environ.copy()
        for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
            environment[name] = "1"
        environment.pop("QUANTA_API_TOKEN", None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        start = time.monotonic()
        cancelled_at = None
        try:
            # The child retains the lock descriptor. If the supervisor dies, a
            # replacement cannot recover its still-running job concurrently.
            self._child = subprocess.Popen([sys.executable, "-m", "quanta.worker", "--directory",
                str(self.directory), "--run-id", job["run_id"]], cwd=self.directory, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(self._lock.fileno(),))
            reason = None
            while self._child.poll() is None:
                elapsed = time.monotonic() - start
                if self._stop.is_set() and not self.store.cancellation_requested(job["run_id"]):
                    self.store.cancel(job["owner"], job["run_id"])
                if self.store.cancellation_requested(job["run_id"]):
                    if cancelled_at is None:
                        cancelled_at = time.monotonic()
                    if time.monotonic() - cancelled_at >= self.cancellation_grace:
                        reason = "Cancellation required a forced process stop; no uncommitted results were retained"
                        break
                if elapsed >= wall_limit:
                    reason = "The numerical child exceeded the enforced process wall-time limit"
                    break
                time.sleep(self.poll_seconds)
            if reason:
                self._child.kill()
            self._child.wait(timeout=5)
            current = self.store.get_job(job["run_id"])
            if current["execution_status"] not in TERMINAL:
                code = "CANCELLED" if current["execution_status"] == "CANCEL_REQUESTED" else "RESOURCE_LIMIT" if reason else "ENGINE_FAILURE"
                self.store.fail(job["run_id"], code, reason or "The numerical child exited without a committed result")
        except Exception:
            if self._child is not None and self._child.poll() is None:
                self._child.kill()
                self._child.wait(timeout=5)
            self.store.fail(job["run_id"], "ENGINE_FAILURE", "The numerical child could not complete execution")
        finally:
            self._child = None

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.cancellation_grace + 10)
            if self._thread.is_alive():
                raise RuntimeError("The numerical supervisor did not stop")
        if self._lock is not None:
            # Close rather than LOCK_UN: a surviving child must retain the lock.
            self._lock.close()
            self._lock = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Internal bounded numerical worker")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        policy = _execution_policy(JobStore(args.directory).get_job(args.run_id))
        memory = int(policy["memory_mib_per_run"] * 1024 * 1024)
        cpu = math.ceil(policy["wall_seconds_per_run"])
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        execute_job(args.directory, args.run_id)
    except ServiceError as exc:
        JobStore(args.directory).fail(args.run_id, exc.code, str(exc))
        return 2
    except Exception:
        JobStore(args.directory).fail(args.run_id, "ENGINE_FAILURE", "The numerical child failed before publication")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
