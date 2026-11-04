#!/usr/bin/env python3
"""Measure consistent SQLite backup, isolated restore and worker recovery.

All data is temporary and this script uses actual bounded numerical children.
The interrupted rows are explicitly claimed fixtures, not an induced host crash.
No OCI disk, systemd reboot, Cloudflare login or volume backup is certified here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time

import quanta
from quanta import __version__
from quanta.backup import BackupError, backup_store, restore_backup, verify_backup
from quanta.hashing import canonical_bytes
from quanta.job_store import ServiceError
from quanta.run_store import validate_run_report
from quanta.service import ExecutionService
from quanta.worker import JobWorker
from verify_numerics import locked_environment
from verify_service import E0, L0, definition

ROOT = Path(__file__).resolve().parents[1]
OWNER = "operations-verification-owner"
TABLES = ("experiments", "revisions", "runs", "idempotency", "events", "artifacts", "sqlite_sequence")


def source_record() -> dict:
    package = Path(quanta.__file__).resolve().parent
    files = {"src/quanta/" + path.name: path for path in package.glob("*.py")}
    for name in ("verify_operations.py", "verify_service.py", "verify_numerics.py"):
        files["scripts/" + name] = Path(__file__).resolve().with_name(name)
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(files.items())}
    record = {"files_sha256": hashes, "source_set_sha256": hashlib.sha256(canonical_bytes(hashes)).hexdigest(),
              "source_set_hash_rule": "RFC 8785 of relative alias to actual imported Python source raw SHA256; report excluded"}
    try:
        record["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL).strip()
        record["git_worktree_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.CalledProcessError):
        record.update(git_head=None, git_worktree_dirty=None)
    return record


def database_record(path: Path) -> dict:
    """Compare every stored value, preserving JSON text and raw BLOB bytes."""
    def encode(value):
        if isinstance(value, bytes):
            return {"sqlite_type": "blob", "hex": value.hex()}
        return {"sqlite_type": type(value).__name__, "value": value}

    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        records = {table: [[encode(value) for value in row]
                    for row in db.execute("SELECT * FROM " + table + " ORDER BY rowid")]
                   for table in TABLES}
    return {"tables": {table: {"row_count": len(rows),
                "values_sha256": hashlib.sha256(canonical_bytes(rows)).hexdigest()}
                for table, rows in records.items()},
            "all_values_sha256": hashlib.sha256(canonical_bytes(records)).hexdigest()}


def wait_for_terminal(service: ExecutionService, run_id: str) -> tuple[dict, float]:
    started = time.monotonic()
    while time.monotonic() - started < 45:
        run = service.store.get_run(OWNER, run_id)
        if run["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return run, time.monotonic() - started
        time.sleep(0.05)
    raise TimeoutError("The bounded numerical measurement did not reach a terminal state")


class Measurements:
    def __init__(self, directory: str):
        self.root = Path(directory)
        self.service = ExecutionService(self.root / "source")
        self.backup = self.root / "snapshot"
        self.restored_path = self.root / "restored"
        self.revision = None
        self.original = None
        self.report = None
        self.interrupted = []
        self.original_record = None
        self.backup_manifest = None
        self.restored = None

    @staticmethod
    def case(ident, checks, **measurements):
        return {"id": ident, "status": "passed" if all(checks.values()) else "failed",
                "checks": checks, **measurements}

    def submit(self, key):
        status, run = self.service.request(OWNER, "POST", "/v1/runs",
            {"revision_id": self.revision["revision_id"]}, idempotency_key=key)
        if status != 202:
            raise ValueError("Measurement execution was not accepted")
        return run

    def o01(self):
        _, experiment = self.service.request(OWNER, "POST", "/v1/experiments", {"title": "Operational reference"})
        _, self.revision = self.service.request(OWNER, "POST",
            f"/v1/experiments/{experiment['experiment_id']}/revisions",
            {"schema_version": "0.2.0", "title": "Harmonic backup reference", "definition": definition()})
        self.original = self.submit("operations-original")
        with JobWorker(self.service.directory):
            terminal, elapsed = wait_for_terminal(self.service, self.original["run_id"])
        self.report = self.service.store.get_report(OWNER, self.original["run_id"])
        if self.report is None:
            raise ValueError("The actual numerical child did not publish a report")
        result = self.report["result"]
        payload = result["steps"][0]["payload"]
        energy_error = abs(payload["energy_j"] / E0 - 0.5 * 3.0 * (1.5 - 0.75) ** 2)
        reference_forces = [[2.25, 0.0, 0.0], [-2.25, 0.0, 0.0]]
        force_error = max(abs(value / (E0 / L0) - expected)
            for row, target in zip(payload["forces_n"], reference_forces) for value, expected in zip(row, target))

        # These rows model durable interrupted states without pretending that a
        # real host/process crash has occurred. The real worker was stopped.
        self.interrupted = [self.submit("operations-interrupted-running")]
        with (self.service.directory / "worker.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            claimed = [self.service.store.claim_next()]
        if [row["run_id"] for row in claimed] != [row["run_id"] for row in self.interrupted]:
            raise ValueError("The interrupted-state fixture did not claim the expected queue entries")

        # An open reader pins a prior view while another connection commits to
        # WAL. A bare copy of jobs.sqlite3 cannot include this later marker.
        with sqlite3.connect(self.service.store.path) as reader:
            reader.execute("PRAGMA journal_mode=WAL")
            reader.execute("PRAGMA wal_autocheckpoint=0")
            reader.execute("BEGIN")
            reader.execute("SELECT count(*) FROM experiments").fetchone()
            marker = self.service.store.create_experiment(OWNER, "Committed in live WAL before backup")
            wal_path = Path(str(self.service.store.path) + "-wal")
            wal_size = wal_path.stat().st_size if wal_path.exists() else 0
            self.original_record = database_record(self.service.store.path)
            self.backup_manifest = backup_store(self.service.directory, self.backup)
            verified = verify_backup(self.backup)
            snapshot_record = database_record(self.backup / "jobs.sqlite3")
            with sqlite3.connect((self.backup / "jobs.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
                marker_present = db.execute("SELECT title FROM experiments WHERE experiment_id=?",
                    (marker["experiment_id"],)).fetchone() == (marker["title"],)
            reader.rollback()
        checks = {"actual_numerical_child_succeeded": terminal["execution_status"] == "SUCCEEDED",
            "independent_energy_reference": math.isfinite(energy_error) and energy_error <= 1e-12,
            "independent_force_and_fixed_reaction_reference": math.isfinite(force_error) and force_error <= 1e-12,
            "original_report_evidence_valid": validate_run_report(self.report)["valid"],
            "live_wal_contains_committed_pages": wal_size > 0,
            "committed_wal_marker_in_snapshot": marker_present,
            "all_source_values_in_consistent_snapshot": snapshot_record == self.original_record,
            "manifest_passes_independent_readback": verified == self.backup_manifest}
        return self.case("O01", checks,
            reference_method="Actual numerical child and harmonic closed form; online SQLite backup while an older reader pins committed WAL pages",
            run_id=self.original["run_id"], numerical_elapsed_seconds=elapsed, wal_size_bytes=wal_size,
            energy_error_reduced=energy_error, force_error_reduced=force_error, tolerance_reduced=1e-12,
            database=self.original_record, backup_manifest=self.backup_manifest,
            interrupted_fixture_method="One durable run manually claimed under the exclusive worker lock after stopping the actual worker; no process crash induced")

    def o02(self):
        restore_summary = restore_backup(self.backup, self.restored_path)
        before_open = database_record(self.restored_path / "jobs.sqlite3")
        self.restored = ExecutionService(self.restored_path)
        revision = self.restored.store.get_revision(OWNER, self.revision["revision_id"])
        restored_report = self.restored.store.get_report(OWNER, self.original["run_id"])
        raw_plan = self.restored.store.get_job(self.original["run_id"])["plan"]
        source_plan = self.service.store.get_job(self.original["run_id"])["plan"]
        artifacts = []
        for metadata in self.service.store.get_artifacts(OWNER, self.original["run_id"]):
            original_metadata, original_bytes = self.service.store.get_artifact(OWNER, metadata["artifact_id"])
            restored_metadata, restored_bytes = self.restored.store.get_artifact(OWNER, metadata["artifact_id"])
            artifacts.append({"artifact_id": metadata["artifact_id"], "size_bytes": len(restored_bytes),
                "sha256": hashlib.sha256(restored_bytes).hexdigest(),
                "passed": original_metadata == restored_metadata and original_bytes == restored_bytes
                    and len(restored_bytes) == metadata["size_bytes"]
                    and hashlib.sha256(restored_bytes).hexdigest() == metadata["sha256"]})
        statuses = [self.restored.store.get_run(OWNER, item["run_id"])["execution_status"] for item in self.interrupted]
        checks = {"new_directory_has_identical_database_values": before_open == self.original_record,
            "immutable_revision_unchanged": revision == self.revision,
            "accepted_frozen_plan_unchanged": raw_plan == source_plan,
            "complete_report_unchanged_and_valid": restored_report == self.report and validate_run_report(restored_report)["valid"],
            "every_original_artifact_byte_preserved": bool(artifacts) and all(row["passed"] for row in artifacts),
            "restore_did_not_recover_or_run_jobs": statuses == ["RUNNING"],
            "source_values_unchanged": database_record(self.service.store.path) == self.original_record}
        return self.case("O02", checks, reference_method="Every SQLite table value and raw artifact byte compared before starting any restored worker",
            restore_summary=restore_summary, restored_database=before_open,
            statuses_before_worker_start=statuses, artifacts=artifacts)

    def o03(self):
        original_terminal = self.restored.store.get_run(OWNER, self.original["run_id"])
        with JobWorker(self.restored.directory):
            recovered = [self.restored.store.get_run(OWNER, item["run_id"]) for item in self.interrupted]
            no_fabricated = all(self.restored.store.get_report(OWNER, item["run_id"]) is None
                and not item["artifacts"] for item in recovered)
            competing = None
            other = JobWorker(self.restored.directory)
            try:
                other.start()
            except ServiceError as exc:
                competing = {"status": exc.status, "code": exc.code}
            else:
                other.stop()
            status, replay = self.restored.request(OWNER, "POST", f"/v1/runs/{self.original['run_id']}/replay", {},
                idempotency_key="operations-restored-replay")
            terminal, elapsed = wait_for_terminal(self.restored, replay["run_id"])
            replay_report = self.restored.store.get_report(OWNER, replay["run_id"])
        if replay_report is None:
            raise ValueError("The restored environment did not publish a replay report")
        # The service permits only one active claim. Exercise the cancellation
        # recovery ordering separately after the real replay has completed.
        _, cancelling = self.restored.request(OWNER, "POST", "/v1/runs",
            {"revision_id": self.revision["revision_id"]}, idempotency_key="operations-interrupted-cancelling")
        with (self.restored.directory / "worker.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            claimed = self.restored.store.claim_next()
            if claimed is None or claimed["run_id"] != cancelling["run_id"]:
                raise ValueError("The cancellation fixture did not claim its run")
            self.restored.store.cancel(OWNER, cancelling["run_id"])
        with JobWorker(self.restored.directory):
            recovered.append(self.restored.store.get_run(OWNER, cancelling["run_id"]))
            no_fabricated = no_fabricated and self.restored.store.get_report(OWNER, cancelling["run_id"]) is None \
                and not recovered[-1]["artifacts"]
        result, source = replay_report["result"], self.report["result"]
        hashes = ("input_sha256", "resolved_input_sha256", "execution_fingerprint")
        checks = {"exclusive_restored_worker": competing == {"status": 409, "code": "WORKER_ACTIVE"},
            "interrupted_running_failed": recovered[0]["execution_status"] == "FAILED",
            "interrupted_cancellation_cancelled": recovered[1]["execution_status"] == "CANCELLED",
            "interruption_diagnostics_retained": all(any(error["code"] == "ENGINE_FAILURE" for error in row["diagnostics"]) for row in recovered),
            "no_checkpoint_result_fabricated": no_fabricated,
            "historical_success_unchanged": self.restored.store.get_run(OWNER, self.original["run_id"]) == original_terminal,
            "new_replay_run_accepted": status == 202 and replay["run_id"] != self.original["run_id"],
            "actual_replay_child_succeeded": terminal["execution_status"] == "SUCCEEDED",
            "replay_result_evidence_valid": validate_run_report(replay_report)["valid"],
            "same_scientific_and_execution_hashes": all(result[name] == source[name] for name in hashes),
            "same_computed_payload": result["steps"][0]["payload"] == source["steps"][0]["payload"],
            "replay_source_retained": result["provenance"]["replay_of"] == self.original["run_id"]}
        return self.case("O03", checks,
            reference_method="New exclusive worker recovers a manually claimed RUNNING fixture and executes a replay child; a later separate worker start recovers a manually claimed CANCEL_REQUESTED fixture",
            recovered_statuses=[row["execution_status"] for row in recovered],
            fixture_recovery_events=[row["events"] for row in recovered], competing_worker=competing,
            replay_run_id=replay["run_id"], source_run_id=self.original["run_id"],
            replay_elapsed_seconds=elapsed, preserved_hashes={name: result[name] for name in hashes})

    def o04(self):
        occupied = self.root / "occupied"
        occupied.mkdir()
        sentinel = occupied / "keep.bin"
        sentinel.write_bytes(b"original destination must survive\x00\xff")
        before = sentinel.read_bytes()
        refusals = {}
        for name, operation in (("backup_existing_destination", lambda: backup_store(self.service.directory, occupied)),
                                ("restore_existing_destination", lambda: restore_backup(self.backup, occupied))):
            try:
                operation()
            except BackupError:
                refusals[name] = True
            else:
                refusals[name] = False
        corrupt = self.root / "tampered-snapshot"
        shutil.copytree(self.backup, corrupt)
        database = corrupt / "jobs.sqlite3"
        with database.open("r+b") as stream:
            stream.seek(-1, 2)
            value = stream.read(1)
            stream.seek(-1, 2)
            stream.write(bytes([value[0] ^ 1]))
        rejected_destination = self.root / "must-not-publish"
        for name, operation in (("tampered_snapshot_verification", lambda: verify_backup(corrupt)),
                                ("tampered_snapshot_restore", lambda: restore_backup(corrupt, rejected_destination))):
            try:
                operation()
            except BackupError:
                refusals[name] = True
            else:
                refusals[name] = False
        checks = {**refusals,
            "existing_destination_bytes_unchanged": sentinel.read_bytes() == before and list(occupied.iterdir()) == [sentinel],
            "invalid_restore_not_published": not rejected_destination.exists(),
            "original_snapshot_still_verifies": verify_backup(self.backup) == self.backup_manifest,
            "original_source_values_still_unchanged": database_record(self.service.store.path) == self.original_record}
        return self.case("O04", checks,
            reference_method="Existing-target refusal and single-byte tampering of a copied backup; original source and known-good snapshot remain intact")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    before, environment, cases = source_record(), locked_environment(), []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="quanta-operations-verification-") as directory:
        measurements = Measurements(directory)
        for method in (measurements.o01, measurements.o02, measurements.o03, measurements.o04):
            try:
                case = method()
                json.dumps(case, allow_nan=False)
            except Exception as exc:
                case = {"id": method.__name__.upper(), "status": "failed",
                        "error_type": type(exc).__name__, "error": str(exc)[:400]}
            cases.append(case)
    after = source_record()
    stable = before["source_set_sha256"] == after["source_set_sha256"]
    passed = environment["valid"] and stable and len(cases) == 4 and all(case["status"] == "passed" for case in cases)
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if passed else "failed", "package_version": __version__,
        "scope": "Local consistent SQLite snapshot, isolated logical restore and new exclusive worker with actual numerical replay",
        "elapsed_seconds": time.monotonic() - started,
        "measurement_metadata": {"origin": "actual_executed_checks", "case_namespace": "O01--O04",
            "source_unchanged_during_measurement": stable, "oci_deployment_verified": False,
            "oci_volume_restore_verified": False, "host_mount_identity_verified": False,
            "systemd_restart_verified": False, "process_crash_induced": False,
            "checkpoint_resume": False},
        "cases": cases, "environment": environment, "code_source": after,
        "physical_validation_status": "unvalidated",
        "limitations": ["Temporary local directories test the logical database restore; no OCI volume is created, mounted or restored.",
            "Interrupted states are explicit manual-claim fixtures under the worker lock, not a claim of a host/process crash or checkpoint resume.",
            "Replay requires the same frozen implementation, dependencies and contracts; this check does not certify a cross-architecture replay.",
            "No cloud login, Tunnel, public TLS, systemd reboot, remote backup durability, measured RPO/RTO or physical model accuracy is certified."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output),
                          "cases": {case["id"]: case["status"] for case in cases}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
