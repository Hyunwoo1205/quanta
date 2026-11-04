"""Real WAL snapshots, checked bytes, and non-destructive publication failures."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from quanta import backup
from quanta.backup import BackupError, backup_store, restore_backup, verify_backup
from quanta.job_store import JobStore
from quanta.planning import plan_experiment
from quanta.workflow import run_experiment


@pytest.fixture
def populated(tmp_path):
    store = JobStore(tmp_path / "source")
    experiment = store.create_experiment("local", "Private experiment")
    source = json.loads((Path(__file__).resolve().parents[1] / "examples" / "pair_energy_forces.json").read_text())
    source["definition"]["system"]["particles"][0]["position_m"][0] = -0.0
    revision = store.create_revision("local", experiment["experiment_id"], source)
    plan = plan_experiment(revision)
    assert plan["valid"]
    run, _ = store.submit("local", revision["revision_id"], plan, idempotency_key="backup-test")
    return store, experiment, revision, run


def rewrite_manifest(directory, update):
    path = directory / "manifest.json"
    value = json.loads(path.read_text())
    update(value)
    path.write_text(json.dumps(value))


def reseal(directory):
    raw = (directory / "jobs.sqlite3").read_bytes()
    rewrite_manifest(directory, lambda value: value["database"].update(
        size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))


def test_wal_snapshot_contains_committed_rows_and_restore_preserves_pending_work(populated, tmp_path):
    store, experiment, revision, run = populated
    # Keep WAL live so copying the main file alone would miss this commit.
    writer = sqlite3.connect(store.path, isolation_level=None)
    try:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE experiments SET title='Committed only in WAL'")
        assert (store.directory / "jobs.sqlite3-wal").stat().st_size > 0
        before = store.get_run("local", run["run_id"])
        manifest = backup_store(store.directory, tmp_path / "snapshot")
        assert manifest["counts"]["runs"] == 1
        assert manifest["run_status_counts"] == {"QUEUED": 1}
        assert verify_backup(tmp_path / "snapshot") == manifest
        restored = restore_backup(tmp_path / "snapshot", tmp_path / "restored")
        assert restored["worker_started"] is False and restored["replay_performed"] is False
        assert {p.name for p in (tmp_path / "restored").iterdir()} == {"jobs.sqlite3"}
        assert (tmp_path / "restored").stat().st_mode & 0o777 == 0o700
        assert (tmp_path / "restored" / "jobs.sqlite3").stat().st_mode & 0o777 == 0o600
        reopened = JobStore(tmp_path / "restored")
        assert reopened.get_experiment("local", experiment["experiment_id"])["title"] == "Committed only in WAL"
        assert reopened.get_run("local", run["run_id"]) == before
        assert reopened.get_revision("local", revision["revision_id"]) == revision
        assert str(reopened.get_revision("local", revision["revision_id"])["definition"]["system"]["particles"][0]["position_m"][0]) == "-0.0"
        assert store.get_run("local", run["run_id"]) == before
    finally:
        writer.close()


def test_completed_report_and_every_artifact_survive_exactly(populated, tmp_path):
    store, _, revision, run = populated
    store.claim_next()
    report = run_experiment(revision, run_id=run["run_id"])
    store.finish(run["run_id"], report)
    before = store.get_run("local", run["run_id"], include_report=True)
    expected = {row["artifact_id"]: store.get_artifact("local", row["artifact_id"])
                for row in before["artifacts"]}
    assert expected
    backup_store(store.directory, tmp_path / "snapshot")
    restore_backup(tmp_path / "snapshot", tmp_path / "restored")
    reopened = JobStore(tmp_path / "restored")
    assert reopened.get_run("local", run["run_id"], include_report=True) == before
    assert {ident: reopened.get_artifact("local", ident) for ident in expected} == expected
    # Even a rewritten outer DB checksum cannot hide corrupt artifact bytes.
    with sqlite3.connect(tmp_path / "snapshot" / "jobs.sqlite3") as db:
        ident, raw = db.execute("SELECT artifact_id,data FROM artifacts LIMIT 1").fetchone()
        db.execute("UPDATE artifacts SET data=? WHERE artifact_id=?", (bytes([raw[0] ^ 1]) + raw[1:], ident))
    reseal(tmp_path / "snapshot")
    with pytest.raises(BackupError, match="artifact bytes"):
        verify_backup(tmp_path / "snapshot")


def test_snapshot_is_consistent_during_concurrent_transactions(populated, tmp_path):
    store, _, _, _ = populated
    ready = threading.Event()
    stop = threading.Event()
    def write():
        db = sqlite3.connect(store.path)
        db.execute("PRAGMA journal_mode=WAL")
        for index in range(1000):
            db.execute("INSERT INTO experiments(experiment_id,owner,title,created_at) VALUES(?,?,?,?)",
                       (f"concurrent-{index}", "local", "concurrent", index))
            db.commit()
            ready.set()
            if stop.is_set():
                break
        db.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        writer = pool.submit(write)
        assert ready.wait(5)
        try:
            manifest = backup_store(store.directory, tmp_path / "snapshot")
            assert verify_backup(tmp_path / "snapshot") == manifest
            assert manifest["counts"]["experiments"] >= 2
        finally:
            stop.set()
            writer.result(timeout=5)


@pytest.mark.parametrize("operation", [backup_store, restore_backup])
def test_existing_empty_directory_file_or_symlink_is_never_overwritten(populated, tmp_path, operation):
    store, _, _, _ = populated
    source = store.directory
    if operation is restore_backup:
        source = tmp_path / "snapshot"
        backup_store(store.directory, source)
    for kind in ("directory", "file", "symlink"):
        target = tmp_path / kind
        if kind == "directory":
            target.mkdir()
        elif kind == "file":
            target.write_bytes(b"preserve")
        else:
            target.symlink_to(tmp_path / "absent")
        with pytest.raises(BackupError):
            operation(source, target)
        if kind == "directory":
            assert list(target.iterdir()) == []
        elif kind == "file":
            assert target.read_bytes() == b"preserve"
        else:
            assert target.is_symlink()


def test_concurrently_created_destination_is_not_replaced(populated, tmp_path, monkeypatch):
    store, _, _, _ = populated
    original = backup._publish
    def publish(stage, target):
        target.mkdir()
        original(stage, target)
    monkeypatch.setattr(backup, "_publish", publish)
    with pytest.raises(BackupError, match="already exist"):
        backup_store(store.directory, tmp_path / "snapshot")
    assert list((tmp_path / "snapshot").iterdir()) == []
    assert not list(tmp_path.glob(".quanta-snapshot-*"))


def test_missing_source_is_not_created_and_nested_paths_are_rejected(populated, tmp_path):
    store, _, _, _ = populated
    missing = tmp_path / "missing"
    with pytest.raises(BackupError):
        backup_store(missing, tmp_path / "snapshot")
    assert not missing.exists()
    with pytest.raises(BackupError, match="separate"):
        backup_store(store.directory, store.directory / "snapshot")
    alias = tmp_path / "alias"
    alias.symlink_to(store.directory, target_is_directory=True)
    with pytest.raises(BackupError, match="symbolic"):
        backup_store(alias, tmp_path / "snapshot")


@pytest.mark.parametrize("mutation", ["database", "path", "count", "extra", "duplicate"])
def test_manifest_and_database_tampering_is_rejected(populated, tmp_path, mutation):
    store, _, _, _ = populated
    source = tmp_path / "snapshot"
    backup_store(store.directory, source)
    if mutation == "database":
        with (source / "jobs.sqlite3").open("ab") as stream:
            stream.write(b"tamper")
    elif mutation == "path":
        rewrite_manifest(source, lambda value: value["database"].update(name="../source/jobs.sqlite3"))
    elif mutation == "count":
        rewrite_manifest(source, lambda value: value["counts"].update(runs=100))
    elif mutation == "extra":
        (source / "worker.lock").touch()
    else:
        path = source / "manifest.json"
        path.write_text(path.read_text().replace('"version": 1', '"version": 1,"version": 1'))
    with pytest.raises(BackupError):
        verify_backup(source)
    with pytest.raises(BackupError):
        restore_backup(source, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_resealed_foreign_key_corruption_and_wrong_schema_are_rejected(populated, tmp_path):
    store, _, _, _ = populated
    source = tmp_path / "snapshot"
    backup_store(store.directory, source)
    with sqlite3.connect(source / "jobs.sqlite3") as db:
        db.execute("DELETE FROM experiments")  # Foreign keys deliberately off.
    reseal(source)
    with pytest.raises(BackupError, match="foreign-key"):
        verify_backup(source)
    arbitrary = tmp_path / "arbitrary"
    arbitrary.mkdir()
    with sqlite3.connect(arbitrary / "jobs.sqlite3") as db:
        db.execute("CREATE TABLE runs(data TEXT)")
    with pytest.raises(BackupError, match="schema"):
        backup_store(arbitrary, tmp_path / "other-snapshot")


def test_disk_budget_and_timeout_leave_no_partial_snapshot(populated, tmp_path, monkeypatch):
    store, _, _, _ = populated
    with pytest.raises(BackupError, match="free space"):
        backup_store(store.directory, tmp_path / "snapshot", min_free_bytes=2**63)
    original = backup._Budget.check
    calls = 0
    def expire(self):
        nonlocal calls
        calls += 1
        if calls >= 1:
            raise BackupError("Snapshot operation exceeded its time limit")
        original(self)
    monkeypatch.setattr(backup._Budget, "check", expire)
    with pytest.raises(BackupError, match="time limit"):
        backup_store(store.directory, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()
    assert not list(tmp_path.glob(".quanta-snapshot-*"))


def test_sqlite_connection_failure_is_a_public_backup_error(populated, tmp_path, monkeypatch):
    store, _, _, _ = populated
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("unable to open database")
    monkeypatch.setattr(backup.sqlite3, "connect", fail)
    with pytest.raises(BackupError, match="SQLite"):
        backup_store(store.directory, tmp_path / "snapshot")


def test_locked_database_obeys_the_actual_timeout(populated, tmp_path):
    store, _, _, _ = populated
    with sqlite3.connect(store.path, isolation_level=None) as writer:
        writer.execute("PRAGMA journal_mode=DELETE")
        writer.execute("BEGIN EXCLUSIVE")
        try:
            with pytest.raises(BackupError, match="time limit"):
                backup_store(store.directory, tmp_path / "snapshot", timeout_seconds=0.01)
        finally:
            writer.rollback()
    assert not (tmp_path / "snapshot").exists()
