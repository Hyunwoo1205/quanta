"""Consistent, checked SQLite snapshots; restoration never opens an active store.

The manifest detects accidental corruption, not a malicious party able to replace
both files. Keep snapshots private and retain the matching trusted runtime for
exact replay. No SQL or Python source from the snapshot is executed.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import ctypes
from datetime import datetime, timezone
import errno
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time

from . import __version__

MIN_FREE_BYTES = 128 * 1024 * 1024
_DATABASE = "jobs.sqlite3"
_MANIFEST = "manifest.json"
_TABLES = ("experiments", "revisions", "runs", "idempotency", "events", "artifacts")
# Whitespace-normalized sqlite_schema for the service schema introduced in 0.6.
# A new schema requires an explicit reader/migration policy, never auto-creation.
_SCHEMA_SHA256 = "440e81d9bf3b895feb6eb56cc954facd2256c05a2d0649980cb608e3da782b1e"
_STATUSES = {"QUEUED", "RUNNING", "CANCEL_REQUESTED", "SUCCEEDED", "FAILED", "CANCELLED"}


class BackupError(ValueError):
    """The snapshot could not be safely created, verified, or restored."""


def _normalize_errors(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, sqlite3.Error) as exc:
            raise BackupError("Snapshot filesystem or SQLite operation failed") from exc
    return checked


class _Budget:
    def __init__(self, timeout_seconds):
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 3600):
            raise BackupError("Timeout must be finite and between 0 and 3600 seconds")
        self.end = time.monotonic() + timeout_seconds

    def check(self):
        if time.monotonic() >= self.end:
            raise BackupError("Snapshot operation exceeded its time limit")


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise BackupError("Duplicate JSON field in snapshot metadata")
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(BackupError("Nonfinite JSON value")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BackupError("Invalid snapshot JSON metadata") from exc


def _safe_path(path, *, exists=True, directory=False):
    value = Path(os.path.abspath(os.fspath(path)))
    # resolve() alone hides symlinks, including a dangling destination symlink.
    for part in [*reversed(value.parents), value]:
        if part.is_symlink():
            raise BackupError("Snapshot paths must not contain symbolic links")
    if exists:
        try:
            info = value.stat()
        except OSError as exc:
            raise BackupError("The source or parent path does not exist") from exc
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(info.st_mode):
            raise BackupError("Snapshot path has an unsupported file type")
    return value


def _destination(source, destination):
    target = _safe_path(destination, exists=False)
    _safe_path(target.parent, directory=True)
    if target.exists():
        raise BackupError("Snapshot destination must not already exist")
    if source == target or source in target.parents or target in source.parents:
        raise BackupError("Source and destination must be separate directory trees")
    return target


def _free(parent, minimum, additional=0):
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
        raise BackupError("The minimum free space must be a nonnegative byte count")
    if shutil.disk_usage(parent).free < minimum + additional:
        raise BackupError("Insufficient free space for a checked snapshot")


def _sync(path, *, directory=False):
    flags = os.O_RDONLY | (os.O_DIRECTORY if directory else 0)
    with_os = os.open(path, flags)
    try:
        os.fsync(with_os)
    finally:
        os.close(with_os)


def _publish(stage, destination):
    # POSIX rename may overwrite a concurrently created empty directory. Linux's
    # no-replace primitive is required rather than a racy exists()+rename().
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise BackupError("Atomic no-replace publication is unavailable on this host")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise BackupError("Snapshot destination must not already exist")
        raise BackupError("Atomic snapshot publication failed") from OSError(code, os.strerror(code))
    _sync(destination.parent, directory=True)


@contextmanager
def _staging(target):
    path = Path(tempfile.mkdtemp(prefix=".quanta-snapshot-", dir=target.parent))
    try:
        yield path
    finally:
        # After publication this name no longer exists; never remove destination.
        if path.exists():
            shutil.rmtree(path)


@contextmanager
def _read_database(path, budget, *, immutable=False):
    uri = path.as_uri() + "?mode=ro" + ("&immutable=1" if immutable else "")
    db = None
    try:
        db = sqlite3.connect(uri, uri=True, timeout=0.1, isolation_level=None)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.set_progress_handler(lambda: int(time.monotonic() >= budget.end), 10000)
        yield db
    except sqlite3.Error as exc:
        budget.check()
        raise BackupError("SQLite snapshot could not be read or validated") from exc
    finally:
        if db is not None:
            db.close()


def _hash_file(path, budget):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            budget.check()
            size += len(chunk)
            digest.update(chunk)
    return {"name": _DATABASE, "size_bytes": size, "sha256": digest.hexdigest()}


def _schema(db):
    rows = [[a, b, c, " ".join(d.split()) if d is not None else None]
            for a, b, c, d in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema "
                                       "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != _SCHEMA_SHA256:
        raise BackupError("The database does not have the supported Quanta service schema")


def _validate_database(path, budget):
    with _read_database(path, budget, immutable=True) as db:
        budget.check()
        _schema(db)
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise BackupError("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise BackupError("SQLite foreign-key check failed")
        counts = {table: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in _TABLES}
        statuses = dict(db.execute("SELECT status,count(*) FROM runs GROUP BY status"))
        if not set(statuses) <= _STATUSES:
            raise BackupError("Snapshot contains an unsupported execution status")
        if db.execute("SELECT 1 FROM revisions v JOIN experiments e USING(experiment_id) "
                      "WHERE v.owner!=e.owner LIMIT 1").fetchone() or db.execute(
                "SELECT 1 FROM runs r JOIN revisions v USING(revision_id) WHERE r.owner!=v.owner LIMIT 1").fetchone():
            raise BackupError("Snapshot owner relationships are inconsistent")
        for ident, experiment, envelope in db.execute("SELECT revision_id,experiment_id,envelope FROM revisions"):
            budget.check()
            value = _json(envelope)
            if (not isinstance(value, dict) or value.get("revision_id") != ident
                    or value.get("experiment_id") != experiment):
                raise BackupError("Snapshot revision identities are inconsistent")
        # Stored numerical reports can belong to an older trusted runtime. Do not
        # reinterpret them under the current implementation or silently replan.
        for ident, revision, plan, progress, diagnostics, report in db.execute(
                "SELECT run_id,revision_id,plan,progress,diagnostics,report FROM runs"):
            budget.check()
            if (not isinstance(_json(plan), dict) or not isinstance(_json(progress), dict)
                    or not isinstance(_json(diagnostics), list)):
                raise BackupError("Snapshot run metadata is malformed")
            if report is not None:
                value = _json(report)
                result = value.get("result") if isinstance(value, dict) else None
                if (not isinstance(result, dict) or result.get("run_id") != ident
                        or result.get("revision_id") != revision):
                    raise BackupError("Snapshot result identities are inconsistent")
        for rowid, ident, run, metadata, size in db.execute(
                "SELECT rowid,artifact_id,run_id,metadata,length(data) FROM artifacts"):
            budget.check()
            value = _json(metadata)
            if (not isinstance(value, dict) or value.get("artifact_id") != ident
                    or type(value.get("size_bytes")) is not int or value["size_bytes"] != size
                    or not isinstance(value.get("sha256"), str)):
                raise BackupError("Snapshot artifact metadata is inconsistent")
            digest = hashlib.sha256()
            with db.blobopen("artifacts", "data", rowid, readonly=True) as blob:
                while chunk := blob.read(1024 * 1024):
                    budget.check()
                    digest.update(chunk)
            if digest.hexdigest() != value["sha256"]:
                raise BackupError("Snapshot artifact bytes failed their SHA-256 check")
        return {"counts": counts, "run_status_counts": statuses}


def _write_manifest(stage, manifest):
    raw = (json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    with (stage / _MANIFEST).open("xb") as stream:
        os.chmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _verify(directory, budget):
    source = _safe_path(directory, directory=True)
    if {p.name for p in source.iterdir()} != {_DATABASE, _MANIFEST}:
        raise BackupError("A snapshot must contain only its database and manifest")
    database = _safe_path(source / _DATABASE)
    metadata = _safe_path(source / _MANIFEST)
    if metadata.stat().st_size > 1024 * 1024:
        raise BackupError("Snapshot manifest exceeds the byte limit")
    value = _json(metadata.read_bytes())
    expected = {"format", "version", "created_at", "quanta_version", "sqlite_version", "schema_sha256",
                "database", "checks", "counts", "run_status_counts"}
    if (not isinstance(value, dict) or set(value) != expected
            or value["format"] != "quanta.sqlite.backup" or type(value["version"]) is not int or value["version"] != 1
            or value["schema_sha256"] != _SCHEMA_SHA256
            or value["checks"] != {"integrity": "ok", "foreign_keys": "ok", "artifact_bytes": "ok"}
            or not all(isinstance(value[key], str) for key in ("created_at", "quanta_version", "sqlite_version"))):
        raise BackupError("Unsupported or malformed snapshot manifest")
    record = value["database"]
    if (not isinstance(record, dict) or set(record) != {"name", "size_bytes", "sha256"}
            or record["name"] != _DATABASE or type(record["size_bytes"]) is not int or record["size_bytes"] <= 0
            or not isinstance(record["sha256"], str) or re.fullmatch("[0-9a-f]{64}", record["sha256"]) is None):
        raise BackupError("Malformed snapshot database descriptor")
    budget.check()
    if database.stat().st_size != record["size_bytes"] or _hash_file(database, budget) != record:
        raise BackupError("Snapshot database bytes differ from its manifest")
    checked = _validate_database(database, budget)
    if any(value[key] != checked[key] for key in checked):
        raise BackupError("Snapshot record counts differ from its manifest")
    if _hash_file(database, budget) != record:
        raise BackupError("Snapshot database changed during verification")
    return source, value


@_normalize_errors
def backup_store(store_directory, destination, *, timeout_seconds=60, min_free_bytes=MIN_FREE_BYTES):
    """Make a bounded, live SQLite backup in a new private destination directory.

    All committed WAL records are included at a consistent SQLite snapshot point.
    A successful online backup does not stop admission or drain queued work.
    """
    budget = _Budget(timeout_seconds)
    source = _safe_path(store_directory, directory=True)
    database = _safe_path(source / _DATABASE)
    target = _destination(source, destination)
    with _read_database(database, budget) as db:
        _schema(db)
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        estimate = db.execute("PRAGMA page_count").fetchone()[0] * page_size
        _free(target.parent, min_free_bytes, estimate)
        with _staging(target) as stage:
            output = stage / _DATABASE
            with closing(sqlite3.connect(output, timeout=0.1)) as snapshot:
                os.chmod(output, 0o600)
                snapshot.execute("PRAGMA synchronous=FULL")
                def progress(status, remaining, total):
                    budget.check()
                    _free(stage, min_free_bytes, remaining * page_size)
                db.backup(snapshot, pages=128, progress=progress, sleep=0.01)
                snapshot.execute("PRAGMA journal_mode=DELETE")
            checked = _validate_database(output, budget)
            manifest = {"format": "quanta.sqlite.backup", "version": 1,
                        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "quanta_version": __version__, "sqlite_version": sqlite3.sqlite_version,
                        "schema_sha256": _SCHEMA_SHA256, "database": _hash_file(output, budget),
                        "checks": {"integrity": "ok", "foreign_keys": "ok", "artifact_bytes": "ok"}, **checked}
            _sync(output)
            _write_manifest(stage, manifest)
            _sync(stage, directory=True)
            budget.check()
            _free(stage, min_free_bytes)
            _publish(stage, target)
            return manifest


@_normalize_errors
def verify_backup(directory, *, timeout_seconds=60):
    """Check size, SHA-256, supported schema, SQLite, owner and artifact integrity."""
    return _verify(directory, _Budget(timeout_seconds))[1]


@_normalize_errors
def restore_backup(backup_directory, destination, *, timeout_seconds=60, min_free_bytes=MIN_FREE_BYTES):
    """Copy a verified snapshot into a new store; never recover, replay or overwrite.

    No worker lock or live WAL/SHM file is restored. Start the service explicitly
    after reviewing the matching runtime and its interrupted-work recovery policy.
    """
    budget = _Budget(timeout_seconds)
    source, manifest = _verify(backup_directory, budget)
    target = _destination(source, destination)
    _free(target.parent, min_free_bytes, manifest["database"]["size_bytes"])
    with _staging(target) as stage:
        output = stage / _DATABASE
        with (source / _DATABASE).open("rb") as original, output.open("xb") as copied:
            os.chmod(copied.fileno(), 0o600)
            while chunk := original.read(1024 * 1024):
                budget.check()
                _free(stage, min_free_bytes, len(chunk))
                copied.write(chunk)
            copied.flush()
            os.fsync(copied.fileno())
        if _hash_file(output, budget) != manifest["database"]:
            raise BackupError("Snapshot changed while restoring database bytes")
        checked = _validate_database(output, budget)
        if any(checked[key] != manifest[key] for key in checked):
            raise BackupError("Restored database records differ from the snapshot")
        _sync(stage, directory=True)
        budget.check()
        _free(stage, min_free_bytes)
        _publish(stage, target)
        return {"restored": True, "database": manifest["database"], **checked,
                "snapshot_created_at": manifest["created_at"], "worker_started": False,
                "replay_performed": False}
