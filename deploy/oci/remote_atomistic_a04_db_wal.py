#!/usr/bin/env python3
"""Observe the fixed OCI jobs database and WAL without a SQLite connection."""

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
import uuid


OPERATION = "inspect-atomistic-a04-db-wal"
SCOPE = "oci_atomistic_a04_db_wal_diagnostic"
DATABASE = Path("/srv/quanta/data/jobs.sqlite3")
LOCK = Path("/run/quanta-application-upgrade.lock")
DATA_OWNER = 10001
SAMPLE_COUNT = 640
SAMPLE_INTERVAL = 0.043
# Match the existing OCI probe's per-file allowance and stream the contents.
MAX_FILE_BYTES = 512 * 1024**2
MAX_READ_BYTES = 2 * MAX_FILE_BYTES
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME | os.O_CLOEXEC
CONFIG_KEYS = {"source_sha", "control_sha", "request_id"}
WAL_STATES = ("absent", "empty", "nonempty")
DIFFERENCES = ("unchanged", "main_only", "wal_only", "both")
FAILURES = {
    "platform", "maintenance_lock", "unsafe_parent", "unsafe_file", "main_missing",
    "file_limit", "read_limit", "no_stable_comparison", "io_error",
}


class DiagnosticError(Exception):
    pass


class FileRace(Exception):
    pass


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def metadata(path, owner, *, optional):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise DiagnosticError("main_missing") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner
            or owner == DATA_OWNER and info.st_gid != DATA_OWNER or info.st_mode & 0o077):
        raise DiagnosticError("unsafe_file")
    if info.st_size > MAX_FILE_BYTES:
        raise DiagnosticError("file_limit")
    return info


class Fingerprints:
    """Reuse a digest only while the full observed file identity still matches."""

    def __init__(self):
        self.cache = {}
        self.remaining_bytes = MAX_READ_BYTES

    def read(self, path, owner, *, optional=False):
        before = metadata(path, owner, optional=optional)
        if before is None:
            return None, None
        stamp = identity(before)
        cached = self.cache.get(path)
        if cached is not None and cached[0] == stamp:
            return cached
        if before.st_size > self.remaining_bytes:
            raise DiagnosticError("read_limit")
        try:
            fd = os.open(path, READ_FLAGS)
        except FileNotFoundError:
            raise FileRace() from None
        digest = hashlib.sha256()
        try:
            if identity(os.fstat(fd)) != stamp:
                raise FileRace()
            pending = before.st_size
            while pending:
                chunk = os.read(fd, min(256 * 1024, pending))
                if not chunk:
                    raise FileRace()
                pending -= len(chunk)
                self.remaining_bytes -= len(chunk)
                digest.update(chunk)
            if identity(os.fstat(fd)) != stamp:
                raise FileRace()
        finally:
            os.close(fd)
        result = (stamp, digest.digest())
        self.cache[path] = result
        return result


def snapshot(files, database, wal, owner):
    main_stamp, main_digest = files.read(database, owner)
    wal_stamp, wal_digest = files.read(wal, owner, optional=True)
    current_wal = metadata(wal, owner, optional=True)
    current_main = metadata(database, owner, optional=True)
    if (current_main is None or identity(current_main) != main_stamp
            or (identity(current_wal) if current_wal is not None else None) != wal_stamp):
        raise FileRace()
    state = "absent" if wal_stamp is None else "empty" if wal_stamp[2] == 0 else "nonempty"
    return (main_digest, wal_digest), state


def observe(database, *, owner, sample_count=SAMPLE_COUNT, interval=SAMPLE_INTERVAL):
    wal = database.with_name(database.name + "-wal")
    files = Fingerprints()
    states = dict.fromkeys(WAL_STATES, 0)
    differences = dict.fromkeys(DIFFERENCES, 0)
    main_seen, wal_seen = set(), set()
    first = last = previous_state = None
    stable = transitions = 0
    for i in range(sample_count):
        if i:
            time.sleep(interval)
        try:
            current, state = snapshot(files, database, wal, owner)
        except FileRace:
            continue
        if first is None:
            first = current
        last = current
        states[state] += 1
        stable += 1
        transitions += previous_state is not None and previous_state != state
        previous_state = state
        main_seen.add(current[0])
        wal_seen.add(current[1])
        main_changed = current[0] != first[0]
        wal_changed = current[1] != first[1]
        differences[DIFFERENCES[int(main_changed) + 2 * int(wal_changed)]] += 1
    if stable < 2:
        raise DiagnosticError("no_stable_comparison")
    return {
        "attempted_samples": sample_count,
        "stable_pairs": stable,
        "unstable_samples": sample_count - stable,
        "main_fingerprints": len(main_seen),
        "wal_fingerprints": len(wal_seen),
        "wal_states": states,
        "wal_state_transitions": transitions,
        "differences_from_first": differences,
        "last_matches_first": {"main": last[0] == first[0], "wal": last[1] == first[1]},
    }


def check_parents(path):
    for parent in reversed(path.parents):
        info = parent.lstat()
        if parent == DATABASE.parent:
            valid = (info.st_uid == info.st_gid == DATA_OWNER and stat.S_IMODE(info.st_mode) == 0o700)
        else:
            valid = info.st_uid == 0 and not info.st_mode & 0o022
        if not stat.S_ISDIR(info.st_mode) or not valid:
            raise DiagnosticError("unsafe_parent")


def execute():
    if platform.system() != "Linux" or platform.machine() != "aarch64" or os.geteuid() != 0:
        raise DiagnosticError("platform")
    check_parents(DATABASE)
    check_parents(LOCK)
    try:
        before = metadata(LOCK, 0, optional=True)
        if before is None or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o600:
            raise DiagnosticError("maintenance_lock")
        fd = os.open(LOCK, READ_FLAGS)
    except OSError:
        raise DiagnosticError("maintenance_lock") from None
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise DiagnosticError("maintenance_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            raise DiagnosticError("maintenance_lock") from None
        return observe(DATABASE, owner=DATA_OWNER)
    finally:
        os.close(fd)


def valid_config(value):
    if (not isinstance(value, dict) or set(value) != CONFIG_KEYS
            or not isinstance(value["source_sha"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["source_sha"])
            or value["source_sha"] != value["control_sha"]
            or not isinstance(value["request_id"], str)):
        return False
    try:
        request = uuid.UUID(value["request_id"])
    except ValueError:
        return False
    return request.version == 4 and str(request) == value["request_id"]


def valid_summary(summary):
    keys = {"attempted_samples", "stable_pairs", "unstable_samples", "main_fingerprints",
            "wal_fingerprints", "wal_states", "wal_state_transitions", "differences_from_first",
            "last_matches_first"}
    if not isinstance(summary, dict) or set(summary) != keys:
        return False
    counts = ("attempted_samples", "stable_pairs", "unstable_samples", "main_fingerprints",
              "wal_fingerprints", "wal_state_transitions")
    if any(type(summary[key]) is not int or not 0 <= summary[key] <= SAMPLE_COUNT for key in counts):
        return False
    stable = summary["stable_pairs"]
    if (summary["attempted_samples"] != SAMPLE_COUNT or stable < 2
            or summary["unstable_samples"] + stable != SAMPLE_COUNT
            or not 1 <= summary["main_fingerprints"] <= stable
            or not 1 <= summary["wal_fingerprints"] <= stable
            or summary["wal_state_transitions"] >= stable):
        return False
    for field, names in (("wal_states", WAL_STATES), ("differences_from_first", DIFFERENCES)):
        data = summary[field]
        if (not isinstance(data, dict) or set(data) != set(names)
                or any(type(x) is not int or x < 0 for x in data.values()) or sum(data.values()) != stable):
            return False
    final = summary["last_matches_first"]
    return (isinstance(final, dict) and set(final) == {"main", "wal"}
            and all(type(value) is bool for value in final.values()))


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or len(raw) > 4096:
            return None
        result = json.loads(raw)
        shared = CONFIG_KEYS | {"schema_version", "operation", "scope", "status"}
        if (not isinstance(result, dict) or result.get("scope") != SCOPE
                or result.get("operation") != OPERATION or type(result.get("schema_version")) is not int
                or result["schema_version"] != 1 or not CONFIG_KEYS <= result.keys()
                or not valid_config({key: result[key] for key in CONFIG_KEYS})):
            return None
        if result.get("status") == "success" and set(result) == shared | {"observation"}:
            return result if valid_summary(result["observation"]) else None
        if result.get("status") == "failed" and set(result) == shared | {"reason"}:
            return result if result["reason"] in FAILURES else None
    except (ValueError, TypeError):
        return None
    return None


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "--fixed-remote" or len(sys.argv[2]) > 1024:
        return 2
    try:
        raw = base64.b64decode(sys.argv[2], validate=True)
        config = json.loads(raw)
        if not valid_config(config) or raw != json.dumps(config, sort_keys=True, separators=(",", ":")).encode("ascii"):
            return 2
    except ValueError:
        return 2
    result = {**config, "schema_version": 1, "operation": OPERATION, "scope": SCOPE}
    try:
        result.update(status="success", observation=execute())
    except DiagnosticError as error:
        result.update(status="failed", reason=str(error))
    except OSError:
        result.update(status="failed", reason="io_error")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    sys.exit(main())
