#!/usr/bin/env python3
"""Fresh production backup/isolated restore without changing the active timer.

The fixed controller loads the reviewed verify_backup.py into the module
``quanta_fixed_backup`` before executing this source. No helpers, paths or
commands are accepted from a request. Only typed, fixed public facts are emitted.
The resulting root-private baseline is not an off-host backup or reboot proof.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

import quanta_fixed_backup as helper


SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
LOCK = Path("/run/quanta-recovery.lock")
BASELINE = Path("/etc/quanta/recovery-backup.json")
REBOOT_BASELINE = Path("/etc/quanta/recovery-reboot.json")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
TIMER = "quanta-backup-boot.timer"
BACKUP_SERVICE = "quanta-backup-boot.service"
MAX_OUTPUT_BYTES = 8192
ACTIONS = frozenset({"prepare-recovery", "refresh-recovery"})
BOOLEAN_FIELDS = (
    "source_verified", "backup_created", "backup_verified", "restore_verified",
    "production_preserved", "timer_state_preserved", "baseline_saved",
    "off_host_backup_verified", "operating_system_rebooted",
    "previous_baseline_archived", "baseline_refreshed",
)
REQUIRED_SUCCESS = BOOLEAN_FIELDS[:7]
STAGES = frozenset({"configuration", "lock", "refresh_preflight", "preflight", "backup", "verify", "restore",
                    "production_check", "archive", "baseline", "complete"})
FAILURES = frozenset({"none", "configuration_invalid", "operation_busy_or_unsafe",
                      "preflight_refused", "backup_failed", "snapshot_verification_failed",
                      "restore_failed", "production_or_timer_changed", "baseline_failed",
                      "refresh_preflight_refused", "archive_failed"})
FIELDS = frozenset(("scope", "action", "status", "stage", "failure_reason", *BOOLEAN_FIELDS))
FAILURE_BY_STAGE = {
    "configuration": "configuration_invalid", "lock": "operation_busy_or_unsafe",
    "preflight": "preflight_refused", "backup": "backup_failed",
    "verify": "snapshot_verification_failed", "restore": "restore_failed",
    "production_check": "production_or_timer_changed", "baseline": "baseline_failed",
    "refresh_preflight": "refresh_preflight_refused", "archive": "archive_failed",
}


def validate_config(config):
    """The installed app remains pinned independently of new operations code."""
    return helper.validate_config(config)


def _argument(value):
    return helper._argument(value)


@contextmanager
def _operation_lock():
    helper._root_parents(LOCK)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        linked = os.lstat(LOCK)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino)):
            raise helper.VerificationError()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise helper.VerificationError() from None
        yield
    finally:
        os.close(descriptor)


def _baseline_absent():
    helper._root_parents(BASELINE)
    try:
        os.lstat(BASELINE)
    except FileNotFoundError:
        return
    raise helper.VerificationError()


def _boot_id():
    raw = helper._read_root(BOOT_ID, limit=64)
    try:
        value = raw.decode("ascii").removesuffix("\n")
        if raw != (value + "\n").encode() or str(uuid.UUID(value)) != value:
            raise ValueError
        return value
    except Exception:
        raise helper.VerificationError() from None


def _timer_state():
    raw = helper._capture(["/usr/bin/systemctl", "show", "--no-pager",
                           "--property=ActiveState,UnitFileState", TIMER], limit=128)
    if raw is None:
        raise helper.VerificationError()
    lines = raw.splitlines()
    if len(lines) != 2 or set(lines) != {b"ActiveState=active", b"UnitFileState=enabled"}:
        raise helper.VerificationError()
    return ("active", "enabled")


def _services_idle():
    # Do not test the timer here: it must remain active and enabled throughout.
    # A start is issued through the same systemd oneshot used by that timer, so
    # a trigger racing these checks cannot run a second runtime backup process.
    for unit in ("quanta-backup.service", BACKUP_SERVICE):
        result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            shell=False, env=helper._environment(), cwd="/", timeout=4, check=False)
        if result.returncode not in {3, 4}:
            raise helper.VerificationError()


def _preflight(config, *, previous=None):
    if os.geteuid() != 0:
        raise helper.VerificationError()
    if previous is None:
        _baseline_absent()
    else:
        _reboot_baseline_absent()
        _expect_previous(previous)
    if helper._json(helper._read_root(helper.ETC / "installed.json", private=True)) != config:
        raise helper.VerificationError()
    if hashlib.sha256(helper._read_root(helper.RUNTIME, limit=16384)).hexdigest() != helper.TRUSTED["runtime"]:
        raise helper.VerificationError()
    helper._verify_units()
    deployment = helper._json(helper._read_root(helper.ETC / "deployment.json", private=True))
    if (not isinstance(deployment, dict) or set(deployment) != {"storage_mode", "filesystem_uuid", "image"}
            or deployment["storage_mode"] != "boot"
            or not isinstance(deployment["filesystem_uuid"], str)
            or str(uuid.UUID(deployment["filesystem_uuid"])) != deployment["filesystem_uuid"]
            or not isinstance(deployment["image"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", deployment["image"])):
        raise helper.VerificationError()
    environment = helper._read_root(helper.ETC / "app.env", private=True)
    prefix = ("QUANTA_PUBLIC_ORIGIN=" + config["public_origin"]
              + "\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=").encode()
    if not environment.startswith(prefix) or not re.fullmatch(rb"[0-9a-f]{64}\n", environment[len(prefix):]):
        raise helper.VerificationError()
    token = environment[len(prefix):-1].decode("ascii")
    helper._root_parents(helper.ROOT / "placeholder")
    device = os.lstat(helper.ROOT).st_dev
    if device != os.lstat("/").st_dev:
        raise helper.VerificationError()
    helper._private_dir(helper.DATA, device)
    helper._private_dir(helper.BACKUPS, device)
    if helper.shutil.disk_usage(helper.ROOT).free < 1024**3:
        raise helper.VerificationError()
    timer = _timer_state()
    _services_idle()
    helper._names_absent()
    image = deployment["image"]
    if helper._capture(helper.DOCKER + ["image", "inspect", "--format",
                "{{.Id}} {{.Architecture}} {{.Os}}", image], limit=128) != (image + " arm64 linux\n").encode():
        raise helper.VerificationError()
    helper._quiet(["/usr/bin/python3", "-I", "-B", str(helper.RUNTIME), "check", "--storage-mode", "boot"], timeout=20)
    helper._quiet(["/usr/bin/systemctl", "is-active", "--quiet", "quanta-boot.service"])
    helper._quiet(["/usr/bin/systemctl", "is-enabled", "--quiet", "quanta-boot.service"])
    helper._ready(config, token)
    identity = helper._production_identity(image, device)
    return image, device, token, identity, timer, _boot_id()


def _baseline_value(snapshot, snapshot_hash, boot_id):
    return {
        "schema_version": 1, "source_sha": SOURCE_SHA, "boot_id": boot_id,
        "snapshot": snapshot.name, "database_size": snapshot_hash[0],
        "database_sha256": snapshot_hash[1].hex(),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _sync_parent(path):
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_baseline(snapshot, snapshot_hash, boot_id):
    """Publish once without replacing an earlier baseline or following links."""
    _baseline_absent()
    value = _baseline_value(snapshot, snapshot_hash, boot_id)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = BASELINE.parent / (".recovery-backup-" + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # link() is atomic and fails if the destination exists; rename() would
        # silently replace a concurrently created baseline.
        os.link(temporary, BASELINE, follow_symlinks=False)
        os.unlink(temporary)
        directory = os.open(BASELINE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if helper._read_root(BASELINE, private=True) != raw:
            raise helper.VerificationError()
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _reboot_baseline_absent():
    helper._root_parents(REBOOT_BASELINE)
    try:
        os.lstat(REBOOT_BASELINE)
    except FileNotFoundError:
        return
    raise helper.VerificationError()


def _identity(path):
    info = os.lstat(path)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _read_previous_baseline():
    _reboot_baseline_absent()
    before = _identity(BASELINE)
    raw = helper._read_root(BASELINE, private=True)
    value = helper._json(raw)
    fields = {"schema_version", "source_sha", "boot_id", "snapshot", "database_size", "database_sha256", "created_at"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["source_sha"] != SOURCE_SHA
            or value["boot_id"] != _boot_id() or not isinstance(value["snapshot"], str)
            or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}", value["snapshot"])
            or type(value["database_size"]) is not int or not 0 < value["database_size"] <= helper.MAX_DATABASE_BYTES
            or not isinstance(value["database_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["database_sha256"])
            or not isinstance(value["created_at"], str)):
        raise helper.VerificationError()
    stamp = datetime.strptime(value["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    snapshot_stamp = datetime.strptime(value["snapshot"][:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
    if max(stamp, snapshot_stamp) > time.time() + 300 or uuid.UUID(hex=value["snapshot"][17:]).version != 4:
        raise helper.VerificationError()
    device = os.lstat(helper.ROOT).st_dev
    snapshot = helper.BACKUPS / value["snapshot"]
    helper._private_dir(snapshot, device)
    helper._children(snapshot, {"jobs.sqlite3", "manifest.json"})
    helper._private_file(snapshot / "manifest.json", device, maximum=1024 * 1024)
    size, digest = helper._hash(snapshot / "jobs.sqlite3", device)
    if (size != value["database_size"] or digest.hex() != value["database_sha256"]
            or _identity(BASELINE) != before):
        raise helper.VerificationError()
    return {"raw": raw, "identity": before, "value": value}


def _expect_previous(previous):
    if (_identity(BASELINE) != previous["identity"]
            or helper._read_root(BASELINE, private=True) != previous["raw"]
            or _identity(BASELINE) != previous["identity"]):
        raise helper.VerificationError()


def _archive_previous(previous):
    _reboot_baseline_absent()
    _expect_previous(previous)
    archive = BASELINE.parent / ("recovery-backup-archive-" + uuid.uuid4().hex + ".json")
    helper._root_parents(archive)
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(previous["raw"])
        stream.flush()
        os.fsync(stream.fileno())
    _sync_parent(archive)
    if helper._read_root(archive, private=True) != previous["raw"]:
        raise helper.VerificationError()
    return archive


def _replace_baseline(snapshot, snapshot_hash, boot_id, previous, archive):
    _reboot_baseline_absent()
    if helper._read_root(archive, private=True) != previous["raw"]:
        raise helper.VerificationError()
    raw = (json.dumps(_baseline_value(snapshot, snapshot_hash, boot_id), sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = BASELINE.parent / (".recovery-backup-refresh-" + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # The private parent and shared operation lock exclude non-root/other
        # Quanta writers. Reject any observed change to the known old marker.
        _expect_previous(previous)
        _reboot_baseline_absent()
        os.replace(temporary, BASELINE)
        _sync_parent(BASELINE)
        if (helper._read_root(BASELINE, private=True) != raw
                or helper._read_root(archive, private=True) != previous["raw"]):
            raise helper.VerificationError()
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _initial_report(action="prepare-recovery"):
    return {"scope": "recovery_backup_preparation", "action": action if isinstance(action, str) and action in ACTIONS else "prepare-recovery",
            "status": "failed", "stage": "configuration",
            "failure_reason": "configuration_invalid", **dict.fromkeys(BOOLEAN_FIELDS, False)}


def _perform(config, report, *, previous=None):
    report["stage"] = "preflight"
    image, device, token, identity, timer, boot_id = _preflight(config) if previous is None else _preflight(config, previous=previous)
    report["source_verified"] = True
    try:
        before = helper._entries()
        report["stage"] = "backup"
        helper._quiet(["/usr/bin/systemctl", "start", BACKUP_SERVICE], timeout=200)
        _services_idle()
        helper._names_absent()
        snapshot = helper._fresh_backup(before, device)
        report["backup_created"] = True
        operation = uuid.uuid4().hex
        report["stage"] = "verify"
        helper._container(image, operation, snapshot, ["verify-backup", "/backup"])
        snapshot_hash = helper._hash(snapshot / "jobs.sqlite3", device)
        report["backup_verified"] = True
        report["stage"] = "restore"
        if helper.shutil.disk_usage(helper.ROOT).free < 128 * 1024**2 + snapshot_hash[0]:
            raise helper.VerificationError()
        scratch = helper._scratch(device, operation)
        helper._container(image, operation, snapshot,
            ["restore-store", "/backup", "--output", "/restore/store"], scratch=scratch)
        restored = scratch / "store"
        helper._private_dir(restored, device)
        helper._children(scratch, {"store"})
        helper._children(restored, {"jobs.sqlite3"})
        if helper._hash(restored / "jobs.sqlite3", device) != snapshot_hash:
            raise helper.VerificationError()
        report["restore_verified"] = True
        report["stage"] = "production_check"
        helper._check_production(config, token, image, device, identity)
        report["production_preserved"] = True
        if _timer_state() != timer or _boot_id() != boot_id:
            raise helper.VerificationError()
        report["timer_state_preserved"] = True
        if previous is not None:
            report["stage"] = "archive"
            archive = _archive_previous(previous)
            report["previous_baseline_archived"] = True
            report["stage"] = "baseline"
            _replace_baseline(snapshot, snapshot_hash, boot_id, previous, archive)
            report["baseline_refreshed"] = True
        else:
            report["stage"] = "baseline"
            _publish_baseline(snapshot, snapshot_hash, boot_id)
        report["baseline_saved"] = True
    finally:
        # These observations also run after a failed verification. There is no
        # timer stop/disable to undo, even when the SSH client disconnects.
        try:
            report["timer_state_preserved"] = _timer_state() == timer
        except Exception:
            report["timer_state_preserved"] = False
        try:
            helper._check_production(config, token, image, device, identity)
            report["production_preserved"] = True
        except Exception:
            report["production_preserved"] = False
    if not all(report[field] for field in REQUIRED_SUCCESS):
        report["stage"] = "production_check"
        raise helper.VerificationError()
    report.update(status="success", stage="complete", failure_reason="none")


def run(config, action="prepare-recovery"):
    report = _initial_report(action)
    try:
        if type(action) is not str or action not in ACTIONS:
            return report
        config = validate_config(config)
    except Exception:
        return report
    try:
        report["stage"] = "lock"
        with helper._deadline(600), _operation_lock():
            if action == "refresh-recovery":
                report["stage"] = "refresh_preflight"
                previous = _read_previous_baseline()
                _perform(config, report, previous=previous)
            else:
                _perform(config, report)
    except Exception:
        report["status"] = "failed"
        report["failure_reason"] = FAILURE_BY_STAGE.get(report["stage"], "production_or_timer_changed")
    return report


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or value["scope"] != "recovery_backup_preparation"
            or not isinstance(value["action"], str) or value["action"] not in ACTIONS
            or not isinstance(value["status"], str) or value["status"] not in {"success", "failed"}
            or not isinstance(value["stage"], str) or value["stage"] not in STAGES
            or not isinstance(value["failure_reason"], str) or value["failure_reason"] not in FAILURES
            or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)
            or value["off_host_backup_verified"] or value["operating_system_rebooted"]):
        raise ValueError("invalid recovery backup report")
    ordered = BOOLEAN_FIELDS[:4]
    if any(value[field] and not all(value[earlier] for earlier in ordered[:index])
           for index, field in enumerate(ordered)):
        raise ValueError("invalid recovery backup report")
    if value["baseline_saved"] and not all(value[field] for field in BOOLEAN_FIELDS[:4]):
        raise ValueError("invalid recovery backup report")
    if (value["action"] == "prepare-recovery" and (value["previous_baseline_archived"] or value["baseline_refreshed"])
            or value["baseline_refreshed"] and not (value["previous_baseline_archived"] and value["baseline_saved"])):
        raise ValueError("invalid recovery backup report")
    if value["status"] == "success":
        if value["stage"] != "complete" or value["failure_reason"] != "none" or not all(value[f] for f in REQUIRED_SUCCESS):
            raise ValueError("invalid recovery backup report")
        if value["action"] == "refresh-recovery" and not (value["previous_baseline_archived"] and value["baseline_refreshed"]):
            raise ValueError("invalid recovery backup report")
    elif value["stage"] == "complete" or value["failure_reason"] == "none":
        raise ValueError("invalid recovery backup report")
    return dict(value)


def sanitize_report(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
        return None
    try:
        return validate_report(helper._json(raw))
    except Exception:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    action = "refresh-recovery" if len(argv) == 2 and argv[1] == "refresh-recovery" else "prepare-recovery"
    try:
        if len(argv) != 1 and not (len(argv) == 2 and argv[1] == "refresh-recovery"):
            raise ValueError
        report = run(_argument(argv[0]), action)
    except Exception:
        report = _initial_report(action)
    try:
        report = validate_report(report)
    except Exception:
        report = _initial_report(action)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
