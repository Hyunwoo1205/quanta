#!/usr/bin/env python3
"""One guarded OS-reboot request and a separate, read-only post-boot check.

The controller injects reviewed quanta_fixed_backup and quanta_fixed_audit
modules. The operator reported daily OCI backups; the server does not attest
that console policy. Reboot preservation uses the quiescent current live store,
independently of any older SQLite snapshot or off-host copy generation.
No arbitrary command/path, key rotation, peer mutation or data deletion exists.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import struct
import sys
import time
import uuid

import quanta_fixed_backup as helper
import quanta_fixed_audit as audit

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
BACKUP_BASELINE = Path("/etc/quanta/recovery-backup.json")
REBOOT_BASELINE = Path("/etc/quanta/recovery-reboot.json")
LOCK = Path("/run/quanta-recovery.lock")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
APP = "quanta-boot.service"
HTTPS = "quanta-https.service"
TIMER = "quanta-backup-boot.timer"
REBOOT_UNIT = "quanta-recovery-reboot"
RESUME_UNIT = "quanta-recovery-resume"
READINESS_TIMEOUT = 20.0
PREREQUISITE_BASIS = "host_checks_without_snapshot_or_off_host_requirement"
BACKUP_POLICY_BASIS = "user_reported_oci_daily"
DATABASE_BASIS = "quiescent_live_store_before_os_reboot"
TABLES = ("artifacts", "events", "experiments", "idempotency", "revisions", "runs")
BOOT_ACTIONS = frozenset({"reboot-recovery", "verify-reboot"})
ACTIONS = BOOT_ACTIONS | {"compare-recovery"}
MAX_ROWS = 1_000_000
MAX_VALUE_BYTES = 64 * 1024**2
MAX_OUTPUT_BYTES = 8192
SETTINGS = (
    "/etc/quanta/installed.json", "/etc/quanta/deployment.json", "/etc/quanta/app.env",
    "/etc/quanta/https.env", "/etc/quanta/Caddyfile", "/usr/local/lib/quanta/runtime.py",
    "/etc/systemd/system/quanta-boot.service", "/etc/systemd/system/quanta-https.service",
    "/etc/systemd/system/quanta-backup-boot.service", "/etc/systemd/system/quanta-backup-boot.timer",
)
BOOLEANS = (
    "audit_prerequisites_met", "backup_baseline_verified", "admission_paused", "backup_timer_paused", "no_pending_runs",
    "application_stopped", "snapshot_semantics_matched", "private_baseline_saved", "reboot_scheduled",
    "boot_changed", "services_restored", "database_preserved", "peer_containers_preserved",
    "settings_preserved", "worker_exclusivity_verified", "fallback_recovery_verified",
    "off_host_backup_verified_by_server", "new_calculation_verified",
    "quiescent_live_baseline_verified", "backup_policy_console_verified",
)
COUNTS = ("experiments", "revisions", "runs", "artifacts", "events", "idempotency", "peer_containers")
STAGES = frozenset({"configuration", "lock", "preflight", "barrier", "stop", "compare", "baseline",
                    "schedule", "postboot", "services", "database", "peers", "settings", "complete"})
FAILURES = frozenset({"none", "invalid_configuration", "busy_or_unsafe", "preflight_refused",
    "admission_barrier_failed", "application_stop_failed", "snapshot_mismatch", "live_baseline_failed", "baseline_failed",
    "scheduling_failed", "boot_not_changed_or_invalid_baseline", "service_recovery_failed",
    "database_changed", "peer_containers_changed", "settings_changed", "fallback_recovery_failed"})
FIELDS = frozenset(("scope", "action", "status", "stage", "failure_reason", *BOOLEANS, *COUNTS))
COMPARISON_DETAILS = frozenset({"not_checked", "snapshot_database_read", "snapshot_database_validation",
    "live_database_read", "live_database_validation", "schema_mismatch", "table_mismatch", "status_mismatch",
    "boot_check", "boot_mismatch", "settings_read", "settings_mismatch", "matched"})
CLEANUP_DETAILS = frozenset({"not_required", "complete", "reboot_unit_cleanup_failed",
                            "service_restore_failed", "resume_unit_cleanup_failed"})
FIELDS = FIELDS | {"comparison_detail", "cleanup_detail", "prerequisite_basis", "backup_policy_basis", "baseline_schema_version"}
COMPARISON_DETAILS = COMPARISON_DETAILS | {"live_baseline_verified"}
COMPARISON_DETAILS = COMPARISON_DETAILS | {"auxiliary_metadata_refused"}
FAILURE_BY_STAGE = {
    "configuration": "invalid_configuration", "lock": "busy_or_unsafe", "preflight": "preflight_refused",
    "barrier": "admission_barrier_failed", "stop": "application_stop_failed", "compare": "live_baseline_failed",
    "baseline": "baseline_failed", "schedule": "scheduling_failed",
    "postboot": "boot_not_changed_or_invalid_baseline", "services": "service_recovery_failed",
    "database": "database_changed", "peers": "peer_containers_changed", "settings": "settings_changed",
}


class RebootError(Exception):
    pass


class AuxiliaryFileError(RebootError):
    pass


def validate_config(config):
    return helper.validate_config(config)


def _argument(value):
    return helper._argument(value)


@contextmanager
def _operation_lock():
    helper._root_parents(LOCK)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        opened, linked = os.fstat(descriptor), os.lstat(LOCK)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_gid != 0
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)):
            raise RebootError()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


@contextmanager
def _interruptions():
    def interrupted(signum, frame):
        raise RebootError()
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGHUP, signal.SIGTERM)}
    try:
        for kind in previous:
            signal.signal(kind, interrupted)
        yield
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)


def _boot_id():
    raw = helper._read_root(BOOT_ID, limit=64)
    value = raw.decode("ascii").removesuffix("\n")
    if raw != (value + "\n").encode() or str(uuid.UUID(value)) != value:
        raise RebootError()
    return value


def _recent(value):
    if not isinstance(value, str):
        raise RebootError()
    stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    if not 0 <= time.time() - stamp <= 86400:
        raise RebootError()
    return stamp


def _baseline_absent():
    helper._root_parents(REBOOT_BASELINE)
    try:
        os.lstat(REBOOT_BASELINE)
    except FileNotFoundError:
        return
    raise RebootError()


def _backup_baseline(*, require_current_boot=True):
    value = helper._json(helper._read_root(BACKUP_BASELINE, private=True))
    fields = {"schema_version", "source_sha", "boot_id", "snapshot", "database_size", "database_sha256", "created_at"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or value["source_sha"] != SOURCE_SHA
            or not isinstance(value["boot_id"], str) or str(uuid.UUID(value["boot_id"])) != value["boot_id"]
            or (require_current_boot and value["boot_id"] != _boot_id()) or not isinstance(value["snapshot"], str)
            or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}", value["snapshot"])
            or type(value["database_size"]) is not int or not 0 < value["database_size"] <= helper.MAX_DATABASE_BYTES
            or not isinstance(value["database_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["database_sha256"])):
        raise RebootError()
    _recent(value["created_at"])
    datetime.strptime(value["snapshot"][:16], "%Y%m%dT%H%M%SZ")
    if uuid.UUID(hex=value["snapshot"][17:]).version != 4:
        raise RebootError()
    device = os.lstat(helper.ROOT).st_dev
    snapshot = helper.BACKUPS / value["snapshot"]
    helper._private_dir(snapshot, device)
    helper._children(snapshot, {"jobs.sqlite3", "manifest.json"})
    helper._private_file(snapshot / "manifest.json", device, maximum=1024**2)
    size, digest = helper._hash(snapshot / "jobs.sqlite3", device)
    if size != value["database_size"] or digest.hex() != value["database_sha256"]:
        raise RebootError()
    return value, snapshot, device


def _typed(value):
    if value is None:
        return b"N"
    if type(value) is int:
        raw, kind = str(value).encode("ascii"), b"I"
    elif type(value) is float:
        if not math.isfinite(value):
            raise RebootError()
        raw, kind = struct.pack(">d", value), b"F"
    elif type(value) is str:
        raw, kind = value.encode("utf-8"), b"T"
    elif type(value) is bytes:
        raw, kind = value, b"B"
    else:
        raise RebootError()
    if len(raw) > MAX_VALUE_BYTES:
        raise RebootError()
    return kind + struct.pack(">Q", len(raw)) + raw


@contextmanager
def _store_reader_identity():
    """Keep SQLite-created WAL/SHM files owned by the application, never root.

    Real UID 0 is retained; finally restores the original effective identity
    even if entering the reduced identity fails part way through. Local tests
    run as an unprivileged user and keep that test user's identity unchanged.
    """
    original_uid, original_gid = os.geteuid(), os.getegid()
    if original_uid != 0:
        yield
        return
    if os.getuid() != 0:
        raise RebootError()
    transitions = {signal.SIGALRM, signal.SIGHUP, signal.SIGTERM}
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, transitions)
    try:
        os.setegid(10001)
        os.seteuid(10001)
        try:
            # SQL work retains the caller's deadline/interruption behavior.
            # The surrounding finally also handles a signal delivered here.
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, transitions)
    finally:
        try:
            os.seteuid(original_uid)
        finally:
            try:
                os.setegid(original_gid)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)


def _check_auxiliary_files(path, device):
    # Never chown/chmod/delete an unexpected auxiliary file. Such a condition
    # needs a separate diagnosis while preserving the store and its WAL bytes.
    for suffix in ("-wal", "-shm", "-journal"):
        item = path.with_name(path.name + suffix)
        try:
            os.lstat(item)
        except FileNotFoundError:
            continue
        try:
            helper._private_file(item, device)
        except Exception:
            raise AuxiliaryFileError() from None


def _semantic_database(path, device):
    """Typed row multisets include committed WAL data and all artifact BLOBs."""
    before = helper._private_file(path, device)
    _check_auxiliary_files(path, device)
    try:
        with _store_reader_identity():
            result = _read_semantics(path)
    finally:
        # Effective identity has been restored before these metadata checks,
        # including when SQLite raises or the fixed deadline interrupts it.
        _check_auxiliary_files(path, device)
        after = helper._private_file(path, device)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RebootError()
    return result


def _read_semantics(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2, isolation_level=None)
    expires = time.monotonic() + 20
    connection.set_progress_handler(lambda: int(time.monotonic() > expires), 1000)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        if connection.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            raise RebootError()
        schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
        if {row[1] for row in schema if row[0] == "table"} != set(TABLES):
            raise RebootError()
        schema_digest = hashlib.sha256()
        for row in schema:
            for value in row:
                schema_digest.update(_typed(value))
        result = {"schema_sha256": schema_digest.hexdigest(), "tables": {}}
        total = 0
        for table in TABLES:
            cursor = connection.execute("SELECT * FROM " + table)
            columns = tuple(item[0] for item in cursor.description)
            rows = []
            for row in cursor:
                total += 1
                if total > MAX_ROWS or time.monotonic() > expires:
                    raise RebootError()
                digest = hashlib.sha256()
                digest.update(struct.pack(">Q", len(row)))
                for value in row:
                    digest.update(_typed(value))
                rows.append(digest.digest())
            table_digest = hashlib.sha256()
            for column in columns:
                table_digest.update(_typed(column))
            for row_digest in sorted(rows):
                table_digest.update(row_digest)
            result["tables"][table] = {"rows": len(rows), "sha256": table_digest.hexdigest()}
        statuses = connection.execute("SELECT status,count(*) FROM runs GROUP BY status").fetchall()
        if any(status not in audit.STATUSES or type(count) is not int for status, count in statuses):
            raise RebootError()
        result["nonterminal_runs"] = sum(count for status, count in statuses if status not in audit.TERMINAL)
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    return result


def _peer_state():
    raw = audit._capture(audit.DOCKER + ["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"], limit=65536)
    ids = raw.decode("ascii").splitlines()
    if not 1 <= len(ids) <= 256 or len(set(ids)) != len(ids) or any(not re.fullmatch(r"[0-9a-f]{64}", i) for i in ids):
        raise RebootError()
    template = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
        '"running":{{json .State.Running}},"restart":{{json .HostConfig.RestartPolicy}},'
        '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},'
        '"config":{{json .Config}},"host_config":{{json .HostConfig}},"mounts":{{json .Mounts}}}')
    peers, app_count = {}, 0
    for identity in sorted(ids):
        value = helper._json(audit._capture(audit.DOCKER + ["container", "inspect", "--format", template, identity], limit=256 * 1024))
        fields = {"id", "name", "image", "running", "restart", "paused", "restarting", "dead", "config", "host_config", "mounts"}
        if (not isinstance(value, dict) or set(value) != fields or value["id"] != identity
                or not isinstance(value["name"], str) or not re.fullmatch(r"/[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", value["name"])
                or not isinstance(value["image"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image"])
                or any(type(value[field]) is not bool for field in ("running", "paused", "restarting", "dead"))
                or any(value[field] for field in ("paused", "restarting", "dead"))
                or not isinstance(value["restart"], dict) or set(value["restart"]) != {"Name", "MaximumRetryCount"}
                or value["restart"]["Name"] not in {"no", "always", "unless-stopped", "on-failure"}
                or type(value["restart"]["MaximumRetryCount"]) is not int
                or not 0 <= value["restart"]["MaximumRetryCount"] <= 2**31 - 1
                or not isinstance(value["config"], dict) or not isinstance(value["host_config"], dict)
                or not isinstance(value["mounts"], list)):
            raise RebootError()
        if value["name"] == "/quanta":
            app_count += 1
            continue
        if value["name"] in {"/quanta-backup", "/quanta-operations-check"}:
            raise RebootError()
        policy = value["restart"]["Name"]
        if value["running"] and policy not in {"always", "unless-stopped"} or not value["running"] and policy == "always":
            raise RebootError()
        config_digest = hashlib.sha256(json.dumps({key: value[key] for key in ("config", "host_config", "mounts")},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        peers[identity] = {"name": value["name"], "image": value["image"], "running": value["running"],
                           "restart": value["restart"], "configuration_sha256": config_digest}
    if app_count != 1:
        raise RebootError()
    return peers


def _settings():
    return {path: hashlib.sha256(helper._read_root(Path(path), limit=16384,
                private=path in {"/etc/quanta/installed.json", "/etc/quanta/deployment.json", "/etc/quanta/app.env", "/etc/quanta/https.env"})).hexdigest()
            for path in SETTINGS}


def _absent_transients():
    for prefix in (REBOOT_UNIT, RESUME_UNIT):
        for suffix in (".service", ".timer"):
            if audit._unit_properties(prefix + suffix, ("LoadState",)) != {"LoadState": "not-found"}:
                raise RebootError()


def _transient(prefix, seconds, command):
    helper._quiet(["/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + prefix,
        "--on-active=" + str(seconds) + "s", "--timer-property=AccuracySec=1s",
        "--property=Type=oneshot", "--property=TimeoutStartSec=90s", *command], timeout=10)
    if audit._unit_properties(prefix + ".timer", ("LoadState", "ActiveState")) != {"LoadState": "loaded", "ActiveState": "active"}:
        raise RebootError()


def _stop_transient(prefix):
    # --collect can unload the inactive service before its timer ever fires.
    # A combined `stop timer service` then returns nonzero for the absent
    # service even when the timer was canceled successfully. Inspect each unit
    # separately and verify the desired state, including already-collected units.
    for suffix in (".timer", ".service"):
        unit = prefix + suffix
        before = audit._unit_properties(unit, ("LoadState", "ActiveState"))
        if before == {"LoadState": "not-found", "ActiveState": "inactive"}:
            continue
        if before.get("LoadState") != "loaded" or before.get("ActiveState") not in {
                "active", "inactive", "failed", "activating", "deactivating", "reloading"}:
            raise RebootError()
        try:
            helper._quiet(["/usr/bin/systemctl", "stop", unit], timeout=10)
        except Exception:
            # A concurrent collect can also make this one-unit stop return 5;
            # only the subsequent inactive/not-found observation permits success.
            pass
        after = audit._unit_properties(unit, ("LoadState", "ActiveState"))
        if after not in ({"LoadState": "not-found", "ActiveState": "inactive"},
                         {"LoadState": "loaded", "ActiveState": "inactive"},
                         {"LoadState": "loaded", "ActiveState": "failed"}):
            raise RebootError()


def _service_state(unit, expected):
    if audit._unit_properties(unit, ("ActiveState",)) != {"ActiveState": expected}:
        raise RebootError()


def _idle_database(device):
    report = audit._initial_report()
    audit._database(report, device)
    if not report["database_checked"] or not report["no_pending_runs"]:
        raise RebootError()


def _idle_backups():
    for unit in ("quanta-backup.service", "quanta-backup-boot.service"):
        values = audit._unit_properties(unit, ("ActiveState", "LoadState"))
        if values == {"ActiveState": "inactive", "LoadState": "not-found"}:
            continue
        if values.get("LoadState") != "loaded" or values.get("ActiveState") not in {"inactive", "failed"}:
            raise RebootError()


def _timer_enabled():
    if audit._unit_properties(TIMER, ("UnitFileState",)) != {"UnitFileState": "enabled"}:
        raise RebootError()


def _publish_baseline(value):
    _baseline_absent()
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(raw) > 1024 * 1024:
        raise RebootError()
    temporary = REBOOT_BASELINE.parent / (".recovery-reboot-" + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, REBOOT_BASELINE, follow_symlinks=False)
        os.unlink(temporary)
        directory = os.open(REBOOT_BASELINE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if helper._read_root(REBOOT_BASELINE, private=True, limit=1024 * 1024) != raw:
            raise RebootError()
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_reboot_baseline():
    value = helper._json(helper._read_root(REBOOT_BASELINE, private=True, limit=1024 * 1024))
    common = {"schema_version", "source_sha", "created_at", "operation_id", "old_boot_id", "database", "peers", "settings"}
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] not in {1, 2}:
        raise RebootError()
    version = value["schema_version"]
    extra = {"backup", "external_copy_verification"} if version == 1 else \
            {"database_basis", "backup_policy_basis", "backup_policy_console_verified"}
    if (set(value) != common | extra or value["source_sha"] != SOURCE_SHA
            or not isinstance(value["operation_id"], str) or str(uuid.UUID(value["operation_id"])) != value["operation_id"]
            or not isinstance(value["old_boot_id"], str) or str(uuid.UUID(value["old_boot_id"])) != value["old_boot_id"]
            or not isinstance(value["database"], dict)
            or not isinstance(value["peers"], dict) or not isinstance(value["settings"], dict)):
        raise RebootError()
    if version == 1:
        if (not isinstance(value["backup"], dict)
                or value["external_copy_verification"] != "separate_operator_check_not_attested_by_server"):
            raise RebootError()
    elif (value["database_basis"] != DATABASE_BASIS or value["backup_policy_basis"] != BACKUP_POLICY_BASIS
          or value["backup_policy_console_verified"] is not False):
        raise RebootError()
    _recent(value["created_at"])
    _validate_semantics(value["database"])
    if (set(value["settings"]) != set(SETTINGS)
            or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in value["settings"].values())):
        raise RebootError()
    if len(value["peers"]) > 256 or any(not re.fullmatch(r"[0-9a-f]{64}", key) for key in value["peers"]):
        raise RebootError()
    return value


def _validate_semantics(value):
    if (not isinstance(value, dict) or set(value) != {"schema_sha256", "tables", "nonterminal_runs"}
            or not isinstance(value["schema_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["schema_sha256"])
            or not isinstance(value["tables"], dict) or set(value["tables"]) != set(TABLES)
            or type(value["nonterminal_runs"]) is not int or value["nonterminal_runs"] != 0):
        raise RebootError()
    for item in value["tables"].values():
        if (not isinstance(item, dict) or set(item) != {"rows", "sha256"}
                or type(item["rows"]) is not int or not 0 <= item["rows"] <= MAX_ROWS
                or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise RebootError()


def _counts(report, database, peers):
    for table in TABLES:
        report[table] = database["tables"][table]["rows"]
    report["peer_containers"] = len(peers)


def _wait_ready(config, token):
    # Type=simple can report service activation before the ASGI listener is
    # ready. Keep the fallback timer until an authenticated warm-up poll passes.
    expires = time.monotonic() + READINESS_TIMEOUT
    try:
        with helper._deadline(READINESS_TIMEOUT):
            while True:
                try:
                    helper._ready(config, token)
                    return
                except Exception:
                    remaining = expires - time.monotonic()
                    if remaining <= 0:
                        raise RebootError() from None
                    time.sleep(min(0.25, remaining))
    except Exception:
        raise RebootError() from None


def _restore_services(config, token):
    # Both units were active before the guarded barrier. Start is idempotent;
    # starting an already active app does not stop a newly accepted calculation.
    helper._quiet(["/usr/bin/systemctl", "start", APP, HTTPS, TIMER], timeout=90)
    _service_state(APP, "active")
    _service_state(HTTPS, "active")
    _service_state(TIMER, "active")
    _timer_enabled()
    _wait_ready(config, token)


def _reboot_audit(config, *, enforce=True):
    """Collect the necessary host checks without reading historical snapshots.

    Full audit.run also inventories backup files. Those observations remain
    available separately; snapshot existence/freshness is not a reboot gate.
    """
    report = audit._initial_report()
    image, device, token = audit._installation(config, report)
    audit._services(report)
    report["authenticated_ready"] = audit._ready(config, token)
    audit._containers(image, report)
    audit._worker(report, device)
    _check_auxiliary_files(helper.DATA / "jobs.sqlite3", device)
    with _store_reader_identity():
        audit._database(report, device)
    _check_auxiliary_files(helper.DATA / "jobs.sqlite3", device)
    report["sufficient_disk_space"] = helper.shutil.disk_usage(helper.ROOT).free >= 1024**3
    required = set(audit.PREREQUISITES) - {"latest_snapshot_present"}
    if enforce and not all(report[field] for field in required):
        raise RebootError()
    report.update(status="success", stage="complete", failure_reason="none")
    return report, device, token


def _request_reboot(config, report):
    report["stage"] = "preflight"
    _baseline_absent()
    result, device, token = _reboot_audit(config)
    report["audit_prerequisites_met"] = True
    boot_id = _boot_id()
    peers = _peer_state()
    settings = _settings()
    _absent_transients()
    resume_attempted = admission_attempted = stop_attempted = scheduling_attempted = False
    accepted = False
    try:
        with helper._deadline(120):
            report["stage"] = "barrier"
            resume_attempted = True
            _transient(RESUME_UNIT, 180, ["/usr/bin/systemctl", "start", APP, HTTPS, TIMER])
            admission_attempted = True
            helper._quiet(["/usr/bin/systemctl", "stop", HTTPS], timeout=30)
            _service_state(HTTPS, "inactive")
            report["admission_paused"] = True
            _idle_database(device)
            report["no_pending_runs"] = True
            # Backup preparation never changes the timer. This short reboot
            # barrier pauses only scheduling, retains enabled state, and refuses
            # an already running backup rather than terminating it at reboot.
            helper._quiet(["/usr/bin/systemctl", "stop", TIMER], timeout=15)
            _service_state(TIMER, "inactive")
            _timer_enabled()
            report["backup_timer_paused"] = True
            _idle_backups()
            report["stage"] = "stop"
            stop_attempted = True
            helper._quiet(["/usr/bin/systemctl", "stop", APP], timeout=60)
            _service_state(APP, "inactive")
            report["application_stopped"] = True
            report["stage"] = "compare"
            report["comparison_detail"] = "live_database_read"
            current_state = _semantic_database(helper.DATA / "jobs.sqlite3", device)
            report["comparison_detail"] = "live_database_validation"
            _validate_semantics(current_state)
            confirmed_state = _semantic_database(helper.DATA / "jobs.sqlite3", device)
            _validate_semantics(confirmed_state)
            if current_state != confirmed_state:
                report["comparison_detail"] = ("schema_mismatch" if current_state["schema_sha256"] != confirmed_state["schema_sha256"]
                    else "table_mismatch" if current_state["tables"] != confirmed_state["tables"] else "status_mismatch")
                raise RebootError()
            report["comparison_detail"] = "boot_check"
            if _boot_id() != boot_id:
                report["comparison_detail"] = "boot_mismatch"
                raise RebootError()
            report["comparison_detail"] = "settings_read"
            if _settings() != settings:
                report["comparison_detail"] = "settings_mismatch"
                raise RebootError()
            report["comparison_detail"] = "live_baseline_verified"
            report["quiescent_live_baseline_verified"] = True
            _counts(report, current_state, peers)
            report["stage"] = "baseline"
            baseline = {"schema_version": 2, "source_sha": SOURCE_SHA,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "operation_id": str(uuid.uuid4()), "old_boot_id": boot_id,
                "database": current_state, "peers": peers, "settings": settings,
                "database_basis": DATABASE_BASIS, "backup_policy_basis": BACKUP_POLICY_BASIS,
                "backup_policy_console_verified": False}
            _publish_baseline(baseline)
            report["private_baseline_saved"] = True
            report["baseline_schema_version"] = 2
            report["stage"] = "schedule"
            scheduling_attempted = True
            _transient(REBOOT_UNIT, 10, ["/usr/bin/systemctl", "reboot"])
            report["reboot_scheduled"] = True
            accepted = True
    finally:
        if not accepted:
            cleanup_ok = True
            if scheduling_attempted:
                try:
                    _stop_transient(REBOOT_UNIT)
                except Exception:
                    cleanup_ok = False
                    report["cleanup_detail"] = "reboot_unit_cleanup_failed"
            if admission_attempted or stop_attempted:
                try:
                    _restore_services(config, token)
                    report["services_restored"] = True
                except Exception:
                    cleanup_ok = False
                    report["cleanup_detail"] = "service_restore_failed"
            if resume_attempted and cleanup_ok:
                try:
                    _stop_transient(RESUME_UNIT)
                except Exception:
                    cleanup_ok = False
                    report["cleanup_detail"] = "resume_unit_cleanup_failed"
            report["fallback_recovery_verified"] = cleanup_ok and report["services_restored"]
            if report["fallback_recovery_verified"]:
                report["cleanup_detail"] = "complete"
            if not cleanup_ok:
                report["failure_reason"] = "fallback_recovery_failed"
    report.update(status="success", stage="complete", failure_reason="none")


def _verify_reboot(config, report):
    report["stage"] = "postboot"
    baseline = _read_reboot_baseline()
    if _boot_id() == baseline["old_boot_id"]:
        raise RebootError()
    report["boot_changed"] = True
    report["private_baseline_saved"] = True
    report["baseline_schema_version"] = baseline["schema_version"]
    report["backup_policy_basis"] = BACKUP_POLICY_BASIS if baseline["schema_version"] == 2 else "unverified_legacy_record"
    report["stage"] = "services"
    result, device, token = _reboot_audit(config)
    report["audit_prerequisites_met"] = True
    report["services_restored"] = True
    report["worker_exclusivity_verified"] = result["worker_exclusivity_verified"]
    report["no_pending_runs"] = result["no_pending_runs"]
    report["stage"] = "database"
    current = _semantic_database(helper.DATA / "jobs.sqlite3", device)
    _validate_semantics(current)
    if current != baseline["database"]:
        raise RebootError()
    report["database_preserved"] = True
    report["quiescent_live_baseline_verified"] = True
    report["stage"] = "peers"
    peers = _peer_state()
    if peers != baseline["peers"]:
        raise RebootError()
    report["peer_containers_preserved"] = True
    report["stage"] = "settings"
    if _settings() != baseline["settings"]:
        raise RebootError()
    report["settings_preserved"] = True
    _counts(report, current, peers)
    report.update(status="success", stage="complete", failure_reason="none")


DIAGNOSTIC_BASE_BOOLS = (
    "source_verified", "backup_baseline_verified", "snapshot_checked", "live_checked", "boot_id_matches",
    "schemas_match", "all_tables_match", "snapshot_no_pending_runs", "live_no_pending_runs",
    "settings_currently_readable", "services_state_checked", "app_active", "https_active",
    "backup_timer_active_enabled", "transient_state_checked", "server_modified",
)
DIAGNOSTIC_TRANSIENT_BOOLS = tuple(prefix + "_" + kind + "_" + fact
    for prefix in ("resume", "reboot") for kind in ("timer", "service") for fact in ("present", "active"))
DIAGNOSTIC_BOOLS = DIAGNOSTIC_BASE_BOOLS + DIAGNOSTIC_TRANSIENT_BOOLS + tuple(table + "_matches" for table in TABLES)
DIAGNOSTIC_COUNTS = tuple(prefix + "_" + table + "_rows" for prefix in ("snapshot", "live") for table in TABLES) \
    + ("snapshot_nonterminal_runs", "live_nonterminal_runs")
DIAGNOSTIC_STAGES = frozenset({"configuration", "preflight", "snapshot_database", "live_database", "inspection", "complete"})
DIAGNOSTIC_FIELDS = frozenset(("scope", "action", "status", "stage", "failure_reason", *DIAGNOSTIC_BOOLS, *DIAGNOSTIC_COUNTS))


def _comparison_initial():
    return {"scope": "recovery_comparison_diagnostic", "action": "compare-recovery", "status": "failed",
            "stage": "configuration", "failure_reason": "invalid_configuration",
            **dict.fromkeys(DIAGNOSTIC_BOOLS, False), **dict.fromkeys(DIAGNOSTIC_COUNTS, 0)}


def _compare_recovery(config):
    """Observe two SQLite transactions; never pause services or publish a marker."""
    report = _comparison_initial()
    try:
        config = validate_config(config)
    except Exception:
        return report
    try:
        with helper._deadline(120):
            report["stage"] = "preflight"
            current, current_device, _token = _reboot_audit(config, enforce=False)
            if current.get("status") != "success" or not current.get("source_verified"):
                raise RebootError()
            report["source_verified"] = True
            report["services_state_checked"] = True
            report["app_active"] = current["app_active"]
            report["https_active"] = current["https_active"]
            report["backup_timer_active_enabled"] = current["backup_timer_active"] and current["backup_timer_enabled"]
            baseline, snapshot, device = _backup_baseline(require_current_boot=False)
            report["backup_baseline_verified"] = True
            report["boot_id_matches"] = _boot_id() == baseline["boot_id"]
            report["stage"] = "snapshot_database"
            snapshot_state = _semantic_database(snapshot / "jobs.sqlite3", device)
            report["snapshot_checked"] = True
            report["snapshot_no_pending_runs"] = snapshot_state["nonterminal_runs"] == 0
            report["snapshot_nonterminal_runs"] = snapshot_state["nonterminal_runs"]
            for table in TABLES:
                report["snapshot_" + table + "_rows"] = snapshot_state["tables"][table]["rows"]
            report["stage"] = "live_database"
            live_state = _semantic_database(helper.DATA / "jobs.sqlite3", device)
            report["live_checked"] = True
            report["live_no_pending_runs"] = live_state["nonterminal_runs"] == 0
            report["live_nonterminal_runs"] = live_state["nonterminal_runs"]
            for table in TABLES:
                report["live_" + table + "_rows"] = live_state["tables"][table]["rows"]
                report[table + "_matches"] = live_state["tables"][table] == snapshot_state["tables"][table]
            report["schemas_match"] = live_state["schema_sha256"] == snapshot_state["schema_sha256"]
            report["all_tables_match"] = all(report[table + "_matches"] for table in TABLES)
            report["stage"] = "inspection"
            try:
                _settings()
                report["settings_currently_readable"] = True
            except Exception:
                pass
            for prefix, unit in (("resume", RESUME_UNIT), ("reboot", REBOOT_UNIT)):
                for kind in ("timer", "service"):
                    values = audit._unit_properties(unit + "." + kind, ("LoadState", "ActiveState"))
                    if (values.get("LoadState") not in {"loaded", "not-found"}
                            or values.get("ActiveState") not in {"active", "inactive", "failed", "activating", "deactivating", "reloading"}
                            or values["LoadState"] == "not-found" and values["ActiveState"] != "inactive"):
                        raise RebootError()
                    report[prefix + "_" + kind + "_present"] = values["LoadState"] == "loaded"
                    report[prefix + "_" + kind + "_active"] = values["ActiveState"] in {"active", "activating", "deactivating", "reloading"}
            report["transient_state_checked"] = True
            # Successful collection does not mean these two generations match.
            report.update(status="success", stage="complete", failure_reason="none")
    except Exception as error:
        report["failure_reason"] = "auxiliary_metadata_refused" if isinstance(error, AuxiliaryFileError) else "inspection_failed"
    return report


def _validate_comparison(value):
    if (not isinstance(value, dict) or set(value) != DIAGNOSTIC_FIELDS
            or value["scope"] != "recovery_comparison_diagnostic" or value["action"] != "compare-recovery"
            or not isinstance(value["status"], str) or value["status"] not in {"success", "failed"}
            or not isinstance(value["stage"], str) or value["stage"] not in DIAGNOSTIC_STAGES
            or not isinstance(value["failure_reason"], str) or value["failure_reason"] not in {"none", "invalid_configuration", "inspection_failed", "auxiliary_metadata_refused"}
            or any(type(value[field]) is not bool for field in DIAGNOSTIC_BOOLS)
            or any(type(value[field]) is not int or not 0 <= value[field] <= MAX_ROWS for field in DIAGNOSTIC_COUNTS)
            or value["server_modified"]
            or (value["status"] == "success") != (value["stage"] == "complete")
            or (value["status"] == "success") != (value["failure_reason"] == "none")):
        raise ValueError("invalid comparison diagnostic")
    if value["status"] == "success" and not all(value[field] for field in (
            "source_verified", "backup_baseline_verified", "snapshot_checked", "live_checked",
            "services_state_checked", "transient_state_checked")):
        raise ValueError("invalid comparison diagnostic")
    if value["all_tables_match"] and not all(value[table + "_matches"] for table in TABLES):
        raise ValueError("invalid comparison diagnostic")
    if any(value[table + "_matches"] and not (value["snapshot_checked"] and value["live_checked"])
           for table in TABLES):
        raise ValueError("invalid comparison diagnostic")
    return dict(value)


def _initial_report(action):
    if action == "compare-recovery":
        return _comparison_initial()
    return {"scope": "os_reboot_recovery", "action": action if isinstance(action, str) and action in BOOT_ACTIONS else "reboot-recovery",
            "status": "failed", "stage": "configuration", "failure_reason": "invalid_configuration",
            "comparison_detail": "not_checked", "cleanup_detail": "not_required",
            "prerequisite_basis": PREREQUISITE_BASIS, "backup_policy_basis": BACKUP_POLICY_BASIS,
            "baseline_schema_version": 0,
            **dict.fromkeys(BOOLEANS, False), **dict.fromkeys(COUNTS, 0)}


def run(config, action="reboot-recovery"):
    if action == "compare-recovery":
        return _compare_recovery(config)
    report = _initial_report(action)
    try:
        if type(action) is not str or action not in ACTIONS:
            return report
        config = validate_config(config)
    except Exception:
        return report
    try:
        report["stage"] = "lock"
        with helper._deadline(240), _interruptions(), _operation_lock():
            if action == "reboot-recovery":
                _request_reboot(config, report)
            else:
                _verify_reboot(config, report)
    except Exception as error:
        report["status"] = "failed"
        if isinstance(error, AuxiliaryFileError):
            report["comparison_detail"] = "auxiliary_metadata_refused"
        if report["failure_reason"] != "fallback_recovery_failed":
            report["failure_reason"] = FAILURE_BY_STAGE.get(report["stage"], "preflight_refused")
    return report


def validate_report(value):
    if isinstance(value, dict) and value.get("scope") == "recovery_comparison_diagnostic":
        return _validate_comparison(value)
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "os_reboot_recovery"
            or not isinstance(value["action"], str) or value["action"] not in BOOT_ACTIONS
            or not isinstance(value["status"], str) or value["status"] not in {"success", "failed"}
            or not isinstance(value["stage"], str) or value["stage"] not in STAGES
            or not isinstance(value["failure_reason"], str) or value["failure_reason"] not in FAILURES
            or not isinstance(value["comparison_detail"], str) or value["comparison_detail"] not in COMPARISON_DETAILS
            or not isinstance(value["cleanup_detail"], str) or value["cleanup_detail"] not in CLEANUP_DETAILS
            or value["prerequisite_basis"] != PREREQUISITE_BASIS
            or not isinstance(value["backup_policy_basis"], str) or value["backup_policy_basis"] not in {BACKUP_POLICY_BASIS, "unverified_legacy_record"}
            or type(value["baseline_schema_version"]) is not int or value["baseline_schema_version"] not in {0, 1, 2}
            or any(type(value[field]) is not bool for field in BOOLEANS)
            or any(type(value[field]) is not int or not 0 <= value[field] <= MAX_ROWS for field in COUNTS)
            or value["off_host_backup_verified_by_server"] or value["new_calculation_verified"]
            or value["backup_policy_console_verified"] or value["backup_baseline_verified"] or value["snapshot_semantics_matched"]
            or (value["status"] == "success") != (value["stage"] == "complete")
            or (value["status"] == "success") != (value["failure_reason"] == "none")):
        raise ValueError("invalid reboot recovery report")
    if value["status"] == "success":
        required = ("audit_prerequisites_met", "admission_paused", "backup_timer_paused", "no_pending_runs",
                    "application_stopped", "quiescent_live_baseline_verified", "private_baseline_saved", "reboot_scheduled") \
                   if value["action"] == "reboot-recovery" else \
                   ("audit_prerequisites_met", "no_pending_runs", "private_baseline_saved", "boot_changed", "services_restored",
                    "database_preserved", "peer_containers_preserved", "settings_preserved", "worker_exclusivity_verified", "quiescent_live_baseline_verified")
        if not all(value[field] for field in required):
            raise ValueError("invalid reboot recovery report")
        if (value["action"] == "reboot-recovery" and value["baseline_schema_version"] != 2
                or value["action"] == "verify-reboot" and value["baseline_schema_version"] not in {1, 2}):
            raise ValueError("invalid reboot recovery report")
    if value["action"] == "reboot-recovery" and any(value[field] for field in ("boot_changed", "database_preserved", "peer_containers_preserved", "settings_preserved")):
        raise ValueError("invalid reboot recovery report")
    if value["action"] == "verify-reboot" and any(value[field] for field in ("reboot_scheduled", "application_stopped", "admission_paused", "backup_timer_paused")):
        raise ValueError("invalid reboot recovery report")
    return dict(value)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
            return None
        return validate_report(helper._json(raw))
    except Exception:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    action = argv[1] if len(argv) == 2 and argv[1] in ACTIONS else "reboot-recovery"
    try:
        if len(argv) != 2 or argv[1] not in ACTIONS:
            raise ValueError
        report = run(_argument(argv[0]), argv[1])
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
