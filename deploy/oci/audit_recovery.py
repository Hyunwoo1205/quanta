#!/usr/bin/env python3
"""Read-only, bounded recovery inventory for the pinned boot-volume installation.

This operation never restarts services, stops a timer, submits a calculation or
changes container policies. Private identities and credentials remain on-host.
A successful audit means collection completed, not that a reboot was performed
or that external backup/recovery was proved.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
ROOT = Path("/srv/quanta")
DATA = ROOT / "data"
BACKUPS = ROOT / "backups"
ETC = Path("/etc/quanta")
RUNTIME = Path("/usr/local/lib/quanta/runtime.py")
SYSTEMD = Path("/etc/systemd/system")
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
MAX_OUTPUT_BYTES = 8192
MAX_DATABASE_BYTES = 8 * 1024**3
MAX_COUNT = 2**31 - 1
TRUSTED = {
    "runtime": "88a865b2755c1ecf4a16a0bee18b4d233c63bc937064a6431e50c052ac1abc38",
    "quanta-boot.service": "e2e0ffcb3de234abe263d9e50084f616036abfab3a7d77065035354301893ce7",
    "quanta-backup-boot.service": "4c8e703a69d332f588c3cd020bfa9da50f9b0a08258f8068fff4c7eb8dc0fa14",
    "quanta-backup-boot.timer": "f19f55776c6763b0c0d3480e2b9ba78f3951780095b0870bcf35dafde594a491",
    "quanta-https.service": "06e60b65101d1321297d55fc396573b35d1e4eafbe9f93166c11ca683f460eab",
}
BOOLEANS = (
    "source_verified", "storage_verified", "boot_id_valid", "app_active", "app_enabled",
    "https_active", "https_enabled", "docker_active", "docker_enabled", "backup_timer_active",
    "backup_timer_enabled", "backup_services_idle", "latest_backup_service_succeeded",
    "latest_snapshot_present", "authenticated_ready", "single_app_container",
    "worker_exclusivity_verified", "database_checked", "no_pending_runs",
    "peer_restart_policies_safe", "sufficient_disk_space", "host_reboot_prerequisites_met",
    "off_host_backup_verified", "safe_to_reboot", "server_modified",
)
INTEGERS = ("experiments", "revisions", "runs", "artifacts", "nonterminal_runs",
            "peer_containers", "running_peer_containers", "restartable_running_peers",
            "backup_snapshots", "latest_snapshot_age_seconds", "free_disk_mib")
STAGES = frozenset({"configuration", "installation", "services", "containers", "worker",
                    "database", "backups", "complete"})
FAILURES = frozenset({"none", "invalid_configuration", "inspection_failed", "deadline"})
FIELDS = frozenset(("scope", "status", "stage", "failure_reason", *BOOLEANS, *INTEGERS))
TERMINAL = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
STATUSES = TERMINAL | {"QUEUED", "RUNNING", "CANCEL_REQUESTED"}
PREREQUISITES = ("source_verified", "storage_verified", "boot_id_valid", "app_active", "app_enabled",
    "https_active", "https_enabled", "docker_active", "docker_enabled", "backup_timer_active", "backup_timer_enabled",
    "backup_services_idle", "latest_snapshot_present", "authenticated_ready", "single_app_container",
    "worker_exclusivity_verified", "database_checked", "no_pending_runs", "peer_restart_policies_safe", "sufficient_disk_space")


class AuditError(Exception):
    pass


class AuditDeadline(AuditError):
    pass


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AuditError()
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(AuditError()))


def validate_config(config):
    if (not isinstance(config, dict) or set(config) != {"source_sha", "public_origin", "auth_mode"}
            or config["source_sha"] != SOURCE_SHA or config["auth_mode"] != "owner-token"
            or not isinstance(config["public_origin"], str)):
        raise ValueError("invalid audit configuration")
    origin = config["public_origin"]
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    host = origin[8:] if origin.startswith("https://") else ""
    if (not 3 <= len(host) <= 253 or not re.fullmatch(label + r"(?:\." + label + r")+", host)
            or not any("a" <= c <= "z" for c in host.rsplit(".", 1)[1])):
        raise ValueError("invalid audit configuration")
    return dict(config)


def _argument(value):
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 4096:
            raise ValueError
        raw = base64.b64decode(value, validate=True)
        config = validate_config(_json(raw))
        if (base64.b64encode(raw).decode() != value
                or json.dumps(config, sort_keys=True, separators=(",", ":")).encode() != raw):
            raise ValueError
        return config
    except Exception:
        raise ValueError("invalid audit configuration") from None


@contextmanager
def _deadline(seconds):
    def expired(signum, frame):
        raise AuditDeadline()
    handler = signal.getsignal(signal.SIGALRM)
    previous = signal.setitimer(signal.ITIMER_REAL, 0)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, handler)
        if previous[0] > 0:
            signal.setitimer(signal.ITIMER_REAL,
                            max(0.001, previous[0] - (time.monotonic() - started)), previous[1])


def _environment():
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
            "HOME": str(ROOT / "docker-config"), "DOCKER_CONFIG": str(ROOT / "docker-config"),
            "DOCKER_HOST": "unix:///var/run/docker.sock"}


def _capture(command, *, timeout=5, limit=8192):
    process = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, env=_environment(), cwd="/")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise AuditError()
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                        raise AuditError()
                    return bytes(output)
                output.extend(chunk)
                if len(output) > limit:
                    raise AuditError()
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except Exception:
                pass
            if process.stdout is not None:
                process.stdout.close()


def _no_links(path):
    for item in (*reversed(path.parents), path):
        if stat.S_ISLNK(os.lstat(item).st_mode):
            raise AuditError()


def _root_parents(path):
    for parent in reversed(path.parents):
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AuditError()


def _read_root(path, *, limit=8192, private=False):
    _root_parents(path)
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
            or before.st_mode & 0o022 or private and stat.S_IMODE(before.st_mode) != 0o600):
        raise AuditError()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise AuditError()
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise AuditError()
    return raw


def _private(path, device, *, directory=False, maximum=MAX_DATABASE_BYTES):
    _no_links(path)
    value = os.lstat(path)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(value.st_mode) or value.st_uid != 10001 or value.st_gid != 10001
            or stat.S_IMODE(value.st_mode) != (0o700 if directory else 0o600)
            or value.st_dev != device or not directory and (value.st_nlink != 1 or value.st_size > maximum)):
        raise AuditError()
    return value


def _unit_properties(unit, properties):
    raw = _capture(["/usr/bin/systemctl", "show", "--all", "--no-pager",
                    "--property=" + ",".join(properties), unit], limit=2048)
    rows = raw.decode("ascii").splitlines()
    if len(rows) != len(properties):
        raise AuditError()
    result = {}
    for row in rows:
        key, separator, value = row.partition("=")
        if not separator or key not in properties or key in result:
            raise AuditError()
        result[key] = value
    if set(result) != set(properties):
        raise AuditError()
    return result


def _verify_units():
    for unit in TRUSTED.keys() - {"runtime"}:
        path = SYSTEMD / unit
        if hashlib.sha256(_read_root(path, limit=16384)).hexdigest() != TRUSTED[unit]:
            raise AuditError()
        properties = _unit_properties(unit, ("FragmentPath", "DropInPaths"))
        if properties != {"FragmentPath": str(path), "DropInPaths": ""}:
            raise AuditError()


def _installation(config, report):
    if os.geteuid() != 0 or _json(_read_root(ETC / "installed.json", private=True)) != config:
        raise AuditError()
    if hashlib.sha256(_read_root(RUNTIME, limit=16384)).hexdigest() != TRUSTED["runtime"]:
        raise AuditError()
    _verify_units()
    deployment = _json(_read_root(ETC / "deployment.json", private=True))
    if (not isinstance(deployment, dict) or set(deployment) != {"storage_mode", "filesystem_uuid", "image"}
            or deployment["storage_mode"] != "boot" or not isinstance(deployment["filesystem_uuid"], str)
            or str(uuid.UUID(deployment["filesystem_uuid"])) != deployment["filesystem_uuid"]
            or not isinstance(deployment["image"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", deployment["image"])):
        raise AuditError()
    environment = _read_root(ETC / "app.env", private=True)
    prefix = ("QUANTA_PUBLIC_ORIGIN=" + config["public_origin"] + "\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=").encode()
    if not environment.startswith(prefix) or not re.fullmatch(rb"[0-9a-f]{64}\n", environment[len(prefix):]):
        raise AuditError()
    token = environment[len(prefix):-1].decode("ascii")
    _root_parents(ROOT / "placeholder")
    device = os.lstat(ROOT).st_dev
    if device != os.lstat("/").st_dev:
        raise AuditError()
    _private(DATA, device, directory=True)
    _private(BACKUPS, device, directory=True)
    for name in ("jobs.sqlite3", "worker.lock"):
        _private(DATA / name, device)
    _database_auxiliaries(device)
    filesystem = _json(_capture(["/usr/bin/findmnt", "--json", "--target", str(ROOT), "--output",
                                "TARGET,UUID,FSTYPE,OPTIONS,FSROOT"], limit=4096))
    rows = filesystem.get("filesystems") if isinstance(filesystem, dict) else None
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get("target") != "/" or rows[0].get("fsroot") != "/"
            or rows[0].get("uuid") != deployment["filesystem_uuid"]
            or rows[0].get("fstype") not in {"ext4", "xfs"}
            or "rw" not in str(rows[0].get("options", "")).split(",")
            or "ro" in str(rows[0].get("options", "")).split(",")):
        raise AuditError()
    expected = (deployment["image"] + " arm64 linux\n").encode()
    for image in (deployment["image"], "quanta:" + SOURCE_SHA):
        if _capture(DOCKER + ["image", "inspect", "--format", "{{.Id}} {{.Architecture}} {{.Os}}", image], limit=128) != expected:
            raise AuditError()
    boot = _read_root(Path("/proc/sys/kernel/random/boot_id"), limit=64).strip().decode("ascii")
    if str(uuid.UUID(boot)) != boot:
        raise AuditError()
    report.update(source_verified=True, storage_verified=True, boot_id_valid=True)
    return deployment["image"], device, token


def _services(report):
    units = (("quanta-boot.service", "app"), ("quanta-https.service", "https"),
             ("docker.service", "docker"), ("quanta-backup-boot.timer", "backup_timer"))
    for unit, label in units:
        values = _unit_properties(unit, ("ActiveState", "UnitFileState"))
        if values["ActiveState"] not in {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"}:
            raise AuditError()
        if values["UnitFileState"] not in {"enabled", "disabled", "static", "indirect", "masked", "generated", "transient", "linked", "alias", "enabled-runtime", "masked-runtime", "linked-runtime", "bad"}:
            raise AuditError()
        report[label + "_active"] = values["ActiveState"] == "active"
        report[label + "_enabled"] = values["UnitFileState"] == "enabled"
    idle = True
    for unit in ("quanta-backup.service", "quanta-backup-boot.service"):
        values = _unit_properties(unit, ("ActiveState", "LoadState"))
        if values["LoadState"] == "not-found":
            if values["ActiveState"] != "inactive":
                raise AuditError()
            continue
        if values["LoadState"] != "loaded" or values["ActiveState"] not in {"inactive", "failed", "active", "activating", "deactivating", "reloading"}:
            raise AuditError()
        idle = idle and values["ActiveState"] in {"inactive", "failed"}
        if unit == "quanta-backup-boot.service":
            values = _unit_properties(unit, ("Result", "ExecMainStatus", "ExecMainStartTimestampMonotonic"))
            report["latest_backup_service_succeeded"] = (values["Result"] == "success"
                and values["ExecMainStatus"] == "0"
                and values["ExecMainStartTimestampMonotonic"].isdigit()
                and int(values["ExecMainStartTimestampMonotonic"]) > 0)
    report["backup_services_idle"] = idle


def _containers(image, report):
    raw = _capture(DOCKER + ["container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"], limit=65536)
    ids = raw.decode("ascii").splitlines()
    if not 1 <= len(ids) <= 256 or len(set(ids)) != len(ids) or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in ids):
        raise AuditError()
    template = "{{.Id}} {{.Name}} {{.Image}} {{.State.Running}} {{.HostConfig.RestartPolicy.Name}} {{.State.Paused}} {{.State.Restarting}} {{.State.Dead}}"
    lines = _capture(DOCKER + ["container", "inspect", "--format", template, *ids], limit=131072).decode("ascii").splitlines()
    if len(lines) != len(ids):
        raise AuditError()
    found = set()
    app = []
    peers = []
    pattern = r"([0-9a-f]{64}) (/[A-Za-z0-9][A-Za-z0-9_.-]{0,254}) (sha256:[0-9a-f]{64}) (true|false) (no|always|unless-stopped|on-failure) (true|false) (true|false) (true|false)"
    for line in lines:
        match = re.fullmatch(pattern, line)
        if match is None or match[1] not in ids or match[1] in found:
            raise AuditError()
        found.add(match[1])
        value = match.groups()
        if value[1] == "/quanta":
            app.append(value)
        elif value[1] in {"/quanta-backup", "/quanta-operations-check"}:
            report["backup_services_idle"] = False
        else:
            peers.append(value)
    report["single_app_container"] = (len(app) == 1 and app[0][2] == image
        and app[0][3] == "true" and app[0][4] == "no" and all(x == "false" for x in app[0][5:]))
    running = [peer for peer in peers if peer[3] == "true"]
    restartable = [peer for peer in running if peer[4] in {"always", "unless-stopped"}
                   and all(value == "false" for value in peer[5:])]
    report.update(peer_containers=len(peers), running_peer_containers=len(running),
                  restartable_running_peers=len(restartable), peer_restart_policies_safe=len(running) == len(restartable))


def _worker(report, device):
    lock = _private(DATA / "worker.lock", device, maximum=1024)
    raw = _read_root(Path("/proc/locks"), limit=1024 * 1024)
    holders = 0
    for row in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"[0-9]+:[ \t]+FLOCK[ \t]+ADVISORY[ \t]+WRITE[ \t]+[0-9]+[ \t]+([0-9a-f]+):([0-9a-f]+):([0-9]+)[ \t]+0[ \t]+EOF", row)
        if match is not None and (int(match[1], 16), int(match[2], 16), int(match[3])) == (os.major(lock.st_dev), os.minor(lock.st_dev), lock.st_ino):
            holders += 1
    report["worker_exclusivity_verified"] = holders == 1


def _ready(config, token):
    connection = http.client.HTTPConnection("127.0.0.1", 8765, timeout=2)
    try:
        connection.request("GET", "/health/ready", headers={"Host": config["public_origin"][8:],
            "Origin": config["public_origin"], "Authorization": "Bearer " + token, "Connection": "close"})
        response = connection.getresponse()
        raw = response.read(1025)
        return response.status == 200 and len(raw) <= 1024 and _json(raw) == {"status": "ready"}
    finally:
        connection.close()


@contextmanager
def _database_identity():
    """Keep SQLite WAL helpers owned by the store user, retaining real root.

    SQLite mode=ro can still create WAL/SHM files. Only this bounded connection
    is opened with effective 10001:10001; inspection before/after remains root.
    Block the audit alarm during each credential transition, including partial
    entry failure and restoration. A pending alarm is delivered after restoring
    the previous mask and still unwinds through the outer finally block.
    """
    previous_uid, previous_gid = os.geteuid(), os.getegid()
    if previous_uid != 0:
        raise AuditError()

    @contextmanager
    def transition():
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGHUP, signal.SIGTERM})
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    try:
        with transition():
            os.setegid(10001)
            os.seteuid(10001)
        yield
    finally:
        with transition():
            try:
                os.seteuid(previous_uid)
            finally:
                os.setegid(previous_gid)


def _database_auxiliaries(device):
    # WAL/SHM are optional, volatile SQLite helpers. Check ownership and bounds
    # without comparing their size/mtime across a live read or changing them.
    for name, maximum in (("jobs.sqlite3-wal", MAX_DATABASE_BYTES),
                          ("jobs.sqlite3-shm", 128 * 1024**2)):
        path = DATA / name
        try:
            os.lstat(path)
            _private(path, device, maximum=maximum)
        except FileNotFoundError:
            continue


def _database(report, device):
    path = DATA / "jobs.sqlite3"
    before = _private(path, device)
    _database_auxiliaries(device)
    with _database_identity():
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2, isolation_level=None)
        try:
            expires = time.monotonic() + 5
            connection.set_progress_handler(lambda: int(time.monotonic() > expires), 1000)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            if connection.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
                raise AuditError()
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables != {"experiments", "revisions", "runs", "idempotency", "events", "artifacts"}:
                raise AuditError()
            counts = {name: connection.execute("SELECT count(*) FROM " + name).fetchone()[0]
                      for name in ("experiments", "revisions", "runs", "artifacts")}
            statuses = connection.execute("SELECT status,count(*) FROM runs GROUP BY status").fetchall()
            if any(status not in STATUSES or type(count) is not int or not 0 <= count <= MAX_COUNT for status, count in statuses):
                raise AuditError()
            counts["nonterminal_runs"] = sum(count for status, count in statuses if status not in TERMINAL)
            if any(type(value) is not int or not 0 <= value <= MAX_COUNT for value in counts.values()):
                raise AuditError()
            connection.execute("ROLLBACK")
        finally:
            connection.close()
    after = _private(path, device)
    _database_auxiliaries(device)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise AuditError()
    report.update(counts)
    report.update(database_checked=True, no_pending_runs=counts["nonterminal_runs"] == 0)


def _backups(report, device):
    now = time.time()
    stamps = []
    entries = 0
    with os.scandir(BACKUPS) as iterator:
        for entry in iterator:
            entries += 1
            if entries > 1000:
                raise AuditError()
            if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}", entry.name):
                continue
            timestamp = datetime.strptime(entry.name[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
            if uuid.UUID(hex=entry.name[17:]).version != 4 or timestamp > now + 300:
                raise AuditError()
            path = BACKUPS / entry.name
            _private(path, device, directory=True)
            _private(path / "jobs.sqlite3", device)
            _private(path / "manifest.json", device, maximum=1024 * 1024)
            stamps.append(timestamp)
    report["backup_snapshots"] = len(stamps)
    report["latest_snapshot_present"] = bool(stamps)
    if stamps:
        report["latest_snapshot_age_seconds"] = min(MAX_COUNT, max(0, int(now - max(stamps))))
    free = shutil.disk_usage(ROOT).free
    report["free_disk_mib"] = min(MAX_COUNT, free // 1024**2)
    report["sufficient_disk_space"] = free >= 1024**3


def _initial_report():
    return {"scope": "recovery_audit", "status": "failed", "stage": "configuration",
            "failure_reason": "invalid_configuration", **dict.fromkeys(BOOLEANS, False), **dict.fromkeys(INTEGERS, 0)}


def _perform(config, report):
    report["stage"] = "installation"
    image, device, token = _installation(config, report)
    report["stage"] = "services"
    _services(report)
    report["authenticated_ready"] = _ready(config, token)
    report["stage"] = "containers"
    _containers(image, report)
    report["stage"] = "worker"
    _worker(report, device)
    report["stage"] = "database"
    _database(report, device)
    report["stage"] = "backups"
    _backups(report, device)
    report["host_reboot_prerequisites_met"] = all(report[field] for field in PREREQUISITES)
    # Neither external copy verification nor a reboot belongs to this read-only operation.
    report.update(status="success", stage="complete", failure_reason="none")


def run(config):
    report = _initial_report()
    try:
        config = validate_config(config)
    except Exception:
        return report
    try:
        with _deadline(45):
            _perform(config, report)
    except AuditDeadline:
        report.update(status="failed", failure_reason="deadline")
    except Exception:
        report.update(status="failed", failure_reason="inspection_failed")
    return report


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "recovery_audit"
            or not isinstance(value["status"], str) or value["status"] not in {"success", "failed"}
            or not isinstance(value["stage"], str) or value["stage"] not in STAGES
            or not isinstance(value["failure_reason"], str) or value["failure_reason"] not in FAILURES
            or any(type(value[key]) is not bool for key in BOOLEANS)
            or any(type(value[key]) is not int or not 0 <= value[key] <= MAX_COUNT for key in INTEGERS)
            or (value["status"] == "success") != (value["stage"] == "complete")
            or (value["status"] == "success") != (value["failure_reason"] == "none")
            or value["server_modified"] or value["off_host_backup_verified"] or value["safe_to_reboot"]
            or value["restartable_running_peers"] > value["running_peer_containers"]
            or value["running_peer_containers"] > value["peer_containers"]
            or value["nonterminal_runs"] > value["runs"]
            or value["no_pending_runs"] and (not value["database_checked"] or value["nonterminal_runs"] != 0)
            or value["host_reboot_prerequisites_met"] and
                (value["status"] != "success" or not all(value[field] for field in PREREQUISITES))):
        raise ValueError("invalid audit report")
    return dict(value)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
            return None
        return validate_report(_json(raw))
    except Exception:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) != 1:
            raise ValueError
        report = run(_argument(argv[0]))
    except Exception:
        report = _initial_report()
    try:
        report = validate_report(report)
    except Exception:
        report = _initial_report()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
