#!/usr/bin/env python3
"""Verify one installed app's fresh backup and isolated restore, then enable units.

Only fixed status/stage/boolean facts are public. Snapshot and restore locations,
tokens, image/container identities and database bytes remain private. Existing
snapshots and production data are never replaced or deleted.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
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
NAME = "quanta-operations-check"
LABEL = "org.quanta.operations.check"
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT_BYTES = 8192
MAX_ENTRIES = 1000
MAX_DATABASE_BYTES = 8 * 1024**3
TRUSTED = {
    "runtime": "88a865b2755c1ecf4a16a0bee18b4d233c63bc937064a6431e50c052ac1abc38",
    "quanta-boot.service": "e2e0ffcb3de234abe263d9e50084f616036abfab3a7d77065035354301893ce7",
    "quanta-backup-boot.service": "4c8e703a69d332f588c3cd020bfa9da50f9b0a08258f8068fff4c7eb8dc0fa14",
    "quanta-backup-boot.timer": "f19f55776c6763b0c0d3480e2b9ba78f3951780095b0870bcf35dafde594a491",
}
BOOLEAN_FIELDS = ("source_verified", "backup_created", "backup_verified", "restore_verified",
                  "production_preserved", "app_enabled", "backup_timer_enabled", "backup_timer_active")
STAGES = frozenset({"configuration", "preflight", "backup", "verify", "restore", "production_check", "enable", "complete"})
FIELDS = frozenset(("scope", "status", "stage", *BOOLEAN_FIELDS))


class VerificationError(Exception):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError()
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(VerificationError()))


def validate_config(config):
    if (not isinstance(config, dict) or set(config) != {"source_sha", "public_origin", "auth_mode"}
            or config["source_sha"] != SOURCE_SHA or config["auth_mode"] != "owner-token"
            or not isinstance(config["public_origin"], str)):
        raise ValueError("invalid verification configuration")
    origin = config["public_origin"]
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    host = origin[8:] if origin.startswith("https://") else ""
    if (not 3 <= len(host) <= 253 or not re.fullmatch(label + r"(?:\." + label + r")+", host)
            or not any("a" <= character <= "z" for character in host.rsplit(".", 1)[1])):
        raise ValueError("invalid verification configuration")
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
        raise ValueError("invalid verification configuration") from None


@contextmanager
def _deadline(seconds):
    def expired(signum, frame):
        raise VerificationError()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL,
                            max(0.001, previous_timer[0] - (time.monotonic() - started)), previous_timer[1])


def _environment():
    return {"PATH": BINPATH, "LC_ALL": "C", "HOME": str(ROOT / "docker-config"),
            "DOCKER_CONFIG": str(ROOT / "docker-config"), "DOCKER_HOST": "unix:///var/run/docker.sock"}


def _quiet(command, *, timeout=10):
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, shell=False, env=_environment(), cwd="/", timeout=timeout, check=False)
        if result.returncode != 0:
            raise VerificationError()
    except Exception:
        raise VerificationError() from None


def _capture(command, *, timeout=5, limit=1024):
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
                    return None
                chunk = os.read(process.stdout.fileno(), min(256, limit + 1 - len(output)))
                if not chunk:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or process.wait(timeout=remaining) != 0:
                        return None
                    return bytes(output)
                output.extend(chunk)
                if len(output) > limit:
                    return None
    except Exception:
        return None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=1)
            except Exception:
                pass
            if process.stdout is not None:
                process.stdout.close()


def _no_links(path):
    for item in (*reversed(path.parents), path):
        if stat.S_ISLNK(os.lstat(item).st_mode):
            raise VerificationError()


def _root_parents(path):
    for parent in reversed(path.parents):
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise VerificationError()


def _read_root(path, *, limit=8192, private=False):
    _root_parents(path)
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
            or before.st_mode & 0o022 or private and stat.S_IMODE(before.st_mode) != 0o600):
        raise VerificationError()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise VerificationError()
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise VerificationError()
    return raw


def _private_dir(path, device):
    _no_links(path)
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 10001 or info.st_gid != 10001
            or stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != device):
        raise VerificationError()
    return info


def _private_file(path, device, *, maximum=MAX_DATABASE_BYTES):
    _no_links(path)
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 10001 or info.st_gid != 10001
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_dev != device or info.st_size > maximum):
        raise VerificationError()
    return info


def _names_absent():
    raw = _capture(DOCKER + ["container", "ls", "--all", "--filter",
        "name=^/(quanta-backup|quanta-operations-check)$", "--format", "{{.Names}}"], limit=128)
    if raw != b"":
        raise VerificationError()


def _inactive_backups():
    try:
        result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "quanta-backup.service",
            "quanta-backup-boot.service", "quanta-backup.timer", "quanta-backup-boot.timer"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            shell=False, env=_environment(), cwd="/", timeout=4, check=False)
        if result.returncode not in {3, 4}:
            raise VerificationError()
    except Exception:
        raise VerificationError() from None


def _ready(config, token):
    connection = http.client.HTTPConnection("127.0.0.1", 8765, timeout=2)
    try:
        connection.request("GET", "/health/ready", headers={"Host": config["public_origin"][8:],
            "Origin": config["public_origin"], "Authorization": "Bearer " + token, "Connection": "close"})
        response = connection.getresponse()
        raw = response.read(1025)
        if response.status != 200 or len(raw) > 1024 or _json(raw) != {"status": "ready"}:
            raise VerificationError()
    finally:
        connection.close()


def _production_identity(image, device):
    raw = _capture(DOCKER + ["container", "inspect", "--format",
        "{{.Id}} {{.Image}} {{.State.Running}} {{.State.StartedAt}}", "quanta"], limit=256)
    match = re.fullmatch(rb"([0-9a-f]{64}) (sha256:[0-9a-f]{64}) true ([0-9]{4}-[0-9T:.-]{15,35}Z)\n", raw or b"")
    if match is None or match[2].decode() != image:
        raise VerificationError()
    directory = _private_dir(DATA, device)
    database = _private_file(DATA / "jobs.sqlite3", device)
    lock = _private_file(DATA / "worker.lock", device, maximum=1024)
    return (match[1], match[2], match[3], directory.st_dev, directory.st_ino,
            database.st_dev, database.st_ino, lock.st_dev, lock.st_ino)


def _verify_units():
    for unit in TRUSTED.keys() - {"runtime"}:
        path = SYSTEMD / unit
        if hashlib.sha256(_read_root(path, limit=16384)).hexdigest() != TRUSTED[unit]:
            raise VerificationError()
        raw = _capture(["/usr/bin/systemctl", "show", "--all", "--no-pager", "--property=FragmentPath,DropInPaths", unit])
        expected = {("FragmentPath=" + str(path)).encode(), b"DropInPaths="}
        if raw is None or len(raw.splitlines()) != 2 or set(raw.splitlines()) != expected:
            raise VerificationError()


def _preflight(config):
    if os.geteuid() != 0:
        raise VerificationError()
    if _json(_read_root(ETC / "installed.json", private=True)) != config:
        raise VerificationError()
    if hashlib.sha256(_read_root(RUNTIME, limit=16384)).hexdigest() != TRUSTED["runtime"]:
        raise VerificationError()
    _verify_units()
    deployment = _json(_read_root(ETC / "deployment.json", private=True))
    if (not isinstance(deployment, dict) or set(deployment) != {"storage_mode", "filesystem_uuid", "image"}
            or deployment["storage_mode"] != "boot" or not isinstance(deployment["filesystem_uuid"], str)
            or str(uuid.UUID(deployment["filesystem_uuid"])) != deployment["filesystem_uuid"]
            or not isinstance(deployment["image"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", deployment["image"])):
        raise VerificationError()
    environment = _read_root(ETC / "app.env", private=True)
    prefix = ("QUANTA_PUBLIC_ORIGIN=" + config["public_origin"] + "\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=").encode()
    if not environment.startswith(prefix) or not re.fullmatch(rb"[0-9a-f]{64}\n", environment[len(prefix):]):
        raise VerificationError()
    token = environment[len(prefix):-1].decode("ascii")
    _root_parents(ROOT / "placeholder")
    device = os.lstat(ROOT).st_dev
    if device != os.lstat("/").st_dev:
        raise VerificationError()
    _private_dir(DATA, device)
    _private_dir(BACKUPS, device)
    if shutil.disk_usage(ROOT).free < 1024**3:
        raise VerificationError()
    _inactive_backups()
    _names_absent()
    image = deployment["image"]
    if _capture(DOCKER + ["image", "inspect", "--format", "{{.Id}} {{.Architecture}} {{.Os}}", image], limit=128) != (image + " arm64 linux\n").encode():
        raise VerificationError()
    _quiet(["/usr/bin/python3", "-I", "-B", str(RUNTIME), "check", "--storage-mode", "boot"], timeout=20)
    _quiet(["/usr/bin/systemctl", "is-active", "--quiet", "quanta-boot.service"])
    _ready(config, token)
    identity = _production_identity(image, device)
    return image, device, token, identity


def _entries():
    result = {}
    with os.scandir(BACKUPS) as entries:
        for entry in entries:
            if len(result) >= MAX_ENTRIES or len(entry.name) > 255:
                raise VerificationError()
            info = entry.stat(follow_symlinks=False)
            result[entry.name] = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns)
    return result


def _fresh_backup(before, device):
    after = _entries()
    if any(name not in after or after[name] != metadata for name, metadata in before.items()):
        raise VerificationError()
    fresh = set(after) - set(before)
    if len(fresh) != 1:
        raise VerificationError()
    name = fresh.pop()
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}", name):
        raise VerificationError()
    datetime.strptime(name[:16], "%Y%m%dT%H%M%SZ")
    if uuid.UUID(hex=name[17:]).version != 4:
        raise VerificationError()
    path = BACKUPS / name
    _private_dir(path, device)
    _children(path, {"jobs.sqlite3", "manifest.json"})
    _private_file(path / "jobs.sqlite3", device)
    _private_file(path / "manifest.json", device, maximum=1024 * 1024)
    return path


def _children(path, expected):
    actual = set()
    with os.scandir(path) as children:
        for child in children:
            actual.add(child.name)
            if len(actual) > len(expected):
                raise VerificationError()
    if actual != expected:
        raise VerificationError()


def _hash(path, device):
    before = _private_file(path, device)
    if before.st_size <= 0:
        raise VerificationError()
    digest, size = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise VerificationError()
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_DATABASE_BYTES:
                raise VerificationError()
            digest.update(chunk)
        final = os.fstat(stream.fileno())
    if (size != before.st_size or (before.st_size, before.st_mtime_ns) != (final.st_size, final.st_mtime_ns)
            or (os.lstat(path).st_dev, os.lstat(path).st_ino) != (before.st_dev, before.st_ino)):
        raise VerificationError()
    _private_file(path, device)
    return size, digest.digest()


def _scratch(device, operation):
    path = ROOT / ("restore-verification-" + operation)
    _root_parents(path)
    os.mkdir(path, 0o700)
    os.chown(path, 10001, 10001, follow_symlinks=False)
    os.chmod(path, 0o700, follow_symlinks=False)
    _private_dir(path, device)
    return path


def _stop_owned(image, operation):
    raw = _capture(DOCKER + ["container", "inspect", "--format",
        '{{index .Config.Labels "' + LABEL + '"}} {{.Image}}', NAME], limit=160)
    if raw == (operation + " " + image + "\n").encode():
        try:
            _quiet(DOCKER + ["stop", "--time", "5", NAME], timeout=10)
        except VerificationError:
            pass


def _container(image, operation, snapshot, arguments, *, scratch=None):
    _names_absent()
    command = DOCKER + ["run", "--rm", "--pull=never", "--name", NAME,
        "--label", LABEL + "=" + operation, "--network", "none", "--user", "10001:10001",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--cpus", "2",
        "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "128", "--workdir", "/tmp",
        "--mount", "type=bind,source=" + str(snapshot) + ",target=/backup,readonly"]
    if scratch is not None:
        command += ["--mount", "type=bind,source=" + str(scratch) + ",target=/restore"]
    command += [image, "python", "-m", "quanta", *arguments]
    try:
        _quiet(command, timeout=90)
        _names_absent()
    except Exception:
        _stop_owned(image, operation)
        raise


def _check_production(config, token, image, device, identity):
    if _production_identity(image, device) != identity:
        raise VerificationError()
    _quiet(["/usr/bin/systemctl", "is-active", "--quiet", "quanta-boot.service"])
    _ready(config, token)


def _initial_report():
    return {"scope": "backup_verification", "status": "failed", "stage": "configuration",
            **dict.fromkeys(BOOLEAN_FIELDS, False)}


def _perform(config, report):
    report["stage"] = "preflight"
    image, device, token, identity = _preflight(config)
    report["source_verified"] = True
    before = _entries()
    report["stage"] = "backup"
    _quiet(["/usr/bin/python3", "-I", "-B", str(RUNTIME), "backup", "--storage-mode", "boot"], timeout=180)
    _names_absent()
    snapshot = _fresh_backup(before, device)
    report["backup_created"] = True
    operation = uuid.uuid4().hex
    report["stage"] = "verify"
    _container(image, operation, snapshot, ["verify-backup", "/backup"])
    snapshot_hash = _hash(snapshot / "jobs.sqlite3", device)
    report["backup_verified"] = True
    report["stage"] = "restore"
    if shutil.disk_usage(ROOT).free < 128 * 1024**2 + snapshot_hash[0]:
        raise VerificationError()
    scratch = _scratch(device, operation)
    _container(image, operation, snapshot, ["restore-store", "/backup", "--output", "/restore/store"], scratch=scratch)
    restored = scratch / "store"
    _private_dir(restored, device)
    _children(scratch, {"store"})
    _children(restored, {"jobs.sqlite3"})
    if _hash(restored / "jobs.sqlite3", device) != snapshot_hash:
        raise VerificationError()
    report["restore_verified"] = True
    report["stage"] = "production_check"
    _check_production(config, token, image, device, identity)
    report["production_preserved"] = True
    report["stage"] = "enable"
    _verify_units()
    _quiet(["/usr/bin/systemctl", "enable", "quanta-boot.service"])
    _quiet(["/usr/bin/systemctl", "is-enabled", "--quiet", "quanta-boot.service"])
    report["app_enabled"] = True
    _quiet(["/usr/bin/systemctl", "enable", "--now", "quanta-backup-boot.timer"])
    _quiet(["/usr/bin/systemctl", "is-enabled", "--quiet", "quanta-backup-boot.timer"])
    report["backup_timer_enabled"] = True
    _quiet(["/usr/bin/systemctl", "is-active", "--quiet", "quanta-backup-boot.timer"])
    report["backup_timer_active"] = True
    report["production_preserved"] = False
    _check_production(config, token, image, device, identity)
    report["production_preserved"] = True
    report.update(status="success", stage="complete")


def run(config):
    report = _initial_report()
    try:
        config = validate_config(config)
    except Exception:
        return report
    try:
        with _deadline(600):
            _perform(config, report)
    except Exception:
        report["status"] = "failed"
    return report


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "backup_verification"
            or not isinstance(value["status"], str) or value["status"] not in {"success", "failed"}
            or not isinstance(value["stage"], str)
            or value["stage"] not in STAGES or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)
            or (value["status"] == "success") != (value["stage"] == "complete")):
        raise ValueError("invalid verification report")
    ordered = BOOLEAN_FIELDS[:4]
    if (any(value[field] and not all(value[earlier] for earlier in ordered[:index])
            for index, field in enumerate(ordered))
            or value["production_preserved"] and not value["restore_verified"]
            or value["app_enabled"] and not value["restore_verified"]
            or value["backup_timer_enabled"] and not value["app_enabled"]
            or value["backup_timer_active"] and not value["backup_timer_enabled"]
            or value["status"] == "success" and not all(value[field] for field in BOOLEAN_FIELDS)):
        raise ValueError("invalid verification report")
    return dict(value)


def parse_output(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
        raise ValueError("invalid verification report")
    try:
        return validate_report(_json(raw))
    except Exception:
        raise ValueError("invalid verification report") from None


def sanitize_report(raw):
    try:
        return parse_output(raw)
    except ValueError:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) != 1:
            raise ValueError
        config = _argument(argv[0])
    except Exception:
        report = _initial_report()
    else:
        report = run(config)
    try:
        report = validate_report(report)
    except Exception:
        report = _initial_report()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
