#!/usr/bin/python3
"""Opt in to ZeroSSL ACME for the fixed, previously verified Quanta deployment.

The email is sent to the CA for automatic free ACME account binding. No API key,
application token, or private key is read or reported. Multi-file commit failures
are guarded and reversible; an exact-original private backup remains on disk.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
from http.client import HTTPException, HTTPResponse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
TEMPLATE_SHA256 = "0af075db4d4f2653931916e40aa22bdd1c76c237407fe6fed5a8cb52b0392df9"
HTTPS_UNIT_SHA256 = "06e60b65101d1321297d55fc396573b35d1e4eafbe9f93166c11ca683f460eab"
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SYSTEMCTL = "/usr/bin/systemctl"
MARKER = Path("/etc/quanta/installed.json")
HTTPS_UNIT = Path("/etc/systemd/system/quanta-https.service")
CADDY = Path("/usr/local/lib/quanta/caddy")
TEMPLATE = Path("/srv/quanta/source") / SOURCE_SHA / "deploy/oci/Caddyfile.example"
CADDYFILE = Path("/etc/quanta/Caddyfile")
HTTPS_ENV = Path("/etc/quanta/https.env")
ACME_RECEIPT = Path("/etc/quanta/acme.json")
ACME_BACKUP = Path("/etc/quanta/acme-backup.json")
FW_HELPER = Path("/usr/local/lib/quanta/web_firewall.py")
ACME_CA = "https://acme.zerossl.com/v2/DV90"
MAX_OUTPUT_BYTES = 8192
MAX_COMMAND_BYTES = 4096
TLS_WAIT_SECONDS = 55
UNIT_DIRECTORIES = (
    "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
    "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
    "/run/systemd/generator.late",
)
SYSTEM_DIRECTORY_ALIASES = {
    Path("/lib"): ({"usr/lib", "/usr/lib"}, Path("/usr/lib")),
    Path("/usr/sbin"): ({"bin", "/usr/bin"}, Path("/usr/bin")),
}
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})+\Z")

class AcmeError(ValueError):
    pass

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AcmeError("invalid structured input")
        result[key] = value
    return result

def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(AcmeError("invalid structured input")))

def _parents(path, *, missing=False):
    if not path.is_absolute():
        raise AcmeError("unsafe fixed path")
    for parent in reversed(path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if missing:
                return
            raise
        if parent in SYSTEM_DIRECTORY_ALIASES and stat.S_ISLNK(info.st_mode):
            allowed, target = SYSTEM_DIRECTORY_ALIASES[parent]
            if info.st_uid != 0 or os.readlink(parent) not in allowed:
                raise AcmeError("untrusted system directory alias")
            _parents(target)
            info = target.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise AcmeError("untrusted system directory alias")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AcmeError("unsafe fixed path")

def _read(path, *, private=False, mode=None, limit=16_384):
    _parents(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
            or private and stat.S_IMODE(before.st_mode) != 0o600
            or mode is not None and stat.S_IMODE(before.st_mode) != mode):
        raise AcmeError("unsafe fixed file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
            raise AcmeError("fixed file changed")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise AcmeError("fixed file exceeds limit")
    return data

def _absent(path):
    _parents(path, missing=True)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise AcmeError("fixed path already exists")

def _trusted_command(path):
    candidate = Path(path)
    visited = set()
    for _ in range(16):
        _parents(candidate)
        if candidate in visited:
            raise AcmeError("untrusted fixed command")
        visited.add(candidate)
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.readlink(candidate))
            if info.st_uid != 0 or ".." in target.parts:
                raise AcmeError("untrusted fixed command")
            candidate = target if target.is_absolute() else candidate.parent / target
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not info.st_mode & 0o111):
            raise AcmeError("untrusted fixed command")
        return
    raise AcmeError("untrusted fixed command")

def _command(command, *, allowed=(0,), timeout=10, limit=MAX_COMMAND_BYTES):
    """Bound private output and elapsed time; never echo identifiers or rules."""
    process = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False, cwd="/",
                                   env={"PATH": BINPATH, "LC_ALL": "C"})
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise AcmeError("fixed command timed out")
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                    if code not in allowed:
                        raise AcmeError("fixed command failed")
                    return code, bytes(output)
                output.extend(chunk)
                if len(output) > limit:
                    raise AcmeError("fixed command output exceeded limit")
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            if process.stdout is not None:
                process.stdout.close()

def _active(unit):
    code, _ = _command([SYSTEMCTL, "is-active", "--quiet", unit], allowed=(0, 3, 4), timeout=3, limit=0)
    return code == 0

def _effective_unit(unit, path):
    _, fragment = _command([SYSTEMCTL, "show", "--property=FragmentPath", "--value", unit],
                            timeout=3, limit=4096)
    _, dropins = _command([SYSTEMCTL, "show", "--property=DropInPaths", "--value", unit],
                           timeout=3, limit=4096)
    if fragment != (str(path) + "\n").encode("ascii") or dropins not in {b"", b"\n"}:
        raise AcmeError("effective fixed service differs")

def _acme_email(value):
    if (not isinstance(value, str) or not value.isascii() or len(value) > 254
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@"
                                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                                r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", value)):
        raise AcmeError("invalid ACME contact email")
    local, domain = value.rsplit("@", 1)
    if local.endswith(".") or ".." in local or len(domain) > 253 or domain.rsplit(".", 1)[-1].isdigit():
        raise AcmeError("invalid ACME contact email")
    return value

def _acme_variant(base):
    return base.replace(b"\tadmin off\n", b"\tadmin off\n\temail {$QUANTA_ACME_EMAIL}\n\tacme_ca "
                        + ACME_CA.encode("ascii") + b"\n")

def _acme_receipt(config, email):
    return {"schema": 1, "source_sha": config["source_sha"], "public_origin": config["public_origin"],
            "auth_mode": config["auth_mode"], "issuer": "zerossl_acme",
            "email_sha256": hashlib.sha256(email.encode("ascii")).hexdigest()}

def _https_config_guard(config, template):
    base = template.replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n")
    host = urlsplit(config["public_origin"]).hostname
    original_env = ("QUANTA_PUBLIC_HOST=" + host + "\n").encode("ascii")
    actual, environment = _read(CADDYFILE, private=True), _read(HTTPS_ENV, private=True)
    if actual == base and environment == original_env:
        _absent(ACME_RECEIPT)
        return
    if actual != _acme_variant(base):
        raise AcmeError("HTTPS configuration differs")
    prefix = original_env + b"QUANTA_ACME_EMAIL="
    if not environment.startswith(prefix) or not environment.endswith(b"\n"):
        raise AcmeError("HTTPS environment differs")
    email = _acme_email(environment[len(prefix):-1].decode("ascii"))
    if environment != prefix + email.encode("ascii") + b"\n":
        raise AcmeError("HTTPS environment differs")
    receipt = _json(_read(ACME_RECEIPT, private=True))
    if not isinstance(receipt, dict) or type(receipt.get("schema")) is not int or receipt != _acme_receipt(config, email):
        raise AcmeError("ACME policy receipt differs")

def _scope(config, *, require_active):
    if os.geteuid() != 0:
        raise AcmeError("root is required")
    if _json(_read(MARKER, private=True)) != config:
        raise AcmeError("application receipt differs")
    if hashlib.sha256(_read(HTTPS_UNIT, mode=0o644)).hexdigest() != HTTPS_UNIT_SHA256:
        raise AcmeError("HTTPS service differs")
    for directory in UNIT_DIRECTORIES:
        fragment = Path(directory) / "quanta-https.service"
        if fragment != HTTPS_UNIT:
            _absent(fragment)
        _absent(Path(directory) / "quanta-https.service.d")
    template = _read(TEMPLATE)
    if hashlib.sha256(template).hexdigest() != TEMPLATE_SHA256:
        raise AcmeError("source template differs")
    _https_config_guard(config, template)
    # The executable is large; inspect metadata and the fixed ARM64 ELF header.
    _parents(CADDY)
    info = CADDY.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o755 or not 64 <= info.st_size <= 64 * 1024 * 1024):
        raise AcmeError("HTTPS executable differs")
    descriptor = os.open(CADDY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        header = stream.read(64)
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
        raise AcmeError("HTTPS executable differs")
    _trusted_command(SYSTEMCTL)
    _effective_unit("quanta-https.service", HTTPS_UNIT)
    if require_active and not _active("quanta-https.service"):
        raise AcmeError("HTTPS is not active")

@contextmanager
def _deadline(seconds):
    def expired(*_):
        raise AcmeError("fixed operation timed out")
    previous = signal.signal(signal.SIGALRM, expired)
    timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *timer)
        signal.signal(signal.SIGALRM, previous)

def _tls_ready(host):
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection(("127.0.0.1", 443), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secured:
                secured.sendall(("GET /ui/auth HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode("ascii"))
                response = HTTPResponse(secured)
                response.begin()
                body = response.read(1025)
                return (response.status == 200 and len(body) <= 1024 and _json(body)
                        == {"mode": "bearer", "authenticated": False, "authentication": "owner_token"})
    except (OSError, ValueError, EOFError, HTTPException):
        return False

def _wait_tls(host):
    try:
        with _deadline(TLS_WAIT_SECONDS):
            deadline = time.monotonic() + TLS_WAIT_SECONDS
            while time.monotonic() < deadline:
                if _tls_ready(host):
                    return True
                time.sleep(0.5)
    except AcmeError:
        pass
    return False


BOOLEAN_FIELDS = (
    "scope_verified", "binary_trusted", "backup_created", "receipt_created", "commit_started",
    "config_replaced", "env_replaced", "configured", "changed", "restart_attempted",
    "service_active", "tls_issued", "rollback_attempted", "rollback_complete",
)
FIELDS = frozenset(("scope", "status", "state", "failure_stage", "failure_reason", *BOOLEAN_FIELDS))
STAGES = frozenset(("config", "preflight", "prepare", "backup", "commit", "restart", "tls", "none"))
_REASONS = {
    "invalid configuration": "invalid_config", "invalid structured input": "invalid_config",
    "invalid ACME contact email": "invalid_contact_email", "root is required": "root_required",
    "unsafe fixed path": "unsafe_path", "unsafe fixed file": "unsafe_file",
    "untrusted system directory alias": "unsafe_path", "untrusted fixed command": "untrusted_command",
    "fixed file changed": "file_changed", "fixed file exceeds limit": "file_limit",
    "fixed path already exists": "existing_path", "fixed command timed out": "command_timeout",
    "fixed command failed": "command_failed", "fixed command output exceeded limit": "command_output_limit",
    "effective fixed service differs": "effective_service_mismatch", "application receipt differs": "receipt_mismatch",
    "HTTPS service differs": "https_service_mismatch", "source template differs": "source_mismatch",
    "HTTPS configuration differs": "https_config_mismatch", "HTTPS environment differs": "https_env_mismatch",
    "HTTPS executable differs": "https_binary_mismatch", "HTTPS is not active": "https_inactive",
    "ACME policy receipt differs": "acme_receipt_mismatch", "current ACME contact differs": "contact_mismatch",
    "fixed file changed before replacement": "concurrent_change", "fixed operation timed out": "operation_timeout",
    "candidate validation failed": "candidate_invalid", "HTTPS restart did not complete": "https_restart_failed",
}
REASONS = frozenset(("none", "operation_failed", "system_path_missing", "permission_denied",
                     "rollback_conflict", *_REASONS.values()))


def validate_config(config):
    if (not isinstance(config, dict) or set(config) != {"source_sha", "public_origin", "auth_mode", "acme_email"}
            or config.get("source_sha") != SOURCE_SHA or config.get("auth_mode") != "owner-token"
            or not isinstance(config.get("public_origin"), str)):
        raise AcmeError("invalid configuration")
    origin = config["public_origin"]
    parsed = urlsplit(origin)
    host = parsed.hostname
    if (not host or len(host) > 253 or not _HOST.fullmatch(host)
            or origin != "https://" + host or parsed.netloc != host
            or host.endswith((".localhost", ".local", ".internal", ".invalid"))
            or host.rsplit(".", 1)[-1].isdigit()):
        raise AcmeError("invalid configuration")
    _acme_email(config.get("acme_email"))
    return dict(config)


def _decode(argument):
    if not isinstance(argument, str) or not 1 <= len(argument) <= 4096:
        raise AcmeError("invalid configuration")
    raw = base64.b64decode(argument.encode("ascii"), validate=True)
    if len(raw) > 2048:
        raise AcmeError("invalid configuration")
    return validate_config(_json(raw))


def _reason(error):
    if type(error) is AcmeError and len(error.args) == 1 and type(error.args[0]) is str:
        return _REASONS.get(error.args[0], "operation_failed")
    if isinstance(error, FileNotFoundError):
        return "system_path_missing"
    if isinstance(error, PermissionError):
        return "permission_denied"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command_timeout"
    return "operation_failed"


def _native_profile():
    # This actual deployment uses firewalld's native persistence. An installed
    # legacy boot helper would need its own reviewed upgrade before a CA change.
    _absent(FW_HELPER)
    _absent(Path("/etc/systemd/system/multi-user.target.wants/quanta-web-firewall.service"))
    for directory in UNIT_DIRECTORIES:
        for suffix in ("", ".d"):
            _absent(Path(directory) / ("quanta-web-firewall.service" + suffix))


def _snapshot(path):
    contents = _read(path, private=True)
    info = path.lstat()
    return {"data": contents, "device": info.st_dev, "inode": info.st_ino,
            "sha256": hashlib.sha256(contents).hexdigest()}


def _matches(path, snapshot):
    try:
        current = _snapshot(path)
        return all(current[key] == snapshot[key] for key in ("device", "inode", "sha256", "data"))
    except (OSError, ValueError):
        return False


def _sync_parent(path):
    _parents(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_private(path, contents, *, result=None, flag=None, created=None):
    _parents(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(descriptor)
    if created is not None:
        created[path] = {"device": info.st_dev, "inode": info.st_ino, "data": contents,
                         "sha256": hashlib.sha256(contents).hexdigest()}
    if result is not None and flag is not None:
        result[flag] = True
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_parent(path)


def _replace_private(path, candidate, expected, *, records, result, flag):
    replacement = _snapshot(candidate)
    if not _matches(path, expected):
        raise AcmeError("fixed file changed before replacement")
    os.replace(candidate, path)
    records.append((path, replacement, expected))
    result[flag] = True
    _sync_parent(path)


def _remove_created_receipt(created):
    expected = created.get(ACME_RECEIPT)
    if expected is None:
        return True
    try:
        current = _snapshot(ACME_RECEIPT)
        # A short write may have left only our own prefix. Never remove another
        # inode or an operator's different contents, even during rollback.
        if (current["device"] != expected["device"] or current["inode"] != expected["inode"]
                or not expected["data"].startswith(current["data"])):
            return False
        ACME_RECEIPT.unlink()
        _sync_parent(ACME_RECEIPT)
        return True
    except FileNotFoundError:
        return True
    except (OSError, ValueError):
        return False


def _rollback(records, created, directory):
    complete = True
    for index, (path, replacement, original) in enumerate(reversed(records)):
        try:
            if not _matches(path, replacement):
                complete = False
                continue
            candidate = directory / ("rollback-" + str(index))
            _create_private(candidate, original["data"])
            if not _matches(path, replacement):
                complete = False
                continue
            os.replace(candidate, path)
            _sync_parent(path)
        except (OSError, ValueError):
            complete = False
    if complete:
        complete = _remove_created_receipt(created)
    return complete


def _validate_candidate(path, email, host, directory):
    environment = {"PATH": BINPATH, "LC_ALL": "C", "QUANTA_PUBLIC_HOST": host,
                   "QUANTA_ACME_EMAIL": email, "XDG_DATA_HOME": str(directory / "data"),
                   "XDG_CONFIG_HOME": str(directory / "config")}
    result = subprocess.run([str(CADDY), "adapt", "--config", str(path), "--adapter", "caddyfile", "--validate"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            shell=False, cwd="/", env=environment, timeout=20, check=False)
    if result.returncode != 0:
        raise AcmeError("candidate validation failed")


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def _report():
    return {"scope": "acme_configuration", "status": "failed", "state": "refused",
            "failure_stage": "config", "failure_reason": "invalid_config",
            **dict.fromkeys(BOOLEAN_FIELDS, False)}


def configure(config):
    result = _report()
    try:
        config = validate_config(config)
        base_config = {key: config[key] for key in ("source_sha", "public_origin", "auth_mode")}
        email, host = config["acme_email"], urlsplit(config["public_origin"]).hostname
        result["failure_stage"] = "preflight"
        _native_profile()
        _scope(base_config, require_active=True)
        result.update(scope_verified=True, binary_trusted=True, service_active=True)
        marker = _snapshot(MARKER)
        template = _read(TEMPLATE)
        base = template.replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n")
        target = _acme_variant(base)
        environment = ("QUANTA_PUBLIC_HOST=" + host + "\nQUANTA_ACME_EMAIL=" + email + "\n").encode("ascii")
        receipt = _json_bytes(_acme_receipt(base_config, email))
        current_config, current_env = _snapshot(CADDYFILE), _snapshot(HTTPS_ENV)
        if current_config["data"] == target:
            if current_env["data"] != environment or _read(ACME_RECEIPT, private=True) != receipt:
                raise AcmeError("current ACME contact differs")
            result["configured"] = True
        else:
            result["failure_stage"] = "prepare"
            _absent(ACME_RECEIPT)
            _absent(ACME_BACKUP)
            with tempfile.TemporaryDirectory(prefix=".acme-prepare-", dir=CADDYFILE.parent) as temporary:
                directory = Path(temporary)
                candidate_config, candidate_env = directory / "Caddyfile", directory / "https.env"
                _create_private(candidate_config, target)
                _create_private(candidate_env, environment)
                _validate_candidate(candidate_config, email, host, directory)
                _native_profile()
                _scope(base_config, require_active=True)
                if (not _matches(MARKER, marker) or not _matches(CADDYFILE, current_config)
                        or not _matches(HTTPS_ENV, current_env)):
                    raise AcmeError("fixed file changed before replacement")
                result["failure_stage"] = "backup"
                backup = {"schema": 1, "source_sha": SOURCE_SHA,
                          "caddyfile_b64": base64.b64encode(current_config["data"]).decode("ascii"),
                          "https_env_b64": base64.b64encode(current_env["data"]).decode("ascii"),
                          "caddyfile_sha256": current_config["sha256"], "https_env_sha256": current_env["sha256"]}
                _create_private(ACME_BACKUP, _json_bytes(backup), result=result, flag="backup_created")
                records, created = [], {}
                try:
                    _create_private(ACME_RECEIPT, receipt, result=result, flag="receipt_created", created=created)
                    result.update(failure_stage="commit", commit_started=True)
                    _replace_private(CADDYFILE, candidate_config, current_config, records=records,
                                     result=result, flag="config_replaced")
                    _replace_private(HTTPS_ENV, candidate_env, current_env, records=records,
                                     result=result, flag="env_replaced")
                    if not _matches(MARKER, marker):
                        raise AcmeError("fixed file changed before replacement")
                    _native_profile()
                    _scope(base_config, require_active=True)
                    result.update(configured=True, changed=True)
                except Exception:
                    result["rollback_attempted"] = bool(records or created)
                    if result["rollback_attempted"]:
                        result["rollback_complete"] = _rollback(records, created, directory)
                    raise
            result.update(failure_stage="restart", restart_attempted=True)
            _command([SYSTEMCTL, "restart", "quanta-https.service"], timeout=40, limit=0)
            result["service_active"] = _active("quanta-https.service")
            if not result["service_active"]:
                raise AcmeError("HTTPS restart did not complete")
        result["failure_stage"] = "tls"
        result["tls_issued"] = _wait_tls(host)
        result["service_active"] = _active("quanta-https.service")
        if not result["service_active"]:
            raise AcmeError("HTTPS is not active")
        result.update(status="success" if result["tls_issued"] else "awaiting_network",
                      state="issued" if result["tls_issued"] else "configured_tls_pending",
                      failure_stage="none", failure_reason="none")
    except Exception as error:
        result["failure_reason"] = _reason(error)
        if result["rollback_attempted"] and not result["rollback_complete"]:
            result["failure_reason"] = "rollback_conflict"
        if result["restart_attempted"]:
            try:
                result["service_active"] = _active("quanta-https.service")
            except Exception:
                result["service_active"] = False
    return validate_report(result)


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "acme_configuration"
            or value["status"] not in {"success", "awaiting_network", "failed"}
            or value["failure_stage"] not in STAGES or value["failure_reason"] not in REASONS
            or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)):
        raise AcmeError("invalid configuration")
    if value["status"] in {"success", "awaiting_network"}:
        if (value["failure_stage"] != "none" or value["failure_reason"] != "none"
                or not all(value[key] for key in ("scope_verified", "binary_trusted", "configured", "service_active"))
                or value["tls_issued"] != (value["status"] == "success")
                or value["state"] != ("issued" if value["tls_issued"] else "configured_tls_pending")):
            raise AcmeError("invalid configuration")
    elif value["state"] != "refused" or value["failure_stage"] == "none" or value["failure_reason"] == "none":
        raise AcmeError("invalid configuration")
    if (value["changed"] and not value["configured"] or value["tls_issued"] and not value["configured"]
            or value["rollback_complete"] and not value["rollback_attempted"]
            or value["configured"] and not value["scope_verified"]
            or value["restart_attempted"] and not value["configured"]):
        raise AcmeError("invalid configuration")
    return dict(value)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
            return None
        return validate_report(_json(raw))
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return None


def main(argv=None):
    try:
        arguments = sys.argv[1:] if argv is None else argv
        if len(arguments) != 1:
            raise AcmeError("invalid configuration")
        result = configure(_decode(arguments[0]))
    except Exception as error:
        result = _report()
        result["failure_reason"] = _reason(error)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
