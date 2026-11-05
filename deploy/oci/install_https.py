#!/usr/bin/python3
"""Install only Quanta's separately authenticated, fixed-source HTTPS proxy.

Run by the authorized SSH transport as root, with one base64 JSON argument.
Existing services, files, firewall rules, and application secrets are preserved.
Only the fixed public report is printed; command output and exceptions are private.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection, HTTPException, HTTPResponse
import io
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
TEMPLATE_SHA256 = "0af075db4d4f2653931916e40aa22bdd1c76c237407fe6fed5a8cb52b0392df9"
CADDY_URL = "https://github.com/caddyserver/caddy/releases/download/v2.11.9/caddy_2.11.9_linux_arm64.tar.gz"
CADDY_SHA256 = "5e377cff994fc9362a6fcf695c53f226cfca3a3ef85bd3a3687cf252d6310165"
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LIB = Path("/usr/local/lib/quanta")
ETC = Path("/etc/quanta")
MARKER = ETC / "installed.json"
APP_ENV = ETC / "app.env"
TEMPLATE = Path("/srv/quanta/source") / SOURCE_SHA / "deploy/oci/Caddyfile.example"
BINARY = LIB / "caddy"
CADDYFILE = ETC / "Caddyfile"
HTTPS_ENV = ETC / "https.env"
UNIT = Path("/etc/systemd/system/quanta-https.service")
STATE = Path("/var/lib/quanta-caddy")
SYSTEMCTL = "/usr/bin/systemctl"
UNIT_DIRECTORIES = (
    "/etc/systemd/system.control", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system", "/run/systemd/generator.late",
)
MAX_OUTPUT_BYTES = 8192
MAX_ARCHIVE = 50 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024
TLS_WAIT_SECONDS = 40
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})+\Z")
BOOLEAN_FIELDS = ("source_verified", "app_ready", "binary_verified", "configured",
                  "service_active", "tls_issued", "host_firewall_changed")
FIELDS = frozenset(("scope", "status", "state", "failure_stage", *BOOLEAN_FIELDS))
STAGES = frozenset(("none", "config", "preflight", "download", "install", "service"))

UNIT_TEXT = """[Unit]
Description=Quanta direct HTTPS entry point
Wants=network-online.target
Requires=quanta-boot.service
After=network-online.target quanta-boot.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
DynamicUser=yes
StateDirectory=quanta-caddy
StateDirectoryMode=0700
UMask=0077
LoadCredential=Caddyfile:/etc/quanta/Caddyfile
EnvironmentFile=/etc/quanta/https.env
Environment=XDG_DATA_HOME=/var/lib/quanta-caddy XDG_CONFIG_HOME=/var/lib/quanta-caddy
ExecStart=/usr/local/lib/quanta/caddy run --config %d/Caddyfile --adapter caddyfile
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/quanta-caddy
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=20
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


class InstallError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InstallError("invalid structured input")
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(InstallError("invalid structured input")))


def validate_config(config) -> dict:
    if (not isinstance(config, dict) or set(config) != {"public_origin", "source_sha", "auth_mode"}
            or config.get("source_sha") != SOURCE_SHA or config.get("auth_mode") != "owner-token"
            or not isinstance(config.get("public_origin"), str)):
        raise InstallError("invalid installation configuration")
    origin = config["public_origin"]
    parsed = urlsplit(origin)
    host = parsed.hostname
    if (not host or len(host) > 253 or not _HOST.fullmatch(host)
            or origin != "https://" + host or parsed.netloc != host
            or host.endswith((".localhost", ".local", ".internal", ".invalid"))
            or host.rsplit(".", 1)[-1].isdigit()):
        raise InstallError("invalid installation configuration")
    return dict(config)


def _config_argument(argument: str) -> dict:
    if not isinstance(argument, str) or not 1 <= len(argument) <= 4096:
        raise InstallError("invalid installation configuration")
    raw = base64.b64decode(argument.encode("ascii"), validate=True)
    if len(raw) > 2048:
        raise InstallError("invalid installation configuration")
    return validate_config(_json(raw))


def _safe_parents(path: Path, *, missing=False) -> None:
    if not path.is_absolute():
        raise InstallError("unsafe installation path")
    for parent in reversed(path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if missing:
                return
            raise
        if parent == Path("/lib") and stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or os.readlink(parent) not in {"usr/lib", "/usr/lib"}:
                raise InstallError("unsafe installation path")
            info = Path("/usr/lib").lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError("unsafe installation path")


def _secure_directory(path: Path) -> None:
    _safe_parents(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise InstallError("unsafe installation directory")


def _read_root_file(path: Path, *, private=False, limit=8192) -> bytes:
    _safe_parents(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_mode & 0o022 or (private and stat.S_IMODE(before.st_mode) != 0o600)):
        raise InstallError("unsafe installation file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
            raise InstallError("installation file changed")
        contents = stream.read(limit + 1)
    if len(contents) > limit:
        raise InstallError("installation file exceeds limit")
    return contents


def _absent(path: Path) -> None:
    _safe_parents(path, missing=True)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise InstallError("installation path already exists")


def _run(command, *, timeout=10, environment=None) -> None:
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, cwd="/", shell=False,
                            env=environment or {"PATH": BINPATH, "LC_ALL": "C"},
                            timeout=timeout, check=False)
    if result.returncode != 0:
        raise InstallError("fixed installation command failed")


def _unit_active() -> bool:
    try:
        _run([SYSTEMCTL, "is-active", "--quiet", "quanta-https.service"], timeout=2)
        return True
    except (OSError, InstallError, subprocess.SubprocessError):
        return False


def _ports_free() -> None:
    for filename, width, remote in (("/proc/net/tcp", 8, b"rem_address"),
                                     ("/proc/net/tcp6", 32, b"remote_address")):
        with open(filename, "rb") as stream:
            raw = stream.read(1_048_577)
        rows = raw.splitlines()
        if (len(raw) > 1_048_576 or not raw.endswith(b"\n") or not rows or len(rows) > 8193
                or rows[0].split()[:4] != [b"sl", b"local_address", remote, b"st"]):
            raise InstallError("unavailable socket table")
        endpoint = re.compile(rb"[0-9A-Fa-f]{" + str(width).encode() + rb"}:([0-9A-Fa-f]{4})\Z")
        for row in rows[1:]:
            fields = row.split()
            if not 10 <= len(fields) <= 32 or not endpoint.fullmatch(fields[1]):
                raise InstallError("unavailable socket table")
            if int(endpoint.fullmatch(fields[1])[1], 16) in {80, 443}:
                raise InstallError("web port already in use")


def _preflight(config: dict) -> bytes:
    if os.geteuid() != 0 or os.uname().machine != "aarch64":
        raise InstallError("a root ARM64 host is required")
    for directory in (LIB, ETC, UNIT.parent):
        _secure_directory(directory)
    marker = _json(_read_root_file(MARKER, private=True))
    if marker != config:
        raise InstallError("application installation differs")
    for path in (BINARY, CADDYFILE, HTTPS_ENV, STATE, Path("/var/lib/private/quanta-caddy"),
                 Path("/etc/caddy"), Path("/var/lib/caddy"), Path("/usr/local/etc/Caddyfile"),
                 Path("/etc/nginx"), Path("/etc/apache2"), Path("/etc/httpd")):
        _absent(path)
    for directory in UNIT_DIRECTORIES:
        for name in ("caddy.service", "quanta-https.service", "nginx.service", "apache2.service", "httpd.service"):
            for suffix in ("", ".d"):
                _absent(Path(directory) / (name + suffix))
    _ports_free()
    template = _read_root_file(TEMPLATE, limit=16_384)
    if hashlib.sha256(template).hexdigest() != TEMPLATE_SHA256:
        raise InstallError("source template differs")
    return template


def _app_ready(config: dict) -> None:
    contents = _read_root_file(APP_ENV, private=True).decode("ascii")
    values = {}
    for line in contents.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise InstallError("application environment differs")
        values[key] = value
    if (set(values) != {"QUANTA_PUBLIC_ORIGIN", "QUANTA_AUTH_MODE", "QUANTA_OWNER_TOKEN"}
            or values["QUANTA_PUBLIC_ORIGIN"] != config["public_origin"]
            or values["QUANTA_AUTH_MODE"] != "owner-token"
            or not re.fullmatch(r"[0-9a-f]{64}", values["QUANTA_OWNER_TOKEN"])):
        raise InstallError("application environment differs")
    connection = HTTPConnection("127.0.0.1", 8765, timeout=3)
    try:
        connection.request("GET", "/health/ready", headers={
            "Host": urlsplit(config["public_origin"]).hostname,
            "Origin": config["public_origin"],
            "Authorization": "Bearer " + values["QUANTA_OWNER_TOKEN"],
        })
        response = connection.getresponse()
        body = response.read(1025)
        if response.status != 200 or len(body) > 1024 or _json(body) != {"status": "ready"}:
            raise InstallError("application is not ready")
    finally:
        connection.close()


@contextmanager
def _deadline(seconds):
    def expired(*_):
        raise InstallError("fixed operation timed out")
    previous = signal.signal(signal.SIGALRM, expired)
    timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *timer)
        signal.signal(signal.SIGALRM, previous)


class _HTTPSRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        parsed = urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.username is not None
                or parsed.hostname not in {"github.com", "release-assets.githubusercontent.com",
                                           "objects.githubusercontent.com"}):
            raise InstallError("unexpected release redirect")
        return super().redirect_request(request, response, code, message, headers, newurl)


def _download_binary() -> bytes:
    chunks = bytearray()
    with _deadline(45):
        with build_opener(_HTTPSRedirect()).open(CADDY_URL, timeout=10) as response:
            while True:
                chunk = response.read(min(65_536, MAX_ARCHIVE + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > MAX_ARCHIVE:
                    raise InstallError("release archive exceeds limit")
    if hashlib.sha256(chunks).hexdigest() != CADDY_SHA256:
        raise InstallError("release archive differs")
    with tarfile.open(fileobj=io.BytesIO(chunks), mode="r:gz") as archive:
        member = archive.getmember("caddy")
        if not member.isfile() or member.issparse() or not 64 <= member.size <= MAX_BINARY:
            raise InstallError("invalid release executable")
        stream = archive.extractfile(member)
        if stream is None:
            raise InstallError("missing release executable")
        with stream:
            binary = stream.read(MAX_BINARY + 1)
    if (len(binary) != member.size or binary[:6] != b"\x7fELF\x02\x01"
            or binary[18:20] != b"\xb7\x00"):
        raise InstallError("invalid ARM64 executable")
    return binary


def _write_new(path: Path, contents: bytes, mode: int) -> None:
    _safe_parents(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def _tls_ready(host: str) -> bool:
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection(("127.0.0.1", 443), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secured:
                secured.sendall(("GET /ui/auth HTTP/1.1\r\nHost: " + host
                                 + "\r\nConnection: close\r\n\r\n").encode("ascii"))
                response = HTTPResponse(secured)
                response.begin()
                body = response.read(1025)
                return (response.status == 200 and len(body) <= 1024 and _json(body)
                        == {"mode": "bearer", "authenticated": False, "authentication": "owner_token"})
    except (OSError, ValueError, EOFError, HTTPException):
        return False


def _wait_for_tls(host: str) -> tuple[bool, bool]:
    try:
        with _deadline(TLS_WAIT_SECONDS):
            deadline = time.monotonic() + TLS_WAIT_SECONDS
            while time.monotonic() < deadline:
                active = _unit_active()
                if active and _tls_ready(host):
                    return True, True
                time.sleep(0.5)
    except InstallError:
        pass
    return _unit_active(), False


def _report():
    return {"scope": "https_install", "status": "failed", "state": "refused",
            "failure_stage": "config", **dict.fromkeys(BOOLEAN_FIELDS, False)}


def install(config: dict) -> dict:
    result = _report()
    try:
        config = validate_config(config)
        result["failure_stage"] = "preflight"
        template = _preflight(config)
        result["source_verified"] = True
        _app_ready(config)
        result["app_ready"] = True
        host = urlsplit(config["public_origin"]).hostname
        if template.count(b"\tadmin 127.0.0.1:2019\n") != 1:
            raise InstallError("unexpected source template")
        configuration = template.replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n")
        result["failure_stage"] = "download"
        binary = _download_binary()
        result["binary_verified"] = True
        result["failure_stage"] = "install"
        with tempfile.TemporaryDirectory(prefix=".https-install-", dir=LIB) as temporary:
            temporary = Path(temporary)
            candidate = temporary / "caddy"
            candidate_config = temporary / "Caddyfile"
            _write_new(candidate, binary, 0o700)
            _write_new(candidate_config, configuration, 0o600)
            environment = {"PATH": BINPATH, "LC_ALL": "C", "QUANTA_PUBLIC_HOST": host,
                           "XDG_DATA_HOME": str(temporary / "data"),
                           "XDG_CONFIG_HOME": str(temporary / "config")}
            _run([str(candidate), "adapt", "--config", str(candidate_config),
                  "--adapter", "caddyfile", "--validate"], environment=environment, timeout=20)
            # Repeat the conservative conflict check after the network operation.
            _preflight(config)
            _app_ready(config)
            _write_new(BINARY, binary, 0o755)
            _write_new(CADDYFILE, configuration, 0o600)
            _write_new(HTTPS_ENV, ("QUANTA_PUBLIC_HOST=" + host + "\n").encode("ascii"), 0o600)
            _write_new(UNIT, UNIT_TEXT.encode("ascii"), 0o644)
        result["configured"] = True
        result["failure_stage"] = "service"
        _run([SYSTEMCTL, "daemon-reload"])
        _run([SYSTEMCTL, "enable", "quanta-https.service"])
        _run([SYSTEMCTL, "start", "--no-block", "quanta-https.service"])
        active, issued = _wait_for_tls(host)
        result["service_active"] = active
        if issued:
            result.update(status="success", state="issued", failure_stage="none", tls_issued=True)
            return validate_report(result)
        if result["service_active"]:
            result.update(status="awaiting_network", state="awaiting_network", failure_stage="none")
    except Exception:
        # Never serialize command output, exception messages, origins or secrets.
        pass
    return validate_report(result)


def validate_report(value) -> dict:
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "https_install"
            or value["status"] not in {"success", "awaiting_network", "failed"}
            or value["failure_stage"] not in STAGES or value["host_firewall_changed"] is not False
            or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)):
        raise InstallError("invalid HTTPS installation report")
    if any(value[later] and not value[earlier]
           for earlier, later in zip(BOOLEAN_FIELDS[:5], BOOLEAN_FIELDS[1:6])):
        raise InstallError("invalid HTTPS installation report")
    if value["status"] in {"success", "awaiting_network"}:
        if (value["state"] != ("issued" if value["status"] == "success" else "awaiting_network")
                or value["failure_stage"] != "none"
                or not all(value[field] for field in BOOLEAN_FIELDS[:5])
                or value["tls_issued"] != (value["status"] == "success")):
            raise InstallError("invalid HTTPS installation report")
    elif value["state"] != "refused" or value["failure_stage"] == "none" or value["tls_issued"]:
        raise InstallError("invalid HTTPS installation report")
    return dict(value)


def sanitize_report(raw: bytes) -> dict | None:
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
            return None
        return validate_report(_json(raw))
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return None


def main(argv=None) -> int:
    try:
        arguments = sys.argv[1:] if argv is None else argv
        if len(arguments) != 1:
            raise InstallError("one configuration argument is required")
        result = install(_config_argument(arguments[0]))
    except Exception:
        result = _report()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
