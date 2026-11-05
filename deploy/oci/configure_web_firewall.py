#!/usr/bin/python3
"""Add only IPv4 TCP 80/443 rules for the already installed Quanta proxy.

The initial operation receives the fixed transport's base64 JSON configuration.
Its root-owned boot copy uses --restore and never requires HTTPS to be started
first. No existing rule, persistence file, Docker chain or cloud rule is removed.
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
import shlex
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
TEMPLATE_SHA256 = "0af075db4d4f2653931916e40aa22bdd1c76c237407fe6fed5a8cb52b0392df9"
HTTPS_UNIT_SHA256 = "06e60b65101d1321297d55fc396573b35d1e4eafbe9f93166c11ca683f460eab"
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SYSTEMCTL = "/usr/bin/systemctl"
IPTABLES = "/usr/sbin/iptables"
UFW = "/usr/sbin/ufw"
MARKER = Path("/etc/quanta/installed.json")
HTTPS_UNIT = Path("/etc/systemd/system/quanta-https.service")
CADDY = Path("/usr/local/lib/quanta/caddy")
TEMPLATE = Path("/srv/quanta/source") / SOURCE_SHA / "deploy/oci/Caddyfile.example"
CADDYFILE = Path("/etc/quanta/Caddyfile")
HTTPS_ENV = Path("/etc/quanta/https.env")
HELPER = Path("/usr/local/lib/quanta/web_firewall.py")
UNIT = Path("/etc/systemd/system/quanta-web-firewall.service")
BOOT_ARGUMENT = "--restore"
PORTS = (80, 443)
MAX_OUTPUT_BYTES = 8192
MAX_COMMAND_BYTES = 65_536
TLS_WAIT_SECONDS = 40
UNIT_DIRECTORIES = (
    "/etc/systemd/system.control", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system", "/run/systemd/generator.late",
)
BOOLEAN_FIELDS = (
    "scope_verified", "rules_inspected", "ufw_active", "rule_mutation_attempted",
    "rules_applied", "persistence_configured", "persistence_service_active",
    "https_service_active", "tls_issued", "ipv6_changed", "cloud_ingress_changed",
)
FIELDS = frozenset(("scope", "status", "failure_stage", *BOOLEAN_FIELDS))
STAGES = frozenset(("none", "config", "preflight", "inspection", "persistence", "rules", "https"))
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})+\Z")

UNIT_TEXT = """[Unit]
Description=Quanta IPv4 web port rules
Wants=network-pre.target
After=network-pre.target netfilter-persistent.service iptables.service ufw.service firewalld.service nftables.service
Before=quanta-https.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/quanta/web_firewall.py --restore
TimeoutStartSec=60
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""


class FirewallError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FirewallError("invalid structured input")
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(FirewallError("invalid structured input")))


def validate_config(config) -> dict:
    if (not isinstance(config, dict) or set(config) != {"public_origin", "source_sha", "auth_mode"}
            or config.get("source_sha") != SOURCE_SHA or config.get("auth_mode") != "owner-token"
            or not isinstance(config.get("public_origin"), str)):
        raise FirewallError("invalid configuration")
    origin = config["public_origin"]
    parsed = urlsplit(origin)
    host = parsed.hostname
    if (not host or len(host) > 253 or not _HOST.fullmatch(host)
            or origin != "https://" + host or parsed.netloc != host
            or host.endswith((".localhost", ".local", ".internal", ".invalid"))
            or host.rsplit(".", 1)[-1].isdigit()):
        raise FirewallError("invalid configuration")
    return dict(config)


def _decode(argument):
    if not isinstance(argument, str) or not 1 <= len(argument) <= 4096:
        raise FirewallError("invalid configuration")
    raw = base64.b64decode(argument.encode("ascii"), validate=True)
    if len(raw) > 2048:
        raise FirewallError("invalid configuration")
    return validate_config(_json(raw))


def _parents(path, *, missing=False):
    if not path.is_absolute():
        raise FirewallError("unsafe fixed path")
    for parent in reversed(path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if missing:
                return
            raise
        if parent == Path("/lib") and stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or os.readlink(parent) not in {"usr/lib", "/usr/lib"}:
                raise FirewallError("unsafe fixed path")
            info = Path("/usr/lib").lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise FirewallError("unsafe fixed path")


def _read(path, *, private=False, mode=None, limit=16_384):
    _parents(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
            or private and stat.S_IMODE(before.st_mode) != 0o600
            or mode is not None and stat.S_IMODE(before.st_mode) != mode):
        raise FirewallError("unsafe fixed file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
            raise FirewallError("fixed file changed")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise FirewallError("fixed file exceeds limit")
    return data


def _absent(path):
    _parents(path, missing=True)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise FirewallError("fixed path already exists")


def _trusted_command(path):
    candidate = Path(path)
    _parents(candidate)
    resolved = candidate.resolve(strict=True)
    _parents(resolved)
    info = resolved.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or not info.st_mode & 0o111):
        raise FirewallError("untrusted fixed command")


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
                    raise FirewallError("fixed command timed out")
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                    if code not in allowed:
                        raise FirewallError("fixed command failed")
                    return code, bytes(output)
                output.extend(chunk)
                if len(output) > limit:
                    raise FirewallError("fixed command output exceeded limit")
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
        raise FirewallError("effective fixed service differs")


def _scope(config, *, require_active):
    if os.geteuid() != 0:
        raise FirewallError("root is required")
    if _json(_read(MARKER, private=True)) != config:
        raise FirewallError("application receipt differs")
    if hashlib.sha256(_read(HTTPS_UNIT, mode=0o644)).hexdigest() != HTTPS_UNIT_SHA256:
        raise FirewallError("HTTPS service differs")
    for directory in UNIT_DIRECTORIES:
        fragment = Path(directory) / "quanta-https.service"
        if fragment != HTTPS_UNIT:
            _absent(fragment)
        _absent(Path(directory) / "quanta-https.service.d")
    template = _read(TEMPLATE)
    if hashlib.sha256(template).hexdigest() != TEMPLATE_SHA256:
        raise FirewallError("source template differs")
    expected = template.replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n")
    if _read(CADDYFILE, private=True) != expected:
        raise FirewallError("HTTPS configuration differs")
    host = urlsplit(config["public_origin"]).hostname
    if _read(HTTPS_ENV, private=True) != ("QUANTA_PUBLIC_HOST=" + host + "\n").encode("ascii"):
        raise FirewallError("HTTPS environment differs")
    # The executable is large; inspect metadata and the fixed ARM64 ELF header.
    _parents(CADDY)
    info = CADDY.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o755 or not 64 <= info.st_size <= 64 * 1024 * 1024):
        raise FirewallError("HTTPS executable differs")
    descriptor = os.open(CADDY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        header = stream.read(64)
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
        raise FirewallError("HTTPS executable differs")
    _trusted_command(SYSTEMCTL)
    _effective_unit("quanta-https.service", HTTPS_UNIT)
    if require_active and not _active("quanta-https.service"):
        raise FirewallError("HTTPS is not active")


def _ufw_active():
    for unit in ("firewalld.service", "nftables.service"):
        if _active(unit):
            raise FirewallError("another firewall manager is active")
    try:
        Path(UFW).lstat()
    except FileNotFoundError:
        return False
    _trusted_command(UFW)
    _, raw = _command([UFW, "status"], timeout=10)
    first = raw.splitlines()[:1]
    if first == [b"Status: active"]:
        return True
    if first == [b"Status: inactive"]:
        return False
    raise FirewallError("unknown firewall status")


def _rule(port):
    if port not in PORTS:
        raise FirewallError("unsupported port")
    return ["-p", "tcp", "--dport", str(port), "-m", "comment", "--comment",
            "quanta-web-v1-" + str(port), "-j", "ACCEPT"]


def _iptables(operation, port):
    suffix = ["1"] if operation == "-I" else []
    if operation not in {"-C", "-I"}:
        raise FirewallError("unsupported firewall operation")
    return [IPTABLES, "-w", "5", "-t", "filter", operation, "INPUT", *suffix, *_rule(port)]


def _inspect_input():
    _, raw = _command([IPTABLES, "-w", "5", "-t", "filter", "-S", "INPUT"], timeout=10)
    lines = raw.decode("ascii").splitlines()
    if not lines or not lines[0].startswith("-P INPUT "):
        raise FirewallError("unknown INPUT rules")
    rules = []
    for index, line in enumerate(lines):
        tokens = shlex.split(line)
        if index == 0:
            if tokens not in (["-P", "INPUT", "ACCEPT"], ["-P", "INPUT", "DROP"]):
                raise FirewallError("unknown INPUT policy")
        elif tokens[:2] == ["-A", "INPUT"] and len(tokens) > 2:
            rules.append(tokens)
        else:
            raise FirewallError("unknown INPUT rules")
    return rules


def _front_ports(rules):
    result = set()
    for tokens in rules:
        normalized = list(tokens)
        while ["-m", "tcp"] in [normalized[index:index + 2] for index in range(len(normalized) - 1)]:
            index = next(index for index in range(len(normalized) - 1) if normalized[index:index + 2] == ["-m", "tcp"])
            del normalized[index:index + 2]
        matches = [port for port in PORTS if normalized == ["-A", "INPUT", *_rule(port)]]
        if not matches:
            break
        result.add(matches[0])
    return result


def _apply_iptables():
    _trusted_command(IPTABLES)
    front = _front_ports(_inspect_input())
    for port in PORTS:
        code, _ = _command(_iptables("-C", port), allowed=(0, 1), timeout=10)
        if code == 1 or port not in front:
            _command(_iptables("-I", port), timeout=10)
            front = _front_ports(_inspect_input())
    if _front_ports(_inspect_input()) != set(PORTS):
        raise FirewallError("web rules are not ahead of existing rules")
    for port in PORTS:
        _command(_iptables("-C", port), timeout=10)


def _apply_ufw():
    for port in PORTS:
        _command([UFW, "prepend", "allow", "in", "proto", "tcp", "from", "0.0.0.0/0",
                  "to", "0.0.0.0/0", "port", str(port), "comment", "quanta-web-v1-" + str(port)], timeout=15)
    if not _ufw_active():
        raise FirewallError("UFW stopped during configuration")


def _own_paths_absent():
    _absent(HELPER)
    _absent(Path("/etc/systemd/system/multi-user.target.wants/quanta-web-firewall.service"))
    for directory in UNIT_DIRECTORIES:
        for suffix in ("", ".d"):
            _absent(Path(directory) / ("quanta-web-firewall.service" + suffix))


def _carried_source():
    """The fixed SSH transport carries this exact source via Python's -c argv."""
    original = getattr(sys, "orig_argv", [])
    if original.count("-c") != 1:
        raise FirewallError("missing carried source")
    index = original.index("-c") + 1
    if index >= len(original) or not isinstance(original[index], str):
        raise FirewallError("missing carried source")
    source = original[index].encode("utf-8")
    if not 1024 <= len(source) <= 65_536 or not source.startswith(b"#!/usr/bin/python3\n"):
        raise FirewallError("invalid carried source")
    compile(source, "quanta-web-firewall", "exec")
    return source


def _write_new(path, contents, mode):
    _parents(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _deadline(seconds):
    def expired(*_):
        raise FirewallError("fixed operation timed out")
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
    except FirewallError:
        pass
    return False


def _report():
    return {"scope": "web_firewall", "status": "failed", "failure_stage": "config",
            **dict.fromkeys(BOOLEAN_FIELDS, False)}


def configure(config):
    result = _report()
    try:
        config = validate_config(config)
        result["failure_stage"] = "preflight"
        _scope(config, require_active=True)
        result.update(scope_verified=True, https_service_active=True)
        _own_paths_absent()
        result["failure_stage"] = "inspection"
        ufw = _ufw_active()
        result["ufw_active"] = ufw
        if not ufw:
            _trusted_command(IPTABLES)
            _inspect_input()
            # Ensure the boot copy is available before any new file/rule is written.
            carried = _carried_source()
        result["rules_inspected"] = True
        if ufw:
            result["failure_stage"] = "rules"
            result["rule_mutation_attempted"] = True
            _apply_ufw()
            result.update(rules_applied=True, persistence_configured=True)
        else:
            result["failure_stage"] = "persistence"
            _write_new(HELPER, carried, 0o755)
            _write_new(UNIT, UNIT_TEXT.encode("ascii"), 0o644)
            _command([SYSTEMCTL, "daemon-reload"], limit=4096)
            _effective_unit("quanta-web-firewall.service", UNIT)
            _command([SYSTEMCTL, "enable", "quanta-web-firewall.service"], limit=4096)
            result["persistence_configured"] = True
            result["failure_stage"] = "rules"
            result["rule_mutation_attempted"] = True
            _command([SYSTEMCTL, "start", "quanta-web-firewall.service"], timeout=65, limit=4096)
            if not _active("quanta-web-firewall.service"):
                raise FirewallError("web rule service is not active")
            result["persistence_service_active"] = True
            _apply_iptables()
            result["rules_applied"] = True
        result["failure_stage"] = "https"
        _command([SYSTEMCTL, "restart", "quanta-https.service"], timeout=40, limit=4096)
        result["https_service_active"] = _active("quanta-https.service")
        if not result["https_service_active"]:
            raise FirewallError("HTTPS restart did not complete")
        result["tls_issued"] = _wait_tls(urlsplit(config["public_origin"]).hostname)
        result.update(status="success", failure_stage="none")
    except Exception:
        pass
    return validate_report(result)


def restore():
    """Boot only: scope the persisted receipt without requiring HTTPS first."""
    config = validate_config(_json(_read(MARKER, private=True)))
    _scope(config, require_active=False)
    if _read(UNIT, mode=0o644) != UNIT_TEXT.encode("ascii"):
        raise FirewallError("web rule service differs")
    _effective_unit("quanta-web-firewall.service", UNIT)
    _read(HELPER, mode=0o755, limit=65_536)
    if _ufw_active():
        raise FirewallError("UFW now owns the firewall")
    _apply_iptables()


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "web_firewall"
            or value["status"] not in {"success", "failed"} or value["failure_stage"] not in STAGES
            or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)
            or value["ipv6_changed"] or value["cloud_ingress_changed"]):
        raise FirewallError("invalid web firewall report")
    if value["status"] == "success":
        required = ("scope_verified", "rules_inspected", "rule_mutation_attempted", "rules_applied",
                    "persistence_configured", "https_service_active")
        if (value["failure_stage"] != "none" or not all(value[key] for key in required)
                or not value["ufw_active"] and not value["persistence_service_active"]):
            raise FirewallError("invalid web firewall report")
    elif value["failure_stage"] == "none":
        raise FirewallError("invalid web firewall report")
    if (value["tls_issued"] and not value["https_service_active"]
            or value["rules_applied"] and not value["rule_mutation_attempted"]
            or value["persistence_service_active"] and not value["persistence_configured"]
            or value["rule_mutation_attempted"] and not value["rules_inspected"]
            or value["rules_inspected"] and not value["scope_verified"]):
        raise FirewallError("invalid web firewall report")
    return dict(value)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
            return None
        return validate_report(_json(raw))
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return None


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == [BOOT_ARGUMENT]:
        try:
            restore()
            return 0
        except Exception:
            return 2
    try:
        if len(arguments) != 1:
            raise FirewallError("one configuration argument is required")
        result = configure(_decode(arguments[0]))
    except Exception:
        result = _report()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
