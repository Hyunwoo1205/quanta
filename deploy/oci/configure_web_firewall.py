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
NFT = "/usr/sbin/nft"
FIREWALL_CMD = "/usr/bin/firewall-cmd"
MARKER = Path("/etc/quanta/installed.json")
HTTPS_UNIT = Path("/etc/systemd/system/quanta-https.service")
CADDY = Path("/usr/local/lib/quanta/caddy")
TEMPLATE = Path("/srv/quanta/source") / SOURCE_SHA / "deploy/oci/Caddyfile.example"
CADDYFILE = Path("/etc/quanta/Caddyfile")
HTTPS_ENV = Path("/etc/quanta/https.env")
ACME_RECEIPT = Path("/etc/quanta/acme.json")
ACME_CA = "https://acme.zerossl.com/v2/DV90"
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
    "scope_verified", "rules_inspected", "ufw_active", "nftables_active", "firewalld_active", "rule_mutation_attempted",
    "rules_applied", "persistence_configured", "persistence_service_active",
    "https_service_active", "tls_issued", "ipv6_changed", "cloud_ingress_changed",
)
FIELDS = frozenset(("scope", "status", "failure_stage", "failure_reason", "manager", *BOOLEAN_FIELDS))
MANAGERS = frozenset(("unknown", "ambiguous", "iptables", "ufw", "nftables", "firewalld"))
STAGES = frozenset(("none", "config", "preflight", "inspection", "persistence", "rules", "https"))
_ERROR_REASONS = {
    "invalid structured input": "invalid_config",
    "invalid configuration": "invalid_config",
    "one configuration argument is required": "invalid_config",
    "unsafe fixed path": "unsafe_path",
    "untrusted system directory alias": "untrusted_system_alias",
    "unsafe fixed file": "unsafe_file",
    "fixed file changed": "file_changed",
    "fixed file exceeds limit": "file_limit",
    "fixed path already exists": "existing_path",
    "untrusted fixed command": "untrusted_command",
    "fixed command timed out": "command_timeout",
    "fixed command failed": "command_failed",
    "fixed command output exceeded limit": "command_output_limit",
    "effective fixed service differs": "effective_service_mismatch",
    "root is required": "root_required",
    "application receipt differs": "receipt_mismatch",
    "HTTPS service differs": "https_service_mismatch",
    "source template differs": "source_mismatch",
    "HTTPS configuration differs": "https_config_mismatch",
    "HTTPS environment differs": "https_env_mismatch",
    "HTTPS executable differs": "https_binary_mismatch",
    "HTTPS is not active": "https_inactive",
    "another firewall manager is active": "other_firewall_active",
    "unknown firewall status": "ufw_status_unknown",
    "unsupported port": "unsupported_operation",
    "unsupported firewall operation": "unsupported_operation",
    "unknown INPUT rules": "input_rules_unknown",
    "unknown INPUT policy": "input_policy_unknown",
    "web rules are not ahead of existing rules": "rule_order_unverified",
    "UFW stopped during configuration": "ufw_inactive",
    "missing carried source": "carried_source_missing",
    "invalid carried source": "carried_source_invalid",
    "fixed operation timed out": "operation_timeout",
    "web rule service is not active": "persistence_inactive",
    "HTTPS restart did not complete": "https_restart_failed",
    "web rule service differs": "persistence_mismatch",
    "UFW now owns the firewall": "ufw_active_during_restore",
    "invalid web firewall report": "report_invalid",
    "multiple firewall managers are active": "manager_overlap",
    "required manager command is missing": "manager_cli_missing",
    "invalid firewalld zone": "firewalld_zone_invalid",
    "invalid nftables ruleset": "nft_ruleset_invalid",
    "unsupported nftables input scope": "nft_scope_unsupported",
    "nftables web rule verification failed": "nft_rule_unverified",
    "invalid ACME contact email": "acme_email_invalid",
    "ACME policy receipt differs": "acme_receipt_mismatch",
}
REASONS = frozenset(("none", "operation_failed", "system_path_missing", "permission_denied",
                     *_ERROR_REASONS.values()))
# Only these fixed system-directory aliases may bypass the normal no-symlink rule.
SYSTEM_DIRECTORY_ALIASES = {
    Path("/lib"): ({"usr/lib", "/usr/lib"}, Path("/usr/lib")),
    Path("/usr/sbin"): ({"bin", "/usr/bin"}, Path("/usr/bin")),
}
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


def _failure_reason(error):
    if type(error) is FirewallError and len(error.args) == 1 and type(error.args[0]) is str:
        return _ERROR_REASONS.get(error.args[0], "operation_failed")
    if isinstance(error, FileNotFoundError):
        return "system_path_missing"
    if isinstance(error, PermissionError):
        return "permission_denied"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command_timeout"
    return "operation_failed"


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
        if parent in SYSTEM_DIRECTORY_ALIASES and stat.S_ISLNK(info.st_mode):
            allowed, target = SYSTEM_DIRECTORY_ALIASES[parent]
            if info.st_uid != 0 or os.readlink(parent) not in allowed:
                raise FirewallError("untrusted system directory alias")
            _parents(target)
            info = target.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise FirewallError("untrusted system directory alias")
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
    visited = set()
    for _ in range(16):
        _parents(candidate)
        if candidate in visited:
            raise FirewallError("untrusted fixed command")
        visited.add(candidate)
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.readlink(candidate))
            if info.st_uid != 0 or ".." in target.parts:
                raise FirewallError("untrusted fixed command")
            candidate = target if target.is_absolute() else candidate.parent / target
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not info.st_mode & 0o111):
            raise FirewallError("untrusted fixed command")
        return
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


def _acme_email(value):
    if (not isinstance(value, str) or not value.isascii() or len(value) > 254
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@"
                                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                                r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", value)):
        raise FirewallError("invalid ACME contact email")
    local, domain = value.rsplit("@", 1)
    if local.endswith(".") or ".." in local or len(domain) > 253 or domain.rsplit(".", 1)[-1].isdigit():
        raise FirewallError("invalid ACME contact email")
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
        raise FirewallError("HTTPS configuration differs")
    prefix = original_env + b"QUANTA_ACME_EMAIL="
    if not environment.startswith(prefix) or not environment.endswith(b"\n"):
        raise FirewallError("HTTPS environment differs")
    email = _acme_email(environment[len(prefix):-1].decode("ascii"))
    if environment != prefix + email.encode("ascii") + b"\n":
        raise FirewallError("HTTPS environment differs")
    receipt = _json(_read(ACME_RECEIPT, private=True))
    if not isinstance(receipt, dict) or type(receipt.get("schema")) is not int or receipt != _acme_receipt(config, email):
        raise FirewallError("ACME policy receipt differs")


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
    _https_config_guard(config, template)
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


def _detect_manager(progress=None):
    facts = {"firewalld_active": False, "nftables_active": False, "ufw_active": False,
             "manager": "unknown"}
    for index, (name, inspect) in enumerate((
            ("firewalld", lambda: _active("firewalld.service")),
            ("nftables", lambda: _active("nftables.service")), ("ufw", _ufw_active))):
        facts[name + "_active"] = inspect()
        active = [item for item in ("firewalld", "nftables", "ufw") if facts[item + "_active"]]
        facts["manager"] = ("ambiguous" if len(active) > 1 else active[0] if active
                            else "iptables" if index == 2 else "unknown")
        if progress is not None:
            progress.update(facts)
    return facts


def _native_command(path):
    try:
        _trusted_command(path)
    except FileNotFoundError:
        raise FirewallError("required manager command is missing") from None


def _firewalld_zone():
    _native_command(FIREWALL_CMD)
    _, raw = _command([FIREWALL_CMD, "--get-default-zone"], timeout=5, limit=128)
    if not re.fullmatch(rb"[A-Za-z][A-Za-z0-9_-]{0,31}\n", raw):
        raise FirewallError("invalid firewalld zone")
    return raw[:-1].decode("ascii")


def _rich_rule(port):
    if port not in PORTS:
        raise FirewallError("unsupported port")
    return f'rule family="ipv4" priority="-100" port port="{port}" protocol="tcp" accept'


def _apply_firewalld(zone):
    # Native rich rules preserve IPv6. Never reload or overwrite runtime state.
    # https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html
    if not isinstance(zone, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", zone):
        raise FirewallError("invalid firewalld zone")
    for port in PORTS:
        rule = _rich_rule(port)
        for permanent in (False, True):
            prefix = [FIREWALL_CMD, "--zone=" + zone] + (["--permanent"] if permanent else [])
            query = prefix + ["--query-rich-rule=" + rule]
            code, _ = _command(query, allowed=(0, 1), timeout=10, limit=4096)
            if code == 1:
                _command(prefix + ["--add-rich-rule=" + rule], allowed=(0, 11), timeout=10, limit=4096)
            _command(query, timeout=10, limit=4096)


def _nft_owned(rule):
    if (not isinstance(rule, dict) or rule.get("comment") != "quanta-web-v1"
            or rule.get("family") not in {"ip", "inet"}
            or set(rule) - {"family", "table", "chain", "expr", "handle", "index", "comment"}):
        return False
    expressions = rule.get("expr")
    if not isinstance(expressions, list) or len(expressions) not in {2, 3, 4} or expressions[-1] != {"accept": None}:
        return False
    kinds = []
    for expression in expressions[:-1]:
        if not isinstance(expression, dict) or set(expression) != {"match"}:
            return False
        match = expression["match"]
        if not isinstance(match, dict) or set(match) != {"op", "left", "right"}:
            return False
        left, right, operator = match["left"], match["right"], match["op"]
        if (left == {"meta": {"key": "nfproto"}} and operator == "=="
                and right in ("ipv4", 2) and type(right) in (str, int)):
            kinds.append("ipv4")
        elif (left == {"meta": {"key": "l4proto"}} and operator == "=="
              and right in ("tcp", 6) and type(right) in (str, int)):
            kinds.append("tcp")
        elif (left == {"payload": {"protocol": "tcp", "field": "dport"}}
              and operator in {"==", "in"}
              and isinstance(right, dict) and set(right) == {"set"}
              and isinstance(right["set"], list) and len(right["set"]) == 2
              and all(type(port) is int for port in right["set"]) and set(right["set"]) == set(PORTS)):
            kinds.append("ports")
        else:
            return False
    accepted = (["ipv4", "ports"], ["ipv4", "ports", "tcp"])
    if rule["family"] == "ip":
        accepted += (["ports"], ["ports", "tcp"])
    return sorted(kinds) in accepted


def _parse_nft(raw):
    # Schema: upstream libnftables-json(5), shipped by Ubuntu 26.04.
    # https://manpages.ubuntu.com/manpages/resolute/man5/libnftables-json.5.html
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1_048_576:
        raise FirewallError("invalid nftables ruleset")
    value = _json(raw)
    if (not isinstance(value, dict) or set(value) != {"nftables"}
            or not isinstance(value["nftables"], list) or len(value["nftables"]) > 16_384):
        raise FirewallError("invalid nftables ruleset")
    tables, chains, rules = {}, {}, []
    for entry in value["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise FirewallError("invalid nftables ruleset")
        kind, item = next(iter(entry.items()))
        if kind not in {"table", "chain", "rule"}:
            continue
        if not isinstance(item, dict):
            raise FirewallError("invalid nftables ruleset")
        if kind == "table":
            key = (item.get("family"), item.get("name"))
            if not all(isinstance(part, str) for part in key) or key in tables:
                raise FirewallError("invalid nftables ruleset")
            tables[key] = item
        elif kind == "chain":
            key = (item.get("family"), item.get("table"), item.get("name"))
            if not all(isinstance(part, str) for part in key) or key in chains:
                raise FirewallError("invalid nftables ruleset")
            chains[key] = item
        else:
            rules.append(item)
    selected = {}
    for key, chain in chains.items():
        family, table, name = key
        if family == "ip6" or chain.get("hook") != "input":
            continue
        if (family not in {"ip", "inet"} or chain.get("type") != "filter"
                or chain.get("policy") not in {"accept", "drop"}
                or type(chain.get("prio")) is not int or not -2_147_483_648 <= chain["prio"] <= 2_147_483_647
                or set(chain) - {"family", "table", "name", "handle", "type", "hook", "prio", "policy", "comment"}
                or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", identifier) for identifier in (table, name))
                or "docker" in (table + "_" + name).lower()
                or table.lower() == "nat"
                or (family, table) not in tables or tables[(family, table)].get("flags") not in (None, [])):
            raise FirewallError("unsupported nftables input scope")
        selected[key] = {"definition": dict(chain), "rules": []}
    if not 1 <= len(selected) <= 8:
        raise FirewallError("unsupported nftables input scope")
    for rule in rules:
        key = (rule.get("family"), rule.get("table"), rule.get("chain"))
        if not all(isinstance(part, str) for part in key):
            raise FirewallError("invalid nftables ruleset")
        if key in selected:
            if not isinstance(rule.get("expr"), list):
                raise FirewallError("invalid nftables ruleset")
            selected[key]["rules"].append(rule)
    return selected


def _inspect_nft():
    _native_command(NFT)
    _, raw = _command([NFT, "--json", "--numeric", "list", "ruleset"], timeout=10, limit=1_048_576)
    return _parse_nft(raw)


def _apply_nft():
    # insert without a position prepends; all identifiers were strictly checked.
    # https://netfilter.org/projects/nftables/manpage.html#lbAJ
    before = _inspect_nft()
    for (family, table, chain), data in before.items():
        if data["rules"] and _nft_owned(data["rules"][0]):
            continue
        ipv4 = ["meta", "nfproto", "ipv4"] if family == "inet" else []
        _command([NFT, "insert", "rule", family, table, chain, *ipv4,
                  "meta", "l4proto", "tcp", "tcp", "dport", "{", "80", ",", "443", "}",
                  "accept", "comment", '"quanta-web-v1"'], timeout=10, limit=4096)
    after = _inspect_nft()
    if set(before) != set(after) or any(
            before[key]["definition"] != after[key]["definition"] or not after[key]["rules"]
            or not _nft_owned(after[key]["rules"][0]) for key in before):
        raise FirewallError("nftables web rule verification failed")


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
            "failure_reason": "invalid_config", "manager": "unknown",
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
        detected = _detect_manager(result)
        result.update(detected)
        manager = detected["manager"]
        if manager == "ambiguous":
            raise FirewallError("multiple firewall managers are active")
        if manager == "iptables":
            _trusted_command(IPTABLES)
            _inspect_input()
        elif manager == "nftables":
            _inspect_nft()
        elif manager == "firewalld":
            zone = _firewalld_zone()
        if manager in {"iptables", "nftables"}:
            # Ensure the boot copy is available before any new file/rule is written.
            carried = _carried_source()
        result["rules_inspected"] = True
        if manager in {"ufw", "firewalld"}:
            result["failure_stage"] = "rules"
            result["rule_mutation_attempted"] = True
            if manager == "ufw":
                _apply_ufw()
            else:
                _apply_firewalld(zone)
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
            if manager == "nftables":
                _apply_nft()
            else:
                _apply_iptables()
            result["rules_applied"] = True
        result["failure_stage"] = "https"
        _command([SYSTEMCTL, "restart", "quanta-https.service"], timeout=40, limit=4096)
        result["https_service_active"] = _active("quanta-https.service")
        if not result["https_service_active"]:
            raise FirewallError("HTTPS restart did not complete")
        result["tls_issued"] = _wait_tls(urlsplit(config["public_origin"]).hostname)
        result.update(status="success", failure_stage="none", failure_reason="none")
    except Exception as error:
        result["failure_reason"] = _failure_reason(error)
    return validate_report(result)


def restore():
    """Boot only: scope the persisted receipt without requiring HTTPS first."""
    config = validate_config(_json(_read(MARKER, private=True)))
    _scope(config, require_active=False)
    if _read(UNIT, mode=0o644) != UNIT_TEXT.encode("ascii"):
        raise FirewallError("web rule service differs")
    _effective_unit("quanta-web-firewall.service", UNIT)
    _read(HELPER, mode=0o755, limit=65_536)
    manager = _detect_manager()["manager"]
    if manager == "ambiguous":
        raise FirewallError("multiple firewall managers are active")
    if manager == "nftables":
        _apply_nft()
    elif manager == "firewalld":
        _apply_firewalld(_firewalld_zone())
    elif manager == "ufw":
        _apply_ufw()
    else:
        _apply_iptables()


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value["scope"] != "web_firewall"
            or value["status"] not in {"success", "failed"} or value["failure_stage"] not in STAGES
            or value["failure_reason"] not in REASONS
            or value["manager"] not in MANAGERS
            or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)
            or value["ipv6_changed"] or value["cloud_ingress_changed"]):
        raise FirewallError("invalid web firewall report")
    if value["status"] == "success":
        required = ("scope_verified", "rules_inspected", "rule_mutation_attempted", "rules_applied",
                    "persistence_configured", "https_service_active")
        if (value["failure_stage"] != "none" or value["failure_reason"] != "none"
                or not all(value[key] for key in required)
                or value["manager"] in {"unknown", "ambiguous"}
                or value["manager"] in {"iptables", "nftables"} and not value["persistence_service_active"]):
            raise FirewallError("invalid web firewall report")
    elif value["failure_stage"] == "none" or value["failure_reason"] == "none":
        raise FirewallError("invalid web firewall report")
    if (value["tls_issued"] and not value["https_service_active"]
            or value["rules_applied"] and not value["rule_mutation_attempted"]
            or value["persistence_service_active"] and not value["persistence_configured"]
            or value["rule_mutation_attempted"] and not value["rules_inspected"]
            or value["rules_inspected"] and not value["scope_verified"]):
        raise FirewallError("invalid web firewall report")
    active = [name for name in ("ufw", "nftables", "firewalld") if value[name + "_active"]]
    if (value["manager"] == "ambiguous" and len(active) < 2
            or value["manager"] == "unknown" and active
            or value["manager"] == "iptables" and active
            or value["manager"] in {"ufw", "nftables", "firewalld"} and active != [value["manager"]]):
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
    except Exception as error:
        result = _report()
        result["failure_reason"] = _failure_reason(error)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
