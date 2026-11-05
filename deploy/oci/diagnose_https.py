#!/usr/bin/python3
"""Read only the installed proxy receipt, bounded journal and local public TLS.

No application environment, ACME account, certificate private key or raw journal
entry is returned. Error labels describe the latest relevant journal event;
historical issuer/rate-limit booleans are separate from that latest event.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import selectors
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
MARKER = Path("/etc/quanta/installed.json")
SYSTEMCTL, JOURNALCTL = "/usr/bin/systemctl", "/usr/bin/journalctl"
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_JOURNAL, MAX_OUTPUT_BYTES = 524_288, 4096
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})+\Z")
_ACME = re.compile(r"urn:ietf:params:acme:error:([A-Za-z]+)")
BOOLEAN_FIELDS = ("scope_verified", "service_active", "journal_read", "caddy_tls_events_seen",
                  "letsencrypt_seen", "zerossl_seen", "unknown_issuer_seen", "registered_domain_rate_limit_seen",
                  "authorization_failure_rate_limit_seen", "retry_pending", "tls_verified")
ERRORS = frozenset({"none", "rate_limit", "dns", "caa", "unauthorized", "connection", "issuer", "unknown"})
SUBTYPES = frozenset({"none", "registered_domain", "authorization_failure", "account", "unknown"})
ISSUERS = frozenset({"none", "letsencrypt", "zerossl", "unknown"})
FIELDS = frozenset({"scope", "status", "failure_stage", "latest_issuer", "acme_error", "rate_limit_subtype",
                    "retry_delay_seconds", *BOOLEAN_FIELDS})


class DiagnosticError(ValueError):
    pass


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DiagnosticError("invalid structured input")
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(DiagnosticError("invalid structured input")))


def validate_config(config):
    try:
        if (type(config) is not dict or set(config) != {"public_origin", "source_sha", "auth_mode"}
                or config["source_sha"] != SOURCE_SHA or config["auth_mode"] != "owner-token"):
            raise ValueError
        origin = config["public_origin"]
        parsed = urlsplit(origin)
        host = parsed.hostname
        if (type(origin) is not str or not host or len(host) > 253 or not _HOST.fullmatch(host)
                or origin != "https://" + host or parsed.netloc != host
                or host.endswith((".localhost", ".local", ".internal", ".invalid"))
                or host.rsplit(".", 1)[-1].isdigit()):
            raise ValueError
        return dict(config)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise DiagnosticError("invalid configuration") from None


def _decode(argument):
    if type(argument) is not str or not 1 <= len(argument) <= 4096:
        raise DiagnosticError("invalid configuration")
    raw = base64.b64decode(argument.encode("ascii"), validate=True)
    if len(raw) > 2048 or base64.b64encode(raw).decode("ascii") != argument:
        raise DiagnosticError("invalid configuration")
    return validate_config(_json(raw))


def _receipt():
    for parent in reversed(MARKER.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise DiagnosticError("unsafe receipt")
    before = MARKER.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600:
        raise DiagnosticError("unsafe receipt")
    descriptor = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        after = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or not stat.S_ISREG(after.st_mode) or after.st_uid != 0 or stat.S_IMODE(after.st_mode) != 0o600):
            raise DiagnosticError("receipt changed")
        raw = stream.read(2049)
    if len(raw) > 2048:
        raise DiagnosticError("receipt exceeds limit")
    return _json(raw)


def _active():
    result = subprocess.run([SYSTEMCTL, "is-active", "--quiet", "quanta-https.service"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
        cwd="/", env={"PATH": BINPATH, "LC_ALL": "C"}, timeout=3, check=False)
    return result.returncode == 0


def _journal():
    process, output = None, bytearray()
    deadline = time.monotonic() + 10
    try:
        process = subprocess.Popen([JOURNALCTL, "-u", "quanta-https.service", "-n", "150", "--since=-30min",
            "-o", "cat", "--no-pager"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, cwd="/", env={"PATH": BINPATH, "LC_ALL": "C"})
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise DiagnosticError("journal unavailable")
                chunk = os.read(process.stdout.fileno(), min(4096, MAX_JOURNAL + 1 - len(output)))
                if not chunk:
                    if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                        raise DiagnosticError("journal unavailable")
                    return bytes(output)
                output.extend(chunk)
                if len(output) > MAX_JOURNAL:
                    raise DiagnosticError("journal exceeds limit")
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=2)
            except Exception:
                pass
            if process.stdout is not None:
                process.stdout.close()


def _issuer(text):
    names = re.findall(r"letsencrypt(?:\.org)?|zerossl(?:\.com)?", text.lower())
    return ("letsencrypt" if names[-1].startswith("letsencrypt") else "zerossl") if names else "unknown"


def classify_journal(raw, host):
    if type(raw) is not bytes or len(raw) > MAX_JOURNAL:
        raise DiagnosticError("invalid journal")
    result = {**dict.fromkeys(BOOLEAN_FIELDS[3:-1], False), "latest_issuer": "none", "acme_error": "none",
              "rate_limit_subtype": "none", "retry_delay_seconds": None}
    for line in raw.splitlines()[-150:]:
        try:
            entry = _json(line)
        except (ValueError, UnicodeError, RecursionError):
            continue
        if (type(entry) is not dict or type(entry.get("logger")) is not str
                or not (entry["logger"] in {"tls.obtain", "tls.renew"} or entry["logger"].startswith("tls.issuance."))
                or (entry.get("identifier") is not None and entry.get("identifier") != host)):
            continue
        result["caddy_tls_events_seen"] = True
        error = entry.get("error") if type(entry.get("error")) is str else ""
        problem = entry.get("problem") if type(entry.get("problem")) is dict else {}
        text = " ".join(value for value in (error, problem.get("type"), problem.get("detail")) if type(value) is str)
        issuer_text = " ".join(value for value in (entry.get("issuer"), entry.get("ca"), text) if type(value) is str)
        for name in ("letsencrypt", "zerossl"):
            if name in issuer_text.lower():
                result[name + "_seen"] = True
        explicit = entry.get("issuer") or entry.get("ca")
        issuer = _issuer(explicit if type(explicit) is str else issuer_text)
        if issuer == "unknown" and (explicit or error or problem):
            result["unknown_issuer_seen"] = True
        message = entry.get("msg") if type(entry.get("msg")) is str else ""
        if message in {"certificate obtained successfully", "certificate renewed successfully", "final attempt; giving up", "obtaining certificate"}:
            result.update(retry_pending=False, retry_delay_seconds=None)
        if message == "will retry":
            delay = entry.get("retrying_in")
            exact = type(delay) in (int, float) and 0 <= delay <= 86400 and int(delay) == delay
            result.update(retry_pending=True, retry_delay_seconds=int(delay) if exact else None)
        if type(entry.get("level")) is not str or entry["level"] not in {"error", "warn"} or not (error or problem):
            continue
        lower = text.lower()
        codes = _ACME.findall(text)
        code = codes[-1].lower() if codes else ""
        label = {"ratelimited": "rate_limit", "dns": "dns", "caa": "caa", "unauthorized": "unauthorized",
                 "connection": "connection", "tls": "connection", "serverinternal": "issuer",
                 "externalaccountrequired": "issuer", "accountdoesnotexist": "issuer"}.get(code, "unknown")
        if not code and any(pattern in lower for pattern in ("too many certificates", "failed authorizations", "rate limit")):
            label = "rate_limit"
        elif not code and any(pattern in lower for pattern in ("registering account", "provisioning client", "external account binding")):
            label = "issuer"
        subtype = "none"
        if label == "rate_limit":
            subtype = ("authorization_failure" if "failed authorizations" in lower or "authorization failures" in lower else
                       "registered_domain" if "too many certificates" in lower and "exact set" not in lower else
                       "account" if "new registrations" in lower or "new orders" in lower or "per account" in lower else "unknown")
            if subtype in {"registered_domain", "authorization_failure"}:
                result[subtype + "_rate_limit_seen"] = True
        result.update(latest_issuer=issuer, acme_error=label, rate_limit_subtype=subtype)
    return result


def _tls(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", 443), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ValueError, EOFError):
        return False


def _report():
    return {"scope": "https_diagnostics", "status": "failed", "failure_stage": "config",
            **dict.fromkeys(BOOLEAN_FIELDS, False), "latest_issuer": "none", "acme_error": "none",
            "rate_limit_subtype": "none", "retry_delay_seconds": None}


def diagnose(config):
    result = _report()
    try:
        config = validate_config(config)
        result["failure_stage"] = "preflight"
        if os.geteuid() != 0 or _receipt() != config:
            raise DiagnosticError("installation differs")
        result["scope_verified"] = True
        result["service_active"] = _active()
        if not result["service_active"]:
            raise DiagnosticError("proxy is inactive")
        result["failure_stage"] = "journal"
        host = urlsplit(config["public_origin"]).hostname
        result.update(classify_journal(_journal(), host), journal_read=True)
        result["failure_stage"] = "tls"
        result["tls_verified"] = _tls(host)
        result.update(status="success", failure_stage="none")
    except Exception:
        pass
    return result


def validate_report(value):
    if (type(value) is not dict or set(value) != FIELDS or value["scope"] != "https_diagnostics"
            or value["status"] not in {"failed", "success"} or value["failure_stage"] not in {"config", "preflight", "journal", "tls", "none"}
            or any(type(value[key]) is not bool for key in BOOLEAN_FIELDS) or value["latest_issuer"] not in ISSUERS
            or value["acme_error"] not in ERRORS or value["rate_limit_subtype"] not in SUBTYPES
            or (value["retry_delay_seconds"] is not None and (type(value["retry_delay_seconds"]) is not int
                or not 0 <= value["retry_delay_seconds"] <= 86400 or not value["retry_pending"]))
            or (value["acme_error"] == "rate_limit") != (value["rate_limit_subtype"] != "none")):
        raise DiagnosticError("invalid report")
    if value["status"] == "success" and (value["failure_stage"] != "none" or not all(value[key] for key in BOOLEAN_FIELDS[:3])):
        raise DiagnosticError("invalid report")
    if (value["status"] == "failed" and value["failure_stage"] == "none"
            or any(value[later] and not value[earlier] for earlier, later in zip(BOOLEAN_FIELDS[:3], BOOLEAN_FIELDS[1:3]))
            or value["tls_verified"] and not value["journal_read"]):
        raise DiagnosticError("invalid report")
    return dict(value)


def sanitize_report(raw):
    try:
        return validate_report(_json(raw)) if type(raw) is bytes and 1 <= len(raw) <= MAX_OUTPUT_BYTES else None
    except Exception:
        return None


def main(argv=None):
    try:
        arguments = sys.argv[1:] if argv is None else argv
        result = diagnose(_decode(arguments[0])) if len(arguments) == 1 else _report()
    except Exception:
        result = _report()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
