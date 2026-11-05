#!/usr/bin/env python3
"""Bounded anonymous deployment checks; never load a real owner or SSH key.

The Linux runner checks DNS, the HTTP redirect and public HTTPS boundaries. A
successful report does not verify owner login, browser behavior or computation.
Only fixed booleans, status codes and phase labels may reach stdout.
"""
from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


TOTAL_TIMEOUT = 40
WORK_TIMEOUT = 38
REQUEST_TIMEOUT = 10
MAX_OUTPUT = 4096
MAX_SHELL = 262_144
MAX_JSON = 4096
WRONG_AUTHORIZATION = "Bearer public-deployment-probe-invalid"
CONFIG_KEYS = ("QUANTA_PUBLIC_ORIGIN", "QUANTA_AUTH_MODE", "QUANTA_OCI_HOST")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"{_LABEL}(?:\.{_LABEL})+\Z")
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_PHASES = frozenset({"configuration", "worker", "dns", "http_redirect", "https_shell",
                     "auth_discovery", "anonymous_api", "wrong_token_api", "complete"})
_STATUSES = frozenset({"not_configured", "failed", "timeout", "output_limit", "invalid_output", "success"})
_CHECKS = ("dns_a_matches_expected", "dns_aaaa_present", "dns_addresses_public",
           "http_redirect_matches_origin", "https_shell_available", "owner_token_mode",
           "anonymous_api_denied", "wrong_token_api_denied")
_CODES = ("http_redirect_status", "https_shell_status", "auth_discovery_status",
          "anonymous_api_status", "wrong_token_api_status")
_CLAIMS = ("valid_owner_credential_used", "owner_authentication_verified", "browser_verified", "compute_verified")


class _ProbeFailure(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _report(status, phase="configuration"):
    return {"scope": "public_deployment_smoke", "status": status, "phase": phase,
            **dict.fromkeys(_CHECKS + _CODES), **dict.fromkeys(_CLAIMS, False)}


def _configuration(environ):
    origin, mode, host = (environ.get(key) for key in CONFIG_KEYS)
    if mode != "owner-token" or not isinstance(origin, str) or not 1 <= len(origin) <= 261:
        return None
    try:
        parsed = urlsplit(origin)
        hostname = parsed.hostname
        if (not hostname or len(hostname) > 253 or not _DOMAIN.fullmatch(hostname)
                or hostname.endswith(".localhost") or hostname.rsplit(".", 1)[-1].isdigit()
                or parsed.port is not None or origin != "https://" + hostname):
            return None
        address = ipaddress.IPv4Address(host)
        if (str(address) != host or not address.is_global or address.is_multicast or address.is_reserved):
            return None
    except (TypeError, ValueError):
        return None
    return origin, hostname, host


def _timeout_signal(signum, frame):
    raise TimeoutError


@contextmanager
def _bounded_step(seconds):
    """Interrupt DNS and slow/dripping reads as well as the connection itself."""
    if seconds <= 0:
        raise TimeoutError
    previous_handler = signal.signal(signal.SIGALRM, _timeout_signal)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] or previous_timer[1]:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def _json_document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _ProbeFailure
            result[key] = value
        return result

    def nonfinite(value):
        raise _ProbeFailure

    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def sanitize_report(raw):
    try:
        if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
            return None
        value = _json_document(raw)
        expected = {"scope", "status", "phase", *_CHECKS, *_CODES, *_CLAIMS}
        if (type(value) is not dict or set(value) != expected or value["scope"] != "public_deployment_smoke"
                or type(value["status"]) is not str or value["status"] not in _STATUSES
                or type(value["phase"]) is not str or value["phase"] not in _PHASES):
            return None
        if any(value[key] is not None and type(value[key]) is not bool for key in _CHECKS):
            return None
        if any(value[key] is not False for key in _CLAIMS):
            return None
        if any(value[key] is not None and (type(value[key]) is not int or not 100 <= value[key] <= 599)
               for key in _CODES):
            return None
        if value["status"] == "success":
            if (value["phase"] != "complete"
                    or any(value[key] is not True for key in _CHECKS if key != "dns_aaaa_present")
                    or type(value["dns_aaaa_present"]) is not bool
                    or value["http_redirect_status"] not in _REDIRECTS
                    or tuple(value[key] for key in _CODES[1:]) != (200, 200, 401, 401)):
                return None
        elif value["phase"] == "complete":
            return None
        return value
    except Exception:
        return None


def _dns_facts(hostname, expected, resolver):
    records = resolver(hostname, 443, family=socket.AF_UNSPEC,
                       type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not records or len(records) > 128:
        raise _ProbeFailure
    ipv4, ipv6, public = set(), False, True
    for family, _, _, _, address in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            raise _ProbeFailure
        parsed = ipaddress.ip_address(address[0])
        if (family == socket.AF_INET) != (parsed.version == 4):
            raise _ProbeFailure
        public = public and parsed.is_global and not parsed.is_multicast and not parsed.is_reserved
        if parsed.version == 4:
            ipv4.add(str(parsed))
        else:
            ipv6 = True
    return ipv4 == {expected}, ipv6, public


def _fetch(opener, url, limit, timeout, *, authorization=None):
    headers = {"Accept": "text/html, application/json", "Accept-Encoding": "identity",
               "User-Agent": "Quanta-public-deployment-check"}
    if authorization is not None:
        headers["Authorization"] = authorization
    with _bounded_step(timeout):
        try:
            response = opener.open(Request(url, headers=headers, method="GET"), timeout=timeout)
        except HTTPError as error:
            response = error
        with response:
            if response.geturl() != url or type(response.status) is not int or not 100 <= response.status <= 599:
                raise _ProbeFailure
            for name in ("Content-Length", "Content-Type", "Location", "Content-Encoding"):
                if len(response.headers.get_all(name, [])) > 1:
                    raise _ProbeFailure
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isascii() or not length.isdigit()
                                       or len(length) > 10 or int(length) > limit):
                raise _ProbeFailure
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise _ProbeFailure
            body = response.read(limit + 1)
            if len(body) > limit or (length is not None and len(body) != int(length)):
                raise _ProbeFailure
            media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            return response.status, media, response.headers.get("Location"), body


def _run_probe(config, *, opener=None, resolver=None, clock=None):
    result = _report("failed", "dns")
    clock = time.monotonic if clock is None else clock
    resolver = socket.getaddrinfo if resolver is None else resolver
    deadline = clock() + WORK_TIMEOUT
    origin, hostname, expected = config
    try:
        if opener is None:
            opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        with _bounded_step(min(REQUEST_TIMEOUT, deadline - clock())):
            matches, ipv6, public = _dns_facts(hostname, expected, resolver)
        result.update(dns_a_matches_expected=matches, dns_aaaa_present=ipv6, dns_addresses_public=public)
        if not matches or not public:
            return result
        result["phase"] = "http_redirect"
        code, _, location, _ = _fetch(opener, "http://" + hostname + "/", MAX_JSON,
                                       min(REQUEST_TIMEOUT, deadline - clock()))
        result["http_redirect_status"] = code
        result["http_redirect_matches_origin"] = code in _REDIRECTS and location == origin + "/"
        if not result["http_redirect_matches_origin"]:
            return result
        result["phase"] = "https_shell"
        code, media, _, body = _fetch(opener, origin + "/", MAX_SHELL,
                                      min(REQUEST_TIMEOUT, deadline - clock()))
        result["https_shell_status"] = code
        result["https_shell_available"] = code == 200 and media == "text/html" and b"<title>Quanta" in body
        if not result["https_shell_available"]:
            return result
        result["phase"] = "auth_discovery"
        code, media, _, body = _fetch(opener, origin + "/ui/auth", MAX_JSON,
                                      min(REQUEST_TIMEOUT, deadline - clock()))
        result["auth_discovery_status"] = code
        discovery = _json_document(body) if code == 200 and media == "application/json" else None
        result["owner_token_mode"] = (type(discovery) is dict and discovery.get("authenticated") is False and
            discovery == {"mode": "bearer", "authenticated": False, "authentication": "owner_token"})
        if not result["owner_token_mode"]:
            return result
        for phase, authorization in (("anonymous_api", None), ("wrong_token_api", WRONG_AUTHORIZATION)):
            result["phase"] = phase
            code, media, _, _ = _fetch(opener, origin + "/v1/capabilities", MAX_JSON,
                min(REQUEST_TIMEOUT, deadline - clock()), authorization=authorization)
            result[phase + "_status"] = code
            result[phase + "_denied"] = code == 401 and media == "application/json"
            if not result[phase + "_denied"]:
                return result
        if clock() >= deadline:
            raise TimeoutError
        result.update(status="success", phase="complete")
    except TimeoutError:
        result["status"] = "timeout"
    except Exception:
        pass
    return result


def _capture(command, environment, *, timeout=TOTAL_TIMEOUT, limit=MAX_OUTPUT):
    process = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, env=environment, cwd="/")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return "timeout", b""
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    return ("completed", bytes(output)) if code in {0, 2} else ("failed", b"")
                output.extend(chunk)
                if len(output) > limit:
                    return "output_limit", b""
    except subprocess.TimeoutExpired:
        return "timeout", b""
    except Exception:
        return "failed", b""
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


def probe(environ=None, *, runner=None):
    environ = os.environ if environ is None else environ
    config = _configuration(environ)
    if config is None:
        return _report("not_configured")
    runner = _capture if runner is None else runner
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                   "QUANTA_PUBLIC_ORIGIN": config[0], "QUANTA_AUTH_MODE": "owner-token", "QUANTA_OCI_HOST": config[2]}
    try:
        status, raw = runner([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"], environment)
        if status != "completed":
            return _report(status if status in {"timeout", "output_limit"} else "failed", "worker")
        return sanitize_report(raw) or _report("invalid_output", "worker")
    except Exception:
        return _report("failed", "worker")


def main(argv=None, environ=None):
    arguments = sys.argv[1:] if argv is None else argv
    environ = os.environ if environ is None else environ
    try:
        if arguments == ["--worker"]:
            config = _configuration(environ)
            result = _run_probe(config) if config is not None else _report("not_configured")
        elif not arguments:
            result = probe(environ)
        else:
            result = _report("not_configured")
    except Exception:
        result = _report("failed", "worker")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
