#!/usr/bin/env python3
"""Explicit, pinned-host PPK login check with the sole remote command ``true``.

This helper never converts a key, scans host keys, or installs anything remotely.
It requires an unencrypted PPK and explicit opt-in. The client output is discarded
so neither credentials nor server-controlled text can appear in public logs.
Normal completion and subprocess timeouts remove the temporary key. Cleanup on
host termination or SIGKILL is best effort and relies on the ephemeral runner.
SSH authentication can create server-side audit records; this is not a claim of
zero server filesystem writes or proof that the key has limited privileges.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


PLINK = "/usr/bin/plink"
TIMEOUT = 15
MAX_KEY_BYTES = 32768
_HEADER = re.compile(r"PuTTY-User-Key-File-([23]): [A-Za-z0-9@._+-]{1,128}\Z")
_PIN = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_CONFIGURATION_ISSUES = frozenset({
    "host_missing", "host_invalid", "host_key_missing", "host_key_invalid",
    "private_key_missing", "private_key_format_invalid",
})


def _report(status: str, attempted: bool = False, configuration_issues=None) -> dict:
    report = {"scope": "ssh_login_true", "status": status,
              "authentication_attempted": attempted}
    if attempted:
        report["requested_command"] = "true"
    if configuration_issues is not None:
        if (status != "not_configured" or attempted
                or any(issue not in _CONFIGURATION_ISSUES for issue in configuration_issues)):
            raise ValueError("invalid configuration diagnostic")
        report["configuration_issues"] = list(configuration_issues)
    return report


def _global_ipv4(host: str | None) -> bool:
    if not isinstance(host, str) or not 1 <= len(host) <= 15:
        return False
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return False
    return (str(address) == host and address.is_global
            and not address.is_multicast and not address.is_reserved)


def _host_key(pin: str | None) -> bool:
    if not isinstance(pin, str) or not _PIN.fullmatch(pin):
        return False
    try:
        digest = base64.b64decode(pin[7:] + "=", validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(digest) == 32 and base64.b64encode(digest).decode().rstrip("=") == pin[7:]


def _base64_section(lines: list[str], index: int, name: str) -> int | None:
    if index >= len(lines):
        return None
    match = re.fullmatch(re.escape(name) + r": ([1-9][0-9]{0,3})", lines[index])
    if not match:
        return None
    count = int(match[1])
    start, end = index + 1, index + 1 + count
    if end >= len(lines) or any(not re.fullmatch(r"[A-Za-z0-9+/=]{1,64}", line)
                                for line in lines[start:end]):
        return None
    encoded = "".join(lines[start:end])
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not decoded or base64.b64encode(decoded).decode() != encoded:
        return None
    return end


def _key_bytes(ppk: str | None) -> tuple[str | None, bytes | None]:
    """Check bounded PPK structure, leaving cryptographic validation to Plink."""
    if not isinstance(ppk, str) or not 1 <= len(ppk) <= MAX_KEY_BYTES:
        return "not_configured", None
    try:
        raw = ppk.encode("utf-8")
    except UnicodeEncodeError:
        return "not_configured", None
    if len(raw) > MAX_KEY_BYTES or "\x00" in ppk:
        return "not_configured", None
    normalized = ppk.replace("\r\n", "\n")
    if "\r" in normalized:
        return "not_configured", None
    lines = normalized.rstrip("\n").split("\n")
    if len(lines) < 2 or not (header := _HEADER.fullmatch(lines[0])):
        return "not_configured", None
    if lines[1].startswith("Encryption: ") and lines[1] != "Encryption: none":
        return "encrypted_key", None
    if (lines[1] != "Encryption: none" or len(lines) < 3
            or not lines[2].startswith("Comment: ")):
        return "not_configured", None
    index = _base64_section(lines, 3, "Public-Lines")
    if index is None:
        return "not_configured", None
    index = _base64_section(lines, index, "Private-Lines")
    mac_length = 40 if header[1] == "2" else 64
    if (index is None or index != len(lines) - 1
            or not re.fullmatch(r"Private-MAC: [0-9a-fA-F]{" + str(mac_length) + r"}", lines[index])):
        return "not_configured", None
    return None, raw


def probe(environ=None, *, runner=None) -> dict:
    """Launch at most one fixed Plink login check after all local guards pass."""
    environ = os.environ if environ is None else environ
    if environ.get("QUANTA_OCI_AUTH_CONFIRMED") != "true":
        return _report("not_configured")
    host, pin = environ.get("QUANTA_OCI_HOST"), environ.get("QUANTA_OCI_HOST_KEY")
    issues = []
    if not _global_ipv4(host):
        issues.append("host_missing" if host is None or host == "" else "host_invalid")
    if not _host_key(pin):
        issues.append("host_key_missing" if pin is None or pin == "" else "host_key_invalid")
    ppk = environ.get("QUANTA_OCI_PPK")
    error, raw_key = _key_bytes(ppk)
    if error == "not_configured":
        issues.append("private_key_missing" if ppk is None or ppk == ""
                      else "private_key_format_invalid")
    if issues:
        return _report("not_configured", configuration_issues=issues)
    if error:
        return _report(error)
    runner = subprocess.run if runner is None else runner
    attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix="quanta-ssh-") as directory:
            os.chmod(directory, 0o700)
            key_path = Path(directory) / "identity.ppk"
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(raw_key)
            command = [PLINK, "-ssh", "-2", "-4", "-batch", "-noagent",
                       "-no-trivial-auth", "-a", "-x", "-T", "-noshare",
                       "-P", "22", "-l", "ubuntu", "-i", str(key_path),
                       "-hostkey", pin, host, "true"]
            child_environment = {"HOME": directory, "PATH": "/usr/bin:/bin",
                                 "LANG": "C.UTF-8"}
            attempted = True
            try:
                result = runner(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=TIMEOUT, check=False, shell=False,
                                env=child_environment, cwd=directory)
            except OSError:
                # Failure to start the client is not an authentication attempt.
                attempted = False
                raise
            status = "success" if result.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        return _report("timeout", attempted)
    except Exception:
        # Never disclose the endpoint, key, path, pin, or client error text.
        return _report("failed", attempted)
    return _report(status, attempted)


def main() -> int:
    try:
        report = probe()
    except Exception:
        report = _report("failed")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
