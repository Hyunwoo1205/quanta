#!/usr/bin/env python3
"""One bounded, unauthenticated TCP/SSH-banner check for an explicit OCI host.

The CLI reads only QUANTA_OCI_HOST. It never sends data, reads an SSH key,
authenticates, verifies a host key, or runs a remote command. An SSH banner is
transport evidence only; it does not establish the server's identity or access.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time


PORT = 22
CONNECT_TIMEOUT = 8
BANNER_TIMEOUT = 5
MAX_BANNER_BYTES = 1024
_IDENTIFICATION = re.compile(rb"SSH-(?:2\.0|1\.99)-[!-~]+(?: [ -~]*)?\r?\n\Z")


def _report(status: str) -> dict:
    """Keep endpoint, server text, and exception details out of public logs."""
    return {"scope": "tcp_ssh_banner", "status": status,
            "authentication_attempted": False, "server_modified": False}


def _global_ipv4(host: str | None) -> bool:
    if not isinstance(host, str) or not 1 <= len(host) <= 15:
        return False
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return False
    return (str(address) == host and address.is_global
            and not address.is_multicast and not address.is_reserved)


def _banner_status(stream, clock) -> str:
    deadline = clock() + BANNER_TIMEOUT
    received = 0
    pending = b""
    while received < MAX_BANNER_BYTES:
        remaining = deadline - clock()
        if remaining <= 0:
            return "unreachable"
        stream.settimeout(remaining)
        amount = min(256, MAX_BANNER_BYTES - received)
        chunk = stream.recv(amount)
        if clock() >= deadline:
            return "unreachable"
        if not chunk:
            return "not_ssh"
        if len(chunk) > amount:
            return "not_ssh"
        received += len(chunk)
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            if line.startswith(b"SSH-"):
                line += b"\n"
                # RFC identification lines are at most 255 bytes, including
                # the line ending. Earlier informational lines share the cap.
                return ("reachable" if len(line) <= 255
                        and _IDENTIFICATION.fullmatch(line) else "not_ssh")
    return "not_ssh"


def probe(host: str | None, *, connector=None, clock=None) -> dict:
    """Validate one global IPv4, connect once to port 22, and read at most 1 KiB.

    Dependency seams let tests redirect the validated address to a local fixture;
    there is no CLI option to bypass address validation or change the port.
    """
    if not _global_ipv4(host):
        return _report("no_config")
    connector = socket.create_connection if connector is None else connector
    clock = time.monotonic if clock is None else clock
    try:
        with connector((host, PORT), timeout=CONNECT_TIMEOUT) as stream:
            status = _banner_status(stream, clock)
    except OSError:
        status = "unreachable"
    return _report(status)


def main() -> int:
    try:
        report = probe(os.environ.get("QUANTA_OCI_HOST"))
    except Exception:
        # Even an unexpected local failure must not publish exception text that
        # could contain the configured endpoint. This is not an SSH diagnosis.
        report = _report("unreachable")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "reachable" else 2


if __name__ == "__main__":
    raise SystemExit(main())
