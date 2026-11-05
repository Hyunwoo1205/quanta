#!/usr/bin/env python3
"""Authorize a fixed login check before any SSH credential is supplied.

The CLI reads only event/ref/manual-confirmation metadata and the fixed public
request file. It neither reads credentials nor starts a client or remote command.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import uuid


REQUEST_PATH = Path(".github/oci/login-request.json")
MAX_REQUEST_BYTES = 1024


def _report(authorized: bool, request_id: str | None = None) -> dict:
    report = {"scope": "login_request", "status": "authorized" if authorized else "denied",
              "operation": "login-check"}
    if authorized and request_id is not None:
        report["request_id"] = request_id
    return report


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request key")
        result[key] = value
    return result


def _request_id(path: Path) -> str | None:
    try:
        if path.is_symlink():
            return None
        with path.open("rb") as request_file:
            raw = request_file.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            return None
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (not isinstance(request, dict)
                or set(request) != {"schema_version", "operation", "request_id"}
                or type(request["schema_version"]) is not int
                or request["schema_version"] != 1
                or request["operation"] != "login-check"):
            return None
        identifier = request["request_id"]
        if (not isinstance(identifier, str) or len(identifier) != 36
                or str(uuid.UUID(identifier)) != identifier):
            return None
        return identifier
    except (OSError, ValueError, TypeError, UnicodeError):
        return None


def authorize(environ=None, *, request_path=None) -> dict:
    """Check exact event/ref guards; the path override is a local test seam."""
    environ = os.environ if environ is None else environ
    event, ref = environ.get("QUANTA_OCI_EVENT"), environ.get("QUANTA_OCI_REF")
    if event == "workflow_dispatch" and ref == "refs/heads/main":
        return _report(environ.get("QUANTA_OCI_MANUAL_CONFIRM") == "true")
    if event == "push" and ref == "refs/heads/ops/oci":
        path = REQUEST_PATH if request_path is None else Path(request_path)
        identifier = _request_id(path)
        return _report(identifier is not None, identifier)
    return _report(False)


def main() -> int:
    try:
        report = authorize()
    except Exception:
        report = _report(False)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "authorized" else 2


if __name__ == "__main__":
    raise SystemExit(main())
