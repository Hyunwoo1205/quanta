#!/usr/bin/env python3
"""Check the installed locked profile and emit observed environment data."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
import hashlib
import json
from pathlib import Path
import platform
import sys

from quanta.profiles import load_lock_files, profile_for_host


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = []
    profile = None
    lock_sha = None
    lock = None
    try:
        profile = profile_for_host()
        files = load_lock_files((root,))
        lock = json.loads(files["requirements.lock.json"])
        lock_sha = hashlib.sha256(files["requirements.lock.txt"]).hexdigest()
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append(str(exc))
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.14":
        errors.append("CPython 3.12.14 is required")
    for package in lock["packages"] if lock else []:
        try:
            installed = version(package["name"])
        except PackageNotFoundError:
            errors.append(f"Missing distribution: {package['name']}")
            continue
        if installed != package["version"]:
            errors.append(f"Version mismatch: {package['name']} expected {package['version']} got {installed}")
    from quanta.environment import environment_report
    observed = environment_report()
    if not observed.get("valid", False):
        errors.append("Observed runtime does not match the one-thread baseline")
    print(json.dumps({"locked_profile_matches": not errors, "profile": profile,
                      "requirements_lock_sha256": lock_sha, "errors": errors,
                      "observations": observed}, indent=2, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
