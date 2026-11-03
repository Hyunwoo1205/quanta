#!/usr/bin/env python3
"""Check the installed locked profile and emit observed environment data."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
import hashlib
import json
from pathlib import Path
import platform
import sys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "requirements.lock.json").read_text(encoding="utf-8"))
    errors = []
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.14":
        errors.append("CPython 3.12.14 is required")
    if sys.platform != "linux" or platform.machine() != "x86_64":
        errors.append("The locked profile requires Linux x86_64")
    digest = hashlib.sha256((root / "requirements.lock.txt").read_bytes()).hexdigest()
    if digest != lock["requirements_lock_sha256"]:
        errors.append("requirements.lock.txt differs from the lock manifest")
    direct_digest = hashlib.sha256((root / "requirements.in").read_bytes()).hexdigest()
    if direct_digest != lock["direct_requirements_sha256"]:
        errors.append("requirements.in changed after the lock was generated")
    for package in lock["packages"]:
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
    print(json.dumps({"locked_profile_matches": not errors, "errors": errors, "observations": observed}, indent=2, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
