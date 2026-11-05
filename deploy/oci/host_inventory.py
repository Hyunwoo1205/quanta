#!/usr/bin/env python3
"""Fixed, read-only inventory with a small public-safe JSON output contract.

No identifiers, credentials, process lists, network addresses or configuration
contents are collected. SSH/PAM and systemd queries may leave normal audit logs.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess


MAX_OUTPUT_BYTES = 8192
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
UNITS = ("quanta.service", "quanta-boot.service", "quanta-backup.timer",
         "quanta-backup-boot.timer")
OS_IDS = frozenset({"ubuntu", "debian", "ol", "rhel", "centos", "fedora", "alpine", "other"})
ARCHITECTURES = frozenset({"aarch64", "x86_64", "armv7l", "other"})
VERSION = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,2}\Z")
BOOLEAN_FIELDS = (
    "docker_cli_present", "git_present", "systemctl_present", "venv_module_present",
    "ensurepip_module_present", "srv_quanta_exists", "srv_quanta_is_directory",
    "srv_quanta_is_symlink", "srv_quanta_root_owned", "srv_quanta_group_other_writable",
    "srv_quanta_same_device_as_root",
)
NUMBER_FIELDS = ("memory_total_gib", "root_filesystem_total_gib", "root_filesystem_free_gib")
FIELDS = frozenset(("scope", "status", "os_id", "os_version", "architecture",
                    "logical_cpus", "quanta_units_active", *BOOLEAN_FIELDS, *NUMBER_FIELDS))


def _safe(function):
    try:
        return function()
    except Exception:
        return None


def _available(name):
    return _safe(lambda: shutil.which(name, path=BINPATH) is not None)


def _unit_active(unit):
    tool = _safe(lambda: shutil.which("systemctl", path=BINPATH))
    if tool is None:
        return None
    result = _safe(lambda: subprocess.run(
        [tool, "is-active", "--quiet", unit], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": BINPATH, "LC_ALL": "C"}, cwd="/", timeout=2, check=False,
    ))
    return result.returncode == 0 if result is not None else None


def _memory_gib():
    with open("/proc/meminfo", encoding="ascii") as memory_file:
        text = memory_file.read(65536)
    match = re.search(r"^MemTotal:\s+([0-9]+)\s+kB$", text, re.M)
    return round(int(match[1]) / 1048576, 2) if match else None


def _path_facts():
    try:
        info = os.lstat("/srv/quanta")
    except FileNotFoundError:
        info, exists = None, False
    except OSError:
        info, exists = None, None
    else:
        exists = True
    directory = stat.S_ISDIR(info.st_mode) if info else None
    root = _safe(lambda: os.stat("/"))
    return {
        "srv_quanta_exists": exists,
        "srv_quanta_is_directory": directory,
        "srv_quanta_is_symlink": stat.S_ISLNK(info.st_mode) if info else None,
        "srv_quanta_root_owned": info.st_uid == 0 if info else None,
        "srv_quanta_group_other_writable": bool(info.st_mode & 0o022) if info else None,
        "srv_quanta_same_device_as_root": info.st_dev == root.st_dev if directory and root else None,
    }


def collect() -> dict:
    """Inspect only fixed sources; no sudo, installation or configuration writes."""
    release = _safe(platform.freedesktop_os_release) or {}
    os_id, version = release.get("ID", ""), release.get("VERSION_ID", "")
    architecture = platform.machine()
    disk = _safe(lambda: shutil.disk_usage("/"))
    result = {
        "scope": "host_inventory", "status": "success",
        "os_id": os_id if os_id in OS_IDS else "other",
        "os_version": version if isinstance(version, str) and VERSION.fullmatch(version) else "unknown",
        "architecture": architecture if architecture in ARCHITECTURES else "other",
        "logical_cpus": os.cpu_count(), "memory_total_gib": _safe(_memory_gib),
        "root_filesystem_total_gib": round(disk.total / 2**30, 2) if disk else None,
        "root_filesystem_free_gib": round(disk.free / 2**30, 2) if disk else None,
        "docker_cli_present": _available("docker"), "git_present": _available("git"),
        "systemctl_present": _available("systemctl"),
        "venv_module_present": _safe(lambda: importlib.util.find_spec("venv") is not None),
        "ensurepip_module_present": _safe(lambda: importlib.util.find_spec("ensurepip") is not None),
        "quanta_units_active": {unit: _unit_active(unit) for unit in UNITS},
    }
    result.update(_path_facts())
    return result


def _boolean(value):
    return value is None or type(value) is bool


def _number(value, maximum):
    return (value is None or (type(value) in (int, float)
            and math.isfinite(value) and 0 <= value <= maximum))


def validate_report(value) -> dict:
    """Reject unknown fields and all unbounded/server-controlled strings."""
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("invalid inventory report")
    if (value["scope"] != "host_inventory" or value["status"] != "success"
            or not isinstance(value["os_id"], str) or value["os_id"] not in OS_IDS
            or not isinstance(value["architecture"], str) or value["architecture"] not in ARCHITECTURES
            or not isinstance(value["os_version"], str)
            or not (value["os_version"] == "unknown" or VERSION.fullmatch(value["os_version"]))):
        raise ValueError("invalid inventory report")
    cpu = value["logical_cpus"]
    if cpu is not None and not (type(cpu) is int and 1 <= cpu <= 4096):
        raise ValueError("invalid inventory report")
    if any(not _boolean(value[field]) for field in BOOLEAN_FIELDS):
        raise ValueError("invalid inventory report")
    if not _number(value["memory_total_gib"], 65536):
        raise ValueError("invalid inventory report")
    if any(not _number(value[field], 1048576) for field in NUMBER_FIELDS[1:]):
        raise ValueError("invalid inventory report")
    total, free = (value[field] for field in NUMBER_FIELDS[1:])
    if total is not None and free is not None and free > total:
        raise ValueError("invalid inventory report")
    units = value["quanta_units_active"]
    if not isinstance(units, dict) or set(units) != set(UNITS) or any(not _boolean(v) for v in units.values()):
        raise ValueError("invalid inventory report")
    return {**value, "quanta_units_active": dict(units)}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid inventory report")
        result[key] = value
    return result


def parse_output(raw: bytes) -> dict:
    """Validate a bounded UTF-8 response before publishing any remote data."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
        raise ValueError("invalid inventory report")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid inventory report")))
        return validate_report(value)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ValueError("invalid inventory report") from None


def sanitize_report(raw: bytes) -> dict | None:
    """Return only a validated report; never return raw or partial remote data."""
    try:
        return parse_output(raw)
    except ValueError:
        return None


def main() -> int:
    try:
        result = validate_report(collect())
    except Exception:
        print('{"scope":"host_inventory","status":"failed"}')
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
