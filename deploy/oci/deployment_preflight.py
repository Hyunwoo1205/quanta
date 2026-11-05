#!/usr/bin/env python3
"""Fixed read-only initial-deployment checks with a boolean-only public contract.

Availability is a conservative socket-table snapshot, not a reservation. Existing
or unverifiable paths are conflicts; nothing is created, stopped or changed.
Local subprocess stderr and identifiers never enter the public report. Normal
SSH/PAM/sudo audit records may still be written by the host.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import PurePosixPath
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid


BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT_BYTES = 4096
MAX_TCP_BYTES = 1048576
MAX_TCP_ROWS = 8192
UNITS = ("quanta.service", "quanta-boot.service", "quanta-backup.service",
         "quanta-backup-boot.service", "quanta-backup.timer", "quanta-backup-boot.timer")
UNIT_DIRECTORIES = (
    "/etc/systemd/system.control", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system", "/run/systemd/generator.late",
)
PORT_FIELDS = ("tcp_80_available", "tcp_443_available", "loopback_8765_available")
DOCKER_FIELDS = ("docker_quanta_name_absent", "docker_quanta_backup_name_absent")
PATH_FIELDS = ("srv_quanta_absent", "etc_quanta_absent", "quanta_unit_paths_absent")
CONFLICT_FIELDS = ("srv_quanta_conflicting", "etc_quanta_conflicting",
                   "quanta_unit_paths_conflicting")
ROOT_FIELDS = ("root_filesystem_type_supported", "root_filesystem_uuid_available",
               "root_filesystem_writable", "root_filesystem_is_root")
READY_FIELDS = ("tcp_tables_inspected", "sudo_noninteractive", "docker_names_inspected",
                "paths_inspected", "root_filesystem_inspected", *PORT_FIELDS,
                *DOCKER_FIELDS, *PATH_FIELDS, *ROOT_FIELDS)
BOOLEAN_FIELDS = (*READY_FIELDS, *CONFLICT_FIELDS, "ready_for_initial_deployment")
FIELDS = frozenset(("scope", "status", *BOOLEAN_FIELDS))


def _bounded_output(command, *, timeout=3, limit=2048):
    """Capture one small fixed local request under a deadline, discarding stderr."""
    process = None
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False,
            env={"PATH": BINPATH, "LC_ALL": "C"}, cwd="/",
        )
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return None
                chunk = os.read(process.stdout.fileno(), min(256, limit + 1 - len(data)))
                if not chunk:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or process.wait(timeout=remaining) != 0:
                        return None
                    return bytes(data)
                data.extend(chunk)
                if len(data) > limit:
                    return None
    except Exception:
        return None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=1)
            except Exception:
                pass
            if process.stdout is not None:
                process.stdout.close()


def _sudo_ready():
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "true"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": BINPATH, "LC_ALL": "C"}, cwd="/", timeout=2, check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _tcp_rows(path, *, ipv6):
    with open(path, "rb") as stream:
        raw = stream.read(MAX_TCP_BYTES + 1)
    if len(raw) > MAX_TCP_BYTES or not raw.endswith(b"\n"):
        raise ValueError("unavailable socket table")
    rows = raw.splitlines()
    remote_header = b"remote_address" if ipv6 else b"rem_address"
    if (not rows or len(rows) > MAX_TCP_ROWS + 1
            or rows[0].split()[:4] != [b"sl", b"local_address", remote_header, b"st"]):
        raise ValueError("unavailable socket table")
    width = 32 if ipv6 else 8
    endpoint = re.compile(rb"([0-9A-Fa-f]{" + str(width).encode() + rb"}):([0-9A-Fa-f]{4})\Z")
    for row in rows[1:]:
        fields = row.split()
        if (not 10 <= len(fields) <= 32 or not re.fullmatch(rb"[0-9]{1,10}:", fields[0])
                or not re.fullmatch(rb"[0-9A-Fa-f]{2}", fields[3])):
            raise ValueError("unavailable socket table")
        local = endpoint.fullmatch(fields[1])
        if local is None or endpoint.fullmatch(fields[2]) is None:
            raise ValueError("unavailable socket table")
        address = local[1]
        # Linux prints each native-endian 32-bit address word as hexadecimal.
        packed = b"".join(int(address[index:index + 8], 16).to_bytes(4, sys.byteorder)
                          for index in range(0, width, 8))
        ip = ipaddress.ip_address(packed)
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        blocks_loopback = (ip.is_unspecified or ip.is_loopback
                           or bool(mapped and (mapped.is_loopback or mapped.is_unspecified)))
        yield int(local[2], 16), blocks_loopback


def _port_facts():
    result = {"tcp_tables_inspected": False, **dict.fromkeys(PORT_FIELDS, False)}
    try:
        rows = [*_tcp_rows("/proc/net/tcp", ipv6=False),
                *_tcp_rows("/proc/net/tcp6", ipv6=True)]
    except Exception:
        return result
    result.update(tcp_tables_inspected=True,
                  tcp_80_available=not any(port == 80 for port, _ in rows),
                  tcp_443_available=not any(port == 443 for port, _ in rows),
                  loopback_8765_available=not any(port == 8765 and local for port, local in rows))
    return result


def _docker_facts(sudo_ready):
    result = {"docker_names_inspected": False, **dict.fromkeys(DOCKER_FIELDS, False)}
    try:
        docker = shutil.which("docker", path=BINPATH)
    except Exception:
        return result
    if docker is None:
        return result
    command = (["/usr/bin/sudo", "-n"] if sudo_ready else []) + [
        docker, "--host", "unix:///var/run/docker.sock", "container", "ls", "--all",
        "--filter", "name=^/(quanta|quanta-backup)$", "--format", "{{.Names}}",
    ]
    raw = _bounded_output(command, limit=128)
    if raw is None or raw not in {b"", b"quanta\n", b"quanta-backup\n",
                                b"quanta\nquanta-backup\n", b"quanta-backup\nquanta\n"}:
        return result
    names = raw.splitlines()
    result.update(docker_names_inspected=True, docker_quanta_name_absent=b"quanta" not in names,
                  docker_quanta_backup_name_absent=b"quanta-backup" not in names)
    return result


def _path_absent(path):
    """Return (absent, inspected), never following a final-component symlink."""
    current = PurePosixPath(path)
    try:
        for parent in reversed(current.parents):
            try:
                info = os.lstat(str(parent))
            except FileNotFoundError:
                return True, True
            if parent == PurePosixPath("/lib") and stat.S_ISLNK(info.st_mode):
                # Ubuntu's root-owned merged-/usr alias is an expected unit path.
                if info.st_uid != 0 or os.readlink("/lib") not in {"usr/lib", "/usr/lib"}:
                    return False, False
                alias = os.lstat("/usr/lib")
                if not stat.S_ISDIR(alias.st_mode) or alias.st_uid != 0 or alias.st_mode & 0o022:
                    return False, False
                continue
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False, False
        os.lstat(path)
    except FileNotFoundError:
        return True, True
    except Exception:
        return False, False
    return False, True


def _path_facts():
    result = {"paths_inspected": False, **dict.fromkeys(PATH_FIELDS, False),
              **dict.fromkeys(CONFLICT_FIELDS, True)}
    srv, srv_ok = _path_absent("/srv/quanta")
    etc, etc_ok = _path_absent("/etc/quanta")
    unit_results = [_path_absent(directory + "/" + unit + suffix)
                    for directory in UNIT_DIRECTORIES for unit in UNITS for suffix in ("", ".d")]
    if not srv_ok or not etc_ok or not all(inspected for _, inspected in unit_results):
        return result
    absent = (srv, etc, all(value for value, _ in unit_results))
    result.update(paths_inspected=True)
    result.update(zip(PATH_FIELDS, absent))
    result.update(zip(CONFLICT_FIELDS, (not value for value in absent)))
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid preflight report")
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid preflight report")))


def _root_facts():
    result = {"root_filesystem_inspected": False, **dict.fromkeys(ROOT_FIELDS, False)}
    raw = _bounded_output(["/usr/bin/findmnt", "--json", "--target", "/", "--output",
                           "TARGET,UUID,FSTYPE,OPTIONS,FSROOT"])
    if raw is None:
        return result
    try:
        value = _json(raw)
        if not isinstance(value, dict) or set(value) != {"filesystems"}:
            return result
        filesystems = value["filesystems"]
        if not isinstance(filesystems, list) or len(filesystems) != 1:
            return result
        filesystem = filesystems[0]
        if (not isinstance(filesystem, dict)
                or set(filesystem) != {"target", "uuid", "fstype", "options", "fsroot"}
                or any(not isinstance(filesystem[key], str) for key in ("target", "fstype", "options", "fsroot"))
                or filesystem["uuid"] is not None and not isinstance(filesystem["uuid"], str)):
            return result
        filesystem_uuid = filesystem["uuid"]
        try:
            uuid_available = (isinstance(filesystem_uuid, str)
                              and str(uuid.UUID(filesystem_uuid)) == filesystem_uuid.lower())
        except ValueError:
            uuid_available = False
        options = filesystem["options"].split(",")
        result.update(root_filesystem_inspected=True,
                      root_filesystem_type_supported=filesystem["fstype"] in {"ext4", "xfs"},
                      root_filesystem_uuid_available=uuid_available,
                      root_filesystem_writable="rw" in options and "ro" not in options,
                      root_filesystem_is_root=filesystem["target"] == "/" and filesystem["fsroot"] == "/")
    except Exception:
        pass
    return result


def collect() -> dict:
    """Inspect only fixed ports, names, paths and root-filesystem metadata."""
    sudo = _sudo_ready()
    result = {"scope": "deployment_preflight", "status": "success", "sudo_noninteractive": sudo}
    result.update(_port_facts())
    result.update(_docker_facts(sudo))
    result.update(_path_facts())
    result.update(_root_facts())
    result["ready_for_initial_deployment"] = all(result[field] for field in READY_FIELDS)
    return result


def validate_report(value) -> dict:
    """Permit the exact schema and booleans; reject raw or inconsistent facts."""
    if (not isinstance(value, dict) or set(value) != FIELDS
            or value["scope"] != "deployment_preflight" or value["status"] != "success"
            or any(type(value[field]) is not bool for field in BOOLEAN_FIELDS)):
        raise ValueError("invalid preflight report")
    for inspected, facts in (("tcp_tables_inspected", PORT_FIELDS),
                             ("docker_names_inspected", DOCKER_FIELDS),
                             ("paths_inspected", PATH_FIELDS),
                             ("root_filesystem_inspected", ROOT_FIELDS)):
        if not value[inspected] and any(value[field] for field in facts):
            raise ValueError("invalid preflight report")
    if (any(value[conflict] == value[absent] for conflict, absent in zip(CONFLICT_FIELDS, PATH_FIELDS))
            or value["ready_for_initial_deployment"] != all(value[field] for field in READY_FIELDS)):
        raise ValueError("invalid preflight report")
    return dict(value)


def parse_output(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
        raise ValueError("invalid preflight report")
    try:
        return validate_report(_json(raw))
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ValueError("invalid preflight report") from None


def sanitize_report(raw: bytes) -> dict | None:
    try:
        return parse_output(raw)
    except ValueError:
        return None


def main() -> int:
    try:
        result = validate_report(collect())
    except Exception:
        print('{"scope":"deployment_preflight","status":"failed"}')
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
