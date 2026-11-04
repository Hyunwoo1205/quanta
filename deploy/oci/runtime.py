#!/usr/bin/python3
"""Host-only mount gate and fixed Docker invocation for one OCI installation.

Install this file root-owned at /usr/local/lib/quanta/runtime.py. No operation
formats, mounts, creates data directories, rotates backups, or changes ownership.
The host's systemd manager alone owns restart policy.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

CONFIG = Path("/etc/quanta/deployment.json")
APP_ENV = Path("/etc/quanta/app.env")
MOUNT = Path("/srv/quanta")
UID = GID = 10001
DOCKER = "/usr/bin/docker"
FINDMNT = "/usr/bin/findmnt"
IMAGE_PATTERN = re.compile(r"(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}\Z")


class DeploymentError(ValueError):
    pass


def _no_symlinks(path: Path) -> None:
    if not path.is_absolute():
        raise DeploymentError("Deployment paths must be absolute")
    for item in (path, *path.parents):
        if item.is_symlink():
            raise DeploymentError("Deployment paths must not contain symlinks")


def _root_file(path: Path, *, private=False) -> bytes:
    _no_symlinks(path)
    info = path.stat()
    parent = path.parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or parent.st_uid != 0 or parent.st_mode & 0o022):
        raise DeploymentError("Deployment configuration must be root-owned and not writable by others")
    if private and info.st_mode & 0o077:
        raise DeploymentError("Application environment must have private permissions")
    with path.open("rb") as stream:
        value = stream.read(8193)
    if len(value) > 8192:
        raise DeploymentError("Deployment configuration exceeds its size limit")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentError("Duplicate deployment configuration key")
        result[key] = value
    return result


def load_config(path: Path = CONFIG) -> dict:
    try:
        config = json.loads(_root_file(path), object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DeploymentError("Deployment configuration must be UTF-8 JSON") from exc
    if not isinstance(config, dict) or set(config) != {"filesystem_uuid", "image"}:
        raise DeploymentError("Deployment configuration requires exactly filesystem_uuid and image")
    filesystem_uuid, image = config["filesystem_uuid"], config["image"]
    if not isinstance(filesystem_uuid, str) or not isinstance(image, str):
        raise DeploymentError("Deployment configuration values must be strings")
    try:
        if str(uuid.UUID(filesystem_uuid)) != filesystem_uuid.lower():
            raise ValueError
    except ValueError as exc:
        raise DeploymentError("A canonical filesystem UUID is required") from exc
    if not IMAGE_PATTERN.fullmatch(image):
        raise DeploymentError("An immutable local image ID or repository digest is required")
    return {"filesystem_uuid": filesystem_uuid.lower(), "image": image}


def check_mount(expected_uuid: str, mount: Path = MOUNT, *, runner=subprocess.run) -> None:
    _no_symlinks(mount)
    info = mount.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise DeploymentError("The data mount root must be a root-owned directory not writable by others")
    if info.st_dev == Path("/").stat().st_dev:
        raise DeploymentError("The data mount must be on a filesystem separate from the boot root")
    result = runner([FINDMNT, "--json", "--mountpoint", str(mount), "--output",
                     "TARGET,UUID,FSTYPE,OPTIONS,FSROOT"], check=False,
                    capture_output=True, text=True, timeout=10)
    try:
        filesystems = json.loads(result.stdout).get("filesystems")
        if result.returncode != 0 or not isinstance(filesystems, list) or len(filesystems) != 1:
            raise ValueError
        filesystem = filesystems[0]
        if (filesystem.get("target") != str(mount)
                or str(filesystem.get("uuid", "")).lower() != expected_uuid
                or filesystem.get("fstype") not in {"ext4", "xfs"}
                or filesystem.get("fsroot") != "/"
                or "rw" not in str(filesystem.get("options", "")).split(",")
                or "ro" in str(filesystem.get("options", "")).split(",")):
            raise ValueError
    except (ValueError, AttributeError, TypeError) as exc:
        raise DeploymentError("The required writable data filesystem is not mounted with the configured UUID") from exc


def check_directory(directory: Path, *, expected_device=None) -> None:
    _no_symlinks(directory)
    info = directory.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != UID or info.st_gid != GID
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise DeploymentError("Data and backup directories must be private 0700 and owned by 10001:10001")
    if expected_device is not None and info.st_dev != expected_device:
        raise DeploymentError("Service directories must remain on the verified data filesystem")


def check_installation(*, config_path=CONFIG, app_env=APP_ENV, mount=MOUNT,
                       runner=subprocess.run, application=True) -> dict:
    config = load_config(config_path)
    check_mount(config["filesystem_uuid"], mount, runner=runner)
    device = mount.stat().st_dev
    check_directory(mount / "data", expected_device=device)
    check_directory(mount / "backups", expected_device=device)
    # SQLite and the worker use these fixed filenames. Never follow a symlink
    # when Docker later starts a privileged host-managed installation.
    for name in ("jobs.sqlite3", "jobs.sqlite3-wal", "jobs.sqlite3-shm", "worker.lock"):
        item = mount / "data" / name
        _no_symlinks(item)
        if item.exists():
            info = item.stat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != UID or info.st_gid != GID
                    or info.st_mode & 0o077 or info.st_dev != device):
                raise DeploymentError("Existing service files must remain private and owned by 10001:10001")
    if application:
        _root_file(app_env, private=True)
    return config


def docker_command(config: dict, *, backup=False, output_name=None) -> list[str]:
    name = "quanta-backup" if backup else "quanta"
    command = [DOCKER, "run", "--rm", "--pull=never", "--name", name,
               "--restart=no", "--network", "none" if backup else "host",
               "--user", "10001:10001", "--read-only",
               "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
               "--cpus", "2", "--memory", "2g", "--memory-swap", "2g",
               "--pids-limit", "128", "--stop-timeout", "40",
               "--log-driver", "local", "--log-opt", "max-size=10m",
               "--log-opt", "max-file=3", "--workdir", "/tmp",
               "--mount", f"type=bind,source={MOUNT}/data,target={MOUNT}/data"]
    if backup:
        if not output_name or not re.fullmatch(r"[0-9TZ-]+-[0-9a-f]{32}", output_name):
            raise DeploymentError("A fresh backup directory name is required")
        command += ["--mount", f"type=bind,source={MOUNT}/backups,target={MOUNT}/backups"]
        application = ["backup-store", "--store", str(MOUNT / "data"),
                       "--output", str(MOUNT / "backups" / output_name)]
    else:
        command += ["--env-file", str(APP_ENV)]
        application = ["serve-production", "--store", str(MOUNT / "data"), "--port", "8765"]
    return command + [config["image"], "python", "-m", "quanta", *application]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "backup"))
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise DeploymentError("This host wrapper must run as root; the application runs as 10001:10001")
        config = check_installation(application=args.command != "backup")
        if args.command == "check":
            print("Quanta storage and configuration checks passed; no files were created")
            return 0
        backup = args.command == "backup"
        output_name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex if backup else None
        os.execv(DOCKER, docker_command(config, backup=backup, output_name=output_name))
    except (OSError, ValueError, subprocess.SubprocessError):
        # Do not print configuration contents, identities, or Docker arguments.
        print("Quanta deployment refused: verify the configured filesystem, private directories and root-owned configuration", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
