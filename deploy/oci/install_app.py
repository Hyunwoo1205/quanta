#!/usr/bin/env python3
"""One explicit initial OCI app installation; output only fixed status/stage.

This root-only installer refuses existing deployment paths, names and published
ports. It never prunes Docker objects, changes daemon settings, enables timers,
or stops unrelated containers. A failed initial installation can leave its own
partial files/image; later invocations refuse those conflicts rather than guess.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import selectors
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
import zlib


SOURCE_SHA = "1738107301ef873bfe5e01f930866c2a74e4ec3f"
ARCHIVE_URL = "https://codeload.github.com/Hyunwoo1205/quanta/tar.gz/" + SOURCE_SHA
ROOT = Path("/srv/quanta")
SOURCE = ROOT / "source" / SOURCE_SHA
ETC = Path("/etc/quanta")
LIB = Path("/usr/local/lib/quanta")
SYSTEMD = Path("/etc/systemd/system")
DOCKER = "/usr/bin/docker"
DOCKER_PREFIX = [DOCKER, "--host", "unix:///var/run/docker.sock"]
TAG = "quanta:" + SOURCE_SHA
SMOKE_NAME = "quanta-install-smoke"
LABEL = "org.quanta.install.source"
BINPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT_BYTES = 8192
MAX_DOWNLOAD = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MEMBERS = 5000
SOURCE_TIMEOUT = 90
BUILD_TIMEOUT = 540
UNITS = ("quanta.service", "quanta-boot.service", "quanta-backup.service",
         "quanta-backup-boot.service", "quanta-backup.timer", "quanta-backup-boot.timer")
BOOT_UNITS = ("quanta-boot.service", "quanta-backup-boot.service", "quanta-backup-boot.timer")
UNIT_DIRS = ("/etc/systemd/system.control", "/run/systemd/system.control",
             "/run/systemd/transient", "/run/systemd/generator.early",
             "/etc/systemd/system", "/etc/systemd/system.attached",
             "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
             "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
             "/lib/systemd/system", "/run/systemd/generator.late")
TRUSTED_FILES = {
    "Dockerfile.aarch64": "2bcfb6192445451d1efcaabba2c59b14e3f91582cae695133e1aeb6e433c47b6",
    "requirements.aarch64.lock.txt": "2bbe3c935e671dee374d73635d8d2677aed927ba92c5ee9b73a49b33c8b5dc9f",
    "deploy/oci/runtime.py": "88a865b2755c1ecf4a16a0bee18b4d233c63bc937064a6431e50c052ac1abc38",
    "deploy/oci/quanta-boot.service": "e2e0ffcb3de234abe263d9e50084f616036abfab3a7d77065035354301893ce7",
    "deploy/oci/quanta-backup-boot.service": "4c8e703a69d332f588c3cd020bfa9da50f9b0a08258f8068fff4c7eb8dc0fa14",
    "deploy/oci/quanta-backup-boot.timer": "f19f55776c6763b0c0d3480e2b9ba78f3951780095b0870bcf35dafde594a491",
}
STAGES = frozenset({"configuration", "preflight", "source", "build", "smoke", "layout",
                    "runtime_check", "app_start", "readiness", "manifest", "complete"})
STATUSES = frozenset({"success", "failed", "conflict", "not_ready", "invalid_config"})


class InstallError(Exception):
    def __init__(self, status="failed"):
        self.status = status


@contextmanager
def _deadline(seconds):
    """Linux main-thread deadline, including blocked HTTP reads and TAR metadata."""
    def expired(signum, frame):
        raise InstallError()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL,
                            max(0.001, previous_timer[0] - (time.monotonic() - started)), previous_timer[1])


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid installation data")
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid installation data")))


def validate_config(config) -> dict:
    if (not isinstance(config, dict) or set(config) != {"source_sha", "public_origin", "auth_mode"}
            or config["source_sha"] != SOURCE_SHA or config["auth_mode"] != "owner-token"):
        raise ValueError("invalid installation configuration")
    origin = config["public_origin"]
    if not isinstance(origin, str) or not origin.startswith("https://"):
        raise ValueError("invalid installation configuration")
    host = origin[8:]
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if (not 3 <= len(host) <= 253 or not re.fullmatch(label + r"(?:\." + label + r")+", host)
            or not any("a" <= character <= "z" for character in host.rsplit(".", 1)[1])):
        raise ValueError("invalid installation configuration")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return dict(config)
    raise ValueError("invalid installation configuration")


def decode_config(value) -> dict:
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 4096:
            raise ValueError
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode("ascii") != value:
            raise ValueError
        config = validate_config(_json(raw))
        if json.dumps(config, sort_keys=True, separators=(",", ":")).encode() != raw:
            raise ValueError
        return config
    except Exception:
        raise ValueError("invalid installation configuration") from None


def _environment(*, build=False):
    environment = {"PATH": BINPATH, "LC_ALL": "C", "HOME": str(ROOT / "docker-config"),
                   "DOCKER_CONFIG": str(ROOT / "docker-config")}
    if build:
        environment["DOCKER_BUILDKIT"] = "0"
    return environment


def _capture(command, *, timeout=5, limit=4096):
    process = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, env=_environment(), cwd="/")
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return None
                chunk = os.read(process.stdout.fileno(), min(1024, limit + 1 - len(output)))
                if not chunk:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or process.wait(timeout=remaining) != 0:
                        return None
                    return bytes(output)
                output.extend(chunk)
                if len(output) > limit:
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


def _quiet(command, *, timeout=10, cwd="/", build=False):
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, shell=False, env=_environment(build=build),
            cwd=str(cwd), timeout=timeout, check=False)
        if result.returncode != 0:
            raise InstallError()
    except InstallError:
        raise
    except Exception:
        raise InstallError() from None


def _secure_directory(info):
    return stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022


def _check_parents(path):
    for parent in reversed(Path(path).parents):
        if not _secure_directory(os.lstat(parent)):
            raise InstallError("conflict")


def _absent(path):
    """Absence only through trusted ancestors; merged-/usr alias is fixed."""
    path = Path(path)
    try:
        for parent in reversed(path.parents):
            try:
                info = os.lstat(parent)
            except FileNotFoundError:
                return True
            if parent == Path("/lib") and stat.S_ISLNK(info.st_mode):
                if (info.st_uid != 0 or os.readlink(parent) not in {"usr/lib", "/usr/lib"}
                        or not all(_secure_directory(os.lstat(alias)) for alias in ("/usr", "/usr/lib"))):
                    raise InstallError("conflict")
            elif not _secure_directory(info):
                raise InstallError("conflict")
        os.lstat(path)
    except FileNotFoundError:
        return True
    except InstallError:
        raise
    except Exception:
        raise InstallError("conflict") from None
    return False


def _new_dir(path, mode=0o755, *, uid=0, gid=0):
    _check_parents(path)
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        raise InstallError("conflict") from None
    os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


def _write_new(path, data, mode=0o600):
    _check_parents(path)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        raise InstallError("conflict") from None
    with os.fdopen(descriptor, "wb") as stream:
        os.fchown(stream.fileno(), 0, 0)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _resources_ready():
    try:
        with open("/proc/meminfo", "rb") as stream:
            memory = stream.read(65537)
        match = re.search(rb"^MemAvailable:\s+([0-9]{1,12})\s+kB$", memory, re.M)
        return (len(memory) <= 65536 and match is not None and int(match[1]) >= 6 * 1048576
                and shutil.disk_usage("/").free >= 10 * 1024**3 and (os.cpu_count() or 0) >= 2)
    except Exception:
        return False


def _ports_free():
    # No listen/accept and no network traffic: close each exclusive bind promptly.
    checks = ((socket.AF_INET, "0.0.0.0", 80), (socket.AF_INET, "0.0.0.0", 443),
              (socket.AF_INET, "127.0.0.1", 8765), (socket.AF_INET6, "::", 80),
              (socket.AF_INET6, "::", 443), (socket.AF_INET6, "::1", 8765))
    try:
        for family, address, port in checks:
            with socket.socket(family, socket.SOCK_STREAM) as endpoint:
                if family == socket.AF_INET6:
                    endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                endpoint.bind((address, port))
        return True
    except OSError:
        return False


def _published_ports_safe(raw):
    if raw is None or len(raw) > 8192:
        return False
    try:
        text = raw.decode("ascii")
        for line in text.splitlines():
            if not line:
                continue
            for entry in line.split(", "):
                if "->" not in entry:
                    internal = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?/(?:tcp|udp|sctp)", entry)
                    if internal is None or not 1 <= int(internal[1]) <= int(internal[2] or internal[1]) <= 65535:
                        return False
                    continue
                match = re.fullmatch(r"(?:(\[[0-9A-Fa-f:.]+\]|[0-9.]+):)?"
                    r"([0-9]{1,5})(?:-([0-9]{1,5}))?->"
                    r"([0-9]{1,5})(?:-([0-9]{1,5}))?/(tcp|udp|sctp)", entry)
                if match is None:
                    return False
                if match[1] is not None:
                    ipaddress.ip_address(match[1].strip("[]"))
                first, last = int(match[2]), int(match[3] or match[2])
                remote_first, remote_last = int(match[4]), int(match[5] or match[4])
                if not (1 <= first <= last <= 65535 and 1 <= remote_first <= remote_last <= 65535):
                    return False
                if any(first <= blocked <= last for blocked in (80, 443, 8765)):
                    return False
        return True
    except Exception:
        return False


def _docker_conflicts_absent(*, include_smoke=True):
    names = "quanta|quanta-backup|quanta-install-smoke" if include_smoke else "quanta|quanta-backup"
    raw = _capture(DOCKER_PREFIX + ["container", "ls", "--all", "--filter",
        "name=^/(" + names + ")$", "--format", "{{.Names}}"], limit=128)
    return raw == b"" and _published_ports_safe(
        _capture(DOCKER_PREFIX + ["ps", "--format", "{{.Ports}}"], limit=8192))


def _root_filesystem():
    raw = _capture(["/usr/bin/findmnt", "--json", "--target", "/", "--output",
                    "TARGET,UUID,FSTYPE,OPTIONS,FSROOT"], limit=4096)
    try:
        value = _json(raw)
        if not isinstance(value, dict) or set(value) != {"filesystems"} or len(value["filesystems"]) != 1:
            raise ValueError
        filesystem = value["filesystems"][0]
        if (not isinstance(filesystem, dict)
                or set(filesystem) != {"target", "uuid", "fstype", "options", "fsroot"}
                or filesystem["target"] != "/" or filesystem["fsroot"] != "/"
                or filesystem["fstype"] not in {"ext4", "xfs"}
                or not isinstance(filesystem["options"], str)
                or "rw" not in filesystem["options"].split(",")
                or "ro" in filesystem["options"].split(",")):
            raise ValueError
        identifier = filesystem["uuid"]
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier.lower():
            raise ValueError
        return identifier.lower()
    except Exception:
        raise InstallError("not_ready") from None


def _unit_paths_free(*, installed=False):
    for directory in UNIT_DIRS:
        for unit in UNITS:
            for suffix in ("", ".d"):
                path = Path(directory) / (unit + suffix)
                if installed and path == SYSTEMD / unit and unit in BOOT_UNITS and not suffix:
                    _check_parents(path)
                    info = os.lstat(path)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                        return False
                    with open(path, "rb") as stream:
                        current = stream.read(2049)
                    if current != _artifact("deploy/oci/" + unit):
                        return False
                elif not _absent(path):
                    return False
    try:
        result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", *UNITS],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            shell=False, env=_environment(), cwd="/", timeout=4, check=False)
        return result.returncode in {3, 4}
    except Exception:
        return False


def _preflight():
    if os.geteuid() != 0 or platform.machine() != "aarch64" or not _resources_ready():
        raise InstallError("not_ready")
    _quiet(["/usr/bin/sudo", "-n", "true"], timeout=2)
    for path in (ROOT, ETC, LIB):
        if not _absent(path):
            raise InstallError("conflict")
        _check_parents(path)
    if not _unit_paths_free() or not _ports_free() or not _docker_conflicts_absent():
        raise InstallError("conflict")
    support = _capture(DOCKER_PREFIX + ["info", "--format",
        "{{.Architecture}} {{.OSType}} {{.MemoryLimit}} {{.SwapLimit}} {{.CPUCfsPeriod}} {{.CPUCfsQuota}} {{.CPUSet}}"])
    if support not in {b"aarch64 linux true true true true true\n", b"arm64 linux true true true true true\n"}:
        raise InstallError("not_ready")
    image = _capture(DOCKER_PREFIX + ["image", "ls", "--filter", "reference=" + TAG,
                                     "--format", "{{.ID}}", "--no-trunc"], limit=128)
    if image != b"":
        raise InstallError("conflict")
    return _root_filesystem()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise InstallError()


def _download(deadline):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "Quanta-fixed-OCI-installer"})
    output = bytearray()
    with opener.open(request, timeout=10) as response:
        if response.status != 200 or response.geturl() != ARCHIVE_URL:
            raise InstallError()
        length = response.headers.get("Content-Length")
        if length is not None and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > MAX_DOWNLOAD):
            raise InstallError()
        while True:
            if time.monotonic() >= deadline:
                raise InstallError()
            chunk = response.read(min(65536, MAX_DOWNLOAD + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_DOWNLOAD:
                raise InstallError()
    return bytes(output)


def _archive_members(compressed, deadline):
    if not isinstance(compressed, bytes) or not 1 <= len(compressed) <= MAX_DOWNLOAD:
        raise InstallError()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = bytearray()
    for offset in range(0, len(compressed), 65536):
        if time.monotonic() >= deadline:
            raise InstallError()
        expanded.extend(decoder.decompress(compressed[offset:offset + 65536], MAX_EXPANDED + 1 - len(expanded)))
        if len(expanded) > MAX_EXPANDED or decoder.unconsumed_tail:
            raise InstallError()
    if not decoder.eof or decoder.unused_data:
        raise InstallError()
    archive = tarfile.open(fileobj=io.BytesIO(expanded), mode="r:")
    members, seen, sizes = [], set(), 0
    prefix = "quanta-" + SOURCE_SHA
    try:
        for member in archive:
            if time.monotonic() >= deadline or len(members) >= MAX_MEMBERS:
                raise InstallError()
            name = member.name
            if member.isdir() and name.endswith("/"):
                name = name[:-1]
            parts = name.split("/")
            if (len(name) > 512 or "\\" in name or any(ord(character) < 32 or ord(character) == 127 for character in name)
                    or any(part in {"", ".", ".."} for part in parts) or parts[0] != prefix
                    or not (member.isdir() or member.isfile()) or member.sparse is not None
                    or any(key.startswith("GNU.sparse") for key in member.pax_headers)
                    or member.size < 0 or member.size > MAX_FILE):
                raise InstallError()
            relative = tuple(parts[1:])
            if relative in seen or not relative and not member.isdir():
                raise InstallError()
            seen.add(relative)
            sizes += member.size
            if sizes > MAX_EXPANDED:
                raise InstallError()
            members.append((relative, member))
        kinds = {parts: member.isdir() for parts, member in members}
        for parts in kinds:
            if any(parts[:index] in kinds and not kinds[parts[:index]] for index in range(1, len(parts))):
                raise InstallError()
        if not members:
            raise InstallError()
        return archive, members
    except Exception:
        archive.close()
        raise


def _stage_source():
    deadline = time.monotonic() + SOURCE_TIMEOUT
    archive, members = _archive_members(_download(deadline), deadline)
    try:
        _new_dir(ROOT)
        _new_dir(ROOT / "source")
        _new_dir(SOURCE)
        _new_dir(ROOT / "docker-config", 0o700)
        created = {SOURCE}
        for parts, member in members:
            if time.monotonic() >= deadline:
                raise InstallError()
            if not parts:
                continue
            destination = SOURCE.joinpath(*parts)
            directories = (*reversed(destination.parents), destination) if member.isdir() else tuple(reversed(destination.parents))
            for directory in directories:
                if directory == SOURCE or SOURCE in directory.parents:
                    if directory not in created:
                        _new_dir(directory)
                        created.add(directory)
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise InstallError()
                with stream:
                    data = stream.read(MAX_FILE + 1)
                if len(data) != member.size or len(data) > MAX_FILE:
                    raise InstallError()
                _write_new(destination, data, 0o644)
        for name in TRUSTED_FILES:
            _artifact(name)
    finally:
        archive.close()


def _artifact(name):
    path = SOURCE / name
    _check_parents(path)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise InstallError()
    with open(path, "rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE or hashlib.sha256(data).hexdigest() != TRUSTED_FILES[name]:
        raise InstallError()
    return data


def _build_image():
    if not _resources_ready():
        raise InstallError("not_ready")
    _quiet(DOCKER_PREFIX + ["build", "--platform", "linux/arm64", "--file", "Dockerfile.aarch64",
        "--tag", TAG, "--force-rm", "--memory", "2g", "--memory-swap", "2g",
        "--cpu-period", "100000", "--cpu-quota", "200000", "--cpuset-cpus", "0,1", "."],
        timeout=BUILD_TIMEOUT, cwd=SOURCE, build=True)
    raw = _capture(DOCKER_PREFIX + ["image", "inspect", "--format", "{{.Id}} {{.Architecture}} {{.Os}}", TAG], limit=128)
    match = re.fullmatch(rb"(sha256:[0-9a-f]{64}) arm64 linux\n", raw or b"")
    if match is None:
        raise InstallError()
    return match[1].decode("ascii")


def _stop_owned_smoke(image):
    raw = _capture(DOCKER_PREFIX + ["container", "inspect", "--format",
        '{{index .Config.Labels "' + LABEL + '"}} {{.Image}}', SMOKE_NAME], limit=160)
    if raw == (SOURCE_SHA + " " + image + "\n").encode():
        try:
            _quiet(DOCKER_PREFIX + ["stop", "--time", "5", SMOKE_NAME], timeout=10)
        except InstallError:
            pass


def _smoke(image):
    command = DOCKER_PREFIX + ["run", "--rm", "--pull=never", "--name", SMOKE_NAME,
        "--label", LABEL + "=" + SOURCE_SHA, "--network", "none", "--user", "10001:10001",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--cpus", "2",
        "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "128", "--workdir", "/tmp",
        image, "python", "-m", "quanta"]
    try:
        _quiet(command + ["check-contracts"], timeout=45)
        _quiet(command + ["evaluate", "/app/examples/pair_energy_forces.json", "--format", "text"], timeout=45)
    except InstallError:
        _stop_owned_smoke(image)
        raise


def _install_layout(config, identifier, image):
    # Recheck after the potentially long image build; never reuse another setup.
    for path in (ETC, LIB, ROOT / "data", ROOT / "backups"):
        if not _absent(path):
            raise InstallError("conflict")
    if not _unit_paths_free():
        raise InstallError("conflict")
    _new_dir(ETC, 0o700)
    _new_dir(LIB)
    _new_dir(ROOT / "data", 0o700, uid=10001, gid=10001)
    _new_dir(ROOT / "backups", 0o700, uid=10001, gid=10001)
    token = secrets.token_hex(32)
    environment = ("QUANTA_PUBLIC_ORIGIN=" + config["public_origin"] + "\n"
                   "QUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=" + token + "\n")
    _write_new(ETC / "app.env", environment.encode("ascii"))
    deployment = {"storage_mode": "boot", "filesystem_uuid": identifier, "image": image}
    _write_new(ETC / "deployment.json", json.dumps(deployment, sort_keys=True, separators=(",", ":")).encode())
    _write_new(LIB / "runtime.py", _artifact("deploy/oci/runtime.py"), 0o755)
    for unit in BOOT_UNITS:
        _write_new(SYSTEMD / unit, _artifact("deploy/oci/" + unit), 0o644)
    return token


def _http(config, token, path, *, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", 8765, timeout=2)
    headers = {"Host": config["public_origin"][8:], "Origin": config["public_origin"],
               "Connection": "close"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(65537)
        if len(data) > 65536:
            raise InstallError()
        return response.status, _json(data)
    finally:
        connection.close()


def _readiness(config, token):
    deadline = time.monotonic() + 60
    while True:
        try:
            unauthorized, _ = _http(config, None, "/health/ready")
            ready, body = _http(config, token, "/health/ready")
            if unauthorized == 401 and ready == 200 and body == {"status": "ready"}:
                break
        except Exception:
            pass
        if time.monotonic() >= deadline:
            raise InstallError()
        time.sleep(0.5)
    status, examples = _http(config, token, "/ui/examples")
    if status != 200 or not isinstance(examples, dict) or not isinstance(examples.get("examples"), list):
        raise InstallError()
    selected = [item for item in examples["examples"] if isinstance(item, dict) and item.get("id") == "pair_energy_forces"]
    if len(selected) != 1 or selected[0].get("schema_version") != "0.2.0" or not isinstance(selected[0].get("definition"), dict):
        raise InstallError()
    payload = json.dumps({"schema_version": "0.2.0", "definition": selected[0]["definition"]},
                         separators=(",", ":"), allow_nan=False).encode()
    status, validation = _http(config, token, "/v1/validate", body=payload)
    if status != 200 or not isinstance(validation, dict) or validation.get("valid") is not True:
        raise InstallError()


def _report(status, stage):
    return {"scope": "app_installation", "status": status, "stage": stage}


def run(config) -> dict:
    stage = "configuration"
    try:
        config = validate_config(config)
    except Exception:
        return _report("invalid_config", stage)
    try:
        stage = "preflight"
        identifier = _preflight()
        stage = "source"
        with _deadline(SOURCE_TIMEOUT):
            _stage_source()
        stage = "build"
        image = _build_image()
        stage = "smoke"
        _smoke(image)
        stage = "layout"
        token = _install_layout(config, identifier, image)
        stage = "runtime_check"
        _quiet(["/usr/bin/python3", "-I", "-B", str(LIB / "runtime.py"), "check", "--storage-mode", "boot"], timeout=20)
        stage = "app_start"
        if not _unit_paths_free(installed=True) or not _ports_free() or not _docker_conflicts_absent():
            raise InstallError("conflict")
        _quiet(["/usr/bin/systemctl", "daemon-reload"], timeout=10)
        _quiet(["/usr/bin/systemctl", "start", "quanta-boot.service"], timeout=30)
        stage = "readiness"
        with _deadline(60):
            _readiness(config, token)
        stage = "manifest"
        _write_new(ETC / "installed.json", json.dumps(config, sort_keys=True, separators=(",", ":")).encode())
        return _report("success", "complete")
    except InstallError as error:
        return _report(error.status if error.status in STATUSES else "failed", stage)
    except Exception:
        return _report("failed", stage)


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != {"scope", "status", "stage"}
            or value["scope"] != "app_installation" or not isinstance(value["status"], str)
            or value["status"] not in STATUSES or not isinstance(value["stage"], str)
            or value["stage"] not in STAGES
            or (value["status"] == "success") != (value["stage"] == "complete")
            or value["status"] == "invalid_config" and value["stage"] != "configuration"):
        raise ValueError("invalid installation report")
    return dict(value)


def parse_output(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT_BYTES:
        raise ValueError("invalid installation report")
    try:
        return validate_report(_json(raw))
    except Exception:
        raise ValueError("invalid installation report") from None


def sanitize_report(raw):
    try:
        return parse_output(raw)
    except ValueError:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) != 1:
            raise ValueError
        config = decode_config(argv[0])
    except Exception:
        result = _report("invalid_config", "configuration")
    else:
        result = run(config)
    try:
        result = validate_report(result)
    except Exception:
        result = _report("failed", "configuration")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
