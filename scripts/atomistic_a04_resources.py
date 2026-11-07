"""Fail-closed memory admission for isolated A04 refinement measurements."""
from pathlib import Path, PurePosixPath
import re


GIB = 1024**3
MEMORY_RESERVE_BYTES = 2 * GIB
MINIMUM_MEMORY_BYTES = 2 * GIB
MEMORY_TIERS_BYTES = tuple(gib * GIB for gib in (10, 11, 12))


def memory_budget(available: int, attempt: int) -> int | None:
    """Clamp a configured tier to observed headroom after the host reserve."""
    if type(available) is not int or available < 0:
        raise ValueError("Invalid available memory")
    if type(attempt) is not int or not 0 <= attempt < len(MEMORY_TIERS_BYTES):
        raise ValueError("Invalid memory attempt")
    budget = min(available - MEMORY_RESERVE_BYTES, MEMORY_TIERS_BYTES[attempt])
    return budget if budget >= MINIMUM_MEMORY_BYTES else None


def _absolute_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.root != "/" or ".." in path.parts:
        raise ValueError("Invalid cgroup path")
    return path


def _mount_path(value: str) -> PurePosixPath:
    # Linux mountinfo escapes spaces, tabs, newlines and backslashes in paths.
    decoded = re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), value)
    return _absolute_path(decoded)


def _cgroup_headroom(directory: Path) -> int | None:
    if not directory.is_dir():
        raise ValueError(f"Missing cgroup directory: {directory}")
    try:
        limit = (directory / "memory.max").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        # Root cgroups and cgroups without an enabled memory controller can
        # lack both files. Any accessible finite ancestor still applies.
        try:
            (directory / "memory.current").stat()
        except FileNotFoundError:
            return None
        raise ValueError(f"Missing cgroup memory.max: {directory}") from None
    if limit == "max":
        return None
    current = (directory / "memory.current").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9]+", limit) or not re.fullmatch(r"[0-9]+", current):
        raise ValueError(f"Invalid cgroup memory limit or usage: {directory}")
    return max(0, int(limit) - int(current))


def available_memory_bytes(*, proc_root: Path = Path("/proc")) -> int:
    """Read MemAvailable and clamp it to all reachable finite v2 ancestors."""
    rows = (proc_root / "meminfo").read_text(encoding="ascii").splitlines()
    entries = [row for row in rows if row.startswith("MemAvailable:")]
    match = re.fullmatch(r"MemAvailable:[ \t]+([0-9]+)[ \t]+kB", entries[0]) if len(entries) == 1 else None
    if match is None:
        raise ValueError("Invalid MemAvailable in meminfo")
    available = int(match[1]) * 1024

    groups = (proc_root / "self/cgroup").read_text(encoding="utf-8").splitlines()
    for row in groups:
        fields = row.split(":", 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[2].startswith("/"):
            raise ValueError("Invalid cgroup membership")
        if "memory" in fields[1].split(","):
            raise ValueError("cgroup v1 memory limits cannot be verified")
    unified = [row for row in groups if row.startswith("0:")]
    if not unified:
        return available
    if len(unified) != 1 or not unified[0].startswith("0::"):
        raise ValueError("Invalid cgroup v2 membership")
    member = _absolute_path(unified[0][3:])

    mounts = (proc_root / "self/mountinfo").read_text(encoding="utf-8").splitlines()
    found = False
    for row in mounts:
        fields, _, filesystem = row.partition(" - ")
        if not filesystem.startswith("cgroup2 "):
            continue
        fields = fields.split()
        if len(fields) < 6:
            raise ValueError("Invalid cgroup v2 mount")
        root = _mount_path(fields[3])
        if not member.is_relative_to(root):
            continue
        found = True
        mount = Path(_mount_path(fields[4]))
        directory = mount / member.relative_to(root)
        while True:
            headroom = _cgroup_headroom(directory)
            if headroom is not None:
                available = min(available, headroom)
            if directory == mount:
                break
            directory = directory.parent
    if not found:
        raise ValueError("No visible mount for cgroup v2 membership")
    return available
