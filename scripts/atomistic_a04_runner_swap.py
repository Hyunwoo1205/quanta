"""Own one short-lived swapfile on the isolated native A04 CI runner."""
from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

from atomistic_a04_resources import GIB


SWAP_BYTES = 16 * GIB


def _active_swap_paths() -> set[str]:
    rows = Path("/proc/swaps").read_text(encoding="utf-8").splitlines()
    if not rows or not rows[0].startswith("Filename"):
        raise ValueError("Cannot verify active host swap")
    return {
        re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), row.split()[0])
        for row in rows[1:]
    }


def _check_runner(work_root: Path) -> None:
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Hyunwoo1205/quanta",
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_ARCH": "X64",
    }
    allowed_workflows = {
        "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-resource-ci.yml@refs/heads/main",
        "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-he16.yml@refs/heads/main",
        "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-he-opt.yml@refs/heads/main",
        "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-even-grid-final.yml@refs/heads/main",
        "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-even-grid-final-retry.yml@refs/heads/main",
        "Hyunwoo1205/quanta/.github/workflows/atomistic-a04-he-basis-pilot.yml@refs/heads/main",
    }
    if (
        os.environ.get("GITHUB_WORKFLOW_REF") not in allowed_workflows
        or os.geteuid() == 0
        or platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or any(os.environ.get(key) != value for key, value in expected.items())
    ):
        raise ValueError("Temporary swap requires the nonroot native GitHub-hosted Quanta runner")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    if not work_root.is_dir() or not work_root.is_relative_to(workspace):
        raise ValueError("Temporary swap must use scratch under the GitHub checkout")


@contextmanager
def bounded_ci_swap(work_root: Path, *, minimum_free_bytes: int) -> Iterator[int]:
    """Add the bounded disk swap for one job and remove only our own file."""
    work_root = work_root.resolve(strict=True)
    _check_runner(work_root)
    if type(minimum_free_bytes) is not int or minimum_free_bytes < 0:
        raise ValueError("Invalid free disk reserve")
    if shutil.disk_usage(work_root).free < SWAP_BYTES + minimum_free_bytes:
        raise ValueError("Insufficient disk headroom for bounded swap and the required reserve")

    # A regular temporary directory would unlink this file if swapoff fails.
    # Leave it intact on failure so the dedicated runner can safely retire it.
    directory = Path(tempfile.mkdtemp(prefix="quanta-a04-swap-", dir=work_root))
    swapfile = directory / "pages.swap"
    path = str(swapfile)
    try:
        fd = os.open(swapfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.posix_fallocate(fd, 0, SWAP_BYTES)
        finally:
            os.close(fd)
        if shutil.disk_usage(work_root).free < minimum_free_bytes:
            raise ValueError("Free disk reserve fell below the minimum during swap allocation")
        subprocess.run(["sudo", "-n", "/usr/bin/chown", "0:0", "--", path], check=True, timeout=30)
        subprocess.run(["sudo", "-n", "/usr/sbin/mkswap", "--quiet", "--", path], check=True, timeout=30)
        subprocess.run(
            ["sudo", "-n", "/usr/sbin/swapon", "--priority", "0", "--", path],
            check=True, timeout=30,
        )
        if path not in _active_swap_paths():
            raise ValueError("Bounded swapfile was not registered on the runner")
        yield SWAP_BYTES
    finally:
        if path in _active_swap_paths():
            subprocess.run(["sudo", "-n", "/usr/sbin/swapoff", "--", path], check=True, timeout=120)
            if path in _active_swap_paths():
                raise RuntimeError("Bounded swapfile remains active and was retained")
        swapfile.unlink(missing_ok=True)
        directory.rmdir()
