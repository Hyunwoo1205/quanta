"""Select trusted architecture-specific locks; never infer a profile from a bundle."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import sys

PYTHON_VERSION = "3.12.14"


def profile_for_host(*, system: str | None = None, machine: str | None = None) -> dict:
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    if system != "Linux" or machine not in {"x86_64", "aarch64"}:
        raise ValueError("A locked profile requires Linux x86_64 or aarch64")
    suffix = ".aarch64" if machine == "aarch64" else ""
    return {"profile_id": f"cpython-{PYTHON_VERSION}-linux-{machine}-cpu-v1",
            "architecture": machine, "lock_text": f"requirements{suffix}.lock.txt",
            "lock_manifest": f"requirements{suffix}.lock.json"}


def expected_target(profile: dict) -> dict:
    return {"implementation": "CPython", "python": PYTHON_VERSION, "os": "Linux",
            "architecture": profile["architecture"], "compute": "CPU"}


def target_matches_observation(target: dict, observed: dict) -> bool:
    """Compare a captured lock target to observations, including old bundle records."""
    return (target.get("implementation") == observed.get("implementation")
            and target.get("python") == observed.get("versions", {}).get("python")
            and target.get("os") == observed.get("platform", {}).get("os")
            and target.get("architecture") == observed.get("platform", {}).get("architecture")
            and target.get("compute") == "CPU")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in dependency lock manifest")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("Nonfinite lock value")


def load_lock_files(roots: tuple[Path, ...] | None = None) -> dict[str, bytes]:
    """Return three stable bundle names backed by one complete matching lock root.

    A complete but invalid first root is an error, not a reason to silently use
    another installed version. Physical ARM filenames remain explicit on disk;
    historical bundle names stay unchanged and contain the selected exact bytes.
    """
    profile = profile_for_host()
    physical = {"requirements.in": "requirements.in", "requirements.lock.txt": profile["lock_text"],
                "requirements.lock.json": profile["lock_manifest"]}
    if roots is None:
        roots = (Path(__file__).resolve().parents[2], Path(sys.prefix) / "share" / "quanta")
    root = next((Path(path) for path in roots if all((Path(path) / name).is_file()
                                                  for name in physical.values())), None)
    if root is None:
        raise ValueError(f"The exact dependency lock artifacts for {profile['architecture']} are unavailable")
    files = {logical: (root / name).read_bytes() for logical, name in physical.items()}
    try:
        lock = json.loads(files["requirements.lock.json"], object_pairs_hook=_unique_object,
                          parse_constant=_nonfinite)
        if lock["target"] != expected_target(profile):
            raise ValueError("The dependency lock target differs from the observed host profile")
        if (hashlib.sha256(files["requirements.in"]).hexdigest() != lock["direct_requirements_sha256"]
                or hashlib.sha256(files["requirements.lock.txt"]).hexdigest() != lock["requirements_lock_sha256"]):
            raise ValueError("Dependency lock content differs from its provenance")
    except (KeyError, TypeError, UnicodeError) as exc:
        raise ValueError("The dependency lock manifest is malformed") from exc
    return files
