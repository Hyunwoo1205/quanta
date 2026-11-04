#!/usr/bin/env python3
"""Prepare, but do not execute, ARM wheels at the verified x86 lock's exact versions.

Both output files are staged completely. The manifest is published last and binds
the text file's SHA-256, so interrupted publication fails closed for lock readers.
This cross-download is artifact preparation, not native ARM validation.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen
import zipfile

from packaging.tags import compatible_tags, cpython_tags
from packaging.utils import parse_wheel_filename


ROOT = Path(__file__).resolve().parents[1]
# Debian bookworm's glibc is 2.36; never select a wheel requiring a newer ABI.
PLATFORMS = tuple(f"manylinux_2_{minor}_aarch64" for minor in range(36, 16, -1)) + ("manylinux2014_aarch64",)
TARGET_TAGS = frozenset(cpython_tags((3, 12), abis=["cp312"], platforms=PLATFORMS)) | frozenset(
    compatible_tags((3, 12), interpreter="cp312", platforms=PLATFORMS))
TARGET = {"implementation": "CPython", "python": "3.12.14", "os": "Linux",
          "architecture": "aarch64", "compute": "CPU"}


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate source lock manifest key")
        result[key] = value
    return result


def nonfinite(value):
    raise ValueError("Nonfinite source lock manifest value")


def source_lock(root: Path) -> tuple[dict, dict[str, bytes]]:
    """Reject a changed or contradictory source before downloading any wheels."""
    sources = {name: (root / name).read_bytes() for name in
               ("requirements.in", "requirements.lock.txt", "requirements.lock.json")}
    manifest = json.loads(sources["requirements.lock.json"], object_pairs_hook=unique_object,
                          parse_constant=nonfinite)
    expected_target = dict(TARGET, architecture="x86_64")
    if (manifest.get("lock_version") != "1.0.0" or manifest.get("target") != expected_target
            or manifest.get("index_url") != "https://pypi.org/simple"):
        raise ValueError("Expected the existing CPython 3.12.14 Linux x86_64 lock")
    if manifest.get("direct_requirements_sha256") != sha256(sources["requirements.in"]):
        raise ValueError("Source direct requirements hash mismatch")
    if manifest.get("requirements_lock_sha256") != sha256(sources["requirements.lock.txt"]):
        raise ValueError("Source lock text hash mismatch")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Source lock has no packages")
    names = set()
    expected_lines = []
    for item in packages:
        name, version, digest = item["name"], item["version"], item["sha256"]
        if (not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
                or not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version)
                or not re.fullmatch(r"[0-9a-f]{64}", digest) or name in names):
            raise ValueError("Invalid or duplicate source package")
        if (item.get("metadata_url") != f"https://pypi.org/pypi/{name}/{version}/json"
                or Path(item["filename"]).name != item["filename"]
                or not item["filename"].endswith(".whl")):
            raise ValueError("Source package is not an official wheel record")
        names.add(name)
        expected_lines.append(f"{name}=={version} --hash=sha256:{digest}")
    actual_lines = [line for line in sources["requirements.lock.txt"].decode().splitlines()
                    if line and not line.startswith("#")]
    if sorted(actual_lines) != sorted(expected_lines):
        raise ValueError("Source text and manifest package records differ")
    return manifest, sources


def release_record(item: dict) -> tuple[str, dict]:
    """Verify source provenance against the official pinned PyPI release."""
    with urlopen(item["metadata_url"], timeout=30) as response:
        release = json.load(response)
    if (canonical_name(release["info"]["name"]) != item["name"]
            or release["info"]["version"] != item["version"]):
        raise ValueError("Official release identity mismatch")
    source = next((file for file in release["urls"] if file["filename"] == item["filename"]), None)
    if (source is None or source["digests"]["sha256"] != item["sha256"]
            or source["url"] != item["download_url"] or source.get("yanked")):
        raise ValueError(f"Official source provenance mismatch: {item['name']}")
    return item["name"], release


def arm_wheel_record(wheel: Path, expected: dict[str, str], releases: dict[str, dict]) -> dict:
    _, _, _, tags = parse_wheel_filename(wheel.name)
    if (not tags.intersection(TARGET_TAGS)
            or any(tag.platform != "any" and tag.platform not in PLATFORMS for tag in tags)):
        raise ValueError(f"Not a selected CPython 3.12 ARM wheel: {wheel.name}")
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [name for name in archive.namelist()
                          if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("Wheel must contain exactly one package METADATA")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
    if len(metadata.get_all("Name", [])) != 1 or len(metadata.get_all("Version", [])) != 1:
        raise ValueError("Wheel metadata identity is ambiguous")
    name, version = canonical_name(metadata["Name"]), metadata["Version"]
    if name not in expected or expected[name] != version:
        raise ValueError("Wheel name/version differs from source lock")
    digest = sha256(wheel.read_bytes())
    published = next((item for item in releases[name]["urls"] if item["filename"] == wheel.name), None)
    if (published is None or published["digests"]["sha256"] != digest
            or published.get("yanked") or not published["url"].startswith("https://files.pythonhosted.org/")):
        raise ValueError(f"Official ARM wheel hash mismatch: {wheel.name}")
    return {"name": name, "version": version, "filename": wheel.name, "sha256": digest,
            "metadata_url": f"https://pypi.org/pypi/{name}/{version}/json",
            "download_url": published["url"], "requires_python": metadata.get("Requires-Python"),
            "requires_dist": metadata.get_all("Requires-Dist", [])}


def publish_pair(root: Path, text: bytes, manifest: bytes) -> None:
    """Stage both complete files; the hash-bound manifest is the commit marker."""
    outputs = [(root / "requirements.aarch64.lock.txt", text),
               (root / "requirements.aarch64.lock.json", manifest)]
    staged = []
    try:
        for destination, raw in outputs:
            with tempfile.NamedTemporaryFile(dir=root, prefix=destination.name + ".", suffix=".tmp", delete=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                staged.append((Path(stream.name), destination))
        for temporary, destination in staged:
            os.replace(temporary, destination)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", default=str(ROOT / ".cache" / "wheels-aarch64"))
    args = parser.parse_args()
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.14":
        raise SystemExit("Cross-download preparation requires CPython 3.12.14")
    manifest, sources = source_lock(ROOT)
    with ThreadPoolExecutor(max_workers=6) as executor:
        releases = dict(executor.map(release_record, manifest["packages"]))
    expected = {item["name"]: item["version"] for item in manifest["packages"]}
    wheelhouse = Path(args.wheelhouse).resolve()
    wheelhouse.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="quanta-arm-lock-", dir=wheelhouse.parent) as directory:
        staging = Path(directory)
        pins = staging / "exact-pins.txt"
        pins.write_text("\n".join(f"{name}=={version}" for name, version in sorted(expected.items())) + "\n")
        command = [sys.executable, "-m", "pip", "--isolated", "download", "--disable-pip-version-check",
                   "--no-deps", "--only-binary=:all:", "--index-url", "https://pypi.org/simple",
                   "--python-version", "3.12.14", "--implementation", "cp", "--abi", "cp312"]
        for target_platform in PLATFORMS:
            command.extend(["--platform", target_platform])
        command.extend(["-r", str(pins), "--dest", str(staging)])
        subprocess.run(command, check=True)
        records = sorted((arm_wheel_record(path, expected, releases) for path in staging.glob("*.whl")),
                         key=lambda item: item["name"])
        actual = {item["name"]: item["version"] for item in records}
        if actual != expected or len(records) != len(expected):
            raise ValueError("ARM package set differs from source lock")
        if any((ROOT / name).read_bytes() != raw for name, raw in sources.items()):
            raise ValueError("Source lock changed during preparation")
        wheelhouse.mkdir(parents=True, exist_ok=True)
        for item in records:
            shutil.copy2(staging / item["filename"], wheelhouse / item["filename"])
    lines = ["# Generated by scripts/prepare_arm_lock.py; do not edit by hand.",
             "# Target: CPython 3.12.14, Linux aarch64 CPU. Binary wheels only.",
             "# Exact x86 lock versions; official PyPI hashes verified. Native ARM validation is separate."]
    lines.extend(f"{item['name']}=={item['version']} --hash=sha256:{item['sha256']}" for item in records)
    text = ("\n".join(lines) + "\n").encode()
    prepared = {"lock_version": "1.0.0", "generated_at": datetime.now(timezone.utc).isoformat(),
                "target": TARGET, "index_url": "https://pypi.org/simple",
                "direct_requirements_sha256": sha256(sources["requirements.in"]),
                "requirements_lock_sha256": sha256(text), "packages": records,
                "preparation": {"method": "cross-download-exact-pins", "native_arm_validation": "not_performed",
                                "source_lock_manifest_sha256": sha256(sources["requirements.lock.json"]),
                                "source_lock_sha256": sha256(sources["requirements.lock.txt"]),
                                "source_architecture": "x86_64", "version_policy": "exact-source-lock-parity",
                                "host": {"os": platform.system(), "architecture": platform.machine(),
                                         "python": platform.python_version()}}}
    publish_pair(ROOT, text, (json.dumps(prepared, indent=2, ensure_ascii=False) + "\n").encode())
    print(json.dumps({"locked_packages": len(records), "target": TARGET, "wheelhouse": str(wheelhouse),
                      "native_arm_validation": "not_performed"}))


if __name__ == "__main__":
    main()
