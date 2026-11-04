#!/usr/bin/env python3
"""Lock compatible binary wheels and verify their hashes with official PyPI metadata."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate preserved lock manifest key")
        result[key] = value
    return result


def nonfinite(value):
    raise ValueError("Nonfinite preserved lock manifest value")


def wheel_record(wheel: Path) -> dict:
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist()
                 if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError(f"Wheel must contain one top-level package METADATA: {wheel.name}")
        metadata = BytesParser().parsebytes(archive.read(names[0]))
    if len(metadata.get_all("Name", [])) != 1 or len(metadata.get_all("Version", [])) != 1:
        raise ValueError("Wheel metadata identity is ambiguous")
    name = canonical_name(metadata["Name"])
    version = metadata["Version"]
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version):
        raise ValueError("Invalid wheel package identity")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    metadata_url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urlopen(metadata_url, timeout=30) as response:
        release = json.load(response)
    published = next((item for item in release["urls"] if item["filename"] == wheel.name), None)
    if (canonical_name(release["info"]["name"]) != name or release["info"]["version"] != version
            or published is None or published["digests"]["sha256"] != digest
            or published.get("yanked") or not published["url"].startswith("https://files.pythonhosted.org/")):
        raise ValueError(f"Official wheel hash mismatch for {wheel.name}")
    return {
        "name": name,
        "version": version,
        "filename": wheel.name,
        "sha256": digest,
        "metadata_url": metadata_url,
        "download_url": published["url"],
        "requires_python": metadata.get("Requires-Python"),
        "requires_dist": metadata.get_all("Requires-Dist", []),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", default=str(ROOT / ".cache" / "wheels"))
    parser.add_argument("--preserve-versions-from", type=Path,
                        help="Constrain and preserve every existing wheel from a prior native lock manifest.")
    args = parser.parse_args()
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.14" or sys.platform != "linux" or platform.machine() != "x86_64":
        raise SystemExit("Lock generation requires CPython 3.12.14 on Linux x86_64")
    wheelhouse = Path(args.wheelhouse).resolve()
    wheelhouse.parent.mkdir(parents=True, exist_ok=True)
    source_manifest = args.preserve_versions_from.read_bytes() if args.preserve_versions_from else None
    preserved = []
    if source_manifest is not None:
        source = json.loads(source_manifest, object_pairs_hook=unique_object, parse_constant=nonfinite)
        if (source.get("target") != {"implementation": "CPython", "python": "3.12.14", "os": "Linux",
                                     "architecture": "x86_64", "compute": "CPU"}
                or source.get("lock_version") != "1.0.0" or source.get("index_url") != "https://pypi.org/simple"):
            raise ValueError("Preserved versions must come from a matching native lock manifest")
        preserved = source.get("packages")
        if not isinstance(preserved, list) or not preserved:
            raise ValueError("Preserved manifest has no packages")
        names = set()
        for item in preserved:
            name, version = item["name"], item["version"]
            if (not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
                    or not re.fullmatch(r"[A-Za-z0-9.!+_-]+", version) or name in names):
                raise ValueError("Invalid or duplicate preserved package")
            names.add(name)
    direct_bytes = (ROOT / "requirements.in").read_bytes()
    with tempfile.TemporaryDirectory(prefix="quanta-lock-", dir=wheelhouse.parent) as directory:
        staging = Path(directory)
        command = [sys.executable, "-m", "pip", "--isolated", "download", "--disable-pip-version-check", "--only-binary=:all:", "--index-url", "https://pypi.org/simple", "-r", str(ROOT / "requirements.in"), "--dest", str(staging)]
        if preserved:
            constraints = staging / "preserved-versions.txt"
            constraints.write_text("\n".join(f"{item['name']}=={item['version']}" for item in preserved) + "\n")
            command.extend(["--constraint", str(constraints)])
        subprocess.run(command, check=True)
        with ThreadPoolExecutor(max_workers=6) as executor:
            records = sorted(executor.map(wheel_record, staging.glob("*.whl")), key=lambda item: item["name"])
        if len({item["name"] for item in records}) != len(records):
            raise ValueError("Multiple wheels for a dependency were resolved")
        actual = {item["name"]: item for item in records}
        for item in preserved:
            observed = actual.get(item["name"], {})
            if any(observed.get(field) != item[field] for field in ("version", "filename", "sha256")):
                raise ValueError(f"A preserved wheel changed: {item['name']}")
        if ((ROOT / "requirements.in").read_bytes() != direct_bytes
                or (source_manifest is not None and args.preserve_versions_from.read_bytes() != source_manifest)):
            raise ValueError("Dependency inputs changed during lock generation")
        wheelhouse.mkdir(parents=True, exist_ok=True)
        for record in records:
            shutil.copy2(staging / record["filename"], wheelhouse / record["filename"])
    lines = [
        "# Generated by scripts/lock_dependencies.py; do not edit by hand.",
        "# Target: CPython 3.12.14, Linux x86_64 CPU. Binary wheels only.",
        "# Every wheel hash was checked against its official PyPI release metadata.",
    ]
    lines.extend(f"{item['name']}=={item['version']} --hash=sha256:{item['sha256']}" for item in records)
    (ROOT / "requirements.lock.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = {
        "lock_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {"implementation": "CPython", "python": "3.12.14", "os": "Linux", "architecture": "x86_64", "compute": "CPU"},
        "index_url": "https://pypi.org/simple",
        "direct_requirements_sha256": hashlib.sha256(direct_bytes).hexdigest(),
        "requirements_lock_sha256": hashlib.sha256((ROOT / "requirements.lock.txt").read_bytes()).hexdigest(),
        "packages": records,
    }
    if source_manifest is not None:
        manifest["generation"] = {"method": "native-resolve-preserving-exact-wheels",
                                  "preserved_manifest_sha256": hashlib.sha256(source_manifest).hexdigest(),
                                  "preserved_distributions": len(preserved)}
    (ROOT / "requirements.lock.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"locked_packages": len(records), "wheelhouse": str(wheelhouse)}))


if __name__ == "__main__":
    main()
