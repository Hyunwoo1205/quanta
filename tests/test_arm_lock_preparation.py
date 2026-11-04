"""Preparation provenance checks with synthetic wheels; no network or ARM execution."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quanta_prepare_arm_lock_tests", ROOT / "scripts" / "prepare_arm_lock.py")
prepare = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(prepare)


def source_root(path: Path) -> Path:
    path.mkdir()
    for name in ("requirements.in", "requirements.lock.txt", "requirements.lock.json"):
        shutil.copyfile(ROOT / name, path / name)
    return path


def manifest(root: Path) -> dict:
    return json.loads((root / "requirements.lock.json").read_text())


def write_manifest(root: Path, value: dict) -> None:
    (root / "requirements.lock.json").write_text(json.dumps(value))


def no_network_main(monkeypatch, root: Path):
    monkeypatch.setattr(prepare, "ROOT", root)
    monkeypatch.setattr(prepare.platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(prepare.platform, "python_version", lambda: "3.12.14")
    monkeypatch.setattr(sys, "argv", ["prepare_arm_lock.py"])
    monkeypatch.setattr(prepare, "release_record", lambda item: pytest.fail("Invalid source reached network lookup"))
    monkeypatch.setattr(prepare.subprocess, "run", lambda *a, **k: pytest.fail("Invalid source reached pip download"))
    monkeypatch.setattr(prepare, "publish_pair", lambda *a, **k: pytest.fail("Invalid source published ARM locks"))


@pytest.mark.parametrize("filename", ["requirements.in", "requirements.lock.txt"])
def test_source_content_tampering_stops_before_network(tmp_path, monkeypatch, filename):
    root = source_root(tmp_path / "source")
    with (root / filename).open("ab") as stream:
        stream.write(b"\n# not the captured source\n")
    no_network_main(monkeypatch, root)
    with pytest.raises(ValueError):
        prepare.main()


def test_resealed_source_package_conflict_stops_before_network(tmp_path, monkeypatch):
    root = source_root(tmp_path / "source")
    value = manifest(root)
    value["packages"][0]["version"] = "0.0.0"
    value["packages"][0]["metadata_url"] = f"https://pypi.org/pypi/{value['packages'][0]['name']}/0.0.0/json"
    write_manifest(root, value)
    no_network_main(monkeypatch, root)
    with pytest.raises(ValueError):
        prepare.main()


@pytest.mark.parametrize("mutation", ["target", "metadata_origin", "duplicate_package", "empty_packages"])
def test_invalid_source_provenance_stops_before_network(tmp_path, monkeypatch, mutation):
    root = source_root(tmp_path / "source")
    value = manifest(root)
    if mutation == "target":
        value["target"]["architecture"] = "aarch64"
    elif mutation == "metadata_origin":
        value["packages"][0]["metadata_url"] = "https://untrusted.example/release.json"
    elif mutation == "duplicate_package":
        value["packages"].append(copy.deepcopy(value["packages"][0]))
    else:
        value["packages"] = []
    write_manifest(root, value)
    no_network_main(monkeypatch, root)
    with pytest.raises(ValueError):
        prepare.main()


@pytest.mark.parametrize("extra", ['"lock_version": "1.0.0",', '"unused": NaN,'])
def test_ambiguous_or_nonfinite_source_json_stops_before_network(tmp_path, monkeypatch, extra):
    root = source_root(tmp_path / "source")
    path = root / "requirements.lock.json"
    text = path.read_text()
    assert text.startswith("{")
    path.write_text("{" + extra + text[1:])
    no_network_main(monkeypatch, root)
    with pytest.raises(ValueError):
        prepare.main()


def make_wheel(tmp_path: Path, *, tag="cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64",
               metadata="Name: demo-pkg\nVersion: 1.2.3\nRequires-Python: >=3.9\nRequires-Dist: helper>=1\n\n",
               extra_metadata=False):
    path = tmp_path / f"demo_pkg-1.2.3-{tag}.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo_pkg-1.2.3.dist-info/METADATA", metadata)
        if extra_metadata:
            archive.writestr("other-1.0.dist-info/METADATA", "Name: other\nVersion: 1.0\n\n")
    record = {"filename": path.name, "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
              "url": f"https://files.pythonhosted.org/packages/synthetic/{path.name}", "yanked": False}
    release = {"info": {"name": "demo-pkg", "version": "1.2.3"}, "urls": [record]}
    return path, {"demo-pkg": "1.2.3"}, {"demo-pkg": release}


def test_official_hash_bound_arm_and_universal_wheels_are_accepted(tmp_path):
    for tag in ("cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64", "py3-none-any"):
        path, expected, releases = make_wheel(tmp_path, tag=tag)
        result = prepare.arm_wheel_record(path, expected, releases)
        assert result["name"] == "demo-pkg"
        assert result["version"] == "1.2.3"
        assert result["filename"] == path.name
        assert result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert result["requires_python"] == ">=3.9"
        assert result["requires_dist"] == ["helper>=1"]


@pytest.mark.parametrize("tag", [
    "cp312-cp312-manylinux_2_17_x86_64", "cp311-cp311-manylinux_2_17_aarch64",
    "cp312-abi3-manylinux_2_17_aarch64", "cp312-cp312-linux_aarch64",
    "cp312-cp312-manylinux_2_17_aarch64.manylinux_2_17_x86_64", "py2-none-any",
])
def test_incompatible_wheel_is_rejected_even_with_matching_official_hash(tmp_path, tag):
    path, expected, releases = make_wheel(tmp_path, tag=tag)
    with pytest.raises(ValueError):
        prepare.arm_wheel_record(path, expected, releases)


@pytest.mark.parametrize("mutation", ["wrong_hash", "yanked", "missing_file", "untrusted_url", "wrong_version", "unlisted_package"])
def test_arm_wheel_requires_exact_expected_identity_and_official_provenance(tmp_path, mutation):
    path, expected, releases = make_wheel(tmp_path)
    published = releases["demo-pkg"]["urls"][0]
    if mutation == "wrong_hash":
        published["digests"]["sha256"] = "0" * 64
    elif mutation == "yanked":
        published["yanked"] = True
    elif mutation == "missing_file":
        releases["demo-pkg"]["urls"] = []
    elif mutation == "untrusted_url":
        published["url"] = f"https://files.pythonhosted.org.evil.example/{path.name}"
    elif mutation == "wrong_version":
        expected["demo-pkg"] = "1.2.4"
    else:
        expected = {}
    with pytest.raises(ValueError):
        prepare.arm_wheel_record(path, expected, releases)


@pytest.mark.parametrize("metadata", [
    "Name: demo-pkg\n\n", "Version: 1.2.3\n\n",
    "Name: demo-pkg\nName: other\nVersion: 1.2.3\n\n",
    "Name: demo-pkg\nVersion: 1.2.3\nVersion: 1.2.4\n\n",
])
def test_missing_or_ambiguous_wheel_identity_is_rejected(tmp_path, metadata):
    path, expected, releases = make_wheel(tmp_path, metadata=metadata)
    with pytest.raises(ValueError):
        prepare.arm_wheel_record(path, expected, releases)


def test_multiple_metadata_records_are_rejected(tmp_path):
    path, expected, releases = make_wheel(tmp_path, extra_metadata=True)
    with pytest.raises(ValueError):
        prepare.arm_wheel_record(path, expected, releases)


@pytest.mark.parametrize("mutation", ["wrong_name", "wrong_version", "wrong_hash", "yanked", "wrong_url", "missing_file"])
def test_official_source_release_is_revalidated(tmp_path, monkeypatch, mutation):
    path, _, releases = make_wheel(tmp_path)
    release = releases["demo-pkg"]
    source = {"name": "demo-pkg", "version": "1.2.3", "filename": path.name,
              "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "download_url": release["urls"][0]["url"],
              "metadata_url": "https://pypi.org/pypi/demo-pkg/1.2.3/json"}
    if mutation == "wrong_name":
        release["info"]["name"] = "other"
    elif mutation == "wrong_version":
        release["info"]["version"] = "1.2.4"
    elif mutation == "wrong_hash":
        release["urls"][0]["digests"]["sha256"] = "0" * 64
    elif mutation == "yanked":
        release["urls"][0]["yanked"] = True
    elif mutation == "wrong_url":
        source["download_url"] = "https://untrusted.example/foreign.whl"
    else:
        release["urls"] = []
    monkeypatch.setattr(prepare, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(release).encode()))
    with pytest.raises(ValueError):
        prepare.release_record(source)
