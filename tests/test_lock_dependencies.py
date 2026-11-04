"""Native lock updates preserve old exact wheels and verify official provenance."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quanta_native_lock_tests", ROOT / "scripts/lock_dependencies.py")
lock = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(lock)


def fixture_wheel(tmp_path, *, metadata="Name: demo-pkg\nVersion: 1.2.3\n\n"):
    p = tmp_path / "demo_pkg-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("demo_pkg-1.2.3.dist-info/METADATA", metadata)
        z.writestr("demo_pkg/_vendor/other-1.0.dist-info/METADATA", "Name: other\nVersion: 1.0\n\n")
    record = {"filename": p.name, "digests": {"sha256": hashlib.sha256(p.read_bytes()).hexdigest()},
              "url": "https://files.pythonhosted.org/packages/synthetic/" + p.name, "yanked": False}
    return p, {"info": {"name": "demo-pkg", "version": "1.2.3"}, "urls": [record]}


def test_native_wheel_uses_only_top_level_identity_and_official_hash(tmp_path, monkeypatch):
    p, release = fixture_wheel(tmp_path)
    monkeypatch.setattr(lock, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(release).encode()))
    record = lock.wheel_record(p)
    assert record["name"] == "demo-pkg"
    assert record["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.mark.parametrize("mutation", ["hash", "yanked", "foreign_url", "release_identity"])
def test_native_wheel_rejects_untrusted_release_records(tmp_path, monkeypatch, mutation):
    p, release = fixture_wheel(tmp_path)
    if mutation == "hash":
        release["urls"][0]["digests"]["sha256"] = "0" * 64
    elif mutation == "yanked":
        release["urls"][0]["yanked"] = True
    elif mutation == "foreign_url":
        release["urls"][0]["url"] = "https://files.pythonhosted.org.evil.example/wheel"
    else:
        release["info"]["version"] = "1.2.4"
    monkeypatch.setattr(lock, "urlopen", lambda *a, **k: io.BytesIO(json.dumps(release).encode()))
    with pytest.raises(ValueError):
        lock.wheel_record(p)


@pytest.mark.parametrize("extra", ['"lock_version":"1.0.0",', '"unused":NaN,'])
def test_ambiguous_preserved_manifest_fails_before_download(tmp_path, monkeypatch, extra):
    source = tmp_path / "previous.json"
    source.write_text("{" + extra + (ROOT / "requirements.lock.json").read_text()[1:])
    monkeypatch.setattr(lock.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(sys, "argv", ["lock_dependencies.py", "--preserve-versions-from", str(source),
                                     "--wheelhouse", str(tmp_path / "wheels")])
    monkeypatch.setattr(lock.subprocess, "run", lambda *a, **k: pytest.fail("Ambiguous source reached download"))
    with pytest.raises(ValueError):
        lock.main()


@pytest.mark.parametrize("mutation", ["version", "sha256", "missing"])
def test_native_resolver_cannot_change_or_drop_preserved_wheels(tmp_path, monkeypatch, mutation):
    source_data = json.loads((ROOT / "requirements.lock.json").read_text())
    source_data["packages"] = source_data["packages"][:1]
    previous = source_data["packages"][0]
    source = tmp_path / "previous.json"
    source.write_text(json.dumps(source_data))
    (tmp_path / "requirements.in").write_text(previous["name"] + "==" + previous["version"] + "\n")
    monkeypatch.setattr(lock, "ROOT", tmp_path)
    monkeypatch.setattr(lock.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(sys, "argv", ["lock_dependencies.py", "--preserve-versions-from", str(source),
                                     "--wheelhouse", str(tmp_path / "wheels")])

    def download(arguments, **kwargs):
        constraints = Path(arguments[arguments.index("--constraint") + 1]).read_text()
        assert constraints == previous["name"] + "==" + previous["version"] + "\n"
        if mutation != "missing":
            destination = Path(arguments[arguments.index("--dest") + 1])
            (destination / previous["filename"]).write_bytes(b"synthetic wheel")

    changed = copy.deepcopy(previous)
    if mutation != "missing":
        changed[mutation] = "0.0.0" if mutation == "version" else "0" * 64
    monkeypatch.setattr(lock.subprocess, "run", download)
    monkeypatch.setattr(lock, "wheel_record", lambda path: changed)
    with pytest.raises(ValueError, match="preserved wheel changed"):
        lock.main()
    assert not (tmp_path / "requirements.lock.txt").exists()
