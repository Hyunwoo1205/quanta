"""Locked host selection and provenance boundaries; no emulated ARM calculation claims."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from quanta import profiles


ROOT = Path(__file__).resolve().parents[1]
LOGICAL_FILES = {"requirements.in", "requirements.lock.txt", "requirements.lock.json"}


def host(monkeypatch, architecture="x86_64", system="Linux"):
    """Inject only the host selector; this does not execute or validate ARM numerics."""
    monkeypatch.setattr(profiles.platform, "system", lambda: system)
    monkeypatch.setattr(profiles.platform, "machine", lambda: architecture)


def x86_root(path: Path) -> Path:
    path.mkdir()
    for name in LOGICAL_FILES:
        shutil.copyfile(ROOT / name, path / name)
    return path


def test_profile_selection_uses_observed_host_and_architecture_specific_locks(monkeypatch):
    x86 = profiles.profile_for_host(system="Linux", machine="x86_64")
    arm = profiles.profile_for_host(system="Linux", machine="aarch64")
    assert x86["architecture"] == "x86_64"
    assert x86["lock_text"] == "requirements.lock.txt"
    assert x86["lock_manifest"] == "requirements.lock.json"
    assert arm["architecture"] == "aarch64"
    assert arm["lock_text"] == "requirements.aarch64.lock.txt"
    assert arm["lock_manifest"] == "requirements.aarch64.lock.json"
    assert isinstance(x86["profile_id"], str) and x86["profile_id"]
    assert isinstance(arm["profile_id"], str) and arm["profile_id"]
    assert x86["profile_id"] != arm["profile_id"]
    for architecture, expected in (("x86_64", x86), ("aarch64", arm)):
        host(monkeypatch, architecture)
        assert profiles.profile_for_host() == expected


@pytest.mark.parametrize("system,machine", [
    ("Linux", "riscv64"), ("Linux", "ppc64le"), ("Linux", ""),
    ("Darwin", "arm64"), ("Windows", "AMD64"), ("Darwin", "x86_64"),
])
def test_unsupported_hosts_do_not_fall_back_to_x86(system, machine):
    with pytest.raises(ValueError):
        profiles.profile_for_host(system=system, machine=machine)


def test_profile_results_cannot_mutate_later_selections():
    first = profiles.profile_for_host(system="Linux", machine="x86_64")
    first["architecture"] = "aarch64"
    first["lock_text"] = "foreign.lock"
    assert profiles.profile_for_host(system="Linux", machine="x86_64")["lock_text"] == "requirements.lock.txt"
    assert profiles.profile_for_host(system="Linux", machine="x86_64")["architecture"] == "x86_64"


def test_x86_and_arm_locks_preserve_pins_and_canonical_bundle_names(monkeypatch):
    observations = {}
    for architecture in ("x86_64", "aarch64"):
        host(monkeypatch, architecture)
        files = profiles.load_lock_files(roots=(ROOT,))
        assert set(files) == LOGICAL_FILES
        assert all(isinstance(raw, bytes) for raw in files.values())
        lock = json.loads(files["requirements.lock.json"])
        assert lock["target"] == {"implementation": "CPython", "python": "3.12.14",
                                  "os": "Linux", "architecture": architecture, "compute": "CPU"}
        assert hashlib.sha256(files["requirements.in"]).hexdigest() == lock["direct_requirements_sha256"]
        assert hashlib.sha256(files["requirements.lock.txt"]).hexdigest() == lock["requirements_lock_sha256"]
        observations[architecture] = (files, lock)
    x86_files, x86_lock = observations["x86_64"]
    arm_files, arm_lock = observations["aarch64"]
    assert x86_files["requirements.in"] == arm_files["requirements.in"]
    assert x86_files["requirements.lock.txt"] != arm_files["requirements.lock.txt"]
    assert x86_files["requirements.lock.json"] != arm_files["requirements.lock.json"]
    x86_versions = {item["name"]: item["version"] for item in x86_lock["packages"]}
    arm_versions = {item["name"]: item["version"] for item in arm_lock["packages"]}
    assert arm_versions == x86_versions
    assert len(arm_versions) == 20
    for lock, architecture in ((x86_lock, "x86_64"), (arm_lock, "aarch64")):
        packages = {item["name"]: item for item in lock["packages"]}
        for name in ("numpy", "scipy", "rpds-py"):
            assert architecture in packages[name]["filename"]


def test_incomplete_checkout_can_fall_back_to_complete_installed_root(tmp_path, monkeypatch):
    host(monkeypatch)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "requirements.in").write_text("incomplete checkout, not a lock set")
    installed = x86_root(tmp_path / "installed")
    files = profiles.load_lock_files(roots=(checkout, installed))
    assert files == {name: (installed / name).read_bytes() for name in LOGICAL_FILES}


def test_incomplete_roots_are_not_combined_into_a_lock_set(tmp_path, monkeypatch):
    host(monkeypatch)
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    shutil.copyfile(ROOT / "requirements.in", first / "requirements.in")
    for name in ("requirements.lock.txt", "requirements.lock.json"):
        shutil.copyfile(ROOT / name, second / name)
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(first, second))


@pytest.mark.parametrize("filename", ["requirements.in", "requirements.lock.txt"])
def test_changed_dependency_bytes_are_rejected(tmp_path, monkeypatch, filename):
    host(monkeypatch)
    root = x86_root(tmp_path / "source")
    with (root / filename).open("ab") as stream:
        stream.write(b"\n# changed after locking\n")
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(root,))


@pytest.mark.parametrize("field,value", [
    ("implementation", "PyPy"), ("python", "3.12.15"), ("os", "Darwin"), ("compute", "GPU"),
])
def test_lock_target_must_match_the_complete_supported_profile(tmp_path, monkeypatch, field, value):
    host(monkeypatch)
    source = x86_root(tmp_path / "source")
    manifest_path = source / "requirements.lock.json"
    lock = json.loads(manifest_path.read_text())
    lock["target"][field] = value
    manifest_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(source,))


def test_arm_host_does_not_use_x86_lock_when_its_own_lock_is_missing(tmp_path, monkeypatch):
    host(monkeypatch, "aarch64")
    source = x86_root(tmp_path / "source")
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(source,))


def test_resealed_wrong_architecture_target_is_rejected_before_fallback(tmp_path, monkeypatch):
    host(monkeypatch)
    source = x86_root(tmp_path / "source")
    installed = x86_root(tmp_path / "installed")
    text_path = source / "requirements.lock.txt"
    with text_path.open("ab") as stream:
        stream.write(b"\n")
    manifest_path = source / "requirements.lock.json"
    lock = json.loads(manifest_path.read_text())
    lock["target"]["architecture"] = "aarch64"
    lock["requirements_lock_sha256"] = hashlib.sha256(text_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(source, installed))


def test_malformed_complete_root_does_not_silently_use_a_different_install(tmp_path, monkeypatch):
    host(monkeypatch)
    source = x86_root(tmp_path / "source")
    installed = x86_root(tmp_path / "installed")
    (source / "requirements.lock.json").write_text("{}")
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(source, installed))


def test_unsupported_observed_host_cannot_load_existing_x86_lock(monkeypatch):
    host(monkeypatch, "riscv64")
    with pytest.raises(ValueError):
        profiles.load_lock_files(roots=(ROOT,))


def test_execution_refuses_captured_lock_for_a_different_observed_architecture(pair, monkeypatch):
    import copy
    from quanta import workflow

    observed = copy.deepcopy(workflow.environment_report())
    assert observed["valid"]
    architecture = observed["platform"]["architecture"]
    observed["platform"]["architecture"] = "aarch64" if architecture == "x86_64" else "x86_64"
    monkeypatch.setattr(workflow, "environment_report", lambda: copy.deepcopy(observed))
    monkeypatch.setattr(workflow, "_dispatch", lambda *a, **k: pytest.fail("Foreign target was executed"))
    report = workflow.run_experiment(pair)
    assert report["result"]["execution_status"] == "FAILED"
    assert report["result"]["execution_fingerprint"] is None
    env_sha = report["result"]["provenance"]["environment_manifest_sha256"]
    saved_observation = json.loads(report["captured_artifacts"][env_sha])
    assert any(error["code"] == "ENV_LOCK_TARGET" for error in saved_observation["errors"])


def test_resealed_executed_environment_must_match_its_captured_lock(pair):
    from quanta.hashing import canonical_bytes
    from quanta.run_store import validate_run_report
    from quanta.workflow import run_experiment

    report = run_experiment(pair)
    assert validate_run_report(report)["valid"]
    result = report["result"]
    observed = json.loads(report["captured_artifacts"][result["provenance"]["environment_manifest_sha256"]])
    original_arch = observed["platform"]["architecture"]
    observed["platform"]["architecture"] = "aarch64" if original_arch == "x86_64" else "x86_64"

    def capture(value):
        raw = canonical_bytes(value)
        sha = hashlib.sha256(raw).hexdigest()
        report["captured_artifacts"][sha] = raw.decode()
        return sha

    environment_sha = capture(observed)
    result["provenance"]["environment_manifest_sha256"] = environment_sha
    result["execution_fingerprint"] = capture({"contract_version": "0.2.0",
        "run_resolved_input_sha256": report["plan"]["resolved_input_sha256"],
        **report["plan"]["execution_manifests"], "environment_manifest_sha256": environment_sha})
    checked = validate_run_report(report)
    assert not checked["valid"]
    assert "platform observation" in checked["errors"][0]["message"]


def test_replay_refuses_other_architecture_lock_before_dispatch(pair, tmp_path, monkeypatch):
    from quanta import planning, workflow
    from quanta.run_store import BundleError, replay_bundle, write_bundle

    report = workflow.run_experiment(pair)
    path = write_bundle(report, tmp_path / "original")
    actual = profiles.profile_for_host()["architecture"]
    other = "aarch64" if actual == "x86_64" else "x86_64"
    profile = profiles.profile_for_host(system="Linux", machine=other)
    other_files = {"requirements.in": (ROOT / "requirements.in").read_bytes(),
                   "requirements.lock.txt": (ROOT / profile["lock_text"]).read_bytes(),
                   "requirements.lock.json": (ROOT / profile["lock_manifest"]).read_bytes()}
    monkeypatch.setattr(planning, "load_lock_files", lambda: other_files)
    monkeypatch.setattr(workflow, "run_experiment", lambda *a, **k: pytest.fail("Foreign lock was replayed"))
    with pytest.raises(BundleError) as caught:
        replay_bundle(path)
    assert caught.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"
