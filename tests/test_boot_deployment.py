"""Explicit boot-volume storage must never hide a lost dedicated data mount."""
import importlib.util
import errno
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("quanta_oci_boot_runtime", ROOT / "deploy/oci/runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
FS_UUID = "c53fe556-c544-4d7f-bc8e-87535c422947"
IMAGE = "sha256:" + "a" * 64


def boot_result(**changes):
    filesystem = {"target": "/", "uuid": FS_UUID, "fstype": "ext4",
                  "options": "rw,relatime", "fsroot": "/"}
    filesystem.update(changes)
    return SimpleNamespace(returncode=0, stdout=json.dumps({"filesystems": [filesystem]}))


@pytest.fixture
def boot_metadata(monkeypatch):
    monkeypatch.setattr(runtime, "_no_symlinks", lambda path: None)
    monkeypatch.setattr(Path, "stat", lambda *a, **kw:
                        SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0, st_dev=1))


def test_boot_layout_requires_an_explicit_configuration_mode(monkeypatch):
    def load(value):
        monkeypatch.setattr(runtime, "_root_file", lambda *a, **kw: json.dumps(value).encode())
        return runtime.load_config()

    legacy = {"filesystem_uuid": FS_UUID, "image": IMAGE}
    assert load(legacy) == legacy
    assert load({**legacy, "storage_mode": "boot"}) == {**legacy, "storage_mode": "boot"}
    for mode in (None, "", "auto", "fallback", "BOOT", 1, True, [], {}):
        with pytest.raises(runtime.DeploymentError, match="Storage mode"):
            load({**legacy, "storage_mode": mode})


def test_boot_layout_checks_the_owning_root_filesystem(boot_metadata):
    seen = []

    def runner(command, **kwargs):
        seen.append((command, kwargs))
        return boot_result()

    runtime.check_boot_storage(FS_UUID, runner=runner)
    command, kwargs = seen[0]
    assert command[command.index("--target") + 1] == "/srv/quanta"
    assert "--mountpoint" not in command
    assert kwargs["timeout"] == 10


@pytest.mark.parametrize("changes", [
    {"target": "/srv/quanta"}, {"target": "/srv"},
    {"uuid": "another-root"}, {"uuid": None},
    {"fstype": "nfs4"}, {"fstype": "overlay"}, {"fstype": "tmpfs"},
    {"fsroot": "/subdirectory"}, {"options": "ro,relatime"}, {"options": "rw,ro"},
])
def test_boot_layout_refuses_other_or_unwritable_filesystem(boot_metadata, changes):
    with pytest.raises(runtime.DeploymentError, match="configured UUID"):
        runtime.check_boot_storage(FS_UUID, runner=lambda *a, **kw: boot_result(**changes))


@pytest.mark.parametrize("stdout", ["invalid", "[]", '{"filesystems":[]}',
                                   '{"filesystems":[{},{}]}'])
def test_boot_layout_refuses_ambiguous_findmnt_output(boot_metadata, stdout):
    with pytest.raises(runtime.DeploymentError):
        runtime.check_boot_storage(FS_UUID, runner=lambda *a, **kw:
            SimpleNamespace(returncode=0, stdout=stdout))


def test_boot_layout_refuses_a_directory_on_a_separate_device(boot_metadata, monkeypatch):
    monkeypatch.setattr(Path, "stat", lambda path, **kw:
        SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                        st_dev=1 if path == Path("/") else 2))
    with pytest.raises(runtime.DeploymentError, match="boot root filesystem"):
        runtime.check_boot_storage(FS_UUID, runner=lambda *a, **kw: pytest.fail("wrong device"))


@pytest.mark.parametrize("uid,mode", [(10001, 0o755), (0, 0o777), (0, 0o775)])
def test_boot_layout_checks_trusted_ancestors(boot_metadata, monkeypatch, uid, mode):
    monkeypatch.setattr(Path, "stat", lambda path, **kw:
        SimpleNamespace(st_mode=stat.S_IFDIR | (mode if path == Path("/srv") else 0o755),
                        st_uid=uid if path == Path("/srv") else 0, st_gid=0, st_dev=1))
    with pytest.raises(runtime.DeploymentError, match="root-owned"):
        runtime.check_boot_storage(FS_UUID, runner=lambda *a, **kw: pytest.fail("unsafe ancestor"))


def test_missing_boot_directory_never_creates_a_store(tmp_path, monkeypatch):
    missing = tmp_path / "missing"
    monkeypatch.setattr(Path, "mkdir", lambda *a, **kw: pytest.fail("must not create storage"))
    with pytest.raises(FileNotFoundError):
        runtime.check_boot_storage(FS_UUID, directory=missing,
                                   runner=lambda *a, **kw: pytest.fail("missing directory"))
    assert not missing.exists()


def test_boot_layout_refuses_a_symlink_even_with_root_uuid(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(runtime.DeploymentError, match="symlinks"):
        runtime.check_boot_storage(FS_UUID, directory=linked)


@pytest.mark.parametrize("configured,selected", [("boot", "dedicated"), ("dedicated", "boot")])
def test_wrong_service_mode_fails_before_storage_access(monkeypatch, configured, selected):
    config = {"filesystem_uuid": FS_UUID, "image": IMAGE}
    if configured == "boot":
        config["storage_mode"] = "boot"
    monkeypatch.setattr(runtime, "load_config", lambda *a: config)
    monkeypatch.setattr(runtime, "check_mount", lambda *a, **kw: pytest.fail("must reject mode first"))
    monkeypatch.setattr(runtime, "check_boot_storage", lambda *a, **kw: pytest.fail("must reject mode first"))
    with pytest.raises(runtime.DeploymentError, match="does not match"):
        runtime.check_installation(required_storage_mode=selected)


def test_boot_installation_keeps_every_service_directory_on_verified_device(monkeypatch):
    config = {"filesystem_uuid": FS_UUID, "image": IMAGE, "storage_mode": "boot"}
    seen = []
    monkeypatch.setattr(runtime, "load_config", lambda *a: config)
    monkeypatch.setattr(runtime, "check_mount", lambda *a, **kw: pytest.fail("no dedicated fallback"))
    monkeypatch.setattr(runtime, "check_boot_storage", lambda *a, **kw: seen.append("boot"))
    monkeypatch.setattr(runtime, "check_directory", lambda path, **kw: seen.append((path.name, kw)))
    monkeypatch.setattr(runtime, "_no_symlinks", lambda *a: None)
    monkeypatch.setattr(runtime, "_root_file", lambda *a, **kw: b"")

    def metadata(path, **kwargs):
        if path.name in {"jobs.sqlite3", "jobs.sqlite3-wal", "jobs.sqlite3-shm", "worker.lock"}:
            raise FileNotFoundError(errno.ENOENT, "missing")
        return SimpleNamespace(st_dev=7)

    monkeypatch.setattr(Path, "stat", metadata)
    assert runtime.check_installation(required_storage_mode="boot") == config
    assert seen == ["boot", ("data", {"expected_device": 7}), ("backups", {"expected_device": 7})]


def test_boot_cli_mode_is_explicit_and_default_remains_dedicated(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime, "check_installation", lambda **kw: calls.append(kw) or {})
    assert runtime.main(["check"]) == 0
    assert runtime.main(["check", "--storage-mode", "boot"]) == 0
    assert calls == [{"application": True, "required_storage_mode": "dedicated"},
                     {"application": True, "required_storage_mode": "boot"}]


def test_boot_and_dedicated_units_are_exclusive_and_keep_one_restart_owner():
    units = ROOT / "deploy/oci"
    boot = (units / "quanta-boot.service").read_text()
    dedicated = (units / "quanta.service").read_text()
    assert "Conflicts=quanta.service" in boot and "Conflicts=quanta-boot.service" in dedicated
    assert "After=docker.service local-fs.target quanta.service" in boot
    assert "Restart=on-failure" in boot and "KillMode=control-group" in boot
    assert "RequiresMountsFor=/srv/quanta" in boot
    assert "BindsTo=srv-quanta.mount" not in boot and "AssertPathIsMountPoint" not in boot
    assert "AssertPathIsDirectory=/srv/quanta" in boot
    assert "check --storage-mode boot" in boot and "run --storage-mode boot" in boot
    backup = (units / "quanta-backup-boot.service").read_text()
    assert "backup --storage-mode boot" in backup
    assert "Conflicts=quanta-backup.service" in backup
    assert "After=docker.service local-fs.target quanta-backup.service" in backup
    timer = (units / "quanta-backup-boot.timer").read_text()
    assert "Unit=quanta-backup-boot.service" in timer and "Conflicts=quanta-backup.timer" in timer
    assert "After=quanta-backup.timer" in timer
    command = runtime.docker_command({"filesystem_uuid": FS_UUID, "image": IMAGE, "storage_mode": "boot"})
    assert command[command.index("--name") + 1] == "quanta" and "--restart=no" in command
