"""Host mount identity and operational invocation boundaries (no Docker needed)."""
import importlib.util
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("quanta_oci_runtime", ROOT / "deploy/oci/runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
FS_UUID = "c53fe556-c544-4d7f-bc8e-87535c422947"
IMAGE = "sha256:" + "a" * 64


def mount_result(**changes):
    filesystem = {"target": "/srv/quanta", "uuid": FS_UUID, "fstype": "ext4",
                  "options": "rw,relatime", "fsroot": "/"}
    filesystem.update(changes)
    return SimpleNamespace(returncode=0, stdout=json.dumps({"filesystems": [filesystem]}))


@pytest.fixture
def mount_metadata(monkeypatch):
    """Supply mount-root metadata, independent of the CI runner's actual UID."""
    monkeypatch.setattr(runtime, "_no_symlinks", lambda path: None)
    monkeypatch.setattr(Path, "stat", lambda path, **kwargs:
                        SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                                        st_dev=1 if path == Path("/") else 2))


def test_exact_mount_is_checked_without_fallback_to_parent(mount_metadata):
    observed = []

    def runner(command, **kwargs):
        observed.append((command, kwargs))
        return mount_result()

    runtime.check_mount(FS_UUID, runner=runner)
    command, options = observed[0]
    assert command[:2] == ["/usr/bin/findmnt", "--json"]
    assert command[command.index("--mountpoint") + 1] == "/srv/quanta"
    assert "--target" not in command
    assert options["timeout"] == 10 and options["capture_output"]


@pytest.mark.parametrize("changes", [
    {"target": "/"}, {"uuid": "another-disk"}, {"uuid": None},
    {"fstype": "nfs4"}, {"fstype": "overlay"}, {"fsroot": "/wrong-subdirectory"},
    {"options": "ro,relatime"}, {"options": "rw,ro"},
])
def test_wrong_or_nonlocal_or_readonly_filesystem_refused(mount_metadata, changes):
    with pytest.raises(runtime.DeploymentError, match="configured UUID"):
        runtime.check_mount(FS_UUID, runner=lambda *a, **kw: mount_result(**changes))


def test_absent_mount_refused_without_creating_storage(mount_metadata, monkeypatch):
    monkeypatch.setattr(Path, "mkdir", lambda *a, **k: pytest.fail("must not create storage"))
    result = SimpleNamespace(returncode=1, stdout="")
    with pytest.raises(runtime.DeploymentError):
        runtime.check_mount(FS_UUID, runner=lambda *a, **kw: result)


@pytest.mark.parametrize("stdout", ["not json", "[]", '{"filesystems":[]}',
                                   '{"filesystems":[{},{}]}'])
def test_ambiguous_or_malformed_mount_information_refused(mount_metadata, stdout):
    with pytest.raises(runtime.DeploymentError):
        runtime.check_mount(FS_UUID, runner=lambda *a, **kw:
                            SimpleNamespace(returncode=0, stdout=stdout))


def test_mount_root_cannot_be_writable_by_application(mount_metadata, monkeypatch):
    monkeypatch.setattr(Path, "stat", lambda *a, **kw:
                        SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=0, st_dev=2))
    with pytest.raises(runtime.DeploymentError, match="mount root"):
        runtime.check_mount(FS_UUID, runner=lambda *a, **kw: pytest.fail("unsafe root"))


def test_bind_of_boot_root_is_not_a_data_volume(mount_metadata, monkeypatch):
    monkeypatch.setattr(Path, "stat", lambda *a, **kw:
                        SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0, st_dev=1))
    with pytest.raises(runtime.DeploymentError, match="separate from the boot root"):
        runtime.check_mount(FS_UUID, runner=lambda *a, **kw: pytest.fail("boot filesystem"))


def test_symlink_path_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(runtime.DeploymentError, match="symlinks"):
        runtime._no_symlinks(link / "data")


def test_configuration_requires_exact_keys_and_immutable_image(monkeypatch):
    def load(value):
        monkeypatch.setattr(runtime, "_root_file", lambda *a, **kw: json.dumps(value).encode())
        return runtime.load_config()

    assert load({"filesystem_uuid": FS_UUID, "image": IMAGE})["image"] == IMAGE
    assert load({"filesystem_uuid": FS_UUID, "image": "registry.example/quanta@" + IMAGE})["image"].endswith(IMAGE)
    for value in [
        {"filesystem_uuid": FS_UUID, "image": "quanta:latest"},
        {"filesystem_uuid": FS_UUID, "image": IMAGE, "extra_docker_flags": "--privileged"},
        {"filesystem_uuid": "not-a-uuid", "image": IMAGE},
        {"filesystem_uuid": FS_UUID, "image": IMAGE + " --privileged"},
    ]:
        with pytest.raises(runtime.DeploymentError):
            load(value)


def test_duplicate_config_key_rejected(monkeypatch):
    monkeypatch.setattr(runtime, "_root_file", lambda *a, **kw:
                        b'{"image":"first","image":"second"}')
    with pytest.raises(runtime.DeploymentError, match="Duplicate"):
        runtime.load_config()


def test_configuration_permissions_and_private_environment(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_bytes(b"configuration")
    config.chmod(0o600)
    original_stat = Path.stat

    def root_owned(path, *args, **kwargs):
        fields = list(original_stat(path, *args, **kwargs))
        fields[4] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", root_owned)
    assert runtime._root_file(config, private=True) == b"configuration"
    config.chmod(0o644)
    assert runtime._root_file(config) == b"configuration"
    with pytest.raises(runtime.DeploymentError, match="private permissions"):
        runtime._root_file(config, private=True)
    config.chmod(0o666)
    with pytest.raises(runtime.DeploymentError, match="root-owned"):
        runtime._root_file(config)
    config.chmod(0o600)
    tmp_path.chmod(0o777)
    with pytest.raises(runtime.DeploymentError, match="root-owned"):
        runtime._root_file(config)


def test_configuration_owned_by_application_is_rejected(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_bytes(b"configuration")
    config.chmod(0o600)
    original_stat = Path.stat

    def application_owned(path, *args, **kwargs):
        fields = list(original_stat(path, *args, **kwargs))
        fields[4] = 10001 if path == config else 0
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", application_owned)
    with pytest.raises(runtime.DeploymentError, match="root-owned"):
        runtime._root_file(config)


def test_private_directory_permissions_and_owner(tmp_path, monkeypatch):
    directory = tmp_path / "data"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(runtime, "UID", os.getuid())
    monkeypatch.setattr(runtime, "GID", os.getgid())
    runtime.check_directory(directory)
    with pytest.raises(runtime.DeploymentError, match="verified data filesystem"):
        runtime.check_directory(directory, expected_device=directory.stat().st_dev + 1)
    directory.chmod(0o755)
    with pytest.raises(runtime.DeploymentError, match="private 0700"):
        runtime.check_directory(directory)
    directory.chmod(0o700)
    monkeypatch.setattr(runtime, "UID", os.getuid() + 1)
    with pytest.raises(runtime.DeploymentError):
        runtime.check_directory(directory)


def test_mount_failure_short_circuits_directory_and_docker_checks(monkeypatch):
    monkeypatch.setattr(runtime, "load_config", lambda path: {"filesystem_uuid": FS_UUID, "image": IMAGE})

    def fail(*a, **kw):
        raise runtime.DeploymentError("absent mount")

    monkeypatch.setattr(runtime, "check_mount", fail)
    monkeypatch.setattr(runtime, "check_directory", lambda *a, **kw: pytest.fail("must stop at mount gate"))
    with pytest.raises(runtime.DeploymentError, match="absent mount"):
        runtime.check_installation()


def test_fixed_application_container_is_nonroot_loopback_and_bounded():
    command = runtime.docker_command({"image": IMAGE})
    for flag, expected in [("--user", "10001:10001"), ("--network", "host"),
                           ("--restart=no", None), ("--read-only", None),
                           ("--cap-drop", "ALL"), ("--memory", "2g"),
                           ("--memory-swap", "2g"), ("--cpus", "2"),
                           ("--pids-limit", "128"), ("--pull=never", None)]:
        assert flag in command
        if expected is not None:
            assert command[command.index(flag) + 1] == expected
    assert "--publish" not in command and "--privileged" not in command
    assert command[-5:] == ["serve-production", "--store", "/srv/quanta/data", "--port", "8765"]
    assert command[command.index("--env-file") + 1] == "/etc/quanta/app.env"
    assert "source=/srv/quanta/data" in command[command.index("--mount") + 1]


def test_backup_container_has_separate_name_no_network_and_new_output():
    name = "20261105T030000Z-" + "b" * 32
    command = runtime.docker_command({"image": IMAGE}, backup=True, output_name=name)
    assert command[command.index("--name") + 1] == "quanta-backup"
    assert command[command.index("--network") + 1] == "none"
    assert "--env-file" not in command
    assert command[-1] == "/srv/quanta/backups/" + name
    assert "backup-store" in command and "--output" in command
    with pytest.raises(runtime.DeploymentError):
        runtime.docker_command({"image": IMAGE}, backup=True, output_name="../data")


def test_systemd_is_single_restart_owner_and_bound_to_mount():
    unit = (ROOT / "deploy/oci/quanta.service").read_text()
    assert "Restart=on-failure" in unit
    assert "BindsTo=srv-quanta.mount" in unit
    assert "After=docker.service srv-quanta.mount" in unit
    assert "AssertPathIsMountPoint=/srv/quanta" in unit
    assert "ExecStartPre=/usr/bin/python3 /usr/local/lib/quanta/runtime.py check" in unit
    assert "KillMode=control-group" in unit and "TimeoutStopSec=60" in unit
    assert "--restart=no" in runtime.docker_command({"image": IMAGE})


@pytest.mark.parametrize("dockerfile", ["Dockerfile", "Dockerfile.aarch64"])
def test_images_default_to_fixed_nonroot_user(dockerfile):
    content = (ROOT / dockerfile).read_text()
    assert "USER 10001:10001" in content
    assert 'CMD ["python", "-m", "quanta", "check-contracts"]' in content
