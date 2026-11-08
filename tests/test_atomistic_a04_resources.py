"""Resource admission must never overlook a finite reachable ancestor."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_helper():
    path = Path(__file__).resolve().parents[1] / "scripts" / "atomistic_a04_resources.py"
    spec = importlib.util.spec_from_file_location("atomistic_a04_resources", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


resources = _load_helper()
GIB = resources.GIB


@pytest.mark.parametrize(("available", "attempt", "expected"), [
    (16 * GIB, 0, 10 * GIB),
    (16 * GIB, 1, 11 * GIB),
    (16 * GIB, 2, 12 * GIB),
    (11 * GIB, 0, 9 * GIB),
    (11 * GIB, 2, 9 * GIB),
    (4 * GIB, 0, 2 * GIB),
    (4 * GIB - 1, 0, None),
])
def test_memory_budget(available, attempt, expected):
    assert resources.memory_budget(available, attempt) == expected


@pytest.mark.parametrize(("available", "attempt"), [(-1, 0), (True, 0), (16 * GIB, -1), (16 * GIB, 3), (16 * GIB, False)])
def test_invalid_memory_budget_arguments(available, attempt):
    with pytest.raises(ValueError):
        resources.memory_budget(available, attempt)


def _proc(tmp_path, *, available=16 * GIB, member="/user.slice/runner", mount_root="/"):
    proc = tmp_path / "proc"
    (proc / "self").mkdir(parents=True)
    (proc / "meminfo").write_text(f"MemAvailable: {available // 1024} kB\n")
    mount = tmp_path / "cgroup"
    mount.mkdir()
    (proc / "self/cgroup").write_text(f"0::{member}\n")
    (proc / "self/mountinfo").write_text(f"1 0 0:1 {mount_root} {mount} rw - cgroup2 cgroup rw\n")
    return proc, mount


def _limits(directory, limit, current):
    directory.mkdir(exist_ok=True, parents=True)
    (directory / "memory.max").write_text(f"{limit}\n")
    (directory / "memory.current").write_text(f"{current}\n")


def test_minimum_ancestor_headroom(tmp_path):
    proc, mount = _proc(tmp_path)
    _limits(mount / "user.slice", 12 * GIB, 5 * GIB)
    _limits(mount / "user.slice/runner", "max", GIB)
    assert resources.available_memory_bytes(proc_root=proc) == 7 * GIB
    _limits(mount / "user.slice/runner", 5 * GIB, 2 * GIB)
    assert resources.available_memory_bytes(proc_root=proc) == 3 * GIB


def test_cgroup_mounted_at_subtree(tmp_path):
    proc, mount = _proc(tmp_path, member="/user.slice/runner", mount_root="/user.slice")
    _limits(mount, 9 * GIB, 2 * GIB)
    _limits(mount / "runner", "max", GIB)
    assert resources.available_memory_bytes(proc_root=proc) == 7 * GIB


def test_mountinfo_escapes_do_not_change_raw_membership(tmp_path):
    member = r"/runner\040name"
    proc, mount = _proc(tmp_path, member=member)
    target = mount.with_name("cgroup mount")
    mount.rename(target)
    escaped_target = str(target).replace(" ", r"\040")
    (proc / "self/mountinfo").write_text(f"1 0 0:1 / {escaped_target} rw - cgroup2 cgroup rw\n")
    _limits(target / member[1:], 5 * GIB, 2 * GIB)
    assert resources.available_memory_bytes(proc_root=proc) == 3 * GIB


def test_memavailable_clamps_unlimited_groups(tmp_path):
    proc, mount = _proc(tmp_path, available=8 * GIB, member="/")
    _limits(mount, "max", 6 * GIB)
    assert resources.available_memory_bytes(proc_root=proc) == 8 * GIB


def test_over_limit_group_has_no_headroom(tmp_path):
    proc, mount = _proc(tmp_path, member="/")
    _limits(mount, 6 * GIB, 7 * GIB)
    assert resources.available_memory_bytes(proc_root=proc) == 0


@pytest.mark.parametrize("invalid", ["", "12", "NaN kB", "42 MB", "1 kB\nMemAvailable: 2 kB"])
def test_bad_host_memory_fails_closed(tmp_path, invalid):
    proc, _ = _proc(tmp_path)
    (proc / "meminfo").write_text(f"MemAvailable: {invalid}\n")
    with pytest.raises(ValueError):
        resources.available_memory_bytes(proc_root=proc)


@pytest.mark.parametrize(("limit", "current"), [("broken", GIB), (9 * GIB, "-1")])
def test_bad_finite_ancestor_fails_closed(tmp_path, limit, current):
    proc, mount = _proc(tmp_path)
    _limits(mount / "user.slice", limit, current)
    _limits(mount / "user.slice/runner", "max", GIB)
    with pytest.raises(ValueError):
        resources.available_memory_bytes(proc_root=proc)


def test_missing_finite_ancestor_counter_fails_closed(tmp_path):
    proc, mount = _proc(tmp_path)
    _limits(mount / "user.slice", 9 * GIB, GIB)
    _limits(mount / "user.slice/runner", "max", GIB)
    (mount / "user.slice/memory.current").unlink()
    with pytest.raises(OSError):
        resources.available_memory_bytes(proc_root=proc)


def test_hidden_cgroup_v2_mount_fails_closed(tmp_path):
    proc, _ = _proc(tmp_path)
    (proc / "self/mountinfo").write_text("")
    with pytest.raises(ValueError, match="No visible mount"):
        resources.available_memory_bytes(proc_root=proc)


@pytest.mark.parametrize(("available", "outcomes", "case_index", "expected", "status"), [
    ([16, 16], ["container_oom", "measured"], 0, [10, 12], "measured"),
    ([8, 16], ["container_oom", "measured"], 0, [6, 8], "measured"),
    ([11, 11], ["container_oom"], 0, [9], "deferred"),
    ([16], ["engine_exit"], 0, [10], "engine_exit"),
    ([5], [], 2, [], "deferred"),
])
def test_only_oom_gets_a_larger_safe_retry(monkeypatch, tmp_path, available, outcomes, case_index, expected, status):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    runner = importlib.import_module("run_atomistic_a04_resource_ci")
    headroom = iter(value * GIB for value in available)
    monkeypatch.setattr(runner, "available_memory_bytes", lambda: next(headroom))
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda _: SimpleNamespace(free=20 * GIB))
    completed = iter(outcomes)
    grants = []

    def attempt(case, number, budget, available, candidate, scratch, diagnostics, record):
        grants.append(budget // GIB)
        record["status"] = next(completed)

    monkeypatch.setattr(runner, "run_attempt", attempt)
    result = {}
    runner.run_case(runner.CASES[case_index], {}, tmp_path, tmp_path, result)
    assert grants == expected and result["status"] == status


@pytest.mark.parametrize(("list_code", "list_stdout", "verified"), [
    (0, "", True),
    (0, "quanta-a04-resource-abc\n", False),
    (1, "", False),
])
def test_container_cleanup_requires_a_successful_exact_absence_query(monkeypatch, list_code, list_stdout, verified):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    runner = importlib.import_module("run_atomistic_a04_resource_ci")
    name = "quanta-a04-resource-abc"
    calls = []

    def docker(*args, check):
        calls.append(args)
        assert check is False
        if args[0] == "rm":
            return SimpleNamespace(returncode=1, stderr="Version-specific missing-container text")
        return SimpleNamespace(returncode=list_code, stdout=list_stdout)

    monkeypatch.setattr(runner, "run_docker", docker)
    if verified:
        runner.clean_container(name)
    else:
        with pytest.raises(RuntimeError, match="Could not verify isolated container removal"):
            runner.clean_container(name)
    assert calls == [
        ("rm", "--force", name),
        ("container", "ls", "--all", "--filter", r"name=^/quanta\-a04\-resource\-abc$", "--format", "{{.Names}}"),
    ]


def test_unverified_cgroup_v1_memory_fails_closed(tmp_path):
    proc, _ = _proc(tmp_path)
    (proc / "self/cgroup").write_text("3:memory:/runner\n0::/runner\n")
    with pytest.raises(ValueError, match="v1 memory limits"):
        resources.available_memory_bytes(proc_root=proc)
