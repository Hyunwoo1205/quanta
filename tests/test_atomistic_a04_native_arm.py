import copy
import json
from pathlib import Path
import signal
import subprocess
import sys

import pytest


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import run_atomistic_a04_native_arm
    return run_atomistic_a04_native_arm


def test_bind_five_exact_x86_references(runner):
    plan = json.loads(runner.PLAN.read_bytes())
    refs = runner.x86_references(plan)
    assert list(refs) == ["h2-short", "h2-reference", "h2", "h2-long", "he"]
    assert [ref["workflow_run_id"] for ref in refs.values()] == [
        42450193275, 42448653582, 42447627356, 42450193275, 42448653582,
    ]
    assert all(x["attempt"]["density"]["grid_counts"] == [150] * 3 for x in list(refs.values())[:4])
    assert refs["he"]["attempt"]["density"]["grid_counts"] == [216] * 3


def test_arm_uses_exact_deck_and_grid_and_strict_scalar_gate(runner):
    plan = json.loads(runner.PLAN.read_bytes())
    ref = runner.x86_references(plan)["he"]
    checks = {c["id"]: c for c in json.loads(runner.VALIDATION_PLAN.read_bytes())["checks"]}
    observed = copy.deepcopy(ref["attempt"])
    observed["density"]["geometry_check"] = {"atoms_and_composition_match": True}
    assert runner.compare_same_input(ref, observed, checks)["passed"]
    observed["engine_energy_hartree"] += 1e-7
    assert not runner.compare_same_input(ref, observed, checks)["passed"]
    observed["submitted_input_sha256"] = "other"
    with pytest.raises(ValueError, match="same submitted input"):
        runner.compare_same_input(ref, observed, checks)


def test_arm_measures_serially_and_preserves_two_gib_headroom(runner, monkeypatch, tmp_path):
    plan = json.loads(runner.PLAN.read_bytes())
    refs = runner.x86_references(plan)
    monkeypatch.setattr(runner, "available_memory_bytes", lambda: 7 * runner.GIB)
    usage = runner.shutil.disk_usage(tmp_path)._replace(free=20 * runner.GIB)
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda _: usage)
    systems = []

    def attempt(case, _, budget, available, candidate, scratch, diagnostics, record, *, architecture, expected_input):
        assert architecture == "arm64" and budget == 3 * runner.GIB
        assert available - budget >= 2 * runner.GIB
        assert expected_input == refs[case.system]["attempt"]["input_sha256"]
        systems.append(case.system)
        record["status"] = "guard_stop"

    monkeypatch.setattr(runner, "run_attempt", attempt)
    report = {"cases": []}
    runner.run_cases(plan, refs, {}, tmp_path, tmp_path, report)
    assert systems == ["h2-short", "h2-reference", "h2", "h2-long"]
    assert report["cases"][-1]["status"] == "deferred_headroom"
    assert report["status"] == "measurement_incomplete"


@pytest.mark.parametrize("available_gib, expected_count", [(5, 0), (7, 4), (8, 5)])
def test_oci_measures_only_with_locked_case_headroom(runner, monkeypatch, tmp_path, available_gib, expected_count):
    plan = json.loads(runner.PLAN.read_bytes())
    references = runner.x86_references(plan)
    monkeypatch.setattr(runner, "available_memory_bytes", lambda: available_gib * runner.GIB)
    usage = runner.shutil.disk_usage(tmp_path)._replace(free=20 * runner.GIB)
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda _: usage)
    measured = []

    def attempt(case, ordinal, budget, available, candidate, scratch, diagnostics, record, *,
                architecture, expected_input, oci_probe_output):
        assert ordinal == 1 and architecture == "arm64" and oci_probe_output == tmp_path
        assert budget == (6 if case.system == "he" else 3) * runner.GIB
        assert available == available_gib * runner.GIB
        ref = references[case.system]["attempt"]
        assert expected_input == ref["input_sha256"]
        record.update(copy.deepcopy(ref))
        record["input_metadata"] = {"source_fixture": next(
            spec["fixture"] for spec in plan["cases"] if spec["system"] == case.system
        ), "atoms": []}
        record["density"]["geometry_check"] = {"atoms_and_composition_match": True}
        measured.append(case.system)

    monkeypatch.setattr(runner, "run_attempt", attempt)
    report = {"cases": []}
    runner.run_cases(plan, references, {}, tmp_path, tmp_path, report, oci_probe_output=tmp_path)
    assert measured == [spec["system"] for spec in plan["cases"][:expected_count]]
    if expected_count == 5:
        assert report["status"] == "measured" and report["all_cross_build_checks_passed"] is True
    else:
        assert report["status"] == "measurement_incomplete"
        assert report["cases"][-1]["status"] == "deferred_headroom"
        assert report["cases"][-1]["minimum_admission_memory_bytes"] == (6 if expected_count == 0 else 8) * runner.GIB


def test_arm_rejects_unapproved_candidate_metadata_before_daemon_load(runner, monkeypatch, tmp_path):
    plan = json.loads(runner.PLAN.read_bytes())
    _, approved, _ = runner.approved_candidate()
    (tmp_path / "candidate-image.json").write_text(json.dumps({**approved, "binary_sha256": "0" * 64}))
    (tmp_path / "candidate-image.tar").touch()
    monkeypatch.setattr(runner, "load_candidate", lambda *_a, **_k: pytest.fail("unapproved image load"))
    with pytest.raises(ValueError, match="metadata differs"):
        runner.arm_image(tmp_path, plan)


def test_oci_guard_interrupts_real_attempt_and_cleans_labeled_work(runner, monkeypatch, tmp_path):
    import run_atomistic_a04_resource_ci as shared

    output = tmp_path / "evidence"
    args = ["runner", "--fixed-oci-a04", "--candidate-dir", str(tmp_path / "candidate"), "--output-dir", str(output)]
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setenv("QUANTA_A04_SOURCE_SHA", "a" * 40)
    monkeypatch.setattr(runner, "require_native_ci", lambda _: pytest.fail("OCI used the GitHub gate"))
    monkeypatch.setattr(runner, "require_oci_arm", lambda _: None)
    monkeypatch.setattr(runner.subprocess, "check_output", lambda *_a, **_k: "ext4")
    monkeypatch.setattr(runner, "available_memory_bytes", lambda: 8 * runner.GIB)
    usage = runner.shutil.disk_usage(tmp_path)._replace(free=20 * runner.GIB)
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda _: usage)
    monkeypatch.setattr(runner, "arm_image", lambda *_: {"image_id": "approved", "binary_sha256": "b", "cp2k_source": "c"})
    created = []
    removed = []

    def interrupt_create(*args):
        assert args[0] == "create"
        assert args[args.index("--label") + 1] == f"org.quanta.atomistic-a04={output}"
        assert args[args.index("--memory") + 1] == args[args.index("--memory-swap") + 1] == str(3 * runner.GIB)
        created.append(args[args.index("--name") + 1])
        runner.stop_measurement(signal.SIGTERM, None)

    monkeypatch.setattr(shared, "run_docker", interrupt_create)
    monkeypatch.setattr(shared, "clean_container", removed.append)
    prior = signal.getsignal(signal.SIGTERM)
    assert runner.main() == 1
    assert signal.getsignal(signal.SIGTERM) == prior
    assert len(created) == 1 and removed == created
    report = json.loads((output / "report.json").read_bytes())
    assert report["scope"] == "isolated_oci_arm_A04_same_input_qualification"
    assert report["quanta_source"] == "a" * 40 and report["workflow_run_id"] is None
    assert report["status"] == "guard_interrupted" and report["error"] == "SIGTERM"
    assert report["scratch_removed"] is True
    assert report["verification_scope"]["execution_lane"] == "isolated_oci_host_probe"
    assert report["cases"][0]["status"] == "guard_interrupted"
    assert report["cases"][0]["attempt"]["container_removed"] is True
    assert not list(tmp_path.glob("quanta-a04-native-arm-*"))


def test_oci_requires_the_exact_inspected_docker_cleanup_label(runner, tmp_path):
    import run_atomistic_a04_resource_ci as shared

    budget = 3 * runner.GIB
    inspected = {
        "HostConfig": {
            "Memory": budget, "MemorySwap": budget, "NanoCpus": 10**9, "PidsLimit": 128,
            "NetworkMode": "none", "ReadonlyRootfs": True, "CgroupnsMode": "private", "ShmSize": shared.SHM_LIMIT,
            "LogConfig": {"Type": "none"}, "Ulimits": [
                {"Name": "fsize", "Soft": runner.GIB, "Hard": runner.GIB}, {"Name": "core", "Soft": 0, "Hard": 0},
            ], "Tmpfs": {"/tmp": f"rw,nosuid,nodev,noexec,size={shared.TMPFS_LIMIT},mode=1777"},
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
        },
        "Mounts": [{"Destination": name, "Type": "bind", "RW": rw} for name, rw in (
            ("/work", True), ("/quanta-input", False), ("/quanta-data", False),
        )],
        "Config": {"Labels": {shared.OCI_PROBE_LABEL: str(tmp_path / "another-probe")}},
    }
    with pytest.raises(ValueError, match="exact OCI cleanup label"):
        shared.checked_controls(inspected, budget, oci_probe_output=tmp_path)
    inspected["Config"]["Labels"][shared.OCI_PROBE_LABEL] = str(tmp_path)
    assert shared.checked_controls(inspected, budget, oci_probe_output=tmp_path)["memory_swap_bytes"] == budget


def test_isolated_oci_entry_point_refuses_github_context(runner, monkeypatch, tmp_path):
    output = tmp_path / "evidence"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("QUANTA_A04_SOURCE_SHA", "a" * 40)
    completed = subprocess.run([
        sys.executable, "-I", "-B", runner.__file__, "--fixed-oci-a04",
        "--candidate-dir", str(tmp_path / "candidate"), "--output-dir", str(output),
    ], cwd=runner.ROOT, check=False, capture_output=True)
    assert completed.returncode == 1
    report = json.loads((output / "report.json").read_bytes())
    assert report["status"] == "controller_error"
    assert "requires isolated Python on native nonroot Linux ARM" in report["error"]
