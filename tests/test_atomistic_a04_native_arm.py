import copy
import json
from pathlib import Path

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
