"""The public single-evaluation boundary must not act like a protocol runner."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from quanta.evaluation import evaluate_experiment
from quanta.hashing import definition_sha256
from quanta.validation import validate_definition, validate_experiment

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def single():
    return json.loads((ROOT / "examples/pair_energy_forces.json").read_text())


def test_public_evaluation_calculates_and_keeps_input_immutable(single):
    before = copy.deepcopy(single)
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert report["calculation_executed"] is True
    assert report["input_validation_status"] == "pass"
    assert report["payload"]["energy_j"] == pytest.approx(4e-21, rel=1e-12, abs=0)
    assert report["payload"]["forces_n"][0][0] == pytest.approx(4e-11, rel=1e-12, abs=0)
    assert report["payload"]["forces_n"][1][0] == pytest.approx(-4e-11, rel=1e-12, abs=0)
    assert single == before


def test_public_evaluation_does_not_invent_execution_identity_or_validation(single):
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert report["physical_validation_status"] == "unvalidated"
    assert report["numerical_status"] == report["resolution_status"] == "not_applicable"
    assert report["input_sha256"] == definition_sha256(single["definition"])
    assert len(report["provenance"]["implementation_source_sha256"]) == 64
    assert report["provenance"]["source_file_sha256"]["autodiff.py"]
    assert report["particle_ids"] == ["p1", "p2"]
    assert not {"run_id", "state_id", "execution_fingerprint", "resolved_input_sha256"} & report.keys()
    assert all(w["code"] != "CONTRACT_VALIDATION_ONLY" for w in report["warnings"])


def test_public_evaluation_cli_completes(single, tmp_path):
    path = tmp_path / "single.json"
    path.write_text(json.dumps(single))
    command = subprocess.run([sys.executable, "-m", "quanta", "evaluate", str(path)],
                             text=True, capture_output=True)
    assert command.returncode == 0, command.stderr or command.stdout
    report = json.loads(command.stdout)
    assert report["evaluation_status"] == "SUCCEEDED"
    assert report["payload"]["evaluations"] == 1


@pytest.mark.parametrize("kind", ["workflow", "sweep", "override", "quantum"])
def test_public_evaluation_rejects_supported_input_that_needs_other_execution(single, kind):
    if kind == "workflow":
        single = json.loads((ROOT / "contracts/v0.2.0/examples/pair_revision.json").read_text())
    elif kind == "quantum":
        single = json.loads((ROOT / "contracts/v0.2.0/examples/quantum_revision.json").read_text())
    elif kind == "sweep":
        single["definition"]["protocol"]["sweep"]["axes"] = [
            {"path": "/system/potential/parameters/k", "values": [2, 3]}]
    else:
        single["definition"]["protocol"]["steps"][0]["overrides"] = [
            {"path": "/system/potential/parameters/k", "value": 3}]
    assert validate_experiment(single)["valid"]
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "FAILED"
    assert report["input_validation_status"] == "pass"
    assert report["payload"] is None and report["calculation_executed"] is False
    assert report["errors"][0]["code"] == "MODEL_UNSUPPORTED"


def test_public_evaluation_rejects_invalid_input_before_calculation(single):
    single["definition"]["system"]["particles"][1]["position_m"] = [0, 0, 0]
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "FAILED"
    assert report["input_validation_status"] == "failed"
    assert report["payload"] is None and report["calculation_executed"] is False
    assert report["errors"]


def test_public_evaluation_omits_unrequested_optional_data(single):
    single["definition"]["observables"] = ["energy", "forces"]
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert "pair_energies" not in report["payload"]
    assert "optimization_history" not in report["payload"]


def test_public_evaluation_rejects_nonbaseline_environment(single, monkeypatch):
    observed = {"valid": False, "versions": {}, "implementation": "CPython", "platform": {},
                "thread_environment": {}, "threadpools": [], "errors": [{"code": "ENV_VERSION"}]}
    monkeypatch.setattr("quanta.evaluation.environment_report", lambda: observed)
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "FAILED"
    assert report["calculation_executed"] is False
    assert report["errors"][0]["code"] == "MODEL_UNSUPPORTED"
    assert report["provenance"]["environment"]["baseline_matches"] is False


def test_definition_validation_needs_no_fabricated_ids(single):
    bare = validate_definition(single["definition"])
    full = validate_experiment(single)
    assert bare["valid"] and full["valid"]
    assert bare["input_sha256"] == full["input_sha256"]
    assert "experiment_id" not in bare and "revision_id" not in bare


@pytest.mark.parametrize("expression", [
    {"op": "mul", "args": [{"op": "const", "value": x} for x in [1e308, 1e308, 1e-308, 1e-308]]},
    {"op": "add", "args": [{"op": "const", "value": x} for x in [1e308, 1e308, -1e308, -1e308]]},
])
def test_value_only_validation_and_engine_agree_on_finite_cancellation(single, expression):
    single["definition"]["system"]["potential"]["expression"] = expression
    assert validate_experiment(single)["valid"]
    report = evaluate_experiment(single)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert all(value == 0 for force in report["payload"]["forces_n"] for value in force)


def test_validation_measures_separation_before_scaling_coordinates(single):
    definition = single["definition"]
    definition["scales"] = {"length_m": 3, "energy_j": 1}
    definition["system"]["potential"]["expression"] = {"op": "const", "value": 1}
    definition["system"]["particles"][0]["position_m"] = [1.5000000000000002, 0, 0]
    definition["system"]["particles"][1]["position_m"] = [1.5000000000000004, 0, 0]
    original = evaluate_experiment(single)
    for particle in definition["system"]["particles"]:
        particle["position_m"][0] -= 1.5
    translated = evaluate_experiment(single)
    assert original["evaluation_status"] == translated["evaluation_status"] == "SUCCEEDED"
    assert original["payload"]["energy_j"] == translated["payload"]["energy_j"] == 1
