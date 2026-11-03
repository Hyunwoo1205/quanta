"""Public relaxation preserves convergence, execution and partial-result meanings."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from quanta.evaluation import evaluate_experiment, relax_experiment
from quanta.validation import validate_experiment

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def relaxation():
    return json.loads((ROOT / "examples/pair_relax.json").read_text())


def test_public_relaxation_converges_without_mutating_input(relaxation):
    before = copy.deepcopy(relaxation)
    report = relax_experiment(relaxation)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert report["calculation_executed"] and not report["partial"]
    assert report["input_validation_status"] == report["numerical_status"] == "pass"
    assert report["physical_validation_status"] == "unvalidated"
    assert report["resolution_status"] == "not_applicable"
    payload = report["payload"]
    assert payload["operation"] == "relax"
    assert payload["free_gradient_inf"] <= relaxation["definition"]["numerics"]["gradient_tolerance"]
    assert payload["minimum_confirmed"] is False
    assert payload["iterations"] >= 1 and payload["evaluations"] >= 2
    for i, particle in enumerate(before["definition"]["system"]["particles"]):
        for axis, fixed in enumerate(particle["fixed"]):
            if fixed:
                assert struct.pack("d", float(particle["position_m"][axis])) == struct.pack("d", payload["final_positions_m"][i][axis])
    assert relaxation == before
    assert not {"run_id", "state_id", "execution_fingerprint", "resolved_input_sha256"} & report.keys()


def test_public_budget_failure_keeps_accepted_partial_data(relaxation):
    relaxation["definition"]["numerics"]["max_evaluations"] = 1
    report = relax_experiment(relaxation)
    assert report["evaluation_status"] == "FAILED"
    assert report["partial"] and report["calculation_executed"]
    assert report["numerical_status"] == "not_converged"
    assert report["errors"][0]["code"] == "RESOURCE_LIMIT"
    assert report["errors"][0]["category"] == "resource"
    assert report["errors"][0]["step_id"] == "relax"
    assert report["payload"]["stop_reason"] == "evaluation_limit"
    assert report["payload"]["evaluations"] == 1
    assert report["payload"]["iterations"] == 0
    assert report["payload"]["initial_positions_m"] == report["payload"]["final_positions_m"]
    assert len(report["payload"]["optimization_history"]) == 1


def test_public_operational_failure_keeps_actual_numerical_status(relaxation, monkeypatch):
    from quanta import relaxation as engine
    from quanta.pair import _PreparedPair

    clock = [0.0]
    original = _PreparedPair.payload

    def delayed_payload(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if kwargs.get("stop_reason") == "gradient_tolerance":
            clock[0] = 61.0
        return result

    monkeypatch.setattr(engine.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(_PreparedPair, "payload", delayed_payload)
    report = relax_experiment(relaxation)
    assert report["evaluation_status"] == "FAILED"
    assert report["errors"][0]["code"] == "RESOURCE_LIMIT"
    assert report["partial"] and report["calculation_executed"]
    assert report["numerical_status"] == "pass"
    assert report["payload"]["free_gradient_inf"] <= relaxation["definition"]["numerics"]["gradient_tolerance"]
    assert report["payload"]["stop_reason"] == "wall_time_limit"
    assert report["payload"]["minimum_confirmed"] is False


def test_public_relaxation_rejects_all_fixed_before_calculation(relaxation):
    for particle in relaxation["definition"]["system"]["particles"]:
        particle["fixed"] = [True, True, True]
    report = relax_experiment(relaxation)
    assert report["evaluation_status"] == "FAILED"
    assert report["input_validation_status"] == "failed"
    assert report["payload"] is None
    assert report["calculation_executed"] is False and not report["partial"]
    assert report["numerical_status"] == "not_checked"


@pytest.mark.parametrize("kind", ["workflow", "sweep", "override", "energy_only", "quantum"])
def test_public_relaxation_does_not_partly_run_unsupported_protocol(relaxation, kind):
    if kind == "workflow":
        relaxation = json.loads((ROOT / "contracts/v0.2.0/examples/pair_revision.json").read_text())
    elif kind == "energy_only":
        relaxation = json.loads((ROOT / "examples/pair_energy_forces.json").read_text())
    elif kind == "quantum":
        relaxation = json.loads((ROOT / "contracts/v0.2.0/examples/quantum_revision.json").read_text())
    elif kind == "sweep":
        relaxation["definition"]["protocol"]["sweep"]["axes"] = [
            {"path": "/system/potential/parameters/k", "values": [2, 3]}]
    else:
        relaxation["definition"]["protocol"]["steps"][0]["overrides"] = [
            {"path": "/system/potential/parameters/k", "value": 3}]
    assert validate_experiment(relaxation)["valid"]
    report = relax_experiment(relaxation)
    assert report["evaluation_status"] == "FAILED"
    assert report["errors"][0]["code"] == "MODEL_UNSUPPORTED"
    assert report["payload"] is None and not report["partial"]
    assert report["calculation_executed"] is False


def test_energy_evaluation_command_does_not_implicitly_relax(relaxation):
    report = evaluate_experiment(relaxation)
    assert report["evaluation_status"] == "FAILED"
    assert report["errors"][0]["code"] == "MODEL_UNSUPPORTED"
    assert report["payload"] is None


@pytest.mark.parametrize("limited", [False, True])
def test_relaxation_cli_success_and_partial_failure_are_distinct(relaxation, tmp_path, limited):
    if limited:
        relaxation["definition"]["numerics"]["max_evaluations"] = 1
    path = tmp_path / "relaxation.json"
    path.write_text(json.dumps(relaxation))
    completed = subprocess.run([sys.executable, "-m", "quanta", "relax", str(path)],
                               text=True, capture_output=True)
    assert completed.returncode == (2 if limited else 0), completed.stderr
    report = json.loads(completed.stdout)
    assert report["evaluation_status"] == ("FAILED" if limited else "SUCCEEDED")
    assert report["partial"] is limited
    assert report["numerical_status"] == ("not_converged" if limited else "pass")


def test_relaxation_cli_missing_file_is_a_structured_failure(tmp_path):
    completed = subprocess.run([sys.executable, "-m", "quanta", "relax", str(tmp_path / "missing.json")],
                               text=True, capture_output=True)
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["evaluation_status"] == "FAILED"
    assert report["errors"][0]["code"] == "INPUT_READ"
    assert not report["partial"] and report["payload"] is None
    assert report["numerical_status"] == "not_checked"
    assert report["input_validation_status"] == "failed"
    assert report["resolution_status"] == "not_applicable"
