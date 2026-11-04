"""Public stationary-state execution keeps numerical and grid evidence separate."""
import copy
import json
import math
from pathlib import Path
import subprocess
import sys

import pytest

from quanta.evaluation import eigenstates_experiment, evaluate_experiment, relax_experiment
from quanta.validation import validate_experiment

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def experiment():
    return json.loads((ROOT / "examples/quantum_eigenstates.json").read_text())


def test_public_eigenstates_solves_without_mutating_input(experiment):
    before = copy.deepcopy(experiment)
    report = eigenstates_experiment(experiment)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert report["input_validation_status"] == report["numerical_status"] == report["resolution_status"] == "pass"
    assert report["physical_validation_status"] == "unvalidated"
    assert report["calculation_executed"] and not report["partial"]
    payload = report["payload"]
    assert len(payload["energies_j"]) == 4
    assert len(payload["x_m"]) == 1025
    assert [g["n_points"] for g in payload["grid_results"]] == [255, 511, 1023]
    hbar = 6.62607015e-34 / (2 * math.pi)
    system = before["definition"]["system"]
    width = system["domain"]["b_m"] - system["domain"]["a_m"]
    for j, energy in enumerate(payload["energies_j"], 1):
        expected = hbar**2 * (j * math.pi / width)**2 / (2 * system["mass_kg"])
        assert abs(energy / expected - 1) <= 2e-5
    assert experiment == before
    assert "quantum.py" in report["provenance"]["source_file_sha256"]
    assert not {"run_id", "state_id", "execution_fingerprint", "resolved_input_sha256", "particle_ids"} & report.keys()


def test_public_no_refinement_is_success_without_resolution_claim(experiment):
    experiment["definition"]["numerics"]["refinement_levels"] = 0
    report = eigenstates_experiment(experiment)
    assert report["evaluation_status"] == "SUCCEEDED", report["errors"]
    assert report["numerical_status"] == "pass"
    assert report["resolution_status"] == "not_checked"
    assert len(report["payload"]["grid_results"]) == 1


def test_public_final_timeout_preserves_verified_numerical_and_resolution_axes(experiment, monkeypatch):
    from quanta import quantum

    experiment["definition"]["numerics"].update(n_points=31, refinement_levels=1, grid_energy_rtol=1.0)
    clock, calls = [0.0], [0]
    original = quantum._check_payload

    def final_timeout(*args, **kwargs):
        original(*args, **kwargs)
        calls[0] += 1
        if calls[0] == 3:
            clock[0] = 61.0

    monkeypatch.setattr(quantum.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(quantum, "_check_payload", final_timeout)
    report = eigenstates_experiment(experiment)
    assert report["evaluation_status"] == "FAILED"
    assert report["errors"][0]["code"] == "RESOURCE_LIMIT"
    assert report["partial"] and report["calculation_executed"]
    assert report["numerical_status"] == report["resolution_status"] == "pass"
    assert len(report["payload"]["grid_results"]) == 2


def test_public_grid_nonconvergence_preserves_valid_partial_solution(experiment):
    experiment["definition"]["numerics"].update(n_points=31, refinement_levels=1,
        grid_energy_atol=1e-14, grid_energy_rtol=1e-14)
    report = eigenstates_experiment(experiment)
    assert report["evaluation_status"] == "FAILED"
    assert report["input_validation_status"] == report["numerical_status"] == "pass"
    assert report["resolution_status"] == "not_converged"
    assert report["calculation_executed"] and report["partial"]
    assert report["errors"][0]["code"] == "NUM_NOT_CONVERGED"
    assert report["errors"][0]["category"] == "numerical"
    assert report["errors"][0]["step_id"] == "spectrum"
    assert len(report["payload"]["x_m"]) == 65


@pytest.mark.parametrize("kind", ["workflow", "override", "sweep", "pair"])
def test_public_eigenstates_rejects_unsupported_execution_scope(experiment, kind):
    definition = experiment["definition"]
    protocol = definition["protocol"]
    if kind == "workflow":
        other = copy.deepcopy(protocol["steps"][0])
        other["step_id"] = "independent"
        protocol["steps"].append(other)
    elif kind == "override":
        protocol["steps"][0]["overrides"] = [{"path": "/system/mass_kg", "value": 2e-30}]
    elif kind == "sweep":
        protocol["sweep"]["axes"] = [{"path": "/system/mass_kg", "values": [1e-30, 2e-30]}]
    else:
        experiment = json.loads((ROOT / "examples/pair_energy_forces.json").read_text())
    assert validate_experiment(experiment)["valid"]
    report = eigenstates_experiment(experiment)
    assert report["errors"][0]["code"] == "MODEL_UNSUPPORTED"
    assert report["input_validation_status"] == "pass"
    assert not report["calculation_executed"] and not report["partial"]
    assert report["payload"] is None
    assert report["numerical_status"] == report["resolution_status"] == "not_checked"


@pytest.mark.parametrize("function", [evaluate_experiment, relax_experiment])
def test_other_commands_do_not_implicitly_solve_quantum_input(experiment, function):
    report = function(experiment)
    assert report["errors"][0]["code"] == "MODEL_UNSUPPORTED"
    assert report["payload"] is None and not report["calculation_executed"]


def test_invalid_grid_is_rejected_before_calculation(experiment):
    experiment["definition"]["numerics"]["n_points"] = 4095
    report = eigenstates_experiment(experiment)
    assert report["input_validation_status"] == "failed"
    assert report["evaluation_status"] == "FAILED"
    assert report["payload"] is None and not report["partial"]
    assert report["numerical_status"] == report["resolution_status"] == "not_checked"


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_eigenstates_cli_file_and_stdin(experiment, tmp_path, output_format):
    experiment["definition"]["numerics"].update(n_points=31, refinement_levels=0)
    raw = json.dumps(experiment)
    path = tmp_path / "quantum.json"
    path.write_text(raw)
    file_arg = str(path) if output_format == "text" else "-"
    completed = subprocess.run([sys.executable, "-m", "quanta", "eigenstates", file_arg,
                                "--format", output_format], input=raw, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    if output_format == "json":
        report = json.loads(completed.stdout)
        assert report["evaluation_status"] == "SUCCEEDED"
        assert report["resolution_status"] == "not_checked"
    else:
        assert "SUCCEEDED" in completed.stdout
        assert "energies_j:" in completed.stdout
        assert "resolution_status: not_checked" in completed.stdout


def test_eigenstates_cli_grid_failure_and_missing_input(experiment, tmp_path):
    experiment["definition"]["numerics"].update(n_points=31, refinement_levels=1,
        grid_energy_atol=1e-14, grid_energy_rtol=1e-14)
    path = tmp_path / "quantum.json"
    path.write_text(json.dumps(experiment))
    failed = subprocess.run([sys.executable, "-m", "quanta", "eigenstates", str(path)],
                            text=True, capture_output=True)
    assert failed.returncode == 2
    report = json.loads(failed.stdout)
    assert report["partial"] and report["resolution_status"] == "not_converged"
    missing = subprocess.run([sys.executable, "-m", "quanta", "eigenstates", str(tmp_path / "missing.json")],
                             text=True, capture_output=True)
    assert missing.returncode == 2
    report = json.loads(missing.stdout)
    assert report["errors"][0]["code"] == "INPUT_READ"
    assert report["numerical_status"] == report["resolution_status"] == "not_checked"
    assert report["payload"] is None and not report["calculation_executed"]
