"""User entry point keeps admission separate from executing a dynamics run."""
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace

from quanta import cli

ROOT = Path(__file__).resolve().parents[1]


def _example():
    value = json.loads((ROOT / "docs/design/pair-dynamics-v0.1/harmonic.request.json").read_text())
    value.pop("draft_schema_version")
    value["contract_version"] = "0.3.0"
    return value


def test_valid_dynamics_cli_is_not_a_simulation(monkeypatch, capsys):
    value = _example()
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=BytesIO(json.dumps(value).encode())))
    assert cli.main(["validate-dynamics", "-"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is True
    assert report["executable"] is False
    assert report["dynamics_simulation_executed"] is False
    assert report["input_sha256"]
    assert "payload" not in report or report["payload"] is None


def test_valid_dynamics_text_discloses_execution_unsupported(tmp_path, capsys):
    path = tmp_path / "request.json"
    path.write_text(json.dumps(_example()))
    assert cli.main(["validate-dynamics", str(path), "--format", "text"]) == 0
    output = capsys.readouterr().out
    assert "VALID_INPUT" in output
    assert "execution_supported: false" in output
    assert "dynamics_simulation_executed: false" in output


def test_dynamics_read_failure_is_structured(tmp_path, capsys):
    assert cli.main(["validate-dynamics", str(tmp_path / "absent.json")]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is False and report["executable"] is False
    assert report["errors"][0]["code"] == "INPUT_READ"


def test_dynamics_invalid_mass_is_not_admitted(tmp_path, capsys):
    value = deepcopy(_example())
    value["system"]["particles"][0]["mass_kg"] = 0
    path = tmp_path / "request.json"
    path.write_text(json.dumps(value))
    assert cli.main(["validate-dynamics", str(path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is False and report["errors"]
    assert report["dynamics_simulation_executed"] is False


def test_new_bundle_is_explicit_and_default_remains_old(capsys):
    assert cli.main(["check-contracts"]) == 0
    assert json.loads(capsys.readouterr().out)["contract_version"] == "0.2.0"
    assert cli.main(["check-contracts", "--contract-version", "0.3.0"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] and report["contract_version"] == "0.3.0"
    assert report["simulation_executed"] is False


def test_existing_execution_command_does_not_gain_dynamics_support(tmp_path, capsys):
    path = tmp_path / "standalone-request.json"
    path.write_text(json.dumps(_example()))
    assert cli.main(["run", str(path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report.get("result") is None
    assert report.get("errors")
