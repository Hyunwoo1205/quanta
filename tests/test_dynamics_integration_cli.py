"""Standalone time integration entry point, distinct from old workflow/API runs."""
import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

from quanta import cli
from quanta.dynamics_results import transport_bytes

ROOT=Path(__file__).resolve().parents[1]


def request(version="0.3.1"):
    value=json.loads((ROOT/"contracts/v0.3.0/examples/free.request.json").read_text())
    value["contract_version"]=version
    return value


def test_cli_integrates_new_standalone_request(monkeypatch,capsys):
    monkeypatch.setattr(cli.sys,"stdin",SimpleNamespace(buffer=BytesIO(json.dumps(request()).encode())))
    assert cli.main(["integrate-dynamics","-"])==0
    captured=capsys.readouterr()
    report=json.loads(captured.out)
    assert report["execution_status"]=="SUCCEEDED"
    assert report["dynamics_simulation_executed"] is True
    assert report["final_state"] is not None
    assert report["physical_validation_status"]=="unvalidated"
    assert captured.out.encode()==transport_bytes(report)
    assert len(captured.out.encode())==report["provenance"]["publication"]["report_transport_bytes"]


def test_cli_rejects_validation_only_request_without_conversion(tmp_path,capsys):
    path=tmp_path/"old-request.json"
    path.write_text(json.dumps(request("0.3.0")))
    assert cli.main(["integrate-dynamics",str(path)])==2
    report=json.loads(capsys.readouterr().out)
    assert report["execution_status"]=="FAILED"
    assert report["payload"] is None and report["final_state"] is None
    assert report["dynamics_simulation_executed"] is False
    assert report["errors"]


def test_cli_read_failure_has_registered_report_shape(tmp_path,capsys):
    from quanta.registry import ContractRegistry
    assert cli.main(["integrate-dynamics",str(tmp_path/"absent.json")])==2
    report=json.loads(capsys.readouterr().out)
    assert report["errors"][0]["code"]=="INPUT_READ"
    assert report["execution_status"]=="FAILED"
    ContractRegistry(contract_version="0.3.1").validator("dynamics_report.schema.json").validate(report)


def test_cli_text_reports_four_axes_and_steps(tmp_path,capsys):
    path=tmp_path/"request.json"
    path.write_text(json.dumps(request()))
    assert cli.main(["integrate-dynamics",str(path),"--format","text"])==0
    out=capsys.readouterr().out
    assert "SUCCEEDED" in out and "numerical_status: pass" in out
    assert "resolution_status: not_checked" in out
    assert "physical_validation_status: unvalidated" in out
    assert "leg[1]: 8/8 steps" in out


def test_cli_bundle_and_admission_versions_remain_explicit(tmp_path,capsys):
    assert cli.main(["check-contracts","--contract-version","0.3.1"])==0
    assert json.loads(capsys.readouterr().out)["contract_version"]=="0.3.1"
    path=tmp_path/"request.json"
    path.write_text(json.dumps(request()))
    assert cli.main(["validate-dynamics",str(path),"--format","text"])==0
    out=capsys.readouterr().out
    assert "execution_supported: true" in out
    assert "dynamics_simulation_executed: false" in out
