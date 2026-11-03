"""Stable user entry-point failures return structured output and exit code 2."""

from importlib.metadata import version
from io import BytesIO
import json
from types import SimpleNamespace

import pytest

from quanta import __version__
from quanta import cli


def test_check_contracts_missing_snapshot_returns_structured_error(monkeypatch, capsys):
    def missing_registry(*args, **kwargs):
        raise FileNotFoundError("Synthetic missing registry snapshot")

    monkeypatch.setattr(cli, "ContractRegistry", missing_registry)
    assert cli.main(["check-contracts"]) == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["valid"] is False
    assert any(error["code"] == "REGISTRY_SNAPSHOT_UNAVAILABLE" for error in report["errors"])
    assert report["physical_validation_status"] == "unvalidated"
    assert "Traceback" not in captured.err


def test_validate_missing_file_returns_input_read_error(tmp_path, capsys):
    assert cli.main(["validate", str(tmp_path / "does-not-exist.json")]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is False
    assert report["input_sha256"] is None
    assert any(error["code"] == "INPUT_READ" for error in report["errors"])
    assert report["physical_validation_status"] == "unvalidated"


def test_validate_malformed_stdin_returns_schema_error(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=BytesIO(b'{"schema_version":')))
    assert cli.main(["validate", "-"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is False
    assert report["input_sha256"] is None
    assert any(error["code"] == "INPUT_SCHEMA" for error in report["errors"])
    assert report["physical_validation_status"] == "unvalidated"


def test_cli_version_matches_installed_distribution(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == __version__ == version("quanta-research-contracts")
