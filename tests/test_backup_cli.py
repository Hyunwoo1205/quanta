"""Operator commands expose checked snapshots without overwriting a store."""
import json

from quanta.cli import main
from quanta.job_store import JobStore


def test_operator_backup_verify_restore_and_existing_target_refusal(tmp_path, capsys):
    source, backup, restored = (tmp_path / name for name in ("source", "snapshot", "restored"))
    store = JobStore(source)
    record = store.create_experiment("local", "보존할 실험")
    assert main(["backup-store", "--store", str(source), "--output", str(backup)]) == 0
    snapshot = json.loads(capsys.readouterr().out)
    assert main(["verify-backup", str(backup)]) == 0
    assert json.loads(capsys.readouterr().out) == snapshot
    assert main(["restore-store", str(backup), "--output", str(restored)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["restored"] and not result["worker_started"]
    recovered = JobStore(restored)
    assert recovered.get_experiment("local", record["experiment_id"]) == record
    assert main(["restore-store", str(backup), "--output", str(source)]) == 2
    assert "must not already exist" in capsys.readouterr().err
    assert store.get_experiment("local", record["experiment_id"]) == record


def test_missing_source_is_reported_without_creating_a_store(tmp_path, capsys):
    missing = tmp_path / "missing"
    assert main(["backup-store", "--store", str(missing), "--output", str(tmp_path / "snapshot")]) == 2
    assert not missing.exists()
    assert capsys.readouterr().err
