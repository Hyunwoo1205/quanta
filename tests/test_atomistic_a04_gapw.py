"""Regression coverage for the native GAPW runner's output directory."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace


def test_gapw_run_creates_the_log_directory(tmp_path, monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("a04_gapw", scripts / "run_atomistic_a04_gapw_ci.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    destination = tmp_path / "nested" / "evidence"
    monkeypatch.setattr(runner, "EVIDENCE", destination)

    def isolated_run(command, *, stdout, stderr, timeout):
        assert command[command.index("--platform") + 1] == "linux/amd64"
        stdout.write(b"test output\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", isolated_run)
    assert runner.run_container("image", tmp_path, tmp_path, "a" * 64, architecture="amd64") == 0
    assert (destination / "regtest.log").read_bytes() == b"test output\n"
