"""Local request authorization only; no key, SSH client, or network access."""
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/authorize_login.py"
spec = importlib.util.spec_from_file_location("quanta_login_request", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
IDENTIFIER = "9a4c12c9-70ba-4f7e-ae03-f1cbb0536253"
VALID = {"schema_version": 1, "operation": "login-check", "request_id": IDENTIFIER}


def metadata(event="push", ref="refs/heads/ops/oci", confirm="false"):
    return {"QUANTA_OCI_EVENT": event, "QUANTA_OCI_REF": ref,
            "QUANTA_OCI_MANUAL_CONFIRM": confirm}


@pytest.mark.parametrize("event,ref,confirm", itertools.product(
    ["push", "workflow_dispatch", "pull_request", "workflow_run", None],
    ["refs/heads/main", "refs/heads/ops/oci", "refs/heads/untrusted", "main", None],
    ["true", "false", "True", None],
))
def test_event_ref_confirmation_cross_product(event, ref, confirm, tmp_path):
    path = tmp_path / "request.json"
    path.write_text(json.dumps(VALID))
    report = gate.authorize(metadata(event, ref, confirm), request_path=path)
    expected = ((event == "workflow_dispatch" and ref == "refs/heads/main" and confirm == "true")
                or (event == "push" and ref == "refs/heads/ops/oci"))
    assert report["status"] == ("authorized" if expected else "denied")
    assert ("request_id" in report) == (expected and event == "push")


def test_metadata_only_reads_the_three_declared_keys(tmp_path):
    class GuardedMetadata(dict):
        def get(self, key, *args):
            assert key in {"QUANTA_OCI_EVENT", "QUANTA_OCI_REF", "QUANTA_OCI_MANUAL_CONFIRM"}
            return super().get(key, *args)

    assert gate.authorize(GuardedMetadata(metadata("workflow_dispatch", "refs/heads/main", "true"))) == gate._report(True)


def test_manual_authorization_does_not_open_the_push_request(monkeypatch):
    monkeypatch.setattr(gate, "_request_id", lambda path: pytest.fail("manual mode must not read a request"))
    assert gate.authorize(metadata("workflow_dispatch", "refs/heads/main", "true")) == gate._report(True)
    assert gate.authorize(metadata("workflow_dispatch", "refs/heads/main", "true\n")) == gate._report(False)


@pytest.mark.parametrize("payload", [
    {}, [], None, "anything", {**VALID, "extra": 0},
    {key: value for key, value in VALID.items() if key != "operation"},
    {**VALID, "schema_version": True}, {**VALID, "schema_version": 1.0},
    {**VALID, "schema_version": "1"}, {**VALID, "schema_version": 2},
    {**VALID, "operation": "runner-check"}, {**VALID, "operation": "ssh"},
    {**VALID, "operation": ["login-check"]}, {**VALID, "request_id": None},
    {**VALID, "request_id": IDENTIFIER.upper()}, {**VALID, "request_id": "{" + IDENTIFIER + "}"},
    {**VALID, "request_id": IDENTIFIER.replace("-", "")},
    {**VALID, "request_id": IDENTIFIER + "\n"}, {**VALID, "request_id": "secret-value"},
])
def test_strict_fixed_schema_rejects_other_requests_without_echo(payload, tmp_path, capsys):
    path = tmp_path / "request.json"
    path.write_text(json.dumps(payload))
    assert gate.authorize(metadata(), request_path=path) == gate._report(False)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("raw", [
    b"", b"not-json-secret", b"\xff", b"[]{}", b"{}\n{}", b"{" * 1025,
    ('{"schema_version":1,"operation":"ssh","operation":"login-check",'
     '"request_id":"' + IDENTIFIER + '"}').encode(),
    ('{"schema_version":1,"schema_version":1,"operation":"login-check",'
     '"request_id":"' + IDENTIFIER + '"}').encode(),
])
def test_malformed_duplicate_or_oversized_file_is_sanitized(raw, tmp_path, capsys):
    path = tmp_path / "request.json"
    path.write_bytes(raw)
    assert gate.authorize(metadata(), request_path=path) == gate._report(False)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("length,expected", [(1024, True), (1025, False)])
def test_byte_boundary_is_inclusive_and_bounded(length, expected, tmp_path):
    raw = json.dumps(VALID).encode()
    path = tmp_path / "request.json"
    path.write_bytes(raw + b" " * (length - len(raw)))
    assert gate.authorize(metadata(), request_path=path) == gate._report(expected, IDENTIFIER if expected else None)


def test_missing_directory_and_symlink_are_denied(tmp_path):
    path = tmp_path / "request.json"
    assert gate.authorize(metadata(), request_path=path) == gate._report(False)
    assert gate.authorize(metadata(), request_path=tmp_path) == gate._report(False)
    target = tmp_path / "public.json"
    target.write_text(json.dumps(VALID))
    path.symlink_to(target)
    assert gate.authorize(metadata(), request_path=path) == gate._report(False)


def test_cli_cannot_override_the_fixed_push_request_path(tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps(VALID))
    env = metadata()
    env["QUANTA_OCI_REQUEST_PATH"] = str(other)
    result = subprocess.run([sys.executable, "-I", str(SCRIPT), str(other)], cwd=tmp_path,
                            env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 2
    assert json.loads(result.stdout) == gate._report(False)
    assert result.stderr == ""


def test_real_cli_valid_push_reads_only_fixed_path(tmp_path):
    path = tmp_path / ".github/oci/login-request.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(VALID))
    result = subprocess.run([sys.executable, "-I", str(SCRIPT)], cwd=tmp_path,
                            env=metadata(), capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert json.loads(result.stdout) == gate._report(True, IDENTIFIER)
    assert result.stderr == ""


def test_real_cli_missing_metadata_denies(tmp_path):
    result = subprocess.run([sys.executable, "-I", str(SCRIPT)], cwd=tmp_path,
                            env={}, capture_output=True, text=True, timeout=5)
    assert result.returncode == 2
    assert json.loads(result.stdout) == gate._report(False)
    assert result.stderr == ""


def test_unexpected_failure_main_has_no_exception_or_value_echo(monkeypatch, capsys):
    def fail():
        raise RuntimeError("private-value")

    monkeypatch.setattr(gate, "authorize", fail)
    assert gate.main() == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == gate._report(False)
    assert captured.err == ""
