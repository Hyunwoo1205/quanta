"""Local guards and fake clients only: no SSH server or genuine private key."""
import base64
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/oci/probe_login.py"
spec = importlib.util.spec_from_file_location("quanta_oci_login_probe", SCRIPT)
login = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login)
HOST = "8.8.8.8"  # Valid configuration fixture, never contacted.
PIN = "SHA256:" + base64.b64encode(bytes(range(32))).decode().rstrip("=")


def fake_key(version=3, newline="\n"):
    # Syntactic container only; neither public nor private bytes are an SSH key.
    return newline.join([
        f"PuTTY-User-Key-File-{version}: ssh-rsa", "Encryption: none",
        "Comment: synthetic-only-秘密", "Public-Lines: 1", "cHVibGlj",
        "Private-Lines: 1", "cHJpdmF0ZQ==",
        "Private-MAC: " + "0" * (40 if version == 2 else 64), "",
    ])


def config(**updates):
    environment = {"QUANTA_OCI_AUTH_CONFIRMED": "true", "QUANTA_OCI_HOST": HOST,
                   "QUANTA_OCI_HOST_KEY": PIN, "QUANTA_OCI_PPK": fake_key(),
                   "GITHUB_TOKEN": "must-not-reach-child", "OTHER_SECRET": "private"}
    environment.update(updates)
    return environment


def forbidden(*args, **kwargs):
    pytest.fail("invalid configuration must not launch a process")


@pytest.mark.parametrize("confirmation", [None, "", "false", "True", "TRUE", "1", " true", "true\n"])
def test_explicit_exact_opt_in_is_required_before_launch(confirmation):
    assert login.probe(config(QUANTA_OCI_AUTH_CONFIRMED=confirmation), runner=forbidden) == {
        "scope": "ssh_login_true", "status": "not_configured", "authentication_attempted": False,
    }


@pytest.mark.parametrize("host", [
    None, "", "example.com", "https://8.8.8.8", "8.8.8.8:22", "ubuntu@8.8.8.8",
    "8.8.8.8\n", "8.8.8.8;id", "-load", "008.8.8.8", "8.8.8", "134744072",
    "::1", "::ffff:8.8.8.8", "0.0.0.0", "10.0.0.1", "100.64.0.1",
    "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "192.0.2.1",
    "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
])
def test_bad_host_never_launches_client(host):
    issue = "host_missing" if host is None or host == "" else "host_invalid"
    assert login.probe(config(QUANTA_OCI_HOST=host), runner=forbidden) == login._report(
        "not_configured", configuration_issues=[issue])


@pytest.mark.parametrize("pin", [
    None, "", "*", "SHA256:*", "-hostkey",
    PIN + ",other", "SHA256:" + "a" * 42, "SHA256:" + "a" * 44,
    "SHA256:" + "a" * 42 + "!", "SHA256:" + "a" * 42 + "B",
    PIN + "=", "sha256:" + PIN[7:], "MD5:" + "aa:" * 16,
])
def test_invalid_fingerprint_is_rejected_before_client(pin):
    issue = "host_key_missing" if pin is None or pin == "" else "host_key_invalid"
    assert login.probe(config(QUANTA_OCI_HOST_KEY=pin), runner=forbidden) == login._report(
        "not_configured", configuration_issues=[issue])


@pytest.mark.parametrize("pin", [
    PIN, " " + PIN + " ", "\t\r\n" + PIN + "\r\n\f", PIN[7:],
    "256 " + PIN + " root@fixture (ED25519)",
    "4096\t" + PIN + "\troot@example (RSA)",
    "256 " + PIN, "1 " + PIN + " comment", "65536 " + PIN + " (RSA)",
    "256 " + PIN + " -proxycmd id", "256 " + PIN + " root@host -load session",
])
def test_supported_fingerprint_representations_use_only_canonical_pin(pin, capsys):
    def runner(argv, **kwargs):
        assert argv[argv.index("-hostkey") + 1] == PIN
        assert argv[-2:] == [HOST, "true"]
        assert "root@fixture" not in " ".join(argv)
        assert "-proxycmd" not in argv and "-load" not in argv
        return subprocess.CompletedProcess(argv, 0)

    report = login.probe(config(QUANTA_OCI_HOST_KEY=pin), runner=runner)
    assert report == login._report("success", True)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("pin", [
    "256 " + PIN + " another " + PIN,
    PIN + "\n" + PIN, "256\n" + PIN, "256 " + PIN + "\nroot@host (ED25519)",
    "junk " + PIN, "-hostkey " + PIN, "-proxycmd " + PIN, "MD5:" + "aa:" * 16,
    "256 MD5:" + "aa:" * 16, "256 " + PIN + " MD5:aa",
    "0 " + PIN, "65537 " + PIN, "999999 " + PIN, "0256 " + PIN,
    "256 " + PIN + "= root@host (ED25519)", PIN[7:] + "=",
    "256 " + "SHA256:" + "a" * 42 + "B root@host (ED25519)",
    "256 " + PIN + "\x00 root@host", "256 " + PIN + "\vroot@host",
    "256 " + PIN + " " + "x" * 1024,
])
def test_ambiguous_nonstandard_or_oversized_fingerprint_is_rejected(pin, capsys):
    assert login.probe(config(QUANTA_OCI_HOST_KEY=pin), runner=forbidden) == login._report(
        "not_configured", configuration_issues=["host_key_invalid"])
    assert capsys.readouterr() == ("", "")


def test_canonical_digest_validator_remains_strict():
    assert login._host_key(PIN)
    assert not login._host_key(" " + PIN)
    assert not login._host_key(PIN + "\n")
    assert not login._host_key(PIN[7:])
    assert not login._host_key("256 " + PIN + " root@host (ED25519)")


def test_normalization_preserves_a_different_digest_without_substitution():
    other_pin = "SHA256:" + base64.b64encode(bytes(reversed(range(32)))).decode().rstrip("=")
    assert other_pin != PIN
    assert login._normalized_host_key("256 " + other_pin + " ignored comment") == other_pin


@pytest.mark.parametrize("ppk", [
    None, "", "not a key", fake_key().replace("File-3", "File-1"),
    fake_key().replace("Encryption: none", "encryption: none"),
    fake_key().replace("Encryption: none", "Encryption: none "),
    fake_key().replace("Comment: ", ""), fake_key().replace("Public-Lines: 1", "Public-Lines: 0"),
    fake_key().replace("Public-Lines: 1", "Public-Lines: 9999"),
    fake_key().replace("cHVibGlj", "&&&"), fake_key().replace("cHJpdmF0ZQ==", "cHJpdmF0ZQ="),
    fake_key().replace("Private-Lines: 1", "Private-Lines: 2"),
    fake_key().replace("Private-MAC: ", "MAC: "), fake_key() + "trailing",
    fake_key() + "\x00", fake_key().replace("\n", "\r"), "x" * 32769,
    fake_key().replace("synthetic-only-秘密", "秘" * 12000), fake_key() + "\ud800",
])
def test_invalid_or_oversized_ppk_is_rejected_before_client(ppk):
    expected = "encrypted_key" if ppk == fake_key().replace("Encryption: none", "Encryption: none ") else "not_configured"
    issues = None if expected == "encrypted_key" else [
        "private_key_missing" if ppk is None or ppk == "" else "private_key_format_invalid"]
    assert login.probe(config(QUANTA_OCI_PPK=ppk), runner=forbidden) == login._report(
        expected, configuration_issues=issues)


def test_all_invalid_fields_are_reported_together_without_input_values(capsys):
    report = login.probe(config(QUANTA_OCI_HOST="secret.invalid",
                               QUANTA_OCI_HOST_KEY="private pin text",
                               QUANTA_OCI_PPK="private key text"), runner=forbidden)
    assert report == {
        "scope": "ssh_login_true", "status": "not_configured",
        "authentication_attempted": False,
        "configuration_issues": ["host_invalid", "host_key_invalid", "private_key_format_invalid"],
    }
    assert capsys.readouterr() == ("", "")
    serialized = json.dumps(report)
    assert "secret.invalid" not in serialized
    assert "private pin text" not in serialized
    assert "private key text" not in serialized


def test_all_missing_fields_are_reported_together():
    assert login.probe({"QUANTA_OCI_AUTH_CONFIRMED": "true"}, runner=forbidden) == {
        "scope": "ssh_login_true", "status": "not_configured",
        "authentication_attempted": False,
        "configuration_issues": ["host_missing", "host_key_missing", "private_key_missing"],
    }


def test_no_secret_field_is_read_without_explicit_opt_in():
    class GuardedEnvironment:
        def get(self, key):
            assert key == "QUANTA_OCI_AUTH_CONFIRMED"
            return "false"

    assert login.probe(GuardedEnvironment(), runner=forbidden) == login._report("not_configured")


@pytest.mark.parametrize("issue", [HOST, PIN, fake_key(), "unknown_issue"])
def test_diagnostic_report_never_accepts_arbitrary_values(issue):
    with pytest.raises(ValueError, match="invalid configuration diagnostic"):
        login._report("not_configured", configuration_issues=[issue])


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("encryption", ["aes256-cbc", "aes128-ctr"])
def test_encrypted_ppk_is_not_written_or_decrypted(version, encryption, monkeypatch):
    monkeypatch.setattr(login.tempfile, "TemporaryDirectory", forbidden)
    key = fake_key(version).replace("Encryption: none", "Encryption: " + encryption)
    assert login.probe(config(QUANTA_OCI_PPK=key), runner=forbidden) == login._report("encrypted_key")


@pytest.mark.parametrize("version,newline", [(2, "\n"), (3, "\n"), (3, "\r\n")])
@pytest.mark.parametrize("outcome,expected", [(0, "success"), (1, "failed"), (-9, "failed"),
                                             ("timeout", "timeout"), ("exception", "failed")])
def test_exact_client_command_private_files_minimal_env_and_cleanup(version, newline, outcome, expected, capsys):
    calls, paths = [], []
    key = fake_key(version, newline)

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        key_path = Path(argv[argv.index("-i") + 1])
        directory = key_path.parent
        paths.extend([key_path, directory])
        assert key_path.read_bytes() == key.encode("utf-8")
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert argv == ["/usr/bin/plink", "-ssh", "-2", "-4", "-batch", "-noagent",
                        "-no-trivial-auth", "-a", "-x", "-T", "-noshare", "-P", "22",
                        "-l", "ubuntu", "-i", str(key_path), "-hostkey", PIN, HOST, "true"]
        assert kwargs == {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                          "stderr": subprocess.DEVNULL, "timeout": 15, "check": False,
                          "shell": False, "env": {"HOME": str(directory),
                          "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, "cwd": str(directory)}
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(argv, 15, output=key, stderr=HOST)
        if outcome == "exception":
            raise RuntimeError(key + PIN + HOST)
        return subprocess.CompletedProcess(argv, outcome)

    report = login.probe(config(QUANTA_OCI_PPK=key), runner=runner)
    assert len(calls) == 1
    assert report == login._report(expected, True)
    assert report["requested_command"] == "true"
    assert "remote_command" not in report
    assert all(not path.exists() for path in paths)
    assert capsys.readouterr() == ("", "")
    assert HOST not in json.dumps(report) and PIN not in json.dumps(report)
    assert "server_modified" not in report


def test_client_cannot_start_is_not_reported_as_authentication(capsys):
    paths = []

    def runner(argv, **kwargs):
        paths.append(Path(argv[argv.index("-i") + 1]).parent)
        raise FileNotFoundError(HOST + fake_key())

    assert login.probe(config(), runner=runner) == login._report("failed")
    assert "requested_command" not in login._report("failed")
    assert "remote_command" not in login._report("failed")
    assert all(not path.exists() for path in paths)
    assert capsys.readouterr() == ("", "")


def test_local_private_file_error_is_sanitized_and_does_not_launch(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError(fake_key() + HOST)

    monkeypatch.setattr(login.os, "open", fail)
    assert login.probe(config(), runner=forbidden) == login._report("failed")
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("status,attempted,exit_code", [
    ("success", True, 0), ("not_configured", False, 2), ("encrypted_key", False, 2),
    ("failed", False, 2), ("failed", True, 2), ("timeout", True, 2),
])
def test_cli_prints_only_fixed_sanitized_json(monkeypatch, capsys, status, attempted, exit_code):
    monkeypatch.setattr(login, "probe", lambda: login._report(status, attempted))
    assert login.main() == exit_code
    captured = capsys.readouterr()
    assert json.loads(captured.out) == login._report(status, attempted)
    assert captured.err == ""


def test_cli_unexpected_failure_is_sanitized(monkeypatch, capsys):
    def fail():
        raise RuntimeError(fake_key() + HOST)

    monkeypatch.setattr(login, "probe", fail)
    assert login.main() == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == login._report("failed")
    assert captured.err == ""


def test_real_cli_without_opt_in_uses_no_key_path_or_client(tmp_path):
    result = subprocess.run([sys.executable, "-I", str(SCRIPT)], cwd=tmp_path,
                            env={"QUANTA_OCI_PPK": fake_key(),
                                 "QUANTA_OCI_HOST": HOST, "QUANTA_OCI_HOST_KEY": PIN},
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 2
    assert json.loads(result.stdout) == login._report("not_configured")
    assert result.stderr == ""
