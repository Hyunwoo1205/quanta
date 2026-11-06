"""Fixed recovery gates and transport; synthetic credentials and no OCI access."""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/oci"


def load(name):
    spec = importlib.util.spec_from_file_location("quanta_recovery_test_" + name, DEPLOY / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load("authorize_recovery")
probe = load("probe_recovery")
login = load("probe_login")
SHA = "a" * 40
RUN = 42130000000
REQUEST_ID = "b0d1ce2d-518b-4ef2-9e16-ef3683dd79ca"
PIN = "SHA256:" + base64.b64encode(bytes(range(32))).decode().rstrip("=")
KEY = "\n".join(["PuTTY-User-Key-File-3: ssh-rsa", "Encryption: none", "Comment: synthetic-fixture",
                  "Public-Lines: 1", "cHVibGlj", "Private-Lines: 1", "cHJpdmF0ZQ==",
                  "Private-MAC: " + "0" * 64, ""])


def request(operation="audit-recovery"):
    return {"schema_version": 1, "operation": operation, "source_sha": gate.SOURCE_SHA,
            "request_id": REQUEST_ID}


def metadata():
    return {"GITHUB_REPOSITORY": "Hyunwoo1205/quanta", "GITHUB_REF": "refs/heads/ops/oci",
            "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "b" * 40,
            "QUANTA_CONTROL_SHA": SHA, "QUANTA_CONTROL_CI_RUN": str(RUN),
            "QUANTA_CI_READ_TOKEN": "synthetic-ci-read-token"}


def credentials(operation="audit-recovery"):
    return {"QUANTA_OCI_AUTH_CONFIRMED": "true", "QUANTA_OCI_INSTALL_OPERATION": operation,
            "QUANTA_OCI_HOST": "8.8.8.8", "QUANTA_OCI_HOST_KEY": PIN, "QUANTA_OCI_PPK": KEY,
            "QUANTA_PUBLIC_ORIGIN": "https://app.example.net", "QUANTA_AUTH_MODE": "owner-token",
            "QUANTA_CONTROL_SHA": SHA, "QUANTA_CONTROL_CI_RUN": str(RUN),
            "UNRELATED_SECRET": "private-never-forward"}


def ci(run=RUN, sha=SHA, path=gate.CONTROL_WORKFLOW):
    return {"id": run, "head_sha": sha, "head_branch": "main", "event": "push", "path": path,
            "status": "completed", "conclusion": "success"}


def ciphertext_fixture():
    payload = bytes.fromhex("060b2a864886f70d0109100117") + b"synthetic-encrypted-payload" * 4
    return b"\x30" + bytes([len(payload)]) + payload


class Response:
    def __init__(self, value, *, url, status=200, raw=None):
        self.raw = json.dumps(value).encode() if raw is None else raw
        self.url, self.status = url, status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, limit):
        return self.raw[:limit]


class GateTests(unittest.TestCase):
    def parse_request(self, value=None, *, raw=None, environ=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_bytes(json.dumps(value).encode() if raw is None else raw)
            return gate.read_request(path, metadata() if environ is None else environ)

    def test_only_fixed_operations_and_deployed_app_source(self):
        self.assertEqual(gate.SOURCE_SHA, probe.SOURCE_SHA)
        self.assertEqual(gate.OPERATIONS, set(probe.OPERATIONS))
        for operation in gate.OPERATIONS:
            self.assertEqual(self.parse_request(request(operation)), request(operation))
        for value in [[], {}, None, {**request(), "command": "reboot"},
                      {**request(), "source_sha": SHA}, {**request(), "schema_version": True},
                      {**request(), "operation": "shutdown"},
                      {**request(), "operation": ["audit-recovery"]},
                      {**request(), "request_id": REQUEST_ID.upper()},
                      {**request(), "request_id": "00000000-0000-0000-0000-000000000000"}]:
            with self.subTest(value=repr(value)[:80]), self.assertRaises((ValueError, TypeError)):
                self.parse_request(value)

    def test_scope_denied_before_request_read(self):
        for key, value in (("GITHUB_REPOSITORY", "other/quanta"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_EVENT_NAME", "workflow_dispatch")):
            with mock.patch.object(Path, "lstat", side_effect=AssertionError("must not read")), \
                    self.assertRaises(ValueError):
                gate.read_request(Path("missing"), {**metadata(), key: value})

    def test_duplicate_nonfinite_junk_and_oversized_requests_rejected(self):
        valid = json.dumps(request()).encode()
        for raw in [b"", b"\xff", b" " * 1025, valid + b"{}",
                    valid[:-1] + b',"operation":"prepare-recovery"}',
                    valid.replace(b'"schema_version": 1', b'"schema_version": NaN')]:
            with self.subTest(length=len(raw)), self.assertRaises((ValueError, UnicodeError)):
                self.parse_request(raw=raw)
        self.assertEqual(self.parse_request(raw=valid + b" " * (1024 - len(valid))), request())

    def test_symlink_hardlink_and_nonfile_requests_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text(json.dumps(request()))
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                gate.read_request(link, metadata())
            parent = root / "alias"
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                gate.read_request(parent / "target", metadata())
            with self.assertRaises(ValueError):
                gate.read_request(root, metadata())
            os.link(target, root / "hard")
            with self.assertRaises(ValueError):
                gate.read_request(target, metadata())

    def test_control_pin_requires_exact_sha_and_run_id(self):
        self.assertEqual(gate.control_pin(metadata()), (SHA, RUN))
        for key, values in {"QUANTA_CONTROL_SHA": [None, "A" * 40, "a" * 39, SHA + "\n"],
                            "QUANTA_CONTROL_CI_RUN": [None, "0", "01", "1\n", str(2**63)]}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    gate.control_pin({**metadata(), key: value})

    def test_control_head_is_checked_separately_from_ops_event_head_with_clean_git_environment(self):
        runner = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout=(SHA + "\n").encode()))
        self.assertTrue(gate.control_checkout_matches(metadata(), runner=runner))
        arguments, kwargs = runner.call_args_list[0]
        self.assertEqual(arguments[0], ["/usr/bin/git", "-C", str(gate.CONTROL_ROOT),
                                        "rev-parse", "--verify", "HEAD"])
        self.assertEqual(kwargs["timeout"], 5)
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("QUANTA_CI_READ_TOKEN", kwargs["env"])
        self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertIn("--no-ext-diff", runner.call_args_list[1].args[0])
        self.assertIn("--no-textconv", runner.call_args_list[1].args[0])
        runner.side_effect = [types.SimpleNamespace(returncode=0, stdout=(SHA + "\n").encode()),
                              types.SimpleNamespace(returncode=1)]
        self.assertFalse(gate.control_checkout_matches(metadata(), runner=runner))
        runner.side_effect = None
        for code, output in [(1, (SHA + "\n").encode()), (0, b"b" * 40 + b"\n"),
                             (0, (SHA + "\nextra").encode())]:
            runner.return_value = types.SimpleNamespace(returncode=code, stdout=output)
            self.assertFalse(gate.control_checkout_matches(metadata(), runner=runner))

    def test_each_ci_proof_is_exact_and_redirects_junk_missing_token_fail_closed(self):
        url = gate.API_ROOT + str(RUN)
        seen = []

        def opener(req, **kwargs):
            seen.append((req, kwargs))
            return Response(ci(), url=url)

        self.assertTrue(gate.ci_passed(RUN, SHA, gate.CONTROL_WORKFLOW, metadata(), opener=opener))
        self.assertEqual(seen[0][0].full_url, url)
        self.assertEqual(seen[0][1], {"timeout": 10})
        for key, values in {"id": [True, RUN + 1], "head_sha": [gate.SOURCE_SHA],
                            "head_branch": ["ops/oci"], "event": ["pull_request"],
                            "path": [".github/workflows/ci.yml"], "status": ["in_progress"],
                            "conclusion": ["failure", None]}.items():
            for value in values:
                changed = {**ci(), key: value}
                with self.subTest(key=key, value=value):
                    self.assertFalse(gate.ci_passed(RUN, SHA, gate.CONTROL_WORKFLOW, metadata(),
                        opener=lambda req, **kwargs: Response(changed, url=url)))
        for response in [Response(ci(), url=url + "/redirect"), Response(ci(), url=url, status=302),
                         Response(ci(), url=url, raw=b" " * (gate.MAX_RESPONSE + 1)),
                         Response(ci(), url=url, raw=b' {"id":NaN}'),
                         Response(ci(), url=url, raw=json.dumps(ci()).encode()[:-1] + b',"id":1}')]:
            self.assertFalse(gate.ci_passed(RUN, SHA, gate.CONTROL_WORKFLOW, metadata(),
                                          opener=lambda req, **kwargs: response))
        with mock.patch.object(gate.urllib.request, "build_opener", side_effect=AssertionError("must not connect")):
            self.assertFalse(gate.ci_passed(RUN, SHA, gate.CONTROL_WORKFLOW, {}))
        self.assertIsNone(gate.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_actual_git_checkout_requires_exact_head_and_unmodified_tracked_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*arguments):
                return subprocess.run(["/usr/bin/git", "-C", str(root), *arguments], check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      stdin=subprocess.DEVNULL, timeout=5).stdout
            git("init", "-q")
            tracked = root / "collector.py"
            tracked.write_text("# fixed control fixture\n")
            git("add", "collector.py")
            git("-c", "user.name=Quanta Test", "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-qm", "Test-only control fixture")
            sha = git("rev-parse", "HEAD").decode().strip()
            env = {**metadata(), "QUANTA_CONTROL_SHA": sha}
            self.assertTrue(gate.control_checkout_matches(env, root=root))
            self.assertFalse(gate.control_checkout_matches({**env, "QUANTA_CONTROL_SHA": "0" * 40}, root=root))
            tracked.write_text("# altered tracked bytes\n")
            self.assertFalse(gate.control_checkout_matches(env, root=root))
            git("add", "collector.py")
            self.assertFalse(gate.control_checkout_matches(env, root=root))

    def test_authorization_orders_both_ci_checks_and_never_uses_ssh_credentials(self):
        env = {**metadata(), "QUANTA_OCI_PPK": "private-must-not-read"}
        with mock.patch.object(gate, "read_request", return_value=request()), \
                mock.patch.object(gate, "control_checkout_matches", return_value=True), \
                mock.patch.object(gate, "ci_passed", side_effect=[True, True]) as passed:
            result = gate.authorize(env)
        self.assertEqual(result["status"], "authorized")
        self.assertEqual(passed.call_args_list[0].args[:3],
                         (gate.APP_CI_RUN, gate.SOURCE_SHA, ".github/workflows/ci.yml"))
        self.assertEqual(passed.call_args_list[1].args[:3], (RUN, SHA, gate.CONTROL_WORKFLOW))
        self.assertNotIn("private", json.dumps(result))
        for outcome, expected, calls in [([False], "app_ci", 1), ([True, False], "control_ci", 2)]:
            with mock.patch.object(gate, "read_request", return_value=request()), \
                    mock.patch.object(gate, "control_checkout_matches", return_value=True), \
                    mock.patch.object(gate, "ci_passed", side_effect=outcome) as passed:
                self.assertEqual(gate.authorize(env)["stage"], expected)
                self.assertEqual(passed.call_count, calls)
        with mock.patch.object(gate, "read_request", return_value=request()), \
                mock.patch.object(gate, "control_checkout_matches", return_value=False), \
                mock.patch.object(gate, "ci_passed") as passed:
            self.assertEqual(gate.authorize(env)["stage"], "control_checkout")
        passed.assert_not_called()

    def test_main_emits_only_fixed_outputs_and_denials_hide_exception_text(self):
        ok = {"scope": "recovery_request", "status": "authorized", "operation": "audit-recovery",
              "request_id": REQUEST_ID}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True), \
                    mock.patch.object(gate.sys, "argv", ["authorize_recovery.py"]), \
                    mock.patch.object(gate, "authorize", return_value=ok), \
                    contextlib.redirect_stdout(io.StringIO()) as text:
                self.assertEqual(gate.main(), 0)
            self.assertEqual(json.loads(text.getvalue()), ok)
            self.assertEqual(output.read_text(), "operation=audit-recovery\nrequest_id=" + REQUEST_ID + "\n")
        with mock.patch.object(gate, "read_request", side_effect=ValueError("untrusted-private-text")):
            self.assertEqual(gate.authorize()["stage"], "request")


class TransportTests(unittest.TestCase):
    @contextlib.contextmanager
    def modules(self, *, match=True, sanitizer=None, validator=None, action=None):
        expected = {"scope": "fixture", "status": "success"}
        if action is not None:
            expected["action"] = action
        if sanitizer is None:
            def sanitizer(raw):
                try:
                    value = json.loads(raw)
                    return value if value == expected else None
                except Exception:
                    return None
        audit = types.SimpleNamespace(validate_config=validator or (lambda value: value),
                                      sanitize_report=sanitizer)
        source = "# fixed single-file collector\nprint('fixture')\n"
        gate_module = types.SimpleNamespace(control_checkout_matches=mock.Mock(return_value=match))
        transport = types.SimpleNamespace(_capture=mock.Mock(return_value=("success", json.dumps(expected).encode(), True)))
        mapping = {"authorize_recovery": gate_module, "probe_inventory": transport, "probe_login": login}
        with mock.patch.object(probe, "_module", side_effect=lambda name: mapping[name]), \
                mock.patch.object(probe, "_payload", return_value=(audit, source)) as payload:
            yield expected, audit, source, gate_module, transport, payload

    def test_no_opt_in_unknown_operation_or_unverified_control_never_starts_transport(self):
        for changes in [{"QUANTA_OCI_AUTH_CONFIRMED": "false"}, {"QUANTA_OCI_INSTALL_OPERATION": "reboot"},
                        {"QUANTA_OCI_INSTALL_OPERATION": []}]:
            with mock.patch.object(probe, "_module", side_effect=AssertionError("must not load")):
                self.assertEqual(probe.probe({**credentials(), **changes})["status"], "not_configured")

    def test_control_mismatch_prevents_module_payload_or_credential_preparation(self):
        with self.modules(match=False) as (_, _, _, gate_module, transport, payload):
            value = probe.probe(credentials())
        self.assertEqual(value["failure_reason"], "control_checkout_invalid")
        payload.assert_not_called()
        transport._capture.assert_not_called()

    def test_bad_host_pin_ppk_or_config_prevents_authentication(self):
        for changes in [{"QUANTA_OCI_HOST": "127.0.0.1"}, {"QUANTA_OCI_HOST_KEY": "untrusted"},
                        {"QUANTA_OCI_PPK": "private-invalid-fixture"}]:
            with self.modules() as (_, _, _, _, transport, _):
                value = probe.probe({**credentials(), **changes})
                self.assertFalse(value["authentication_attempted"])
                transport._capture.assert_not_called()
        def invalid(value):
            raise ValueError("private-origin-diagnostic")
        with self.modules(validator=invalid) as (_, _, _, _, transport, _):
            value = probe.probe(credentials())
        self.assertEqual(value["failure_reason"], "configuration_invalid")
        transport._capture.assert_not_called()
        self.assertNotIn("private-origin", json.dumps(value))

    def test_plink_flags_private_key_cleanup_and_minimal_environment_for_both_operations(self):
        for operation in ["audit-recovery", "prepare-recovery", "reboot-recovery", "verify-reboot", "post-reboot-compute"]:
            paths = []
            with self.modules(action=operation if operation in probe.BOOT_OPERATIONS else None) as (expected, _, source, _, _, _):
                def runner(command, environment, directory):
                    paths.append(Path(directory))
                    key_path = Path(command[command.index("-i") + 1])
                    self.assertEqual(key_path.read_text(), KEY)
                    self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
                    self.assertEqual(set(environment), {"HOME", "PATH", "LANG"})
                    self.assertEqual(environment["HOME"], directory)
                    self.assertEqual(command[:13], [login.PLINK, "-ssh", "-2", "-4", "-batch", "-noagent",
                                                     "-no-trivial-auth", "-a", "-x", "-T", "-noshare", "-P", "22"])
                    remote = shlex.split(command[-1])
                    self.assertEqual(remote[:6], ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c"])
                    self.assertEqual(remote[6], source)
                    config = json.loads(base64.b64decode(remote[7]))
                    self.assertEqual(set(config), {"source_sha", "public_origin", "auth_mode"})
                    self.assertEqual(config["source_sha"], gate.SOURCE_SHA)
                    if operation in probe.BOOT_OPERATIONS:
                        self.assertEqual(remote[8:], [operation])
                    else:
                        self.assertEqual(len(remote), 8)
                    self.assertNotIn("QUANTA_OWNER_TOKEN", command[-1])
                    return "success", json.dumps(expected).encode(), True
                result = probe.probe(credentials(operation), runner=runner)
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["requested_operation"], operation)
            self.assertEqual(result["result"], expected)
            self.assertTrue(paths)
            self.assertTrue(all(not path.exists() for path in paths))

    def test_raw_output_unknown_status_timeout_and_exceptions_are_sanitized(self):
        cases = [("success", b"private-server-output", "invalid_output"),
                 ("failed", b"private-server-output", "remote_failed"),
                 ("timeout", b"private-server-output", "timeout"),
                 ("output_limit", b"private-server-output", "output_limit"),
                 ("untrusted-private-status", b"", "failed")]
        for status, raw, expected in cases:
            with self.modules():
                value = probe.probe(credentials(), runner=lambda *args: (status, raw, True))
            self.assertEqual(value["status"], expected)
            self.assertNotIn("private", json.dumps(value))
        paths = []
        def broken(command, environment, directory):
            paths.append(Path(directory))
            raise RuntimeError("private-transport-diagnostic")
        with self.modules():
            value = probe.probe(credentials(), runner=broken)
        self.assertEqual(value["status"], "failed")
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertNotIn("diagnostic", json.dumps(value))

    def test_interrupt_removes_temporary_key_without_intercepting_user_interrupt(self):
        paths = []
        def interrupt(command, environment, directory):
            paths.append(Path(directory))
            raise KeyboardInterrupt()
        with self.modules(), self.assertRaises(KeyboardInterrupt):
            probe.probe(credentials(), runner=interrupt)
        self.assertTrue(all(not path.exists() for path in paths))

    def test_remote_failed_audit_is_not_promoted_to_success(self):
        partial = {"scope": "fixture", "status": "failed"}
        with self.modules(sanitizer=lambda raw: partial):
            value = probe.probe(credentials(), runner=lambda *args: ("success", b"{}", True))
        self.assertEqual(value["status"], "remote_failed")
        self.assertEqual(value["result"], partial)

    def test_default_capture_is_bounded_separately_for_audit_and_backup(self):
        for operation, timeout in [("audit-recovery", 120), ("prepare-recovery", 600),
                                   ("reboot-recovery", 300), ("verify-reboot", 300),
                                   ("post-reboot-compute", 180)]:
            with self.modules(action=operation if operation in probe.BOOT_OPERATIONS else None) as (_, _, _, _, transport, _):
                self.assertEqual(probe.probe(credentials(operation))["status"], "success")
                self.assertEqual(transport._capture.call_args.kwargs, {"timeout": timeout, "limit": 8192})

    def test_only_fixed_backup_helper_can_be_bundled_and_is_never_main(self):
        with self.assertRaises(ValueError):
            probe._payload("../arbitrary")
        helper_source = "value = 4\nif __name__ == '__main__': raise AssertionError('helper must not run as main')\n"
        main_source = "import quanta_fixed_backup\nassert quanta_fixed_backup.value == 4\n"
        fixed = types.SimpleNamespace(value=4)
        reads = []
        def read(path, **kwargs):
            reads.append(path.name)
            return helper_source if path.name == "verify_backup.py" else main_source
        with mock.patch.object(Path, "read_text", read), \
                mock.patch.object(probe, "_module", side_effect=lambda name: fixed), \
                mock.patch.dict(probe.sys.modules):
            _, remote = probe._payload("prepare-recovery")
            exec(compile(remote, "<test-fixed-program>", "exec"), {"__name__": "__main__"})
        self.assertEqual(reads, ["recovery_backup.py", "verify_backup.py"])

    def test_boot_uses_only_fixed_backup_and_audit_helpers_with_no_helper_main(self):
        helper_source = "value = 4\nif __name__ == '__main__': raise AssertionError('helper main')\n"
        audit_source = "value = 8\nif __name__ == '__main__': raise AssertionError('audit main')\n"
        main_source = ("import quanta_fixed_backup, quanta_fixed_audit\n"
                       "assert quanta_fixed_backup.value + quanta_fixed_audit.value == 12\n")
        for operation in probe.BOOT_OPERATIONS:
            reads = []
            def read(path, **kwargs):
                reads.append(path.name)
                return {"verify_backup.py": helper_source, "audit_recovery.py": audit_source,
                        "reboot_recovery.py": main_source}[path.name]
            with mock.patch.object(Path, "read_text", read), \
                    mock.patch.object(probe, "_module", return_value=types.SimpleNamespace()), \
                    mock.patch.dict(probe.sys.modules):
                _, remote = probe._payload(operation)
                exec(compile(remote, "<test-fixed-boot-program>", "exec"), {"__name__": "__main__"})
            self.assertEqual(reads, ["reboot_recovery.py", "verify_backup.py", "audit_recovery.py"])

    def test_reboot_acknowledgement_does_not_claim_a_verified_boot(self):
        acknowledged = {"scope": "fixture", "status": "success", "action": "reboot-recovery", "reboot_requested": True,
                        "boot_verified": False}
        with self.modules(sanitizer=lambda raw: acknowledged):
            value = probe.probe(credentials("reboot-recovery"),
                                runner=lambda *args: ("success", b"{}", True))
        self.assertEqual(value["status"], "success")
        self.assertFalse(value["result"]["boot_verified"])
        self.assertEqual(set(value), {"scope", "status", "authentication_attempted", "requested_operation", "result"})

    def test_boot_response_action_must_match_requested_fixed_action(self):
        wrong = {"scope": "fixture", "status": "success", "action": "verify-reboot", "boot_changed": True}
        with self.modules(sanitizer=lambda raw: wrong):
            value = probe.probe(credentials("reboot-recovery"), runner=lambda *args: ("success", b"{}", True))
        self.assertEqual(value["status"], "invalid_output")
        self.assertNotIn("result", value)

    def test_reboot_disconnect_or_timeout_is_failure_and_never_triggers_a_retry(self):
        for status, expected in [("failed", "remote_failed"), ("timeout", "timeout"),
                                 ("output_limit", "output_limit")]:
            runner = mock.Mock(return_value=(status, b"private-disconnected-text", True))
            with self.modules():
                value = probe.probe(credentials("reboot-recovery"), runner=runner)
            self.assertEqual(value["status"], expected)
            self.assertEqual(value["requested_operation"], "reboot-recovery")
            self.assertNotIn("result", value)
            self.assertEqual(runner.call_count, 1)
            self.assertNotIn("private", json.dumps(value))

    def test_encrypted_export_capture_never_returns_ciphertext_bytes_or_plaintext(self):
        raw = ciphertext_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "encrypted.cms"
            save = probe._save_ciphertext
            with self.modules(), mock.patch.object(probe, "_save_ciphertext", side_effect=lambda value: save(value, path)):
                value = probe.probe(credentials("export-recovery"), runner=lambda *args: ("success", raw, True))
            self.assertEqual(value["status"], "success")
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(value["ciphertext"], {"size_bytes": len(raw), "sha256": probe.hashlib.sha256(raw).hexdigest()})
            self.assertNotIn("synthetic-encrypted-payload", json.dumps(value))
        for status, output, expected in [("success", b"private-db-bytes", "invalid_output"),
                                          ("failed", raw, "remote_failed"),
                                          ("timeout", raw, "timeout"),
                                          ("output_limit", raw, "output_limit")]:
            with self.modules(), mock.patch.object(probe, "_save_ciphertext", wraps=probe._save_ciphertext) as save:
                value = probe.probe(credentials("export-recovery"), runner=lambda *args: (status, output, True))
                self.assertEqual(save.call_count, int(status == "success"))
            self.assertEqual(value["status"], expected)
            self.assertNotIn("private-db", json.dumps(value))
            self.assertNotIn("ciphertext", value)

    def test_export_size_deadline_and_output_limit_are_fixed(self):
        with self.modules() as (_, _, _, _, transport, _), \
                mock.patch.object(probe, "_save_ciphertext", return_value={"size_bytes": 100, "sha256": "a" * 64}):
            self.assertEqual(probe.probe(credentials("export-recovery"))["status"], "success")
        self.assertEqual(transport._capture.call_args.kwargs, {"timeout": 600, "limit": 128 * 1024**2})

    def test_der_container_validation_rejects_wrong_oid_truncation_nonminimal_lengths_and_oversize(self):
        raw = ciphertext_fixture()
        self.assertTrue(probe._cms_der(raw))
        payload = bytes.fromhex("060b2a864886f70d0109100117") + b"x" * 200
        longer = b"\x30\x81" + bytes([len(payload)]) + payload
        self.assertTrue(probe._cms_der(longer))
        for value in [None, b"", b"private", raw[:-1], raw + b"x", b"\x31" + raw[1:],
                      raw.replace(bytes.fromhex("060b2a864886f70d0109100117"),
                                  bytes.fromhex("060b2a864886f70d0109100118")),
                      b"\x30\x80" + raw[2:] + b"\x00\x00",
                      b"\x30\x81" + raw[1:],
                      b"\x30\x82\x00" + bytes([len(payload)]) + payload]:
            with self.subTest(length=len(value) if isinstance(value, bytes) else None):
                self.assertFalse(probe._cms_der(value))
        with mock.patch.object(probe, "MAX_EXPORT", len(raw) - 1):
            self.assertFalse(probe._cms_der(raw))

    def test_export_destination_rejects_existing_file_symlink_parent_and_cleans_own_partial(self):
        raw = ciphertext_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.cms"
            existing.write_bytes(b"keep-existing")
            with self.assertRaises(FileExistsError):
                probe._save_ciphertext(raw, existing)
            self.assertEqual(existing.read_bytes(), b"keep-existing")
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                probe._save_ciphertext(raw, alias / "new.cms")
            output = root / "new.cms"
            with mock.patch.object(probe.os, "fsync", side_effect=OSError("private-error")), self.assertRaises(OSError):
                probe._save_ciphertext(raw, output)
            self.assertFalse(output.exists())


class WorkflowTests(unittest.TestCase):
    def test_recovery_ci_has_native_architectures_and_no_secret_or_remote_step(self):
        source = (ROOT / ".github/workflows/oci-recovery-tests.yml").read_text()
        for value in ["ubuntu-24.04-arm", "ubuntu-24.04", "3.12.14", "test_oci_recovery_control.py",
                      "test_oci_audit_recovery.py", "test_oci_recovery_backup.py", "test_oci_recovery_export.py",
                      "test_oci_reboot_recovery.py", "test_oci_recovery_smoke.py"]:
            self.assertIn(value, source)
        for forbidden in ["secrets.", "oci-preflight", "probe_recovery.py", "putty-tools", "workflow_dispatch"]:
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
