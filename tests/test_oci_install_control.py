"""Fixed-install authorization and transport, with no OCI, real keys, or network."""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import stat
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy/oci"


def load(name):
    spec = importlib.util.spec_from_file_location("quanta_test_" + name, DEPLOY / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


authorize = load("authorize_install")
probe = load("probe_install")
REQUEST_ID = "b0d1ce2d-518b-4ef2-9e16-ef3683dd79ca"
HOST = "8.8.8.8"  # Syntactic fixture only; no test starts an SSH client.
PIN = "SHA256:" + base64.b64encode(bytes(range(32))).decode().rstrip("=")
KEY = "\n".join([
    "PuTTY-User-Key-File-3: ssh-rsa", "Encryption: none", "Comment: synthetic-fixture",
    "Public-Lines: 1", "cHVibGlj", "Private-Lines: 1", "cHJpdmF0ZQ==",
    "Private-MAC: " + "0" * 64, "",
])
PRIVATE = "untrusted-private-fixture"


def request(operation="install-app"):
    return {"schema_version": 1, "operation": operation, "source_sha": authorize.SOURCE_SHA,
            "request_id": REQUEST_ID}


def metadata():
    return {"GITHUB_REPOSITORY": "Hyunwoo1205/quanta", "GITHUB_REF": "refs/heads/ops/oci",
            "GITHUB_EVENT_NAME": "push"}


def ci_response():
    return {"id": authorize.CI_RUN, "head_sha": authorize.SOURCE_SHA, "head_branch": "main",
            "event": "push", "path": ".github/workflows/ci.yml",
            "status": "completed", "conclusion": "success"}


class Response:
    def __init__(self, raw, *, status=200, url=None):
        self.raw, self.status = raw, status
        self.url = authorize.CI_URL if url is None else url
        self.read_limits = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, limit):
        self.read_limits.append(limit)
        return self.raw[:limit]


class RequestAuthorizationTests(unittest.TestCase):
    def check_raw(self, raw, allowed=False, *, environ=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_bytes(raw)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                if allowed:
                    result = authorize.read_request(path, metadata() if environ is None else environ)
                else:
                    with self.assertRaises((ValueError, TypeError, OSError)):
                        authorize.read_request(path, metadata() if environ is None else environ)
                    result = None
            self.assertEqual(captured.getvalue(), "")
            return result

    def test_only_declared_fixed_operations_and_source_are_authorized(self):
        self.assertEqual(authorize.SOURCE_SHA, probe.SOURCE_SHA)
        self.assertRegex(authorize.SOURCE_SHA, r"\A[0-9a-f]{40}\Z")
        self.assertEqual(authorize.CI_URL, "https://api.github.com/repos/Hyunwoo1205/quanta/actions/runs/" + str(authorize.CI_RUN))
        for operation in ("install-app", "install-https", "configure-web-firewall", "verify-backup", "diagnose-https"):
            with self.subTest(operation=operation):
                self.assertEqual(self.check_raw(json.dumps(request(operation)).encode(), True), request(operation))

    def test_repository_ref_and_event_must_match_before_any_file_read(self):
        for key, values in {
            "GITHUB_REPOSITORY": [None, "attacker/quanta", "Hyunwoo1205/quanta\n"],
            "GITHUB_REF": [None, "refs/heads/main", "ops/oci", "refs/heads/ops/oci\n"],
            "GITHUB_EVENT_NAME": [None, "pull_request", "workflow_dispatch", "workflow_run"],
        }.items():
            for value in values:
                env = {**metadata(), key: value}
                with self.subTest(key=key, value=value), mock.patch.object(Path, "lstat", side_effect=AssertionError("must not read")):
                    with self.assertRaises(ValueError):
                        authorize.read_request(Path("unused.json"), env)

    def test_request_schema_types_uuid_and_source_cannot_be_overridden(self):
        payloads = [None, [], {}, PRIVATE, {**request(), "extra": PRIVATE},
                    {key: value for key, value in request().items() if key != "source_sha"}]
        payloads += [{**request(), key: value} for key, values in {
            "schema_version": [True, 1.0, "1", 2],
            "operation": [None, [], "ssh", "../install_app", "install-app\n"],
            "source_sha": ["0" * 40, authorize.SOURCE_SHA.upper(), None],
            "request_id": [None, True, REQUEST_ID.upper(), REQUEST_ID.replace("-", ""),
                           "{" + REQUEST_ID + "}", REQUEST_ID + "\n", PRIVATE],
        }.items() for value in values]
        for payload in payloads:
            with self.subTest(payload=repr(payload)[:90]):
                self.check_raw(json.dumps(payload).encode())

    def test_malformed_duplicate_and_oversized_bytes_are_rejected(self):
        valid = json.dumps(request()).encode()
        for raw in [b"", b"\xff", b"{", valid + b"{}", b" " * 1025,
                    valid[:-1] + b',"operation":"install-https"}',
                    valid.replace(b'"schema_version": 1', b'"schema_version": NaN'),
                    valid.replace(b'"schema_version": 1', b'"schema_version": Infinity')]:
            with self.subTest(length=len(raw)):
                self.check_raw(raw)
        self.check_raw(valid + b" " * (1024 - len(valid)), True)
        self.check_raw(valid + b" " * (1025 - len(valid)))

    def test_symlink_directory_and_missing_request_are_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "real.json"
            target.write_text(json.dumps(request()))
            link = parent / "link.json"
            link.symlink_to(target)
            for path in (link, parent, parent / "missing.json"):
                with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                    authorize.read_request(path, metadata())

    def test_main_authorizes_only_after_ci_and_writes_one_bounded_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            stdout = io.StringIO()
            with mock.patch.object(authorize, "read_request", return_value=request("install-https")), \
                    mock.patch.object(authorize, "ci_passed", return_value=True) as ci, \
                    mock.patch.dict(authorize.os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True), \
                    contextlib.redirect_stdout(stdout):
                self.assertEqual(authorize.main(), 0)
            ci.assert_called_once_with()
            self.assertEqual(output.read_text(), "operation=install-https\n")
            self.assertEqual(json.loads(stdout.getvalue()), {"scope": "install_request", "status": "authorized",
                "operation": "install-https", "request_id": REQUEST_ID})

    def test_main_denial_stages_never_echo_private_exception_or_write_operation(self):
        for stage in ("request", "native_ci"):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                stdout, stderr = io.StringIO(), io.StringIO()
                read = mock.Mock(side_effect=RuntimeError(PRIVATE)) if stage == "request" else mock.Mock(return_value=request())
                with mock.patch.object(authorize, "read_request", read), \
                        mock.patch.object(authorize, "ci_passed", return_value=False) as ci, \
                        mock.patch.dict(authorize.os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(authorize.main(), 2)
                self.assertEqual(json.loads(stdout.getvalue()), {"scope": "install_request", "status": "denied", "stage": stage})
                self.assertFalse(output.exists())
                self.assertEqual(stderr.getvalue(), "")
                self.assertNotIn(PRIVATE, stdout.getvalue())
                if stage == "request":
                    ci.assert_not_called()


class FixedNativeCIGateTests(unittest.TestCase):
    def check(self, value=None, *, raw=None, status=200, url=None):
        response = Response(json.dumps(ci_response() if value is None else value).encode() if raw is None else raw,
                            status=status, url=url)
        opened = []
        def opener(request, *, timeout):
            self.assertEqual(request.full_url, authorize.CI_URL)
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-ci-token")
            self.assertEqual(timeout, 10)
            opened.append(request)
            return response
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = authorize.ci_passed({"QUANTA_CI_READ_TOKEN": "synthetic-ci-token", "CI_URL": "https://attacker.example/"}, opener=opener)
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
        self.assertEqual(len(opened), 1)
        if response.read_limits:
            self.assertEqual(response.read_limits, [262145])
        return result

    def test_exact_completed_push_run_for_fixed_source_and_workflow_is_required(self):
        self.assertTrue(self.check())
        for key, values in {
            "id": [True, str(authorize.CI_RUN), authorize.CI_RUN + 1],
            "head_sha": ["0" * 40, None], "head_branch": ["ops/oci", None],
            "event": ["pull_request", "workflow_dispatch"],
            "path": [".github/workflows/other.yml", None],
            "status": ["in_progress", "queued", None],
            "conclusion": ["failure", "cancelled", "neutral", "skipped", None],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.assertFalse(self.check({**ci_response(), key: value}))

    def test_redirects_non_200_duplicate_oversized_and_malformed_ci_responses_deny(self):
        valid = json.dumps(ci_response()).encode()
        for kwargs in [{"status": 302}, {"status": 403}, {"url": "https://attacker.example/"},
                       {"raw": b"[]"}, {"raw": b"\xff"}, {"raw": b"{}{}"},
                       {"raw": valid[:-1] + b',"conclusion":"success"}'},
                       {"raw": valid + b" " * (262145 - len(valid))}]:
            with self.subTest(kwargs={k: len(v) if isinstance(v, bytes) else v for k, v in kwargs.items()}):
                self.assertFalse(self.check(**kwargs))

    def test_invalid_ci_token_never_opens_a_connection(self):
        for token in [None, "", True, "x" * 4097, "line\nsecret", " leading", "unicode-한"]:
            opener = mock.Mock(side_effect=AssertionError("must not open"))
            with self.subTest(token_type=type(token).__name__):
                self.assertFalse(authorize.ci_passed({"QUANTA_CI_READ_TOKEN": token}, opener=opener))
                opener.assert_not_called()

    def test_default_opener_refuses_redirects_and_network_errors_are_silent(self):
        response = Response(json.dumps(ci_response()).encode())
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(authorize.urllib.request, "build_opener", return_value=opener) as build:
            self.assertTrue(authorize.ci_passed({"QUANTA_CI_READ_TOKEN": "synthetic-ci-token"}))
        self.assertIsInstance(build.call_args.args[0], authorize.NoRedirect)
        self.assertIsNone(build.call_args.args[0].redirect_request(None, None, None, None, None, None))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            self.assertFalse(authorize.ci_passed({"QUANTA_CI_READ_TOKEN": "synthetic-ci-token"},
                opener=mock.Mock(side_effect=OSError(PRIVATE))))
        self.assertEqual(out.getvalue(), "")


class FixedInstallationTransportTests(unittest.TestCase):
    @staticmethod
    def config(operation="install-app"):
        return {"QUANTA_OCI_AUTH_CONFIRMED": "true", "QUANTA_OCI_INSTALL_OPERATION": operation,
                "QUANTA_OCI_HOST": HOST, "QUANTA_OCI_HOST_KEY": PIN, "QUANTA_OCI_PPK": KEY,
                "QUANTA_PUBLIC_ORIGIN": "https://quanta.example.com", "QUANTA_AUTH_MODE": "owner-token",
                "QUANTA_CI_READ_TOKEN": PRIVATE, "GITHUB_TOKEN": PRIVATE,
                "REMOTE_COMMAND": PRIVATE, "QUANTA_SOURCE_SHA": "0" * 40}

    @contextlib.contextmanager
    def installer(self, *, operation="install-app", sanitized=None, validation_error=False):
        name = probe.INSTALLERS[operation]
        source = "# fixed " + name + " source\nprint('fixed-fixture')\n"
        module = types.SimpleNamespace(validate_config=mock.Mock(), sanitize_report=mock.Mock(return_value=sanitized))
        if validation_error:
            module.validate_config.side_effect = ValueError(PRIVATE)
        real_module = probe.transport._module
        def selected(module_name):
            if module_name == name:
                return module
            self.assertEqual(module_name, "probe_login")
            return real_module(module_name)
        def read_source(path, *args, **kwargs):
            self.assertEqual(path, DEPLOY / (name + ".py"))
            self.assertEqual(kwargs, {"encoding": "utf-8"})
            return source
        with mock.patch.object(probe.transport, "_module", side_effect=selected), \
                mock.patch.object(Path, "read_text", autospec=True, side_effect=read_source):
            yield module, source

    def test_only_explicit_confirmation_and_fixed_installers_are_accepted(self):
        with mock.patch.object(probe.transport, "_module", side_effect=AssertionError("must not load")):
            for operation in (None, [], "../install_app", "ssh", "install-app\n"):
                with self.subTest(operation=operation):
                    self.assertEqual(probe.probe(self.config(operation))["status"], "not_configured")
            for confirmation in (None, True, "True", "true\n", "false"):
                self.assertEqual(probe.probe({**self.config(), "QUANTA_OCI_AUTH_CONFIRMED": confirmation})["status"], "not_configured")

    def test_invalid_host_pin_or_key_never_starts_runner(self):
        for field, value in [("QUANTA_OCI_HOST", "127.0.0.1"), ("QUANTA_OCI_HOST", HOST + " -m evil"),
                             ("QUANTA_OCI_HOST_KEY", "*"), ("QUANTA_OCI_PPK", "not-a-key")]:
            runner = mock.Mock(side_effect=AssertionError("must not launch"))
            with self.subTest(field=field):
                result = probe.probe({**self.config(), field: value}, runner=runner)
                self.assertEqual(result["status"], "not_configured")
                self.assertFalse(result["authentication_attempted"])
                runner.assert_not_called()

    def test_invalid_install_configuration_stops_before_private_file_or_runner(self):
        with self.installer(validation_error=True) as (module, _), \
                mock.patch.object(probe.tempfile, "TemporaryDirectory", side_effect=AssertionError("must not create")):
            runner = mock.Mock(side_effect=AssertionError("must not launch"))
            result = probe.probe(self.config(), runner=runner)
            self.assertEqual(result["status"], "configuration_invalid")
            self.assertFalse(result["authentication_attempted"])
            runner.assert_not_called()
            module.validate_config.assert_called_once_with({"source_sha": probe.SOURCE_SHA,
                "public_origin": "https://quanta.example.com", "auth_mode": "owner-token"})

    def test_fixed_quoted_source_json_config_private_ppk_environment_and_cleanup(self):
        paths = []
        for operation in ("install-app", "install-https", "configure-web-firewall", "verify-backup", "diagnose-https"):
            clean = {"scope": "fixed_install_fixture", "status": "success"}
            with self.subTest(operation=operation), self.installer(operation=operation, sanitized=clean) as (module, source):
                def runner(argv, environment, directory):
                    key_path = Path(argv[argv.index("-i") + 1])
                    paths.extend((key_path, Path(directory)))
                    self.assertEqual(key_path.read_bytes(), KEY.encode())
                    self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
                    self.assertEqual(environment, {"HOME": directory, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                    self.assertEqual(argv[:-1], ["/usr/bin/plink", "-ssh", "-2", "-4", "-batch", "-noagent",
                        "-no-trivial-auth", "-a", "-x", "-T", "-noshare", "-P", "22", "-l", "ubuntu",
                        "-i", str(key_path), "-hostkey", PIN, HOST])
                    remote = shlex.split(argv[-1])
                    self.assertEqual(remote[:6], ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-B", "-c"])
                    self.assertEqual(len(remote), 8)
                    self.assertEqual(remote[6], source)
                    self.assertEqual(json.loads(base64.b64decode(remote[7], validate=True)),
                        {"source_sha": probe.SOURCE_SHA, "public_origin": "https://quanta.example.com", "auth_mode": "owner-token"})
                    self.assertNotIn(PRIVATE, argv[-1])
                    self.assertNotIn(KEY, argv[-1])
                    return "success", b"untrusted raw output", True
                result = probe.probe(self.config(operation), runner=runner)
                self.assertEqual(result, {"scope": "ssh_fixed_installation", "status": "success",
                    "authentication_attempted": True, "requested_operation": operation, "result": clean})
                module.sanitize_report.assert_called_once_with(b"untrusted raw output")
            self.assertTrue(all(not path.exists() for path in paths))

    def test_remote_failure_is_sanitized_and_never_echoes_raw_credentials(self):
        for transport_status, remote_status, expected in [
            ("failed", "failed", "remote_failed"), ("failed", "success", "remote_failed"),
            ("success", "failed", "remote_failed"), ("success", "success", "success"),
        ]:
            clean = {"scope": "fixed_install_fixture", "status": remote_status, "stage": "fixture"}
            raw = (PRIVATE + "\n" + KEY).encode()
            with self.subTest(transport=transport_status, remote=remote_status), self.installer(sanitized=clean):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    result = probe.probe(self.config(), runner=lambda *args: (transport_status, raw, True))
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["result"], clean)
                self.assertTrue(result["authentication_attempted"])
                self.assertEqual(output.getvalue(), "")
                serialized = json.dumps(result)
                for private in (PRIVATE, KEY, PIN, HOST):
                    self.assertNotIn(private, serialized)

    def test_invalid_output_timeout_limits_and_unknown_transport_status_fail_closed(self):
        for transport_status, expected in [("success", "invalid_output"), ("failed", "remote_failed"),
                                           ("timeout", "timeout"), ("output_limit", "output_limit"),
                                           (PRIVATE, "failed")]:
            with self.subTest(status=transport_status), self.installer(sanitized=None) as (module, _):
                result = probe.probe(self.config(), runner=lambda *args: (transport_status, PRIVATE.encode(), True))
                self.assertEqual(result["status"], expected)
                self.assertNotIn("result", result)
                self.assertNotIn(PRIVATE, json.dumps(result))
                if transport_status not in {"success", "failed"}:
                    module.sanitize_report.assert_not_called()

    def test_default_capture_has_install_timeout_and_output_bound(self):
        clean = {"scope": "fixed_install_fixture", "status": "success"}
        with self.installer(sanitized=clean), mock.patch.object(probe.transport, "_capture", return_value=("success", b"ok", True)) as capture:
            self.assertEqual(probe.probe(self.config())["status"], "success")
        self.assertEqual(capture.call_args.kwargs, {"timeout": 900, "limit": 8192})

    def test_private_files_are_cleaned_even_when_runner_or_sanitizer_fails(self):
        paths = []
        def fail(argv, environment, directory):
            paths.append(Path(directory))
            raise OSError(PRIVATE)
        with self.installer(sanitized=None):
            result = probe.probe(self.config(), runner=fail)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["authentication_attempted"])
        self.assertTrue(all(not path.exists() for path in paths))
        with self.installer() as (module, _):
            module.sanitize_report.side_effect = ValueError(PRIVATE)
            result = probe.probe(self.config(), runner=lambda *args: ("success", PRIVATE.encode(), True))
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["authentication_attempted"])
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_main_serializes_only_sanitized_result_and_hides_unexpected_exception(self):
        clean = probe.report("remote_failed", True, operation="install-app",
                             result={"scope": "fixed_install_fixture", "status": "failed"})
        for outcome in (clean, OSError(PRIVATE)):
            stdout, stderr = io.StringIO(), io.StringIO()
            replacement = mock.Mock(side_effect=outcome) if isinstance(outcome, Exception) else mock.Mock(return_value=outcome)
            with mock.patch.object(probe, "probe", replacement), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(probe.main(), 2)
            self.assertEqual(json.loads(stdout.getvalue()), probe.report("failed") if isinstance(outcome, Exception) else clean)
            self.assertEqual(stderr.getvalue(), "")
            self.assertNotIn(PRIVATE, stdout.getvalue())


class InstallWorkflowTests(unittest.TestCase):
    def test_public_recheck_job_has_no_ssh_or_owner_credentials(self):
        workflow = (ROOT / '.github/workflows/oci-install.yml').read_text()
        public = workflow.split('\n  public:\n', 1)[1]
        self.assertIn('needs: install', public)
        self.assertIn('needs.install.outputs.operation', public)
        self.assertIn('configure-web-firewall', public)
        self.assertIn('environment: oci-preflight', public)
        self.assertIn('python3 -I deploy/oci/probe_public.py', public)
        self.assertNotIn('QUANTA_OCI_PPK', public)
        self.assertNotIn('QUANTA_OCI_HOST_KEY', public)
        self.assertNotIn('QUANTA_OWNER_TOKEN', public)
        self.assertNotIn('probe_install.py', public)

    def test_protected_fixed_gate_precedes_private_credentials_and_install_execution(self):
        workflow = (ROOT / ".github/workflows/oci-install.yml").read_text()
        self.assertIn("- ops/oci", workflow)
        self.assertIn("- .github/oci/install-request.json", workflow)
        self.assertIn("github.repository == 'Hyunwoo1205/quanta'", workflow)
        self.assertIn("github.ref == 'refs/heads/ops/oci'", workflow)
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("environment: oci-preflight", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("actions: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        gate = workflow.index("python3 -I deploy/oci/authorize_install.py")
        execution = workflow.index("- name: Execute the authorized fixed installer")
        self.assertLess(gate, execution)
        self.assertNotIn("${{ secrets.", workflow[:execution])
        self.assertIn("QUANTA_CI_READ_TOKEN: ${{ github.token }}", workflow[:execution])
        self.assertIn("QUANTA_OCI_INSTALL_OPERATION: ${{ steps.authorize.outputs.operation }}", workflow[execution:])
        self.assertIn("python3 -I deploy/oci/probe_install.py", workflow[execution:])
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("continue-on-error:", workflow)


if __name__ == "__main__":
    unittest.main()
