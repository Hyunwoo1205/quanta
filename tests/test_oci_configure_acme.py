"""Fixed CA opt-in and guarded private-file transactions; no OCI or network."""
import base64
from contextlib import ExitStack, contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("quanta_configure_acme_test", ROOT / "deploy/oci/configure_acme.py")
acme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acme)
EMAIL = "owner+quanta@example.net"
BASE_CONFIG = {"source_sha": acme.SOURCE_SHA, "public_origin": "https://app.example.net", "auth_mode": "owner-token"}
TEMPLATE = (ROOT / "deploy/oci/Caddyfile.example").read_bytes()
BASE = TEMPLATE.replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n")
ORIGINAL_ENV = b"QUANTA_PUBLIC_HOST=app.example.net\n"


def config(**changes):
    return {**BASE_CONFIG, "acme_email": EMAIL, **changes}


class ConfigurationTests(unittest.TestCase):
    def test_exact_four_field_configuration_does_not_change_three_field_receipt_contract(self):
        original = config()
        self.assertEqual(acme.validate_config(original), original)
        self.assertIsNot(acme.validate_config(original), original)
        self.assertEqual(acme._decode(base64.b64encode(json.dumps(original).encode()).decode()), original)
        for value in ({**original, "secret": "private"}, BASE_CONFIG, config(source_sha="0" * 40), config(auth_mode="access")):
            with self.assertRaises(ValueError):
                acme.validate_config(value)

    def test_common_ascii_emails_are_supported_and_caddy_environment_injection_is_rejected(self):
        for email in (EMAIL, "first.last@example.org", "A_B%tag+mail@Sub.Example.net"):
            self.assertEqual(acme.validate_config(config(acme_email=email))["acme_email"], email)
        for email in (None, "", "owner", "a@localhost", "a@127.0.0.1", ".a@example.net", "a.@example.net",
                      "a..b@example.net", "a'@example.net", 'a"@example.net', "a$@example.net", "a`@example.net",
                      "a#@example.net", "a\\@example.net", "a{@example.net", "한글@example.net",
                      "a@example.net\nOTHER=value", "a@example.net\r", "a@example.net other", "a" * 65 + "@example.net"):
            with self.subTest(kind=type(email).__name__), self.assertRaises(ValueError):
                acme.validate_config(config(acme_email=email))

    def test_origins_and_encoded_configuration_are_bounded_without_echoing_input(self):
        for origin in ("http://app.example.net", "https://app.example.net/", "https://app.example.net:443",
                       "https://user@app.example.net", "https://127.0.0.1", "https://APP.example.net", "https://app.invalid"):
            with self.assertRaises(ValueError):
                acme.validate_config(config(public_origin=origin))
        for encoded in ("", "!", "a" * 4097, base64.b64encode(b" " * 2049).decode(),
                        base64.b64encode(b'{"acme_email":"a","acme_email":"b"}').decode()):
            with self.assertRaises(ValueError):
                acme._decode(encoded)

    def test_variant_has_only_fixed_acme_endpoint_and_receipt_contains_email_hash(self):
        variant = acme._acme_variant(BASE)
        self.assertEqual(variant.replace(b"\temail {$QUANTA_ACME_EMAIL}\n\tacme_ca " + acme.ACME_CA.encode() + b"\n", b""), BASE)
        self.assertNotIn(EMAIL.encode(), variant)
        self.assertNotIn(b"issuer zerossl", variant)
        receipt = acme._acme_receipt(BASE_CONFIG, EMAIL)
        self.assertEqual(receipt, {"schema": 1, **BASE_CONFIG, "issuer": "zerossl_acme",
                                   "email_sha256": hashlib.sha256(EMAIL.encode()).hexdigest()})
        self.assertNotIn(EMAIL, json.dumps(receipt))


class TransactionTests(unittest.TestCase):
    @contextmanager
    def host(self, *, issued=True):
        with tempfile.TemporaryDirectory(prefix="quanta-acme-test-") as temporary, ExitStack() as stack:
            directory = Path(temporary)
            paths = {name: directory / basename for name, basename in (
                ("MARKER", "installed.json"), ("CADDYFILE", "Caddyfile"), ("HTTPS_ENV", "https.env"),
                ("ACME_RECEIPT", "acme.json"), ("ACME_BACKUP", "acme-backup.json"), ("TEMPLATE", "template"))}
            for name, path in paths.items():
                stack.enter_context(patch.object(acme, name, path))
            marker = acme._json_bytes(BASE_CONFIG)
            for path, contents in ((paths["MARKER"], marker), (paths["CADDYFILE"], BASE),
                                   (paths["HTTPS_ENV"], ORIGINAL_ENV), (paths["TEMPLATE"], TEMPLATE)):
                path.write_bytes(contents)
                path.chmod(0o600)
            app = directory / "app.env"
            app.write_bytes(b"private application token sentinel")
            app.chmod(0o600)
            # Only transaction files are real temporary files. Root/proxy scope
            # is independently tested by the shared firewall guard suite.
            def read(path, *, private=False, **_):
                if private:
                    self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
                return path.read_bytes()
            reads = stack.enter_context(patch.object(acme, "_read", side_effect=read))
            stack.enter_context(patch.object(acme, "_parents"))
            stack.enter_context(patch.object(acme, "_native_profile"))
            def scope(value, *, require_active):
                self.assertEqual(value, BASE_CONFIG)
                self.assertTrue(require_active)
                self.assertEqual(json.loads(read(paths["MARKER"])), BASE_CONFIG)
                acme._https_config_guard(value, TEMPLATE)
            scopes = stack.enter_context(patch.object(acme, "_scope", side_effect=scope))
            candidate = stack.enter_context(patch.object(acme, "_validate_candidate"))
            commands = stack.enter_context(patch.object(acme, "_command", return_value=(0, b"")))
            stack.enter_context(patch.object(acme, "_active", return_value=True))
            wait = stack.enter_context(patch.object(acme, "_wait_tls", return_value=issued))
            yield types.SimpleNamespace(directory=directory, paths=paths, marker=marker, app=app,
                                        candidate=candidate, commands=commands, scopes=scopes, reads=reads, wait=wait)
            self.assertEqual(paths["MARKER"].read_bytes(), marker)
            self.assertEqual(app.read_bytes(), b"private application token sentinel")
            self.assertNotIn(app, [call.args[0] for call in reads.call_args_list])

    def test_known_native_profile_checks_absence_and_unexpected_boot_helper_refuses_before_writes(self):
        with patch.object(acme, "_absent") as absent:
            acme._native_profile()
        paths = {call.args[0] for call in absent.call_args_list}
        self.assertIn(acme.FW_HELPER, paths)
        self.assertIn(Path("/etc/systemd/system/quanta-web-firewall.service"), paths)
        self.assertIn(Path("/etc/systemd/system/quanta-web-firewall.service.d"), paths)
        self.assertIn(Path("/etc/systemd/system/multi-user.target.wants/quanta-web-firewall.service"), paths)
        with self.host() as host, patch.object(acme, "_native_profile", side_effect=acme.AcmeError("fixed path already exists")):
            result = acme.configure(config())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_stage"], "preflight")
            self.assertFalse(result["backup_created"])
            self.assertFalse(result["receipt_created"])
            self.assertEqual(host.paths["CADDYFILE"].read_bytes(), BASE)
            host.candidate.assert_not_called()
            host.commands.assert_not_called()

    def test_success_validates_before_exclusive_backup_commit_and_restarts_only_proxy(self):
        with self.host() as host:
            def validate(path, email, public_host, directory):
                self.assertEqual(email, EMAIL)
                self.assertEqual(public_host, "app.example.net")
                self.assertEqual(path.read_bytes(), acme._acme_variant(BASE))
                self.assertEqual(host.paths["CADDYFILE"].read_bytes(), BASE)
                self.assertFalse(host.paths["ACME_BACKUP"].exists())
                self.assertFalse(host.paths["ACME_RECEIPT"].exists())
            host.candidate.side_effect = validate
            def command(argv, **kwargs):
                self.assertEqual(argv, [acme.SYSTEMCTL, "restart", "quanta-https.service"])
                self.assertEqual(host.paths["CADDYFILE"].read_bytes(), acme._acme_variant(BASE))
                acme._https_config_guard(BASE_CONFIG, TEMPLATE)
                return 0, b""
            host.commands.side_effect = command
            result = acme.configure(config())
            self.assertEqual(result["status"], "success")
            for key in ("configured", "changed", "backup_created", "receipt_created", "commit_started",
                        "config_replaced", "env_replaced", "restart_attempted", "tls_issued"):
                self.assertTrue(result[key])
            self.assertFalse(result["rollback_attempted"])
            host.commands.assert_called_once_with([acme.SYSTEMCTL, "restart", "quanta-https.service"], timeout=40, limit=0)
            backup = json.loads(host.paths["ACME_BACKUP"].read_bytes())
            self.assertEqual(base64.b64decode(backup["caddyfile_b64"]), BASE)
            self.assertEqual(base64.b64decode(backup["https_env_b64"]), ORIGINAL_ENV)
            for name in ("CADDYFILE", "HTTPS_ENV", "ACME_RECEIPT", "ACME_BACKUP"):
                self.assertEqual(stat.S_IMODE(host.paths[name].stat().st_mode), 0o600)
            for name in ("CADDYFILE", "ACME_RECEIPT", "ACME_BACKUP"):
                self.assertNotIn(EMAIL.encode(), host.paths[name].read_bytes())
            self.assertNotIn(EMAIL, json.dumps(result))

    def test_valid_configuration_with_certificate_pending_is_distinct_and_idempotent(self):
        with self.host(issued=False) as host:
            first = acme.configure(config())
            self.assertEqual(first["status"], "awaiting_network")
            self.assertEqual(first["state"], "configured_tls_pending")
            self.assertTrue(first["configured"])
            self.assertFalse(first["tls_issued"])
            identities = {name: path.stat().st_ino for name, path in host.paths.items()}
            host.commands.reset_mock()
            host.candidate.reset_mock()
            second = acme.configure(config())
            self.assertEqual(second["status"], "awaiting_network")
            self.assertFalse(second["changed"])
            self.assertFalse(second["restart_attempted"])
            self.assertEqual({name: path.stat().st_ino for name, path in host.paths.items()}, identities)
            host.commands.assert_not_called()
            host.candidate.assert_not_called()

    def test_unknown_config_receipt_or_backup_is_never_overwritten(self):
        for which in ("CADDYFILE", "HTTPS_ENV", "ACME_RECEIPT", "ACME_BACKUP"):
            with self.subTest(path=which), self.host() as host:
                host.paths[which].write_bytes(b"operator-owned-private-value")
                result = acme.configure(config())
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["configured"])
                self.assertEqual(host.paths[which].read_bytes(), b"operator-owned-private-value")
                host.commands.assert_not_called()

    def test_candidate_failure_precedes_backup_receipt_and_config_mutation(self):
        with self.host() as host:
            host.candidate.side_effect = RuntimeError(EMAIL)
            result = acme.configure(config())
            self.assertEqual(result["failure_stage"], "prepare")
            self.assertFalse(result["backup_created"])
            self.assertFalse(result["receipt_created"])
            self.assertEqual(host.paths["CADDYFILE"].read_bytes(), BASE)
            self.assertEqual(host.paths["HTTPS_ENV"].read_bytes(), ORIGINAL_ENV)
            host.commands.assert_not_called()
            self.assertNotIn(EMAIL, json.dumps(result))

    def test_second_replace_failure_rolls_back_only_owned_first_replace(self):
        with self.host() as host:
            replace = acme._replace_private
            def fail_second(path, *args, **kwargs):
                if path == host.paths["HTTPS_ENV"]:
                    raise acme.AcmeError("fixed file changed before replacement")
                return replace(path, *args, **kwargs)
            with patch.object(acme, "_replace_private", side_effect=fail_second):
                result = acme.configure(config())
            self.assertTrue(result["config_replaced"])
            self.assertFalse(result["env_replaced"])
            self.assertTrue(result["rollback_attempted"])
            self.assertTrue(result["rollback_complete"])
            self.assertEqual(host.paths["CADDYFILE"].read_bytes(), BASE)
            self.assertEqual(host.paths["HTTPS_ENV"].read_bytes(), ORIGINAL_ENV)
            self.assertFalse(host.paths["ACME_RECEIPT"].exists())
            self.assertTrue(host.paths["ACME_BACKUP"].exists())
            host.commands.assert_not_called()

    def test_fsync_failure_after_rename_still_has_a_recorded_owned_rollback(self):
        with self.host() as host:
            sync = acme._sync_parent
            failed = False
            def fail_once(path):
                nonlocal failed
                if path == host.paths["CADDYFILE"] and not failed:
                    failed = True
                    raise OSError(EMAIL)
                return sync(path)
            with patch.object(acme, "_sync_parent", side_effect=fail_once):
                result = acme.configure(config())
            self.assertTrue(result["config_replaced"])
            self.assertTrue(result["rollback_complete"])
            self.assertEqual(host.paths["CADDYFILE"].read_bytes(), BASE)
            self.assertFalse(host.paths["ACME_RECEIPT"].exists())

    def test_operator_modified_contents_survive_rollback_and_report_conflict(self):
        with self.host() as host:
            replace = acme._replace_private
            def fail_second(path, *args, **kwargs):
                if path == host.paths["HTTPS_ENV"]:
                    host.paths["CADDYFILE"].write_bytes(b"operator changed configuration")
                    raise OSError(EMAIL)
                return replace(path, *args, **kwargs)
            with patch.object(acme, "_replace_private", side_effect=fail_second):
                result = acme.configure(config())
            self.assertEqual(result["failure_reason"], "rollback_conflict")
            self.assertFalse(result["rollback_complete"])
            self.assertEqual(host.paths["CADDYFILE"].read_bytes(), b"operator changed configuration")
            self.assertTrue(host.paths["ACME_BACKUP"].exists())
            host.commands.assert_not_called()

    def test_partial_owned_receipt_cleanup_and_foreign_inode_preservation(self):
        with self.host() as host:
            contents = acme._json_bytes(acme._acme_receipt(BASE_CONFIG, EMAIL))
            host.paths["ACME_RECEIPT"].write_bytes(contents[:5])
            info = host.paths["ACME_RECEIPT"].stat()
            host.paths["ACME_RECEIPT"].chmod(0o600)
            created = {host.paths["ACME_RECEIPT"]: {"device": info.st_dev, "inode": info.st_ino, "data": contents}}
            self.assertTrue(acme._remove_created_receipt(created))
            self.assertFalse(host.paths["ACME_RECEIPT"].exists())
            acme._create_private(host.paths["ACME_RECEIPT"], contents, created=created)
            other = host.directory / "operator"
            other.write_bytes(contents)
            other.chmod(0o600)
            other.replace(host.paths["ACME_RECEIPT"])
            self.assertFalse(acme._remove_created_receipt(created))
            self.assertTrue(host.paths["ACME_RECEIPT"].exists())

    def test_committed_configuration_is_preserved_if_owned_proxy_restart_fails(self):
        with self.host() as host:
            host.commands.side_effect = acme.AcmeError("fixed command failed")
            result = acme.configure(config())
            self.assertEqual(result["failure_stage"], "restart")
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["configured"])
            self.assertTrue(result["changed"])
            self.assertFalse(result["rollback_attempted"])
            self.assertEqual(host.paths["CADDYFILE"].read_bytes(), acme._acme_variant(BASE))

    def test_existing_verified_variant_cannot_silently_change_contact_email(self):
        with self.host() as host:
            self.assertEqual(acme.configure(config())["status"], "success")
            prior = {name: path.read_bytes() for name, path in host.paths.items()}
            host.commands.reset_mock()
            result = acme.configure(config(acme_email="other@example.net"))
            self.assertEqual(result["failure_reason"], "contact_mismatch")
            self.assertEqual({name: path.read_bytes() for name, path in host.paths.items()}, prior)
            host.commands.assert_not_called()


class ProcessAndReportTests(unittest.TestCase):
    def test_candidate_command_uses_only_owned_binary_private_email_environment_and_no_logs(self):
        with patch.object(acme.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            acme._validate_candidate(Path("/private/candidate"), EMAIL, "app.example.net", Path("/private/temporary"))
        self.assertEqual(run.call_args.args[0], [str(acme.CADDY), "adapt", "--config", "/private/candidate", "--adapter", "caddyfile", "--validate"])
        options = run.call_args.kwargs
        self.assertEqual(set(options["env"]), {"PATH", "LC_ALL", "QUANTA_PUBLIC_HOST", "QUANTA_ACME_EMAIL", "XDG_DATA_HOME", "XDG_CONFIG_HOME"})
        self.assertEqual(options["env"]["QUANTA_ACME_EMAIL"], EMAIL)
        self.assertEqual(options["stdout"], acme.subprocess.DEVNULL)
        self.assertEqual(options["stderr"], acme.subprocess.DEVNULL)
        self.assertFalse(options["shell"])
        self.assertEqual(options["timeout"], 20)
        self.assertNotIn(EMAIL, str(run.call_args.args[0]))

    def test_report_and_main_reject_private_fields_and_never_serialize_exception(self):
        raw = acme._json_bytes(acme._report())
        self.assertEqual(acme.sanitize_report(raw), acme._report())
        for invalid in (b"", b"x" * 8193, b"null", b"\xff", raw + b"private",
                        acme._json_bytes({**acme._report(), "email": EMAIL}),
                        acme._json_bytes({**acme._report(), "failure_reason": EMAIL}),
                        acme._json_bytes({**acme._report(), "configured": 1})):
            self.assertIsNone(acme.sanitize_report(invalid))
        encoded = base64.b64encode(json.dumps(config()).encode()).decode()
        with patch.object(acme, "configure", side_effect=RuntimeError(EMAIL)), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(acme.main([encoded]), 2)
        self.assertNotIn(EMAIL, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["failure_reason"], "operation_failed")


if __name__ == "__main__":
    unittest.main()
