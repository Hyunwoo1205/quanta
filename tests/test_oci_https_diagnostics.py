"""Private journal fixtures and mocked local TLS; no OCI or external requests."""
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import ssl
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/diagnose_https.py"
spec = importlib.util.spec_from_file_location("quanta_https_diagnostics", SCRIPT)
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
CONFIG = {"public_origin": "https://quanta.example.com", "source_sha": diagnostic.SOURCE_SHA, "auth_mode": "owner-token"}
HOST = "quanta.example.com"
PRIVATE = "private-host-key-path-must-never-appear"


def entry(error="", **changes):
    return {"level": "error", "logger": "tls.obtain", "msg": "could not get certificate from issuer",
            "identifier": HOST, "issuer": "acme-v02.api.letsencrypt.org-directory", "error": error, **changes}


def journal(*entries):
    return b"\n".join(json.dumps(value).encode() for value in entries)


class HTTPSDiagnosticTests(unittest.TestCase):
    def test_config_has_only_the_three_pinned_fields_and_canonical_base64(self):
        raw = json.dumps(CONFIG).encode()
        encoded = base64.b64encode(raw).decode()
        self.assertEqual(diagnostic._decode(encoded), CONFIG)
        for changed in ({**CONFIG, "auth_mode": "access"}, {**CONFIG, "source_sha": "0" * 40},
                        {**CONFIG, "token": PRIVATE}, {**CONFIG, "public_origin": "http://" + HOST},
                        {**CONFIG, "public_origin": CONFIG["public_origin"] + ":443"},
                        {**CONFIG, "public_origin": CONFIG["public_origin"] + "/"}):
            with self.subTest(changed=changed), self.assertRaises(diagnostic.DiagnosticError):
                diagnostic.validate_config(changed)
        for encoded in ("", "?", base64.b64encode(b'{"auth_mode":1,"auth_mode":2}').decode(), "ZX=="):
            with self.subTest(encoded=encoded), self.assertRaises((ValueError, UnicodeError)):
                diagnostic._decode(encoded)

    def test_rate_limit_subtypes_and_retry_seconds_are_allowlisted(self):
        cases = [("too many certificates already issued for registered domain " + PRIVATE, "registered_domain"),
                 ("too many failed authorizations for " + PRIVATE, "authorization_failure"),
                 ("too many new orders per account " + PRIVATE, "account"),
                 ("too many certificates already issued for this exact set of identifiers " + PRIVATE, "unknown")]
        for text, subtype in cases:
            with self.subTest(subtype=subtype):
                raw = journal(entry("HTTP 429 urn:ietf:params:acme:error:rateLimited - " + text),
                    entry("HTTP 429 urn:ietf:params:acme:error:rateLimited - " + text, msg="will retry", retrying_in=120.0))
                value = diagnostic.classify_journal(raw, HOST)
                self.assertEqual((value["acme_error"], value["rate_limit_subtype"]), ("rate_limit", subtype))
                self.assertTrue(value["retry_pending"])
                self.assertEqual(value["retry_delay_seconds"], 120)
                self.assertNotIn(PRIVATE, json.dumps(value))
        for delay in (True, -1, 86401, 1.5, PRIVATE):
            value = diagnostic.classify_journal(journal(entry("failure", msg="will retry", retrying_in=delay)), HOST)
            self.assertIsNone(value["retry_delay_seconds"])
            self.assertTrue(value["retry_pending"])

    def test_latest_error_wins_but_historical_issuer_and_rate_limits_remain(self):
        raw = journal(entry("urn:ietf:params:acme:error:rateLimited - too many certificates for " + PRIVATE),
                      entry("registering account: provisioning client " + PRIVATE, issuer="acme.zerossl.com-v2-DV90"))
        value = diagnostic.classify_journal(raw, HOST)
        self.assertEqual((value["latest_issuer"], value["acme_error"], value["rate_limit_subtype"]), ("zerossl", "issuer", "none"))
        self.assertTrue(value["letsencrypt_seen"] and value["zerossl_seen"] and value["registered_domain_rate_limit_seen"])
        self.assertNotIn(PRIVATE, json.dumps(value))
        for code, expected in (("dns", "dns"), ("caa", "caa"), ("unauthorized", "unauthorized"),
                               ("connection", "connection"), ("tls", "connection"), ("other", "unknown")):
            value = diagnostic.classify_journal(journal(entry("urn:ietf:params:acme:error:" + code)), HOST)
            self.assertEqual(value["acme_error"], expected)
        value = diagnostic.classify_journal(journal(entry(problem={"type": "urn:ietf:params:acme:error:connection", "detail": PRIVATE})), HOST)
        self.assertEqual(value["acme_error"], "connection")

    def test_only_caddy_tls_json_for_this_host_is_classified(self):
        raw = b'plain private text\n{"logger":"tls.obtain","logger":"tls.obtain"}\n' + journal(
            entry("urn:ietf:params:acme:error:caa", identifier="other.example.com"),
            entry("urn:ietf:params:acme:error:dns", logger="other.service"),
            entry("", level="info", msg="waiting on internal rate limiter"),
            entry("", level="info", msg="certificate obtained successfully"))
        value = diagnostic.classify_journal(raw, HOST)
        self.assertEqual(value["acme_error"], "none")
        self.assertFalse(value["retry_pending"])
        self.assertTrue(value["caddy_tls_events_seen"])
        with self.assertRaises(diagnostic.DiagnosticError):
            diagnostic.classify_journal(b"x" * (diagnostic.MAX_JOURNAL + 1), HOST)

    def test_preflight_refuses_before_journal_or_tls_when_root_receipt_or_service_differs(self):
        for uid, receipt, active in ((1, CONFIG, True), (0, {}, True), (0, CONFIG, False)):
            with self.subTest(uid=uid, active=active), patch.object(diagnostic.os, "geteuid", return_value=uid), \
                    patch.object(diagnostic, "_receipt", return_value=receipt), patch.object(diagnostic, "_active", return_value=active), \
                    patch.object(diagnostic, "_journal") as logs, patch.object(diagnostic, "_tls") as tls:
                value = diagnostic.diagnose(CONFIG)
                self.assertEqual((value["status"], value["failure_stage"]), ("failed", "preflight"))
                logs.assert_not_called()
                tls.assert_not_called()

    def test_successful_collection_does_not_claim_certificate_or_modify_services(self):
        raw = journal(entry("urn:ietf:params:acme:error:rateLimited - too many failed authorizations " + PRIVATE,
                            msg="will retry", retrying_in=3600))
        with patch.object(diagnostic.os, "geteuid", return_value=0), patch.object(diagnostic, "_receipt", return_value=CONFIG), \
                patch.object(diagnostic, "_active", return_value=True), patch.object(diagnostic, "_journal", return_value=raw), \
                patch.object(diagnostic, "_tls", return_value=False) as tls:
            value = diagnostic.diagnose(CONFIG)
        self.assertEqual((value["status"], value["failure_stage"]), ("success", "none"))
        self.assertFalse(value["tls_verified"])
        tls.assert_called_once_with(HOST)
        self.assertEqual(diagnostic.sanitize_report(json.dumps(value).encode()), value)
        self.assertNotIn(PRIVATE, json.dumps(value))

    def test_tls_connects_only_to_loopback_with_public_sni_and_system_ca(self):
        stream, secured = MagicMock(), MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = secured
        with patch.object(diagnostic.socket, "create_connection", return_value=stream) as connect, \
                patch.object(diagnostic.ssl, "create_default_context", return_value=context) as trust:
            self.assertTrue(diagnostic._tls(HOST))
        connect.assert_called_once_with(("127.0.0.1", 443), timeout=3)
        trust.assert_called_once_with()
        context.wrap_socket.assert_called_once_with(stream.__enter__.return_value, server_hostname=HOST)
        context.load_cert_chain.assert_not_called()
        with patch.object(diagnostic.socket, "create_connection", side_effect=ssl.SSLCertVerificationError(PRIVATE)):
            self.assertFalse(diagnostic._tls(HOST))

    def test_report_parser_and_cli_never_emit_raw_values_or_false_success(self):
        value = diagnostic._report()
        self.assertIsNotNone(diagnostic.sanitize_report(json.dumps(value).encode()))
        for changed in ({"hostname": PRIVATE}, {"acme_error": PRIVATE}, {"latest_issuer": PRIVATE},
                        {"retry_delay_seconds": True}, {"scope_verified": 1}, {"status": "success"},
                        {"retry_delay_seconds": 10}, {"rate_limit_subtype": "registered_domain"}):
            self.assertIsNone(diagnostic.sanitize_report(json.dumps({**value, **changed}).encode()))
        with patch.object(diagnostic, "diagnose", side_effect=ValueError(PRIVATE)), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostic.main([base64.b64encode(json.dumps(CONFIG).encode()).decode()]), 2)
        self.assertNotIn(PRIVATE, output.getvalue())
        self.assertIsNotNone(diagnostic.sanitize_report(output.getvalue().encode()))

    def test_fixed_journal_command_is_bounded_and_stderr_is_private(self):
        real_spawn = subprocess.Popen
        captured = []

        def local_spawn(command, **kwargs):
            captured.append((command, kwargs))
            return real_spawn([sys.executable, "-I", "-c", "import sys;sys.stderr.write('hidden');print('{}')"], **kwargs)

        with patch.object(diagnostic.subprocess, "Popen", side_effect=local_spawn):
            self.assertEqual(diagnostic._journal(), b"{}\n")
        command, kwargs = captured[0]
        self.assertEqual(command, [diagnostic.JOURNALCTL, "-u", "quanta-https.service", "-n", "150", "--since=-30min", "-o", "cat", "--no-pager"])
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"], {"PATH": diagnostic.BINPATH, "LC_ALL": "C"})
        def too_large(command, **kwargs):
            return real_spawn([sys.executable, "-I", "-c", "print('x'*600000)"], **kwargs)
        with patch.object(diagnostic.subprocess, "Popen", side_effect=too_large), self.assertRaises(diagnostic.DiagnosticError):
            diagnostic._journal()

    def test_receipt_requires_root_private_regular_file_and_does_not_follow_symlinks(self):
        root_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        private = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_dev=1, st_ino=2)
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.read.return_value = json.dumps(CONFIG).encode()
        with patch.object(Path, "lstat", autospec=True, side_effect=lambda path: private if path == diagnostic.MARKER else root_dir), \
                patch.object(diagnostic.os, "open", return_value=12) as opened, patch.object(diagnostic.os, "fdopen", return_value=stream), \
                patch.object(diagnostic.os, "fstat", return_value=private):
            self.assertEqual(diagnostic._receipt(), CONFIG)
        self.assertTrue(opened.call_args.args[1] & diagnostic.os.O_NOFOLLOW)
        for mode in (stat.S_IFREG | 0o644, stat.S_IFLNK | 0o600):
            bad = SimpleNamespace(st_mode=mode, st_uid=0, st_dev=1, st_ino=2)
            with patch.object(Path, "lstat", autospec=True, side_effect=lambda path: bad if path == diagnostic.MARKER else root_dir), \
                    patch.object(diagnostic.os, "open") as opened, self.assertRaises(diagnostic.DiagnosticError):
                diagnostic._receipt()
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
