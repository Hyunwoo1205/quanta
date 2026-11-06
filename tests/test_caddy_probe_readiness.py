"""Local TLS readiness and bounded diagnostics; no Caddy/OCI/network required."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import ssl
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quanta_caddy_readiness", ROOT / "scripts/verify_caddy.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
CA = Path("/synthetic-local-ca/root.crt")
PORT = 19443


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def socket_fixture(alpn="http/1.1"):
    raw = mock.MagicMock()
    raw.__enter__.return_value = raw
    secured = mock.MagicMock()
    secured.__enter__.return_value = secured
    secured.selected_alpn_protocol.return_value = alpn
    context = types.SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED,
                                    set_alpn_protocols=mock.Mock(), wrap_socket=mock.Mock(return_value=secured))
    return raw, secured, context


class TLSReadinessTests(unittest.TestCase):
    def test_first_success_uses_ca_sni_alpn_and_sends_no_http(self):
        raw, secured, context = socket_fixture()
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe.ssl, "create_default_context", return_value=context) as create, \
                mock.patch.object(probe.socket, "create_connection", return_value=raw) as connect, \
                mock.patch.object(probe.time, "sleep") as sleep:
            probe._wait_for_local_tls(process, CA, PORT)
        create.assert_called_once_with(cafile=CA)
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        connect.assert_called_once_with(("127.0.0.1", PORT), timeout=0.5)
        context.wrap_socket.assert_called_once_with(raw, server_hostname=probe.HOST)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(raw.settimeout.call_args.args[0], 0)
        self.assertLessEqual(raw.settimeout.call_args.args[0], 0.5)
        raw.sendall.assert_not_called()
        secured.sendall.assert_not_called()
        sleep.assert_not_called()

    def test_waits_for_missing_ca_and_leaf_before_accepting_verified_tls(self):
        raw, secured, context = socket_fixture()
        context.wrap_socket.side_effect = [ssl.SSLCertVerificationError("synthetic leaf not ready"), secured]
        clock = Clock()
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe.ssl, "create_default_context", side_effect=[FileNotFoundError(), context, context]) as create, \
                mock.patch.object(probe.socket, "create_connection", return_value=raw) as connect, \
                mock.patch.object(probe.time, "monotonic", side_effect=clock.monotonic), \
                mock.patch.object(probe.time, "sleep", side_effect=clock.sleep):
            probe._wait_for_local_tls(process, CA, PORT)
        self.assertEqual(create.call_count, 3)
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(context.wrap_socket.call_count, 2)
        self.assertAlmostEqual(clock.now, 0.1)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        secured.sendall.assert_not_called()

    def test_connection_refusal_is_a_readiness_retry(self):
        raw, _, context = socket_fixture()
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe.ssl, "create_default_context", return_value=context), \
                mock.patch.object(probe.socket, "create_connection", side_effect=[ConnectionRefusedError(), raw]) as connect, \
                mock.patch.object(probe.time, "sleep") as sleep:
            probe._wait_for_local_tls(process, CA, PORT)
        self.assertEqual(connect.call_count, 2)
        sleep.assert_called_once()

    def test_caddy_exit_is_reported_before_another_connection(self):
        process = mock.Mock()
        process.poll.return_value = 1
        with mock.patch.object(probe.ssl, "create_default_context") as create, \
                mock.patch.object(probe.socket, "create_connection") as connect, \
                self.assertRaisesRegex(RuntimeError, "exited during TLS startup"):
            probe._wait_for_local_tls(process, CA, PORT)
        create.assert_not_called()
        connect.assert_not_called()

    def test_caddy_exit_after_incomplete_handshake_is_not_hidden_by_retry(self):
        raw, _, context = socket_fixture()
        context.wrap_socket.side_effect = ssl.SSLError("synthetic startup")
        process = mock.Mock()
        process.poll.side_effect = [None, 1]
        with mock.patch.object(probe.ssl, "create_default_context", return_value=context), \
                mock.patch.object(probe.socket, "create_connection", return_value=raw) as connect, \
                mock.patch.object(probe.time, "sleep"), \
                self.assertRaisesRegex(RuntimeError, "exited during TLS startup"):
            probe._wait_for_local_tls(process, CA, PORT)
        connect.assert_called_once()

    def test_unready_ca_has_a_twenty_second_deadline_without_real_sleep(self):
        clock = Clock()
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe.ssl, "create_default_context", side_effect=FileNotFoundError()), \
                mock.patch.object(probe.socket, "create_connection") as connect, \
                mock.patch.object(probe.time, "monotonic", side_effect=clock.monotonic), \
                mock.patch.object(probe.time, "sleep", side_effect=clock.sleep), \
                self.assertRaisesRegex(RuntimeError, r"TLS startup timed out \(FileNotFoundError\)"):
            probe._wait_for_local_tls(process, CA, PORT)
        self.assertAlmostEqual(clock.now, 20)
        self.assertTrue(all(0 < seconds <= 0.05 for seconds in clock.sleeps))
        connect.assert_not_called()

    def test_wrong_alpn_fails_instead_of_weakening_or_retrying(self):
        raw, _, context = socket_fixture(alpn="h2")
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(probe.ssl, "create_default_context", return_value=context), \
                mock.patch.object(probe.socket, "create_connection", return_value=raw), \
                mock.patch.object(probe.time, "sleep") as sleep, \
                self.assertRaisesRegex(RuntimeError, "did not negotiate HTTP/1.1"):
            probe._wait_for_local_tls(process, CA, PORT)
        sleep.assert_not_called()


class CurlFailureTests(unittest.TestCase):
    def test_exit_code_and_fixture_stderr_are_preserved(self):
        response = types.SimpleNamespace(returncode=35, stderr=b"curl: (35) synthetic TLS alert\n")
        self.assertEqual(probe._curl_failure("http1_known_length", response),
                         "http1_known_length: curl failed (exit=35; stderr=curl: (35) synthetic TLS alert)")

    def test_stderr_is_bounded_and_invalid_utf8_does_not_hide_failure(self):
        response = types.SimpleNamespace(returncode=60, stderr=b"\xff" + b"x" * 1023 + b"not-in-report")
        message = probe._curl_failure("http1_known_length", response)
        self.assertIn("exit=60", message)
        self.assertIn("\ufffd", message)
        self.assertNotIn("not-in-report", message)
        self.assertLess(len(message), 1200)

    def test_empty_stderr_keeps_exit_reason(self):
        response = types.SimpleNamespace(returncode=7, stderr=b"")
        self.assertIn("exit=7; stderr=<empty>", probe._curl_failure("http1_known_length", response))


if __name__ == "__main__":
    unittest.main()
