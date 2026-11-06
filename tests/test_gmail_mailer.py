"""Delivery and private-file boundaries; all SMTP connections are synthetic."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest

from quanta.gmail_mailer import GmailMailer, MailUnavailable, MAX_DAILY_ATTEMPTS


class FakeSMTP:
    def __init__(self, calls, *, refused=None, failure=False):
        self.calls, self.refused, self.failure = calls, refused, failure

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def login(self, username, password):
        self.calls.append(("login", username, password))
        if self.failure:
            raise RuntimeError("synthetic-secret-that-must-not-escape")

    def send_message(self, message, **kwargs):
        self.calls.append(("send", message, kwargs))
        return self.refused or {}


class GmailMailerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.calls = []
        self.now = [1_800_000_000.0]
        self.connections = []

    def tearDown(self):
        self.temporary.cleanup()

    def mailer(self, **options):
        def factory(host, port, **kwargs):
            self.connections.append((host, port, kwargs))
            return FakeSMTP(self.calls, **options)
        return GmailMailer(self.root, smtp_factory=factory, clock=lambda: self.now[0])

    def configured(self, **options):
        mailer = self.mailer(**options)
        mailer.configure("Sender@Example.com", "abcd efgh ijkl mnop")
        return mailer

    def test_configuration_is_private_and_survives_a_new_adapter(self):
        self.assertFalse(self.mailer().configured)
        first = self.configured()
        self.assertTrue(first.configured)
        self.assertEqual(os.stat(first.path).st_mode & 0o777, 0o600)
        self.assertTrue(self.mailer().configured)
        self.assertEqual(json.loads(first.path.read_text())["username"], "sender@example.com")

    def test_verified_tls_fixed_host_and_single_sender_recipient(self):
        mailer = self.configured()
        self.assertIsNone(mailer("Recipient@example.net", "Quanta 인증번호", "Synthetic verification only"))
        host, port, options = self.connections[0]
        self.assertEqual((host, port, options["timeout"]), ("smtp.gmail.com", 465, 10))
        self.assertTrue(options["context"].check_hostname)
        self.assertEqual(options["context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(self.calls[0], ("login", "sender@example.com", "abcdefghijklmnop"))
        _, message, delivery = self.calls[1]
        self.assertEqual(str(message["From"]), "sender@example.com")
        self.assertEqual(delivery, {"from_addr": "sender@example.com", "to_addrs": ["recipient@example.net"]})

    def test_bad_credentials_or_header_injection_never_open_a_connection(self):
        for username, password in [("a@example.com\r\nBcc: b@example.com", "abcdefghijklmnop"),
                                   ("a@example.com", "short"), ("a@example.com", "abcdefghijklmnop\n")]:
            with self.subTest(username=username), self.assertRaises(ValueError):
                self.mailer().configure(username, password)
        mailer = self.configured()
        for recipient, subject in [("a@example.com,b@example.com", "test"),
                                   ("a@example.com", "test\r\nBcc: x@example.net")]:
            with self.assertRaises(MailUnavailable):
                mailer(recipient, subject, "body")
        self.assertEqual(self.connections, [])

    def test_unconfigured_delivery_fails_closed_without_network(self):
        with self.assertRaises(MailUnavailable):
            self.mailer()("a@example.com", "test", "body")
        self.assertEqual(self.connections, [])

    def test_provider_exception_details_never_escape(self):
        mailer = self.configured(failure=True)
        with self.assertRaises(MailUnavailable) as caught:
            mailer("a@example.com", "test", "body")
        self.assertNotIn("synthetic-secret", str(caught.exception))
        self.assertEqual(len(json.loads(mailer.budget_path.read_text())["attempts"]), 1)

    def test_recipient_refusal_is_not_successful_delivery(self):
        with self.assertRaises(MailUnavailable):
            self.configured(refused={"a@example.com": (550, b"synthetic refusal")})("a@example.com", "test", "body")

    def test_budget_is_persistent_across_instances_and_counts_failed_attempts(self):
        mailer = self.configured(failure=True)
        for _ in range(10):
            with self.assertRaises(MailUnavailable):
                mailer("a@example.com", "test", "body")
        previous = len(self.connections)
        with self.assertRaises(MailUnavailable):
            self.mailer()("b@example.com", "test", "body")
        self.assertEqual(len(self.connections), previous)
        self.now[0] += 61
        self.mailer()("a@example.com", "test", "body")

    def test_daily_budget_cannot_be_reset_by_reconfiguration(self):
        mailer = self.configured()
        for index in range(MAX_DAILY_ATTEMPTS):
            if index and index % 10 == 0:
                self.now[0] += 61
            mailer("a@example.com", "test", "body")
        self.now[0] += 61
        mailer.configure("other@example.com", "abcdefghijklmnop")
        with self.assertRaises(MailUnavailable):
            mailer("a@example.com", "test", "body")
        self.now[0] += 86401
        mailer("a@example.com", "test", "body")

    def test_backward_clock_and_corrupt_budget_fail_closed(self):
        mailer = self.configured()
        mailer("a@example.com", "test", "body")
        self.now[0] -= 1
        with self.assertRaises(MailUnavailable):
            mailer("a@example.com", "test", "body")
        self.now[0] += 2
        mailer.budget_path.write_text('{"schema_version":1,"schema_version":1,"attempts":[]}')
        with self.assertRaises(MailUnavailable):
            mailer("a@example.com", "test", "body")

    def test_symlink_and_world_readable_config_are_not_repaired_or_used(self):
        outside = self.root / "outside"
        outside.write_text("preserve me")
        path = self.root / "gmail-smtp.json"
        path.symlink_to(outside)
        mailer = self.mailer()
        self.assertFalse(mailer.configured)
        with self.assertRaises(MailUnavailable):
            mailer.configure("a@example.com", "abcdefghijklmnop")
        self.assertEqual(outside.read_text(), "preserve me")
        path.unlink()
        mailer.configure("a@example.com", "abcdefghijklmnop")
        path.chmod(0o644)
        self.assertFalse(mailer.configured)
        with self.assertRaises(MailUnavailable):
            mailer("a@example.com", "test", "body")
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_hardlinked_config_is_refused(self):
        mailer = self.configured()
        os.link(mailer.path, self.root / "linked-config")
        self.assertFalse(mailer.configured)
        with self.assertRaises(MailUnavailable):
            mailer.configure("a@example.com", "abcdefghijklmnop")

    def test_oversize_message_is_refused_before_budget_or_network(self):
        mailer = self.configured()
        with self.assertRaises(MailUnavailable):
            mailer("a@example.com", "test", "x" * 8193)
        self.assertFalse(mailer.budget_path.exists())
        self.assertEqual(self.connections, [])


if __name__ == "__main__":
    unittest.main()
