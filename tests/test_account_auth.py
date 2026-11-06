"""Account, email proof and session boundaries using synthetic mail only.

No test contacts an SMTP server or uses production credentials. Most lifecycle
tests inject a deliberately cheap *test-only* hasher; a separate test exercises
the actual locked scrypt policy.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from quanta.account_auth import AccountStore, AuthError


OWNER_SECRET = "a1" * 32
OWNER_EMAIL = "owner@example.test"
PASSWORD = "Synthetic long password 47!"
SECOND_PASSWORD = "Another synthetic password 82!"


class Clock:
    def __init__(self):
        self.value = 1_800_000_000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class Mailbox:
    def __init__(self):
        self.messages = []
        self.failure = False

    def __call__(self, email, subject, body):
        if self.failure:
            raise RuntimeError("Synthetic private SMTP server detail")
        self.messages.append((email, subject, body))

    def last_code(self):
        matches = re.findall(r"\b[0-9]{6}\b", self.messages[-1][2])
        if len(matches) != 1:
            raise AssertionError("Expected exactly one synthetic code")
        return matches[0]


class FastHasher:
    """Only a fixture; this is never selected by the deployed application."""
    def __init__(self):
        self.calls = []

    def __call__(self, password, salt):
        self.calls.append((password, salt))
        return hashlib.sha256(b"quanta-test-only\0" + salt + password.encode("utf-8")).digest()


class AccountStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "store"
        self.directory.mkdir(mode=0o700)
        self.clock = Clock()
        self.mailbox = Mailbox()
        self.hasher = FastHasher()
        self.store = AccountStore(self.directory, OWNER_SECRET, mailer=self.mailbox,
                                  clock=self.clock, password_hasher=self.hasher)

    def configure(self):
        return self.store.configure_owner(OWNER_EMAIL, owner_authorized=True)

    def signup(self, *, email=OWNER_EMAIL, username="researcher", password=PASSWORD):
        self.configure()
        self.clock.advance(31)
        pending = self.store.request_signup(email)
        result = self.store.complete_signup(pending.payload["challenge_id"], self.mailbox.last_code(),
                                             username, password)
        return result

    def pending(self, email):
        self.clock.advance(31)
        result = self.store.request_signup(email)
        return result.payload["challenge_id"], self.mailbox.last_code()

    def mfa_enabled_session(self):
        signed = self.signup()
        self.clock.advance(31)
        pending = self.store.request_mfa(signed.session_token, PASSWORD, True)
        result = self.store.complete_mfa(signed.session_token, pending.payload["challenge_id"],
                                        self.mailbox.last_code())
        return result

    @staticmethod
    def wrong_code(code):
        return f"{(int(code) + 1) % 1_000_000:06d}"

    def assert_error(self, status, function, *args, **kwargs):
        with self.assertRaises(AuthError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.status, status)
        return caught.exception

    def test_unconfigured_store_never_grants_owner_to_first_visitor(self):
        status = self.store.status()
        self.assertEqual(status["mode"], "account")
        self.assertFalse(status["authenticated"])
        self.assertTrue(status["bootstrap_required"])
        self.assertEqual(status["registration"], "open")
        self.assertIsNone(self.store.identity("b" * 64))
        self.assert_error(503, self.store.request_signup, OWNER_EMAIL)
        self.assertFalse(self.mailbox.messages)
        self.assert_error(403, self.store.configure_owner, OWNER_EMAIL)

    def test_bootstrap_reservation_correction_requires_private_owner_authorization(self):
        self.assertTrue(self.configure().payload["configured"])
        self.assertTrue(self.configure().payload["configured"])
        self.assert_error(403, self.store.configure_owner, "replacement@example.test")
        self.assertTrue(self.store.configure_owner("replacement@example.test", owner_authorized=True).payload["configured"])
        self.assertTrue(self.store.configure_owner("replacement@example.test", owner_authorized=True).payload["configured"])
        self.assertFalse(self.store.status()["bootstrap_required"])
        self.assertFalse(self.store.status()["authenticated"])

    def test_owner_correction_invalidates_old_sent_and_pending_signup_proofs(self):
        replacement = "corrected-owner@example.test"
        for state in ("sent", "pending"):
            with self.subTest(state=state):
                directory = self.directory / state
                directory.mkdir(mode=0o700)
                mailbox, entered, release = Mailbox(), threading.Event(), threading.Event()

                def sending(email, subject, body):
                    mailbox(email, subject, body)
                    if state == "pending":
                        entered.set()
                        if not release.wait(timeout=5):
                            raise RuntimeError("Synthetic blocked mail timed out")

                store = AccountStore(directory, OWNER_SECRET, mailer=sending, clock=self.clock,
                                     password_hasher=self.hasher)
                store.configure_owner(OWNER_EMAIL, owner_authorized=True)
                if state == "sent":
                    old = store.request_signup(OWNER_EMAIL)
                    identifier = old.payload["challenge_id"]
                    code = mailbox.last_code()
                    store.configure_owner(replacement, owner_authorized=True)
                else:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(store.request_signup, OWNER_EMAIL)
                        try:
                            self.assertTrue(entered.wait(timeout=5))
                            with sqlite3.connect(directory / "auth.sqlite3") as db:
                                identifier = db.execute("SELECT id FROM challenges WHERE state='pending'").fetchone()[0]
                            code = mailbox.last_code()
                            store.configure_owner(replacement, owner_authorized=True)
                        finally:
                            release.set()
                        with self.assertRaises(AuthError) as caught:
                            future.result(timeout=5)
                        self.assertEqual(caught.exception.status, 503)
                self.assert_error(401, store.complete_signup, identifier, code, "old.owner", PASSWORD)
                # Stop blocking subsequent sends; the new address must still
                # supply a fresh email proof before obtaining the legacy owner.
                store._mailer = mailbox
                fresh = store.request_signup(replacement)
                signed = store.complete_signup(fresh.payload["challenge_id"], mailbox.last_code(),
                                               "new.owner", PASSWORD)
                self.assertEqual(signed.payload["account"]["owner"], "local")
                self.assertTrue(signed.payload["account"]["is_admin"])

    def test_owner_correction_cannot_promote_an_existing_public_account(self):
        ordinary = self.signup(email="public.user@example.test", username="public.user")
        before = self.store.identity(ordinary.session_token)
        self.assertFalse(before["is_admin"])
        self.assertNotEqual(before["owner"], "local")
        self.assert_error(409, self.store.configure_owner, before["email"], owner_authorized=True)
        after = self.store.identity(ordinary.session_token)
        self.assertEqual(after, before)
        challenge, code = self.pending(OWNER_EMAIL)
        admin = self.store.complete_signup(challenge, code, "reserved.owner", PASSWORD)
        self.assertEqual(admin.payload["account"]["owner"], "local")
        self.assertEqual(self.store.identity(ordinary.session_token)["owner"], before["owner"])

    def test_established_owner_reservation_is_immutable_and_same_email_is_idempotent(self):
        signed = self.signup()
        before = self.store.identity(signed.session_token)
        self.assert_error(409, self.store.configure_owner, "replacement@example.test", owner_authorized=True)
        self.assertTrue(self.store.configure_owner(OWNER_EMAIL, owner_authorized=True).payload["configured"])
        self.assertEqual(self.store.identity(signed.session_token), before)

    def test_owner_correction_and_old_signup_race_have_only_safe_outcomes(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        identifier, code = pending.payload["challenge_id"], self.mailbox.last_code()
        barrier = threading.Barrier(2)

        def compete(function, *args, **kwargs):
            barrier.wait(timeout=3)
            try:
                return "ok", function(*args, **kwargs)
            except AuthError as error:
                return "error", error.status

        with ThreadPoolExecutor(max_workers=2) as pool:
            corrected = pool.submit(compete, self.store.configure_owner, "replacement@example.test",
                                    owner_authorized=True)
            completed = pool.submit(compete, self.store.complete_signup, identifier, code, "old.owner", PASSWORD)
            correction, signup = corrected.result(timeout=5), completed.result(timeout=5)
        with sqlite3.connect(self.directory / "auth.sqlite3") as db:
            admins = db.execute("SELECT email,owner FROM accounts WHERE admin=1").fetchall()
        if signup[0] == "ok":
            self.assertEqual(correction, ("error", 409))
            self.assertEqual(admins, [(OWNER_EMAIL, "local")])
        else:
            self.assertEqual(signup, ("error", 401))
            self.assertEqual(correction[0], "ok")
            self.assertEqual(admins, [])
            fresh = self.store.request_signup("replacement@example.test")
            signed = self.store.complete_signup(fresh.payload["challenge_id"], self.mailbox.last_code(),
                                               "new.owner", PASSWORD)
            self.assertEqual(signed.payload["account"]["owner"], "local")

    def test_signup_requires_email_proof_and_session_is_private(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        challenge = pending.payload["challenge_id"]
        code = self.mailbox.last_code()
        self.assertIsNone(pending.session_token)
        self.assertFalse(self.store.status()["authenticated"])
        self.assert_error(401, self.store.complete_signup, challenge, self.wrong_code(code),
                          "researcher", PASSWORD)
        result = self.store.complete_signup(challenge, code, "researcher", PASSWORD)
        self.assertTrue(result.payload["authenticated"])
        self.assertEqual(result.payload["account"]["owner"], "local")
        self.assertTrue(result.payload["account"]["is_admin"])
        self.assertEqual(result.payload["account"]["email"], OWNER_EMAIL)
        self.assertRegex(result.session_token, r"^[0-9a-f]{64}$")
        self.assertNotIn(result.session_token, json.dumps(result.payload))
        self.assertEqual(self.store.identity(result.session_token)["owner"], "local")
        self.assert_error(401, self.store.complete_signup, challenge, code, "researcher", PASSWORD)

    def test_public_verified_users_have_distinct_immutable_data_owners(self):
        owner = self.signup()
        first_id, first_code = self.pending("first@example.test")
        first = self.store.complete_signup(first_id, first_code, "first.user", PASSWORD)
        second_id, second_code = self.pending("second@example.test")
        second = self.store.complete_signup(second_id, second_code, "second.user", PASSWORD)
        identities = [self.store.identity(result.session_token) for result in (owner, first, second)]
        self.assertEqual(len({item["owner"] for item in identities}), 3)
        for identity in identities[1:]:
            self.assertNotEqual(identity["owner"], "local")
            self.assertNotIn(identity["owner"], {identity["username"], identity["email"]})
            self.assertFalse(identity["is_admin"])
        again = self.store.login("FIRST.USER", PASSWORD)
        self.assertEqual(again.payload["account"]["owner"], identities[1]["owner"])

    def test_email_normalization_cannot_create_duplicate_accounts(self):
        self.signup()
        self.clock.advance(31)
        pending = self.store.request_signup("OWNER@EXAMPLE.TEST")
        # The public acknowledgement must not advertise whether an account exists.
        self.assertIn("challenge_id", pending.payload)
        self.assertIsNone(pending.session_token)
        self.assert_error(401, self.store.complete_signup, pending.payload["challenge_id"],
                          "000000", "new.name", SECOND_PASSWORD)

    def test_wrong_and_unknown_passwords_have_same_safe_error(self):
        self.signup()
        wrong = self.assert_error(401, self.store.login, "researcher", "Wrong synthetic password 99!")
        unknown = self.assert_error(401, self.store.login, "missing.user", PASSWORD)
        self.assertEqual(wrong.code, unknown.code)
        self.assertEqual(str(wrong), str(unknown))
        self.assertNotIn("researcher", str(wrong))
        self.assertNotIn(PASSWORD, str(wrong))

    def test_mfa_login_never_issues_session_before_email_code(self):
        enabled = self.mfa_enabled_session()
        self.assertTrue(self.store.identity(enabled.session_token)["mfa_enabled"])
        self.clock.advance(31)
        pending = self.store.login("researcher", PASSWORD)
        self.assertTrue(pending.payload["mfa_required"])
        self.assertIsNone(pending.session_token)
        code = self.mailbox.last_code()
        self.assert_error(401, self.store.complete_login, pending.payload["challenge_id"], self.wrong_code(code))
        logged = self.store.complete_login(pending.payload["challenge_id"], code)
        self.assertTrue(logged.payload["authenticated"])
        self.assertTrue(self.store.identity(logged.session_token)["mfa_enabled"])
        self.assert_error(401, self.store.complete_login, pending.payload["challenge_id"], code)

    def test_mfa_toggle_requires_password_email_proof_and_rotates_sessions(self):
        signed = self.signup()
        old = signed.session_token
        self.assert_error(401, self.store.request_mfa, old, "Wrong synthetic password 99!", True)
        self.clock.advance(31)
        pending = self.store.request_mfa(old, PASSWORD, True)
        self.assertFalse(self.store.identity(old)["mfa_enabled"])
        code = self.mailbox.last_code()
        self.assert_error(401, self.store.complete_login, pending.payload["challenge_id"], code)
        enabled = self.store.complete_mfa(old, pending.payload["challenge_id"], code)
        self.assertIsNone(self.store.identity(old))
        self.assertNotEqual(enabled.session_token, old)
        self.assertTrue(self.store.identity(enabled.session_token)["mfa_enabled"])
        self.clock.advance(31)
        pending = self.store.request_mfa(enabled.session_token, PASSWORD, False)
        disabled = self.store.complete_mfa(enabled.session_token, pending.payload["challenge_id"],
                                         self.mailbox.last_code())
        self.assertIsNone(self.store.identity(enabled.session_token))
        self.assertFalse(self.store.identity(disabled.session_token)["mfa_enabled"])

    def test_email_challenges_expire_and_are_bound_to_purpose(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        challenge, code = pending.payload["challenge_id"], self.mailbox.last_code()
        self.assert_error(401, self.store.complete_login, challenge, code)
        self.clock.advance(601)
        self.assert_error(401, self.store.complete_signup, challenge, code, "researcher", PASSWORD)
        self.assertFalse(self.store.status()["authenticated"])

    def test_five_failed_codes_invalidate_challenge_before_correct_code(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        challenge, code = pending.payload["challenge_id"], self.mailbox.last_code()
        for _ in range(5):
            self.assert_error(401, self.store.complete_signup, challenge, self.wrong_code(code),
                              "researcher", PASSWORD)
        self.assert_error(401, self.store.complete_signup, challenge, code, "researcher", PASSWORD)

    def test_resend_cooldown_does_not_send_mail_and_new_challenge_replaces_old(self):
        self.configure()
        first = self.store.request_signup(OWNER_EMAIL)
        first_code = self.mailbox.last_code()
        self.assert_error(429, self.store.request_signup, OWNER_EMAIL)
        self.assertEqual(len(self.mailbox.messages), 1)
        self.clock.advance(31)
        second = self.store.request_signup(OWNER_EMAIL)
        self.assertNotEqual(first.payload["challenge_id"], second.payload["challenge_id"])
        self.assert_error(401, self.store.complete_signup, first.payload["challenge_id"], first_code,
                          "researcher", PASSWORD)

    def test_wrong_code_budget_survives_resend_and_expires_only_after_window(self):
        self.configure()
        first = self.store.request_signup(OWNER_EMAIL)
        first_code = self.mailbox.last_code()
        for _ in range(3):
            self.assert_error(401, self.store.complete_signup, first.payload["challenge_id"],
                              self.wrong_code(first_code), "researcher", PASSWORD)
        self.clock.advance(31)
        second = self.store.request_signup(OWNER_EMAIL)
        second_code = self.mailbox.last_code()
        for _ in range(2):
            self.assert_error(401, self.store.complete_signup, second.payload["challenge_id"],
                              self.wrong_code(second_code), "researcher", PASSWORD)
        self.assert_error(401, self.store.complete_signup, second.payload["challenge_id"],
                          second_code, "researcher", PASSWORD)
        self.clock.advance(31)
        self.assert_error(429, self.store.request_signup, OWNER_EMAIL)
        self.clock.advance(901)
        fresh = self.store.request_signup(OWNER_EMAIL)
        result = self.store.complete_signup(fresh.payload["challenge_id"], self.mailbox.last_code(),
                                           "researcher", PASSWORD)
        self.assertTrue(result.payload["authenticated"])

    def test_mail_failure_is_sanitized_and_cannot_activate_account(self):
        self.configure()
        self.mailbox.failure = True
        error = self.assert_error(503, self.store.request_signup, OWNER_EMAIL)
        self.assertNotIn("SMTP", str(error))
        self.assertNotIn("private", str(error))
        self.assertFalse(self.store.status()["authenticated"])

    def test_unconfigured_mailer_fails_closed(self):
        other = self.directory / "no-mail"
        other.mkdir(mode=0o700)
        store = AccountStore(other, OWNER_SECRET, clock=self.clock, password_hasher=self.hasher)
        store.configure_owner(OWNER_EMAIL, owner_authorized=True)
        self.assertFalse(store.status()["mail_configured"])
        self.assert_error(503, store.request_signup, OWNER_EMAIL)

    def test_logout_revokes_server_session_and_expiry_survives_reopen(self):
        signed = self.signup()
        original = signed.session_token
        reopened = AccountStore(self.directory, OWNER_SECRET, mailer=self.mailbox,
                                clock=self.clock, password_hasher=self.hasher)
        self.assertEqual(reopened.identity(original)["owner"], "local")
        response = reopened.logout(original)
        self.assertTrue(response.clear_session)
        self.assertIsNone(self.store.identity(original))
        logged = self.store.login("researcher", PASSWORD)
        self.clock.advance(24 * 60 * 60 + 1)
        self.assertIsNone(reopened.identity(logged.session_token))

    def test_absolute_expiry_cannot_be_extended_by_regular_activity(self):
        signed = self.signup()
        for day in range(8):
            if day:
                self.clock.advance(23 * 60 * 60)
            self.assertIsNotNone(self.store.identity(signed.session_token))
        # Total age exceeds seven days, but the most recent use is only eight
        # hours ago: this proves absolute expiry rather than the idle timeout.
        self.clock.advance(8 * 60 * 60 + 1)
        self.assertIsNone(self.store.identity(signed.session_token))

    def test_csrf_is_bound_to_session_and_rotates_on_new_login(self):
        signed = self.signup()
        first = self.store.identity(signed.session_token)
        self.assertRegex(first["csrf_token"], r"^[0-9a-f]{64}$")
        self.assertEqual(first["csrf_token"], self.store.status(signed.session_token)["csrf_token"])
        second = self.store.login("researcher", PASSWORD)
        self.assertNotEqual(first["csrf_token"], self.store.identity(second.session_token)["csrf_token"])

    def test_password_reset_requires_email_proof_and_revokes_old_sessions(self):
        signed = self.signup()
        self.clock.advance(31)
        pending = self.store.request_password_reset(OWNER_EMAIL)
        challenge, code = pending.payload["challenge_id"], self.mailbox.last_code()
        self.assert_error(401, self.store.complete_password_reset, challenge, self.wrong_code(code), SECOND_PASSWORD)
        result = self.store.complete_password_reset(challenge, code, SECOND_PASSWORD)
        self.assertIsNone(result.session_token)
        self.assertIsNone(self.store.identity(signed.session_token))
        self.assert_error(401, self.store.login, "researcher", PASSWORD)
        logged = self.store.login("researcher", SECOND_PASSWORD)
        self.assertEqual(logged.payload["account"]["owner"], "local")
        self.assert_error(401, self.store.complete_password_reset, challenge, code, PASSWORD)

    def test_sensitive_input_is_never_stored_in_cleartext(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        code = self.mailbox.last_code()
        signed = self.store.complete_signup(pending.payload["challenge_id"], code, "researcher", PASSWORD)
        database = self.directory / "auth.sqlite3"
        self.assertEqual(database.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(PASSWORD.encode(), database.read_bytes())
        self.assertNotIn(signed.session_token.encode(), database.read_bytes())
        with sqlite3.connect(database) as db:
            for (name,) in db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
                self.assertRegex(name, r"^[a-z_]+$")
                for row in db.execute('SELECT * FROM "' + name + '"'):
                    self.assertNotIn(code, row)
                    self.assertNotIn(PASSWORD, row)
                    self.assertNotIn(signed.session_token, row)

    def test_result_representation_never_discloses_session_secret(self):
        signed = self.signup()
        self.assertNotIn(signed.session_token, repr(signed))
        self.assertNotIn(signed.session_token, str(signed))

    def test_changed_or_missing_password_scheme_refuses_existing_accounts(self):
        self.signup()
        database = self.directory / "auth.sqlite3"
        with sqlite3.connect(database) as db:
            row = db.execute("SELECT value FROM meta WHERE key='password_scheme'").fetchone()
            self.assertIsNotNone(row)
            original_scheme = row[0]
            db.execute("UPDATE meta SET value='unsupported-test-scheme' WHERE key='password_scheme'")
        self.assert_error(503, AccountStore, self.directory, OWNER_SECRET, mailer=self.mailbox,
                          clock=self.clock, password_hasher=self.hasher)
        with sqlite3.connect(database) as db:
            db.execute("UPDATE meta SET value=? WHERE key='password_scheme'", (original_scheme,))
            db.execute("DELETE FROM meta WHERE key='password_scheme'")
        self.assert_error(503, AccountStore, self.directory, OWNER_SECRET, mailer=self.mailbox,
                          clock=self.clock, password_hasher=self.hasher)
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM accounts").fetchone()[0], 1)

    def test_auth_storage_does_not_modify_scientific_database(self):
        science = self.directory / "jobs.sqlite3"
        science.write_bytes(b"Synthetic scientific database sentinel")
        before = science.read_bytes()
        self.signup()
        self.assertEqual(science.read_bytes(), before)

    def test_invalid_identity_input_is_rejected_before_mail_or_hash(self):
        self.configure()
        for email in ["not-an-email", "x@example.test\r\nBcc:other@example.test", "é@example.test"]:
            self.assert_error(422, self.store.request_signup, email)
        self.assertFalse(self.mailbox.messages)
        self.assertFalse(self.hasher.calls)
        pending = self.store.request_signup(OWNER_EMAIL)
        code = self.mailbox.last_code()
        for username, password in [("ab", PASSWORD), ("name with space", PASSWORD), ("researcher", "short")]:
            self.assert_error(422, self.store.complete_signup, pending.payload["challenge_id"], code,
                              username, password)

    def test_password_attempt_budget_is_applied_before_expensive_hash(self):
        self.signup()
        blocked = False
        for _ in range(9):
            calls_before = len(self.hasher.calls)
            try:
                self.store.login("researcher", "Wrong synthetic password 99!")
            except AuthError as error:
                if error.status == 429:
                    self.assertEqual(len(self.hasher.calls), calls_before)
                    blocked = True
                    break
                self.assertEqual(error.status, 401)
            else:
                self.fail("Wrong password authenticated")
        self.assertTrue(blocked, "Account failures must be rate limited within the configured budget")
        self.clock.advance(301)
        self.assertTrue(self.store.login("researcher", PASSWORD).payload["authenticated"])

    def test_mfa_confirmation_is_bound_to_the_requesting_session(self):
        first = self.signup()
        second = self.store.login("researcher", PASSWORD)
        self.clock.advance(31)
        pending = self.store.request_mfa(first.session_token, PASSWORD, True)
        code = self.mailbox.last_code()
        self.assert_error(401, self.store.complete_mfa, second.session_token,
                          pending.payload["challenge_id"], code)
        self.assertFalse(self.store.identity(first.session_token)["mfa_enabled"])
        successful = self.store.complete_mfa(first.session_token, pending.payload["challenge_id"], code)
        self.assertTrue(self.store.identity(successful.session_token)["mfa_enabled"])

    def test_password_reset_between_password_check_and_mfa_login_issue_denies_stale_proof(self):
        self.mfa_enabled_session()
        self.clock.advance(31)
        reset = self.store.request_password_reset(OWNER_EMAIL)
        reset_code = self.mailbox.last_code()
        self.clock.advance(31)
        original_hash = self.store._hash
        reset_completed = False

        def hash_then_reset(password, salt):
            nonlocal reset_completed
            digest = original_hash(password, salt)
            if not reset_completed:
                reset_completed = True
                self.store.complete_password_reset(reset.payload["challenge_id"], reset_code, SECOND_PASSWORD)
            return digest

        messages_before = len(self.mailbox.messages)
        with patch.object(self.store, "_hash", side_effect=hash_then_reset):
            self.assert_error(401, self.store.login, "researcher", PASSWORD)
        self.assertTrue(reset_completed)
        self.assertEqual(len(self.mailbox.messages), messages_before)

    def test_password_reset_between_mfa_password_check_and_issue_rejects_revoked_session(self):
        signed = self.signup()
        self.clock.advance(31)
        reset = self.store.request_password_reset(OWNER_EMAIL)
        reset_code = self.mailbox.last_code()
        self.clock.advance(31)
        original_hash = self.store._hash
        reset_completed = False

        def hash_then_reset(password, salt):
            nonlocal reset_completed
            digest = original_hash(password, salt)
            if not reset_completed:
                reset_completed = True
                self.store.complete_password_reset(reset.payload["challenge_id"], reset_code, SECOND_PASSWORD)
            return digest

        messages_before = len(self.mailbox.messages)
        with patch.object(self.store, "_hash", side_effect=hash_then_reset):
            self.assert_error(401, self.store.request_mfa, signed.session_token, PASSWORD, True)
        self.assertEqual(len(self.mailbox.messages), messages_before)
        self.assertIsNone(self.store.identity(signed.session_token))

    def test_reset_invalidates_pending_mfa_login_and_keeps_mfa_enabled(self):
        self.mfa_enabled_session()
        self.clock.advance(31)
        login = self.store.login("researcher", PASSWORD)
        login_code = self.mailbox.last_code()
        self.clock.advance(31)
        reset = self.store.request_password_reset(OWNER_EMAIL)
        self.store.complete_password_reset(reset.payload["challenge_id"], self.mailbox.last_code(), SECOND_PASSWORD)
        self.assert_error(401, self.store.complete_login, login.payload["challenge_id"], login_code)
        self.clock.advance(31)
        next_login = self.store.login("researcher", SECOND_PASSWORD)
        self.assertTrue(next_login.payload["mfa_required"])
        self.assertIsNone(next_login.session_token)
        signed = self.store.complete_login(next_login.payload["challenge_id"], self.mailbox.last_code())
        self.assertTrue(self.store.identity(signed.session_token)["mfa_enabled"])

    def test_password_minimum_and_exact_whitespace_are_preserved(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        code = self.mailbox.last_code()
        self.assert_error(422, self.store.complete_signup, pending.payload["challenge_id"], code,
                          "researcher", "12345678901234")
        spaced = " " + PASSWORD + " "
        self.store.complete_signup(pending.payload["challenge_id"], code, "researcher", spaced)
        self.assert_error(401, self.store.login, "researcher", PASSWORD)
        self.assertTrue(self.store.login("researcher", spaced).payload["authenticated"])

    def test_unicode_password_is_not_normalized(self):
        composed = "é" * 15
        decomposed = "e\u0301" * 15
        self.signup(password=composed)
        self.assert_error(401, self.store.login, "researcher", decomposed)
        self.assertTrue(self.store.login("researcher", composed).payload["authenticated"])

    def test_duplicate_concurrent_email_verification_creates_only_one_account(self):
        self.configure()
        pending = self.store.request_signup(OWNER_EMAIL)
        challenge, code = pending.payload["challenge_id"], self.mailbox.last_code()
        barrier = threading.Barrier(2)
        def finish():
            barrier.wait(timeout=3)
            try:
                return self.store.complete_signup(challenge, code, "researcher", PASSWORD)
            except AuthError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(finish) for _ in range(2)]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(sum(result is not None for result in results), 1)
        with sqlite3.connect(self.directory / "auth.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM accounts").fetchone()[0], 1)

    def test_file_symlink_hardlink_and_unsafe_modes_are_refused(self):
        target = self.directory / "target"
        target.write_bytes(b"Synthetic untouched bytes")
        target.chmod(0o600)
        for kind in ("symlink", "hardlink", "mode"):
            with self.subTest(kind=kind):
                folder = self.directory / kind
                folder.mkdir(mode=0o700)
                database = folder / "auth.sqlite3"
                if kind == "symlink":
                    database.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, database)
                else:
                    database.touch(mode=0o644)
                    database.chmod(0o644)
                with self.assertRaises((AuthError, ValueError, OSError)):
                    AccountStore(folder, OWNER_SECRET, mailer=self.mailbox,
                                 clock=self.clock, password_hasher=self.hasher)
        self.assertEqual(target.read_bytes(), b"Synthetic untouched bytes")

    def test_unrecognized_existing_database_is_rejected_without_modifying_bytes(self):
        folder = self.directory / "unrecognized"
        folder.mkdir(mode=0o700)
        database = folder / "auth.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE unrelated_scientific_data(value TEXT)")
            connection.execute("INSERT INTO unrelated_scientific_data VALUES('synthetic preserved record')")
            connection.commit()
        finally:
            connection.close()
        database.chmod(0o600)
        before = database.read_bytes()
        self.assert_error(503, AccountStore, folder, OWNER_SECRET, mailer=self.mailbox,
                          clock=self.clock, password_hasher=self.hasher)
        self.assertEqual(database.read_bytes(), before)

    def test_mail_free_login_prunes_old_username_buckets_and_keeps_current_limits(self):
        # Unknown names are attacker-selected. Maintenance must not depend on
        # an email flow occurring later to reclaim their persistent buckets.
        for day in range(4):
            username = f"unknown.user.{day}"
            for _ in range(8):
                self.assert_error(401, self.store.login, username, PASSWORD)
            calls = len(self.hasher.calls)
            self.assert_error(429, self.store.login, username, PASSWORD)
            self.assertEqual(len(self.hasher.calls), calls)
            with sqlite3.connect(self.store.path) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM rate_windows").fetchone()[0], 2)
                self.assertEqual(db.execute("SELECT count(*) FROM accounts").fetchone()[0], 0)
            if day < 3:
                self.clock.advance(86401)
        self.assertFalse(self.mailbox.messages)
        self.assertEqual(len(self.hasher.calls), 32)


class RealScryptTests(unittest.TestCase):
    def test_real_scrypt_round_trip_is_usable_for_owner_login(self):
        with tempfile.TemporaryDirectory() as directory:
            mailbox = Mailbox()
            clock = Clock()
            store = AccountStore(Path(directory), OWNER_SECRET, mailer=mailbox, clock=clock)
            store.configure_owner(OWNER_EMAIL, owner_authorized=True)
            pending = store.request_signup(OWNER_EMAIL)
            signed = store.complete_signup(pending.payload["challenge_id"], mailbox.last_code(),
                                           "real.scrypt", PASSWORD)
            self.assertEqual(store.identity(signed.session_token)["owner"], "local")
            logged = store.login("real.scrypt", PASSWORD)
            self.assertTrue(logged.payload["authenticated"])
            self.assertIsNotNone(logged.session_token)
            self.assertEqual(store.status(logged.session_token)["principal"]["username"], "real.scrypt")


if __name__ == "__main__":
    unittest.main()
