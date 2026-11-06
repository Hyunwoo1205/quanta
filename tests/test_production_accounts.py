"""Actual account-store flows across the ASGI authentication boundary.

Only the numerical service/worker are doubles. Email is accepted by an in-memory
fixture and test hashing is deliberately cheap; production scrypt is separately
covered by account-store tests. No real credentials or network mail are used.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from quanta.account_auth import AccountStore, AuthError
from quanta.owner_token import OwnerTokenConfig

ORIGIN = "https://quanta.example.com"
OWNER_TOKEN = "0123456789abcdef" * 4
PASSWORD = "account fixture password"
SESSION = "__Host-quanta_session"


class ServiceError(ValueError):
    def __init__(self, status, code, message, details=None):
        super().__init__(message)
        self.status, self.code, self.details = status, code, details or {}


def production_module():
    # The transport is loaded against a small, explicit service interface so
    # these tests can run with stdlib unittest without scientific dependencies.
    errors = types.ModuleType("quanta.job_store")
    errors.ServiceError = ServiceError
    web = types.ModuleType("quanta.server")
    web._CSP = "default-src 'self'"
    web._WEB_RESOURCES = {"/": ("index.html", "text/html; charset=utf-8")}
    web.error_document = lambda error: {"error": {"code": error.code, "message": str(error)}}
    workers = types.ModuleType("quanta.worker")
    workers.JobWorker = lambda directory: Worker()
    spec = importlib.util.spec_from_file_location("quanta._account_http_under_test", ROOT / "src/quanta/production.py")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"quanta.job_store": errors, "quanta.server": web, "quanta.worker": workers}):
        spec.loader.exec_module(module)
    return module


production = production_module()


class Worker:
    healthy = True

    def start(self):
        self.healthy = True

    def stop(self):
        self.healthy = False


class Service:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.store = types.SimpleNamespace(path=directory / "jobs.sqlite3")
        with sqlite3.connect(self.store.path) as db:
            db.execute("CREATE TABLE runs(id INTEGER)")
        self.records = {"local": [{"title": "Existing private experiment"}]}
        self.requests = []

    def request(self, owner, method, path, body, *, idempotency_key=None):
        self.requests.append((owner, method, path))
        if method == "GET" and path == "/v1/capabilities":
            return 200, {"execution": {}}
        if path == "/v1/experiments":
            if method == "GET":
                return 200, {"items": list(self.records.get(owner, []))}
            if method == "POST":
                self.records.setdefault(owner, []).append({"title": body["title"]})
                return 201, {"saved": True}
        return 404, {"error": {"code": "NOT_FOUND"}}


class Mailer:
    def __init__(self):
        self.configured = False
        self.fail_configure = False
        self.messages = []

    @staticmethod
    def validate_credentials(username, password):
        if not isinstance(username, str) or not username.endswith("@gmail.com") or password != "abcdefghijklmnop":
            raise ValueError("Synthetic invalid settings")
        return username, password

    def configure(self, username, password):
        if self.fail_configure:
            raise OSError("Synthetic private SMTP failure must never be returned")
        self.configured = True

    def __call__(self, email, subject, body):
        if not self.configured:
            raise RuntimeError("Synthetic private mail credentials must never be returned")
        self.messages.append((email, subject, body))

    def code(self):
        return re.search(r"\b([0-9]{6})\b", self.messages[-1][2])[1]


class ProductionAccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.service = Service(Path(self.temp.name) / "service")
        self.mailer = Mailer()
        self.now = [1_800_000_000.0]
        self.accounts = AccountStore(self.service.directory, OWNER_TOKEN, mailer=self.mailer,
            clock=lambda: self.now[0], password_hasher=lambda password, salt: hashlib.sha256(salt + password.encode()).digest())
        self.app = production.create_app(self.service, OwnerTokenConfig(ORIGIN, OWNER_TOKEN),
            worker=Worker(), account_store=self.accounts, mailer=self.mailer)
        self.app._started = True

    def request(self, path="/ui/auth", *, method="GET", value=None, raw=None, token=None,
                csrf=None, authorization=None, extra=(), replacements=None, auth_header=True):
        if raw is None:
            raw = b"" if value is None else json.dumps(value).encode()
        headers = [(b"host", b"quanta.example.com"), (b"content-length", str(len(raw)).encode())]
        if method not in {"GET", "HEAD"}:
            headers += [(b"origin", ORIGIN.encode()), (b"content-type", b"application/json")]
        if auth_header and path.startswith("/auth/"):
            headers.append((b"x-quanta-auth", b"1"))
        if token is not None:
            headers.append((b"cookie", (SESSION + "=" + token).encode()))
        if csrf is not None:
            headers.append((b"x-quanta-csrf", csrf.encode()))
        if authorization is not None:
            headers.append((b"authorization", authorization.encode()))
        if replacements:
            headers = [(key, value) for key, value in headers if key not in replacements]
            headers += [(key, value) for key, value in replacements.items() if value is not None]
        headers += list(extra)
        target, _, query = path.partition("?")
        sent = []

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send(event):
            sent.append(event)

        asyncio.run(self.app({"type": "http", "method": method, "path": target, "raw_path": target.encode(),
            "query_string": query.encode(), "headers": headers}, receive, send))
        payload = json.loads(sent[1]["body"]) if sent[1]["body"] else None
        return sent[0]["status"], payload, dict(sent[0]["headers"])

    def configure(self, email="owner@example.com"):
        return self.request("/auth/admin/configure", method="POST", value={
            "smtp_username": "sender@gmail.com", "smtp_password": "abcdefghijklmnop", "owner_email": email},
            authorization="Bearer " + OWNER_TOKEN)

    def signup(self, email="owner@example.com", username="owner.fixture"):
        self.now[0] += 31
        status, challenge, _ = self.request("/auth/signup/request", method="POST", value={"email": email})
        self.assertEqual(status, 202)
        status, body, headers = self.request("/auth/signup/complete", method="POST", value={
            "challenge_id": challenge["challenge_id"], "code": self.mailer.code(), "username": username, "password": PASSWORD})
        self.assertEqual(status, 201)
        cookie = headers[b"set-cookie"].decode()
        token = cookie.split(";", 1)[0].split("=", 1)[1]
        return token, body["csrf_token"], body, cookie

    def test_anonymous_discovery_is_bounded_and_registration_waits_for_owner_setup(self):
        status, value, headers = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(value["mode"], "account")
        self.assertFalse(value["configured"])
        self.assertFalse(value["authenticated"])
        self.assertIsNone(value["principal"])
        self.assertIsNone(value["csrf_token"])
        self.assertNotIn(b"set-cookie", headers)
        status, value, _ = self.request("/auth/signup/request", method="POST", value={"email": "owner@example.com"})
        self.assertEqual(status, 503)
        self.assertNotIn("owner@example.com", json.dumps(value))

    def test_private_bearer_setup_does_not_return_smtp_secret_or_skip_email_verification(self):
        status, body, headers = self.configure()
        self.assertEqual(status, 200)
        self.assertNotIn("abcdefghijklmnop", json.dumps(body))
        self.assertNotIn(b"set-cookie", headers)
        self.assertFalse(self.request()[1]["authenticated"])
        self.assertEqual(self.request("/auth/login", method="POST", value={"username": "owner.fixture", "password": PASSWORD})[0], 401)

    def test_smtp_failure_reserves_owner_without_opening_registration_and_can_be_retried(self):
        self.mailer.fail_configure = True
        status, body, _ = self.configure()
        self.assertEqual(status, 503)
        self.assertNotIn("Synthetic private", json.dumps(body))
        self.assertFalse(self.request()[1]["configured"])
        self.mailer.fail_configure = False
        # An authenticated owner may correct a mistyped reservation until the
        # first verified owner account exists. It never reassigns a live owner.
        self.assertEqual(self.configure("someone@example.com")[0], 200)
        self.assertTrue(self.mailer.configured)
        self.assertEqual(self.configure()[0], 200)
        self.signup()
        self.assertEqual(self.configure("someone@example.com")[0], 409)

    def test_verified_signup_issues_http_only_cookie_and_preserves_local_experiments(self):
        self.configure()
        token, csrf, body, cookie = self.signup()
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Path=/", cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertNotIn(token, json.dumps(body))
        status, current, _ = self.request(token=token)
        self.assertEqual(status, 200)
        self.assertTrue(current["authenticated"])
        self.assertEqual(current["principal"]["owner"], "local")
        self.assertTrue(current["principal"]["is_admin"])
        self.assertEqual(current["csrf_token"], csrf)
        self.assertEqual(self.request("/v1/experiments", token=token)[1]["items"], [{"title": "Existing private experiment"}])

    def test_public_verified_second_account_has_an_independent_owner_scope(self):
        self.configure()
        owner_token, owner_csrf, _, _ = self.signup()
        guest, csrf, body, _ = self.signup("guest@example.com", "guest.fixture")
        self.assertNotEqual(body["account"]["owner"], "local")
        self.assertFalse(body["account"]["is_admin"])
        self.assertEqual(self.request("/v1/experiments", token=guest)[1]["items"], [])
        self.assertEqual(self.request("/v1/experiments", method="POST", value={"title": "Guest"}, token=guest, csrf=csrf)[0], 201)
        self.assertEqual(self.request("/v1/experiments", token=owner_token)[1]["items"], [{"title": "Existing private experiment"}])
        self.assertEqual(self.request("/v1/capabilities", token=guest)[1]["execution"]["authentication"], "verified_account_session")

    def test_legacy_owner_bearer_remains_usable_without_browser_csrf(self):
        status, _, _ = self.request("/v1/experiments", method="POST", value={"title": "Operations"}, authorization="Bearer " + OWNER_TOKEN)
        self.assertEqual(status, 201)
        self.assertEqual(self.service.requests[-1][0], "local")

    def test_invalid_bearer_never_falls_back_to_valid_session_even_for_discovery(self):
        self.configure()
        token, csrf, _, _ = self.signup()
        for path in ("/ui/auth", "/v1/experiments"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path, token=token, authorization="Bearer " + "0" * 64)[0], 401)
        self.assertEqual(self.request("/v1/experiments", method="POST", value={"title": "Denied"}, token=token, csrf=csrf,
            authorization="Bearer " + "0" * 64)[0], 401)

    def test_valid_owner_bearer_api_and_setup_do_not_resolve_an_unrelated_cookie(self):
        cookie = "e" * 64
        unavailable = AuthError(503, "AUTH_UNAVAILABLE", "Account verification is temporarily unavailable")
        with patch.object(self.accounts, "identity", side_effect=unavailable) as identity:
            status, records, _ = self.request("/v1/experiments", token=cookie, authorization="Bearer " + OWNER_TOKEN)
            self.assertEqual(status, 200)
            self.assertEqual(records["items"], [{"title": "Existing private experiment"}])
            self.assertEqual(self.request("/auth/admin/configure", method="POST", value={
                "smtp_username": "sender@gmail.com", "smtp_password": "abcdefghijklmnop", "owner_email": "owner@example.com"},
                token=cookie, authorization="Bearer " + OWNER_TOKEN)[0], 200)
            self.assertEqual(self.request("/v1/experiments", token=cookie, authorization="Bearer " + "0" * 64)[0], 401)
            identity.assert_not_called()
            self.assertEqual(self.request("/v1/experiments", token=cookie)[0], 503)
            self.assertEqual(identity.call_count, 1)
            self.assertEqual(self.request("/auth/mfa/request", method="POST", value={"password": PASSWORD, "enabled": True},
                token=cookie, authorization="Bearer " + OWNER_TOKEN)[0], 503)
            self.assertEqual(identity.call_count, 2)

    def test_cookie_mutations_require_exact_csrf_and_cannot_spoof_owner(self):
        self.configure()
        token, csrf, _, _ = self.signup()
        for candidate in (None, "0" * 64):
            self.assertEqual(self.request("/v1/experiments", method="POST", value={"title": "Denied"}, token=token, csrf=candidate)[0], 403)
        self.assertEqual(self.request("/v1/experiments", method="POST", value={"title": "Scoped"}, token=token, csrf=csrf,
            extra=[(b"x-owner", b"someone-else"), (b"x-forwarded-user", b"someone-else")])[0], 201)
        self.assertEqual(self.service.requests[-1][0], "local")

    def test_cross_origin_missing_json_and_custom_header_are_rejected_before_account_work(self):
        self.configure()
        body = {"email": "guest@example.com"}
        for replacements, expected in (({b"origin": None}, 403), ({b"origin": b"https://evil.example"}, 403),
                                       ({b"content-type": b"text/plain"}, 415)):
            self.assertEqual(self.request("/auth/signup/request", method="POST", value=body, replacements=replacements)[0], expected)
        self.assertEqual(self.request("/auth/signup/request", method="POST", value=body, auth_header=False)[0], 403)
        self.assertEqual(self.mailer.messages, [])

    def test_auth_route_allowlist_rejects_query_suffix_and_other_http_methods(self):
        for path, method in (("/auth/login?x=1", "POST"), ("/auth/login/", "POST"), ("/auth/login", "GET"),
                             ("/auth/signup/request/extra", "POST"), ("/auth/admin/configure", "PUT")):
            with self.subTest(path=path, method=method):
                self.assertEqual(self.request(path, method=method, value={})[0], 401)

    def test_bootstrap_cannot_be_authorized_by_an_admin_cookie_alone(self):
        self.configure()
        token, csrf, _, _ = self.signup()
        self.assertEqual(self.request("/auth/admin/configure", method="POST", value={
            "smtp_username": "sender@gmail.com", "smtp_password": "abcdefghijklmnop", "owner_email": "owner@example.com"},
            token=token, csrf=csrf)[0], 401)

    def test_duplicate_cookie_or_auth_headers_are_rejected(self):
        self.configure()
        token, _, _, _ = self.signup()
        self.assertEqual(self.request(token=token, extra=[(b"cookie", (SESSION + "=" + token).encode())])[0], 400)
        self.assertEqual(self.request(extra=[(b"cookie", (SESSION + "=" + token + "; " + SESSION + "=" + token).encode())])[0], 400)
        self.assertEqual(self.request("/auth/login", method="POST", value={}, extra=[(b"x-quanta-auth", b"1")])[0], 400)

    def test_expired_or_malformed_cookie_is_anonymous_and_cleared(self):
        self.configure()
        token, _, _, _ = self.signup()
        self.now[0] += 86401
        for candidate in (token, "not-a-session"):
            status, payload, headers = self.request(token=candidate)
            self.assertEqual(status, 200)
            self.assertFalse(payload["authenticated"])
            self.assertIn(b"Max-Age=0", headers[b"set-cookie"])
        self.assertEqual(self.request("/v1/experiments", token=token)[0], 401)

    def test_logout_revokes_server_session_and_requires_csrf_when_logged_in(self):
        self.configure()
        token, csrf, _, _ = self.signup()
        self.assertEqual(self.request("/auth/logout", method="POST", value={}, token=token)[0], 403)
        status, body, headers = self.request("/auth/logout", method="POST", value={}, token=token, csrf=csrf)
        self.assertEqual(status, 200)
        self.assertFalse(body["authenticated"])
        self.assertIn(b"Max-Age=0", headers[b"set-cookie"])
        self.assertEqual(self.request("/v1/experiments", token=token)[0], 401)
        self.assertEqual(self.request("/auth/logout", method="POST", value={})[0], 200)

    def test_mfa_password_step_does_not_issue_or_retain_a_browser_session(self):
        self.configure()
        token, csrf, _, _ = self.signup()
        self.now[0] += 31
        status, challenge, _ = self.request("/auth/mfa/request", method="POST", value={"password": PASSWORD, "enabled": True}, token=token, csrf=csrf)
        self.assertEqual(status, 202)
        status, body, headers = self.request("/auth/mfa/confirm", method="POST", value={"challenge_id": challenge["challenge_id"], "code": self.mailer.code()}, token=token, csrf=csrf)
        self.assertEqual(status, 200)
        self.assertTrue(body["account"]["mfa_enabled"])
        token = headers[b"set-cookie"].decode().split(";", 1)[0].split("=", 1)[1]
        self.now[0] += 31
        status, pending, headers = self.request("/auth/login", method="POST", value={"username": "owner.fixture", "password": PASSWORD}, token=token)
        self.assertEqual(status, 202)
        self.assertTrue(pending["mfa_required"])
        self.assertNotIn("csrf_token", pending)
        self.assertIn(b"Max-Age=0", headers[b"set-cookie"])
        self.assertEqual(self.request("/v1/experiments", token=token)[0], 401)
        code = self.mailer.code()
        wrong = "000000" if code != "000000" else "000001"
        status, _, headers = self.request("/auth/login/verify", method="POST", value={"challenge_id": pending["challenge_id"], "code": wrong})
        self.assertEqual(status, 401)
        self.assertNotIn(b"set-cookie", headers)
        status, completed, headers = self.request("/auth/login/verify", method="POST", value={"challenge_id": pending["challenge_id"], "code": code})
        self.assertEqual(status, 200)
        self.assertTrue(completed["authenticated"])
        self.assertNotIn(headers[b"set-cookie"].split(b";", 1)[0].split(b"=", 1)[1].decode(), json.dumps(completed))

    def test_auth_body_limit_schema_and_worker_readiness_fail_closed(self):
        self.configure()
        self.assertEqual(self.request("/auth/login", method="POST", raw=b"x" * 8193)[0], 413)
        self.assertEqual(self.request("/auth/login", method="POST", raw=b'{"username":"a","username":"b"}')[0], 422)
        self.assertEqual(self.request("/auth/login", method="POST", value={"username": "a", "password": PASSWORD, "owner": "local"})[0], 422)
        self.app.worker.healthy = False
        self.assertEqual(self.request("/auth/login", method="POST", value={"username": "a", "password": PASSWORD})[0], 503)

    def test_signup_verification_code_cannot_be_used_as_a_login_challenge(self):
        self.configure()
        status, challenge, _ = self.request("/auth/signup/request", method="POST", value={"email": "owner@example.com"})
        self.assertEqual(status, 202)
        code = self.mailer.code()
        status, _, headers = self.request("/auth/login/verify", method="POST", value={"challenge_id": challenge["challenge_id"], "code": code})
        self.assertEqual(status, 401)
        self.assertNotIn(b"set-cookie", headers)
        self.assertFalse(self.request()[1]["authenticated"])
        self.assertEqual(self.request("/auth/signup/complete", method="POST", value={
            "challenge_id": challenge["challenge_id"], "code": code, "username": "owner.fixture", "password": PASSWORD})[0], 201)

    def test_verified_password_reset_revokes_existing_session_without_auto_login(self):
        self.configure()
        token, _, _, _ = self.signup()
        status, challenge, _ = self.request("/auth/password/reset/request", method="POST", value={"email": "owner@example.com"})
        self.assertEqual(status, 202)
        changed = PASSWORD + " changed"
        status, result, headers = self.request("/auth/password/reset/complete", method="POST", value={
            "challenge_id": challenge["challenge_id"], "code": self.mailer.code(), "new_password": changed})
        self.assertEqual(status, 200)
        self.assertTrue(result["password_changed"])
        self.assertFalse(result["authenticated"])
        self.assertIn(b"Max-Age=0", headers[b"set-cookie"])
        self.assertEqual(self.request("/v1/experiments", token=token)[0], 401)
        self.assertEqual(self.request("/auth/login", method="POST", value={"username": "owner.fixture", "password": PASSWORD})[0], 401)
        self.assertEqual(self.request("/auth/login", method="POST", value={"username": "owner.fixture", "password": changed})[0], 200)

    @unittest.skipUnless(importlib.util.find_spec("rfc8785") is not None, "Full service dependencies are installed by the pinned CI environment")
    def test_actual_execution_service_preserves_old_owner_records_and_isolates_public_accounts(self):
        from quanta.production import create_app
        from quanta.service import ExecutionService
        service = ExecutionService(Path(self.temp.name) / "actual-service")
        service.request("local", "POST", "/v1/experiments", {"title": "Pre-account experiment"})
        self.accounts = AccountStore(service.directory, OWNER_TOKEN, mailer=self.mailer,
            clock=lambda: self.now[0], password_hasher=lambda password, salt: hashlib.sha256(salt + password.encode()).digest())
        self.app = create_app(service, OwnerTokenConfig(ORIGIN, OWNER_TOKEN), worker=Worker(),
                              account_store=self.accounts, mailer=self.mailer)
        self.app._started = True
        self.configure()
        owner, _, _, _ = self.signup()
        guest, csrf, _, _ = self.signup("guest@example.com", "guest.fixture")
        self.assertEqual([row["title"] for row in self.request("/v1/experiments", token=owner)[1]["items"]], ["Pre-account experiment"])
        self.assertEqual(self.request("/v1/experiments", token=guest)[1]["items"], [])
        self.assertEqual(self.request("/v1/experiments", method="POST", value={"title": "Guest isolated"}, token=guest, csrf=csrf)[0], 201)
        self.assertEqual([row["title"] for row in self.request("/v1/experiments", token=owner)[1]["items"]], ["Pre-account experiment"])
        self.assertEqual([row["title"] for row in self.request("/v1/experiments", token=guest)[1]["items"]], ["Guest isolated"])


if __name__ == "__main__":
    unittest.main()
