"""Verified account cookies reach the actual CLI, Uvicorn and numerical child.

Email acceptance is synthetic and accounts are seeded in a private temporary
store. This is loopback HTTP behind the same Host/Origin checks used behind
Caddy, not a public TLS/browser or real Gmail-delivery verification.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

import pytest

from quanta.account_auth import AccountStore
from quanta.gmail_mailer import GmailMailer
from quanta.service import ExecutionService

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://accounts.integration.example"
HOST = "accounts.integration.example"
OWNER_KEY = "0123456789abcdef" * 4
PASSWORD = "Synthetic numerical account phrase 27!"
COOKIE_NAME = "__Host-quanta_session"


class AcceptedFixtureMail:
    configured = True

    def __init__(self):
        self.messages = []

    def __call__(self, email, subject, body):
        self.messages.append((email, subject, body))

    def code(self):
        return re.search(r"\b([0-9]{6})\b", self.messages[-1][2])[1]


def test_account_cookie_login_to_independent_numerical_result_and_artifact(tmp_path):
    directory = tmp_path / "private-service"
    service = ExecutionService(directory)
    _, existing = service.request("local", "POST", "/v1/experiments", {"title": "Before account login"})
    mailbox = AcceptedFixtureMail()
    accounts = AccountStore(directory, OWNER_KEY, mailer=mailbox)
    accounts.configure_owner("owner@fixture.example", owner_authorized=True)
    for email, username in (("owner@fixture.example", "numerical-owner"),
                            ("guest@fixture.example", "numerical-guest")):
        challenge = accounts.request_signup(email)
        registered = accounts.complete_signup(challenge.payload["challenge_id"], mailbox.code(), username, PASSWORD)
        accounts.logout(registered.session_token)
    # The subprocess reads a real, private mail configuration but these tests
    # only perform password login for already-verified accounts with MFA off.
    # No SMTP call occurs, and no real Gmail credential is supplied.
    GmailMailer(directory).configure("quanta.fixture@gmail.com", "abcdefghijklmnop")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("QUANTA_") and key != "PYTHONPATH"}
    environment.update(QUANTA_AUTH_MODE="owner-token", QUANTA_PUBLIC_ORIGIN=ORIGIN,
                       QUANTA_OWNER_TOKEN=OWNER_KEY)
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        environment[name] = "1"

    def request(path, *, method="GET", value=None, cookie=None, csrf=None, bearer=False, key=None):
        raw = None if value is None else json.dumps(value, allow_nan=False).encode()
        headers = {"Host": HOST}
        if method not in {"GET", "HEAD"}:
            headers.update(Origin=ORIGIN, **{"Content-Type": "application/json"})
        if path.startswith("/auth/"):
            headers["X-Quanta-Auth"] = "1"
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-Quanta-CSRF"] = csrf
        if bearer:
            headers["Authorization"] = "Bearer " + OWNER_KEY
        if key:
            headers["Idempotency-Key"] = key
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        try:
            connection.request(method, path, body=raw, headers=headers)
            response = connection.getresponse()
            body = response.read(8 * 1024**2 + 1)
            assert len(body) <= 8 * 1024**2
            return response.status, body, {name.lower(): value for name, value in response.getheaders()}
        finally:
            connection.close()

    def document(path, **options):
        status, raw, headers = request(path, **options)
        return status, json.loads(raw), headers

    def login(username):
        status, result, headers = document("/auth/login", method="POST", value={"username": username, "password": PASSWORD})
        assert status == 200 and result["authenticated"] is True
        configured_cookie = headers["set-cookie"]
        assert "Secure" in configured_cookie and "HttpOnly" in configured_cookie
        assert "SameSite=Strict" in configured_cookie and "Domain=" not in configured_cookie
        cookie = configured_cookie.split(";", 1)[0]
        assert cookie.startswith(COOKIE_NAME + "=")
        assert cookie.split("=", 1)[1] not in json.dumps(result)
        status, session, _ = document("/ui/auth", cookie=cookie)
        assert status == 200 and session["authenticated"] is True
        return cookie, session["csrf_token"], session["principal"]

    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([sys.executable, "-m", "quanta", "serve-production", "--store", str(directory),
                                    "--port", str(port)], cwd=tmp_path, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=errors, start_new_session=True)
        try:
            expires = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    errors.seek(0)
                    pytest.fail("Production CLI exited before readiness: " + errors.read(1024).decode(errors="replace"))
                try:
                    if request("/health/ready", bearer=True)[0] == 200:
                        break
                except (ConnectionError, OSError, http.client.HTTPException):
                    pass
                if time.monotonic() >= expires:
                    pytest.fail("Account production CLI did not become ready within 20 seconds")
                time.sleep(0.05)

            assert request("/v1/experiments")[0] == 401
            assert document("/ui/auth")[1]["mode"] == "account"
            assert document("/auth/login", method="POST", value={"username": "numerical-owner", "password": "Wrong synthetic password"})[0] == 401
            owner_cookie, owner_csrf, owner = login("numerical-owner")
            guest_cookie, _, guest = login("numerical-guest")
            assert owner["owner"] == "local" and owner["is_admin"] is True
            assert guest["owner"] != "local" and guest["is_admin"] is False
            status, saved, _ = document("/v1/experiments", cookie=owner_cookie)
            assert status == 200 and [row["title"] for row in saved["items"]] == ["Before account login"]
            assert document("/v1/experiments", cookie=guest_cookie)[1]["items"] == []
            experiment_path = "/v1/experiments/" + existing["experiment_id"]
            assert request(experiment_path, cookie=guest_cookie)[0] == 404

            definition = json.loads((ROOT / "examples/pair_energy_forces.json").read_text())["definition"]
            status, revision, _ = document(experiment_path + "/revisions", method="POST", cookie=owner_cookie,
                csrf=owner_csrf, value={"schema_version": "0.2.0", "title": "Cookie numerical verification", "definition": definition})
            assert status == 201
            status, submitted, _ = document("/v1/runs", method="POST", cookie=owner_cookie, csrf=owner_csrf,
                value={"revision_id": revision["revision_id"]}, key="account-cookie-numerical-fixture")
            assert status == 202
            run_path = "/v1/runs/" + submitted["run_id"]
            assert request(run_path, cookie=guest_cookie)[0] == 404
            expires = time.monotonic() + 45
            while True:
                status, current, _ = document(run_path, cookie=owner_cookie)
                assert status == 200
                if current["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                    assert current["execution_status"] == "SUCCEEDED", current["diagnostics"]
                    break
                if time.monotonic() >= expires:
                    pytest.fail("Cookie-authenticated numerical run did not complete within 45 seconds")
                time.sleep(0.05)

            status, result, _ = document(run_path + "/result", cookie=owner_cookie)
            assert status == 200 and result["physical_validation_status"] == "unvalidated"
            payload = result["steps"][0]["payload"]
            assert payload["energy_j"] == pytest.approx(4e-21, rel=1e-12, abs=1e-33)
            for observed, reference in zip(payload["forces_n"], ([4e-11, 0.0, 0.0], [-4e-11, 0.0, 0.0])):
                assert observed == pytest.approx(reference, rel=1e-12, abs=1e-24)
            status, manifest, _ = document(run_path + "/artifacts", cookie=owner_cookie)
            assert status == 200 and manifest["artifacts"]
            artifact = manifest["artifacts"][-1]
            artifact_path = "/v1/artifacts/" + artifact["artifact_id"]
            status, raw, headers = request(artifact_path, cookie=owner_cookie)
            assert status == 200 and len(raw) == artifact["size_bytes"]
            assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]
            assert headers["cache-control"] == "no-store"
            assert request(artifact_path, cookie=guest_cookie)[0] == 404
            assert request(artifact_path)[0] == 401
            assert document("/auth/logout", method="POST", value={}, cookie=owner_cookie, csrf=owner_csrf)[0] == 200
            assert request("/v1/experiments", cookie=owner_cookie)[0] == 401
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                pytest.fail("Production CLI did not stop its numerical supervisor within 25 seconds")
        # Pinned Uvicorn 0.54.0 re-raises a captured SIGTERM after its graceful
        # shutdown; its main-thread CLI therefore normally exits as -SIGTERM.
        assert process.returncode in (0, -signal.SIGTERM)
        expires = time.monotonic() + 2
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= expires:
                pytest.fail("A production CLI or numerical child survived test cleanup")
            time.sleep(0.02)
