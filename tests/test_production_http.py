"""Production ASGI boundaries and real authenticated Uvicorn execution.

Keys are generated in memory for these tests. They do not represent an external
Cloudflare session or establish OCI, TLS, or browser verification.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import http.client
import json
from pathlib import Path
import socket
import struct
import threading
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
import uvicorn

from quanta.access_auth import AccessConfig, AccessVerifier
from quanta.production import create_app
from quanta.service import ExecutionService

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://quanta.example.com"
HOST = "quanta.example.com"


@pytest.fixture(scope="module")
def identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid="production-http-test", alg="RS256", use="sig")
    return key, {"keys": [public]}


def configuration():
    return AccessConfig(public_origin=ORIGIN, team_domain="quanta.cloudflareaccess.com",
                        audience="app-aud", allowed_email="owner@example.com", owner="local")


def assertion(identity, **changes):
    now = int(time.time())
    claims = {"iss": "https://quanta.cloudflareaccess.com", "aud": ["app-aud"],
              "email": "owner@example.com", "sub": "verified-test-subject", "type": "app",
              "iat": now - 1, "nbf": now - 1, "exp": now + 600}
    claims.update(changes)
    return jwt.encode(claims, identity[0], algorithm="RS256", headers={"kid": "production-http-test"})


class RecordingWorker:
    """A lifecycle double only; actual numerical execution is tested below."""
    def __init__(self):
        self.started = False
        self.stopped = False
        self.error = None

    @property
    def healthy(self):
        return self.started and not self.stopped and self.error is None

    def start(self):
        self.started = True
        return self

    def stop(self):
        self.stopped = True


def app_for(service, identity, *, worker=None):
    config = configuration()
    return create_app(service, config,
                      verifier=AccessVerifier(config, fetch_keys=lambda: identity[1]), worker=worker)


class StartupFailed(RuntimeError):
    pass


def test_response_backpressure_keeps_capacity_reserved_until_send_finishes(tmp_path, identity):
    async def scenario():
        app = app_for(ExecutionService(tmp_path / "service"), identity, worker=RecordingWorker())
        opened, release = asyncio.Queue(), asyncio.Event()
        async def request_body():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def blocked_send(message):
            if message["type"] == "http.response.start":
                await opened.put(True)
                await release.wait()
        scope = {"type": "http", "method": "GET", "path": "/ui/auth", "query_string": b"",
                 "headers": [(b"host", HOST.encode()),
                             (b"cf-access-jwt-assertion", assertion(identity).encode())]}
        async with lifespan(app):
            tasks = [asyncio.create_task(app(scope, request_body, blocked_send)) for _ in range(32)]
            try:
                for _ in tasks:
                    await asyncio.wait_for(opened.get(), 10)
                assert app._active == 32
                assert (await call(app, identity, "/ui/auth"))[0] == 503
            finally:
                release.set()
                await asyncio.gather(*tasks)
            assert app._active == 0
    asyncio.run(scenario())


def test_incomplete_body_timeout_does_not_create_scientific_records(tmp_path, identity, monkeypatch):
    import quanta.production as production
    original_timeout = asyncio.timeout
    monkeypatch.setattr(production.asyncio, "timeout", lambda seconds: original_timeout(0.01))
    async def scenario():
        service = ExecutionService(tmp_path / "service")
        app = app_for(service, identity, worker=RecordingWorker())
        sent = []
        async def receive():
            await asyncio.Event().wait()
        async def send(message):
            sent.append(message)
        scope = {"type": "http", "method": "POST", "path": "/v1/experiments", "query_string": b"",
                 "headers": [(b"host", HOST.encode()), (b"origin", ORIGIN.encode()),
                             (b"content-type", b"application/json"), (b"content-length", b"10"),
                             (b"cf-access-jwt-assertion", assertion(identity).encode())]}
        async with lifespan(app):
            await app(scope, receive, send)
        assert sent[0]["status"] == 408
        assert service.store.list_experiments("local")["items"] == []
    asyncio.run(scenario())


@asynccontextmanager
async def lifespan(app):
    incoming, outgoing = asyncio.Queue(), asyncio.Queue()
    task = asyncio.create_task(app({"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}},
                                   incoming.get, outgoing.put))
    await incoming.put({"type": "lifespan.startup"})
    message = await asyncio.wait_for(outgoing.get(), 10)
    if message["type"] == "lifespan.startup.failed":
        await asyncio.wait_for(task, 10)
        raise StartupFailed(message.get("message", "Startup failed"))
    assert message["type"] == "lifespan.startup.complete"
    try:
        yield app
    finally:
        await incoming.put({"type": "lifespan.shutdown"})
        message = await asyncio.wait_for(outgoing.get(), 20)
        assert message["type"] == "lifespan.shutdown.complete"
        await asyncio.wait_for(task, 20)


async def call(app, identity, path="/v1/experiments", *, method="GET", raw=b"", auth=True,
               extra_headers=(), replace_headers=None, chunks=None):
    headers = [(b"host", HOST.encode())]
    if auth:
        headers.append((b"cf-access-jwt-assertion", assertion(identity).encode()))
    if method not in {"GET", "HEAD"}:
        headers += [(b"origin", ORIGIN.encode()), (b"content-type", b"application/json")]
    headers.append((b"content-length", str(len(raw)).encode()))
    if replace_headers:
        headers = [(name, value) for name, value in headers if name not in replace_headers]
        headers += [(name, value) for name, value in replace_headers.items() if value is not None]
    headers += list(extra_headers)
    target, _, query = path.partition("?")
    messages = list(chunks) if chunks is not None else [{"type": "http.request", "body": raw, "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app({"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
               "http_version": "1.1", "method": method, "scheme": "http", "path": target,
               "raw_path": target.encode(), "query_string": query.encode(), "headers": headers,
               "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 12345)}, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return start["status"], body, {key.decode().lower(): value.decode() for key, value in start["headers"]}


@pytest.mark.parametrize("path", ["/", "/assets/app.js", "/ui/examples", "/v1/experiments", "/health/ready"])
def test_production_resources_require_verified_access_assertion(tmp_path, identity, path):
    async def scenario():
        service = ExecutionService(tmp_path / "service")
        async with lifespan(app_for(service, identity, worker=RecordingWorker())) as app:
            status, raw, _ = await call(app, identity, path, auth=False,
                extra_headers=[(b"cf-access-authenticated-user-email", b"owner@example.com"),
                               (b"authorization", b"Bearer this-is-not-an-access-assertion")])
            assert status == 401
            assert b"owner@example.com" not in raw
    asyncio.run(scenario())


def test_auth_discovery_and_verified_principal_do_not_return_credentials(tmp_path, identity):
    async def scenario():
        service = ExecutionService(tmp_path / "service")
        worker = RecordingWorker()
        async with lifespan(app_for(service, identity, worker=worker)) as app:
            status, raw, headers = await call(app, identity, "/ui/auth", auth=False)
            unauthenticated = json.loads(raw)
            assert status == 401 and unauthenticated["mode"] == "access"
            assert unauthenticated["authenticated"] is False
            assert "principal" not in unauthenticated
            status, raw, headers = await call(app, identity, "/ui/auth")
            session = json.loads(raw)
            assert status == 200 and session["authenticated"] is True
            assert session["mode"] == "access"
            assert session["principal"] == {"email": "owner@example.com", "owner": "local"}
            assert session["login_url"] == "/"
            assert session["logout_url"] == "/cdn-cgi/access/logout"
            assert assertion(identity).encode() not in raw
            assert headers["cache-control"] == "no-store"
            assert "access-control-allow-origin" not in headers
            assert (await call(app, identity, "/health/ready"))[0] == 200
        assert worker.stopped
    asyncio.run(scenario())


@pytest.mark.parametrize("claim,value", [("email", "someone-else@example.com"), ("exp", 1), ("aud", ["other-app"])])
def test_invalid_or_foreign_access_identity_cannot_read_data(tmp_path, identity, claim, value):
    async def scenario():
        app = app_for(ExecutionService(tmp_path / "service"), identity, worker=RecordingWorker())
        async with lifespan(app):
            status, _, _ = await call(app, identity, replace_headers={
                b"cf-access-jwt-assertion": assertion(identity, **{claim: value}).encode()})
            assert status in {401, 403}
    asyncio.run(scenario())


@pytest.mark.parametrize("name,value", [
    (b"host", HOST.encode()), (b"origin", ORIGIN.encode()),
    (b"cf-access-jwt-assertion", b"duplicate"), (b"content-type", b"application/json"),
    (b"content-length", b"2"), (b"idempotency-key", b"second-key"),
])
def test_ambiguous_security_and_request_headers_are_rejected(tmp_path, identity, name, value):
    async def scenario():
        service = ExecutionService(tmp_path / "service")
        app = app_for(service, identity, worker=RecordingWorker())
        extra = [(name, value)]
        if name == b"idempotency-key":
            extra.insert(0, (name, b"first-key"))
        async with lifespan(app):
            status, _, _ = await call(app, identity, method="POST", raw=b"{}", extra_headers=extra)
            assert status == 400
            assert service.store.list_experiments("local")["items"] == []
    asyncio.run(scenario())


@pytest.mark.parametrize("headers,status", [
    ({b"host": b"attacker.example.com", b"x-forwarded-host": HOST.encode()}, 400),
    ({b"origin": b"https://attacker.example.com"}, 403),
    ({b"origin": None}, 403),
    ({b"content-type": b"text/plain"}, 415),
    ({b"content-length": b"-1"}, 400),
    ({b"content-length": b"3"}, 400),
    ({b"transfer-encoding": b"chunked"}, 400),
])
def test_public_origin_and_request_framing_are_explicit(tmp_path, identity, headers, status):
    async def scenario():
        app = app_for(ExecutionService(tmp_path / "service"), identity, worker=RecordingWorker())
        async with lifespan(app):
            actual, _, _ = await call(app, identity, method="POST", raw=b"{}", replace_headers=headers)
            assert actual == status
    asyncio.run(scenario())


@pytest.mark.parametrize("raw,status", [
    (b'{"title":"one","title":"two"}', 422), (b'{"title":NaN}', 422),
    (b'{"title":"\xff"}', 422), (b"x" * 1_048_577, 413),
])
def test_raw_json_is_bounded_and_not_normalized_before_validation(tmp_path, identity, raw, status):
    async def scenario():
        app = app_for(ExecutionService(tmp_path / "service"), identity, worker=RecordingWorker())
        async with lifespan(app):
            actual, _, _ = await call(app, identity, method="POST", raw=raw)
            assert actual == status
    asyncio.run(scenario())


def test_revision_negative_zero_and_owner_boundary_are_preserved(tmp_path, identity):
    async def scenario():
        service = ExecutionService(tmp_path / "service")
        foreign = service.store.create_experiment("other-owner", "Foreign private experiment")
        app = app_for(service, identity, worker=RecordingWorker())
        async with lifespan(app):
            assert (await call(app, identity, "/v1/experiments/" + foreign["experiment_id"]))[0] == 404
            status, raw, _ = await call(app, identity, "/v1/experiments", method="POST", raw=b'{"title":"Signed zero"}')
            assert status == 201
            experiment = json.loads(raw)
            definition = json.loads((ROOT / "examples/pair_energy_forces.json").read_text())["definition"]
            definition["system"]["particles"][0]["position_m"][0] = -0.0
            definition["system"]["particles"][0]["fixed"][0] = True
            payload = json.dumps({"schema_version": "0.2.0", "title": "Signed zero", "definition": definition}).replace("-0.0", "-0", 1).encode()
            status, raw, _ = await call(app, identity, f"/v1/experiments/{experiment['experiment_id']}/revisions", method="POST", raw=payload)
            assert status == 201
            revision = json.loads(raw)
            _, saved, _ = await call(app, identity, "/v1/revisions/" + revision["revision_id"])
            coordinate = json.loads(saved)["definition"]["system"]["particles"][0]["position_m"][0]
            assert struct.pack("!d", coordinate) == struct.pack("!d", -0.0)
    asyncio.run(scenario())


def test_startup_and_worker_failure_do_not_claim_readiness_or_accept_writes(tmp_path, identity):
    async def scenario():
        worker = RecordingWorker()
        app = app_for(ExecutionService(tmp_path / "service"), identity, worker=worker)
        assert (await call(app, identity, "/ui/auth"))[0] == 503
        async with lifespan(app):
            worker.error = "SimulatedSupervisorFailure"
            assert (await call(app, identity, "/health/ready"))[0] == 503
            assert (await call(app, identity, method="POST", raw=b'{"title":"Not accepted"}'))[0] == 503
            assert (await call(app, identity))[0] == 200
        assert worker.stopped
    asyncio.run(scenario())


def test_second_application_cannot_start_a_competing_numerical_supervisor(tmp_path, identity):
    async def check():
        service = ExecutionService(tmp_path / "service")
        first, second = app_for(service, identity), app_for(service, identity)
        async with lifespan(first):
            with pytest.raises(StartupFailed):
                async with lifespan(second):
                    pytest.fail("A competing numerical supervisor started")
            assert (await call(first, identity, "/health/ready"))[0] == 200
    asyncio.run(check())


@pytest.fixture
def live_server(tmp_path, identity):
    service = ExecutionService(tmp_path / "live-service")
    app = app_for(service, identity)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, workers=1,
        lifespan="on", proxy_headers=False, access_log=False, log_level="error", server_header=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "Uvicorn did not finish ASGI startup"
    try:
        yield port, service
    finally:
        server.should_exit = True
        thread.join(timeout=25)
        listener.close()
        assert not thread.is_alive(), "Uvicorn did not shut down its worker"


def http_request(port, identity, path, *, method="GET", value=None, key=None, authenticated=True):
    body = None if value is None else json.dumps(value, allow_nan=False).encode()
    headers = {"Host": HOST}
    if authenticated:
        headers["Cf-Access-Jwt-Assertion"] = assertion(identity)
    if method not in {"GET", "HEAD"}:
        headers.update(Origin=ORIGIN, **{"Content-Type": "application/json"})
    if key:
        headers["Idempotency-Key"] = key
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(), {k.lower(): v for k, v in response.getheaders()}
    finally:
        connection.close()


def test_real_uvicorn_verified_login_to_result_download_and_replay(live_server, identity):
    port, service = live_server

    def request(path, method="GET", value=None, key=None):
        status, raw, _ = http_request(port, identity, path, method=method, value=value, key=key)
        return status, json.loads(raw)

    status, session = request("/ui/auth")
    assert status == 200 and session["principal"]["owner"] == "local"
    assert http_request(port, identity, "/")[0] == 200
    status, experiment = request("/v1/experiments", "POST", {"title": "Authenticated Uvicorn calculation"})
    assert status == 201
    definition = json.loads((ROOT / "examples/pair_energy_forces.json").read_text())["definition"]
    status, revision = request(f"/v1/experiments/{experiment['experiment_id']}/revisions", "POST", {
        "schema_version": "0.2.0", "title": "Authenticated Uvicorn calculation", "definition": definition})
    assert status == 201
    status, run = request("/v1/runs", "POST", {"revision_id": revision["revision_id"]}, "same-run-key")
    assert status == 202
    _, duplicate = request("/v1/runs", "POST", {"revision_id": revision["revision_id"]}, "same-run-key")
    assert duplicate["run_id"] == run["run_id"]

    def terminal(run_id):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            _, current = request("/v1/runs/" + run_id)
            if current["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                assert current["execution_status"] == "SUCCEEDED", current["diagnostics"]
                return current
            time.sleep(0.05)
        pytest.fail("Authenticated production run did not complete within 45 seconds")

    terminal(run["run_id"])
    status, result = request(f"/v1/runs/{run['run_id']}/result")
    assert status == 200 and result["physical_validation_status"] == "unvalidated"
    assert result["steps"][0]["payload"]["energy_j"] == pytest.approx(4e-21, rel=1e-12)
    _, manifest = request(f"/v1/runs/{run['run_id']}/artifacts")
    artifact = manifest["artifacts"][-1]
    path = "/v1/artifacts/" + artifact["artifact_id"]
    status, raw, headers = http_request(port, identity, path)
    assert status == 200
    assert len(raw) == artifact["size_bytes"] and hashlib.sha256(raw).hexdigest() == artifact["sha256"]
    assert headers["cache-control"] == "no-store"
    assert http_request(port, identity, path, authenticated=False)[0] == 401
    status, replay = request(f"/v1/runs/{run['run_id']}/replay", "POST", {}, "same-replay-key")
    assert status == 202 and replay["run_id"] != run["run_id"]
    terminal(replay["run_id"])
    assert len(service.store.list_runs("local")["items"]) == 2
