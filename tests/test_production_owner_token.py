"""Optional owner-token authentication keeps the production transport boundaries.

All tokens are fixed test fixtures. These tests do not establish external TLS,
Caddy configuration, OCI deployment or the entropy of a real supplied token.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import http.client
from importlib import resources
import json
import threading
import time

import pytest

from quanta import owner_token
from quanta.owner_token import OwnerTokenConfig, OwnerTokenDenied, OwnerTokenVerifier
from quanta.production import create_app
from quanta.production_server import ProductionServer
from quanta.service import ExecutionService

ORIGIN = "https://quanta.example.com"
TOKEN = "0123456789abcdef" * 4
AUTHORIZATION = "Bearer " + TOKEN
PUBLIC = {
    "/": "index.html", "/index.html": "index.html", "/assets/app.css": "app.css",
    "/assets/app.js": "app.js", "/assets/view-model.mjs": "view-model.mjs",
}


class RecordingWorker:
    def __init__(self):
        self.healthy = False

    def start(self):
        self.healthy = True

    def stop(self):
        self.healthy = False


@asynccontextmanager
async def running(app):
    incoming, outgoing = asyncio.Queue(), asyncio.Queue()
    task = asyncio.create_task(app({"type": "lifespan"}, incoming.get, outgoing.put))
    await incoming.put({"type": "lifespan.startup"})
    assert (await asyncio.wait_for(outgoing.get(), 5))["type"] == "lifespan.startup.complete"
    try:
        yield app
    finally:
        await incoming.put({"type": "lifespan.shutdown"})
        assert (await asyncio.wait_for(outgoing.get(), 5))["type"] == "lifespan.shutdown.complete"
        await asyncio.wait_for(task, 5)


def application(tmp_path):
    return create_app(ExecutionService(tmp_path / "service"), OwnerTokenConfig(ORIGIN, TOKEN),
                      worker=RecordingWorker(), account_store=False)


async def request(app, path="/v1/experiments", *, method="GET", raw=b"", authorization=AUTHORIZATION,
                  extra=(), replacements=None):
    headers = [(b"host", b"quanta.example.com"), (b"content-length", str(len(raw)).encode())]
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("utf-8")))
    if method not in {"GET", "HEAD"}:
        headers += [(b"origin", ORIGIN.encode()), (b"content-type", b"application/json")]
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

    await app({"type": "http", "method": method, "scheme": "http", "path": target,
               "raw_path": target.encode(), "query_string": query.encode(), "headers": headers}, receive, send)
    return sent[0]["status"], sent[1]["body"], dict(sent[0]["headers"])


def test_secret_is_hidden_in_validated_immutable_configuration():
    config = OwnerTokenConfig(ORIGIN, TOKEN)
    assert TOKEN not in repr(config)
    assert config.owner == "local"
    with pytest.raises(AttributeError):
        config.token = "a" * 64
    assert OwnerTokenVerifier(config).verify(AUTHORIZATION) == {"owner": "local"}


@pytest.mark.parametrize("token", [None, b"a" * 64, "", "a" * 63, "a" * 65, "A" * 64,
                                  "g" * 64, "a" * 63 + "\n", "a" * 63 + "é"])
def test_invalid_token_configuration_is_refused_without_echo(token):
    with pytest.raises(ValueError) as error:
        OwnerTokenConfig(ORIGIN, token)
    if isinstance(token, str) and token:
        assert token not in str(error.value)


@pytest.mark.parametrize("origin", [None, "http://quanta.example.com", "https://localhost",
    "https://127.0.0.1", "https://[::1]", "https://quanta.example.com/", "https://quanta.example.com?",
    "https://quanta.example.com:443", "https://user:password@quanta.example.com", "https://QUANTA.example.com"])
def test_owner_token_requires_the_same_strict_https_origin(origin):
    with pytest.raises(ValueError):
        OwnerTokenConfig(origin, TOKEN)


@pytest.mark.parametrize("owner", [None, "", "local\nother", "local other", "a" * 201])
def test_owner_configuration_cannot_be_ambiguous(owner):
    with pytest.raises(ValueError):
        OwnerTokenConfig(ORIGIN, TOKEN, owner=owner)


@pytest.mark.parametrize("authorization", [None, b"Bearer fixture", "", TOKEN, "bearer " + TOKEN,
    "Bearer " + TOKEN.upper(), "Bearer " + TOKEN[:-1], "Bearer " + TOKEN + "x", "Bearer " + "é" * 64,
    "Bearer " + "0" * 64, "Bearer " + TOKEN + ", Bearer " + TOKEN])
def test_only_exact_owner_credential_authorizes(authorization):
    with pytest.raises(OwnerTokenDenied) as error:
        OwnerTokenVerifier(OwnerTokenConfig(ORIGIN, TOKEN)).verify(authorization)
    assert TOKEN not in str(error.value)


def test_secret_equality_uses_constant_time_bytes_comparison(monkeypatch):
    original = owner_token.hmac.compare_digest
    compared = []

    def compare(candidate, expected):
        compared.append((type(candidate), type(expected), len(candidate), len(expected)))
        return original(candidate, expected)

    monkeypatch.setattr(owner_token.hmac, "compare_digest", compare)
    verifier = OwnerTokenVerifier(OwnerTokenConfig(ORIGIN, TOKEN))
    assert verifier.verify(AUTHORIZATION) == {"owner": "local"}
    with pytest.raises(OwnerTokenDenied):
        verifier.verify("Bearer " + "0" * 64)
    assert compared == [(bytes, bytes, 64, 64)] * 2


@pytest.mark.parametrize("path,name", PUBLIC.items())
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_exact_public_shell_is_credential_free_package_content(tmp_path, path, name, method):
    async def scenario():
        async with running(application(tmp_path)) as app:
            status, raw, headers = await request(app, path, method=method, authorization=None)
            packaged = resources.files("quanta").joinpath("web", name).read_bytes()
            assert status == 200
            assert raw == (packaged if method == "GET" else b"")
            assert int(headers[b"content-length"]) == len(packaged)
            assert TOKEN.encode() not in raw
            assert headers[b"cache-control"] == b"no-store"
            assert b"access-control-allow-origin" not in headers
    asyncio.run(scenario())


def test_owner_token_discovery_exposes_only_the_fixed_mode(tmp_path):
    async def scenario():
        async with running(application(tmp_path)) as app:
            for authorization in (None, AUTHORIZATION):
                status, raw, _ = await request(app, "/ui/auth", authorization=authorization)
                assert status == 200 and json.loads(raw) == {
                    "mode": "bearer", "authenticated": False, "authentication": "owner_token"}
                assert TOKEN.encode() not in raw
    asyncio.run(scenario())


@pytest.mark.parametrize("path,method", [(path, "GET") for path in (
    "/ui/examples", "/v1/capabilities", "/v1/experiments", "/health/ready", "/v1/artifacts/private",
    "/assets/unknown.js", "/assets/../app.js", "/?query=1", "/ui/auth?query=1", "/ui/auth/",
)] + [("/", "POST"), ("/ui/auth", "POST"), ("/assets/app.js", "OPTIONS")])
def test_public_shell_allowlist_never_opens_private_or_modified_routes(tmp_path, path, method):
    async def scenario():
        async with running(application(tmp_path)) as app:
            status, raw, headers = await request(app, path, method=method, authorization=None,
                extra=[(b"cf-access-jwt-assertion", b"forged"),
                       (b"cf-access-authenticated-user-email", b"owner@example.com"),
                       (b"cookie", b"CF_Authorization=forged")])
            assert status == 401
            assert headers[b"www-authenticate"] == b"Bearer"
            assert b"owner@example.com" not in raw
    asyncio.run(scenario())


@pytest.mark.parametrize("path", ["/", "/ui/auth", "/v1/experiments"])
@pytest.mark.parametrize("headers,status", [
    ({b"host": b"attacker.example.com", b"x-forwarded-host": b"quanta.example.com"}, 400),
    ({b"origin": b"https://attacker.example.com"}, 403),
    ({b"transfer-encoding": b"chunked"}, 400),
    ({b"content-length": b"1048577"}, 413),
])
def test_public_shell_and_private_data_share_host_origin_and_framing_checks(tmp_path, path, headers, status):
    async def scenario():
        async with running(application(tmp_path)) as app:
            assert (await request(app, path, replacements=headers))[0] == status
    asyncio.run(scenario())


@pytest.mark.parametrize("path", ["/", "/ui/auth", "/v1/experiments"])
def test_duplicate_authorization_is_rejected_even_on_the_public_shell(tmp_path, path):
    async def scenario():
        async with running(application(tmp_path)) as app:
            assert (await request(app, path, extra=[(b"authorization", AUTHORIZATION.encode())]))[0] == 400
    asyncio.run(scenario())


@pytest.mark.parametrize("path", ["/", "/ui/auth"])
def test_public_shell_rejects_request_bodies_without_authentication(tmp_path, path):
    async def scenario():
        async with running(application(tmp_path)) as app:
            assert (await request(app, path, raw=b"{}", authorization=None))[0] == 400
    asyncio.run(scenario())


def test_valid_token_keeps_data_and_mutations_scoped_to_the_fixed_owner(tmp_path):
    async def scenario():
        async with running(application(tmp_path)) as app:
            _, foreign = app.service.request("someone-else", "POST", "/v1/experiments", {"title": "Foreign"})
            assert (await request(app, "/v1/experiments/" + foreign["experiment_id"]))[0] == 404
            for authorization in (None, "Bearer " + "0" * 64):
                assert (await request(app, method="POST", raw=b'{"title":"Denied"}', authorization=authorization))[0] == 401
            assert app.service.store.list_experiments("local")["items"] == []
            status, _, _ = await request(app, method="POST", raw=b'{"title":"Private"}',
                extra=[(b"x-owner", b"someone-else"), (b"x-forwarded-user", b"someone-else")])
            assert status == 201
            assert [item["title"] for item in app.service.store.list_experiments("local")["items"]] == ["Private"]
            assert (await request(app, method="POST", raw=b'{}', replacements={b"origin": None}))[0] == 403
            status, raw, _ = await request(app, "/v1/capabilities")
            assert status == 200
            assert json.loads(raw)["execution"]["authentication"] == "server_configured_bearer_principal"
            assert (await request(app, "/ui/examples"))[0] == 200
    asyncio.run(scenario())


def test_owner_token_preserves_readiness_and_worker_failure_boundaries(tmp_path):
    async def scenario():
        app = application(tmp_path)
        assert (await request(app, "/"))[0] == 503
        async with running(app):
            assert (await request(app, "/health/ready", authorization=None))[0] == 401
            assert (await request(app, "/health/ready"))[0] == 200
            app.worker.healthy = False
            assert (await request(app, "/health/ready"))[0] == 503
            assert (await request(app, method="POST", raw=b'{"title":"Not accepted"}'))[0] == 503
            assert (await request(app))[0] == 200
    asyncio.run(scenario())


def test_real_uvicorn_owner_token_transport_preserves_the_private_boundary(tmp_path):
    app = application(tmp_path)
    server = ProductionServer(app, port=0)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started, "Owner-token Uvicorn did not finish startup"
        port = server.servers[0].sockets[0].getsockname()[1]

        def http_request(path, *, method="GET", body=None, authorization=AUTHORIZATION, headers=None):
            request_headers = {"Host": "quanta.example.com"}
            if authorization is not None:
                request_headers["Authorization"] = authorization
            if method != "GET":
                request_headers.update(Origin=ORIGIN, **{"Content-Type": "application/json"})
            request_headers.update(headers or {})
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request(method, path, body=body, headers=request_headers)
                response = connection.getresponse()
                return response.status, response.read(), dict(response.getheaders())
            finally:
                connection.close()

        assert http_request("/", authorization=None)[0] == 200
        status, raw, _ = http_request("/ui/auth", authorization=None)
        assert status == 200 and json.loads(raw)["authentication"] == "owner_token"
        assert http_request("/v1/experiments", authorization=None)[0] == 401
        assert http_request("/v1/experiments", authorization="Bearer " + "0" * 64)[0] == 401
        assert http_request("/v1/experiments", method="POST", body=b'{"title":"Denied"}', authorization=None)[0] == 401
        assert http_request("/v1/experiments", method="POST", body=b'{"title":"Denied"}',
                    headers={"Origin": "https://attacker.example.com"})[0] == 403
        assert http_request("/v1/experiments", headers={"Host": "attacker.example.com",
                    "X-Forwarded-Host": "quanta.example.com"})[0] == 400
        status, _, _ = http_request("/v1/experiments", method="POST", body=b'{"title":"Owner-token transport fixture"}')
        assert status == 201
        status, raw, headers = http_request("/v1/experiments")
        assert status == 200 and len(json.loads(raw)["items"]) == 1
        assert TOKEN.encode() not in raw
        assert headers["cache-control"] == "no-store"
        assert "access-control-allow-origin" not in headers
        assert http_request("/v1/artifacts/private", authorization=None)[0] == 401
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive(), "Owner-token Uvicorn did not shut down"
    assert not app.worker.healthy
