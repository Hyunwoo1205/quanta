"""Single-worker ASGI transport behind a configured Cloudflare Access Tunnel."""
from __future__ import annotations

import asyncio
import hashlib
from importlib import resources
import json
import shutil
import sqlite3
from urllib.parse import urlsplit

from .access_auth import AccessConfig, AccessDenied, AccessVerifier, AuthUnavailable
from .job_store import ServiceError
from .parsing import parse_json
from .server import _CSP, _WEB_RESOURCES, error_document
from .worker import JobWorker

MAX_BODY = 1_048_576
MIN_FREE_BYTES = 128 * 1024 * 1024


class ProductionApp:
    def __init__(self, service, config: AccessConfig, *, verifier=None, worker=None):
        if not isinstance(config, AccessConfig):
            raise ValueError("A validated Access configuration is required")
        self.service = service
        self.config = config
        self.verifier = verifier if verifier is not None else AccessVerifier(config)
        self.worker = worker if worker is not None else JobWorker(service.directory)
        self.authority = urlsplit(config.public_origin).netloc.lower()
        self._started = False
        self._active = 0

    def _session(self, identity=None):
        result = {"mode": "access", "authenticated": identity is not None,
                  "login_url": "/", "logout_url": "/cdn-cgi/access/logout"}
        if identity is not None:
            result["principal"] = {"owner": identity["owner"], "email": identity["email"]}
        return result

    async def _lifespan(self, receive, send):
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                try:
                    if self._started:
                        raise RuntimeError("Application already started")
                    await asyncio.to_thread(self.worker.start)
                    self._started = True
                    await send({"type": "lifespan.startup.complete"})
                except Exception:
                    await send({"type": "lifespan.startup.failed", "message": "Numerical worker startup failed"})
                    return
            elif event["type"] == "lifespan.shutdown":
                self._started = False
                try:
                    await asyncio.to_thread(self.worker.stop)
                    await send({"type": "lifespan.shutdown.complete"})
                except Exception:
                    await send({"type": "lifespan.shutdown.failed", "message": "Numerical worker shutdown failed"})
                return

    @staticmethod
    def _single(headers, name, *, required=False):
        values = [v for k, v in headers if k.lower() == name]
        if len(values) > 1 or (required and not values):
            raise ServiceError(400, "HTTP_REQUEST", "Missing or duplicate request header")
        return values[0].decode("latin-1") if values else None

    def _ready(self):
        if not self._started or not self.worker.healthy:
            return False
        try:
            if shutil.disk_usage(self.service.directory).free < MIN_FREE_BYTES:
                return False
            with sqlite3.connect(self.service.store.path, timeout=1) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("SELECT 1 FROM runs LIMIT 1").fetchone()
                db.rollback()
            return True
        except (OSError, sqlite3.Error):
            return False

    def _dispatch(self, method, path, raw, identity, key):
        if path == "/ui/auth" and method in {"GET", "HEAD"}:
            return 200, self._session(identity), None
        if path == "/health/ready" and method in {"GET", "HEAD"}:
            if not self._ready():
                raise ServiceError(503, "SERVICE_UNAVAILABLE", "The service is not ready")
            return 200, {"status": "ready"}, None
        if method not in {"GET", "HEAD"} and not self._ready():
            raise ServiceError(503, "SERVICE_UNAVAILABLE", "The service is not ready")
        if method in {"GET", "HEAD"} and path in _WEB_RESOURCES:
            name, media = _WEB_RESOURCES[path]
            return 200, resources.files("quanta").joinpath("web", name).read_bytes(), media
        body = None
        if raw:
            try:
                body = parse_json(raw)
            except ValueError as exc:
                raise ServiceError(422, "INPUT_SCHEMA", str(exc)) from exc
        status, response = self.service.request(identity["owner"], method, path, body, idempotency_key=key)
        if method == "GET" and path == "/v1/capabilities" and status == 200:
            response["execution"]["authentication"] = "cloudflare_access_jwt"
        return status, response, None

    async def _request(self, scope, receive):
        if not self._started:
            raise ServiceError(503, "SERVICE_UNAVAILABLE", "The service is not ready")
        headers = scope.get("headers", [])
        if len(headers) > 128 or sum(len(k) + len(v) for k, v in headers) > 65_536:
            raise ServiceError(431, "HTTP_REQUEST", "Request headers exceed the limit")
        host = self._single(headers, b"host", required=True)
        if host.lower() != self.authority:
            raise ServiceError(400, "HTTP_HOST", "The request must target the configured public host")
        origin = self._single(headers, b"origin")
        method = scope.get("method", "")
        if (origin is not None and origin != self.config.public_origin) or (
                method not in {"GET", "HEAD"} and origin != self.config.public_origin):
            raise ServiceError(403, "HTTP_ORIGIN", "Requests must use the configured origin")
        raw_path = scope.get("raw_path", scope.get("path", "/").encode("utf-8"))
        query = scope.get("query_string", b"")
        target = raw_path + (b"?" + query if query else b"")
        if len(target) > 4096:
            raise ServiceError(414, "RESOURCE_LIMIT", "Request target exceeds the byte limit")
        try:
            path = target.decode("ascii")
        except UnicodeDecodeError:
            raise ServiceError(400, "HTTP_REQUEST", "Request target must be ASCII encoded") from None
        if not path.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in path):
            raise ServiceError(400, "HTTP_REQUEST", "Invalid request target")
        assertion = self._single(headers, b"cf-access-jwt-assertion")
        # These identity/transport headers never establish an authenticated owner.
        try:
            identity = await asyncio.to_thread(self.verifier.verify, assertion or "")
        except AccessDenied:
            error = ServiceError(401, "UNAUTHORIZED", "A valid permitted login is required")
            return 401, {**error_document(error), **self._session()}, None
        except AuthUnavailable:
            raise ServiceError(503, "AUTH_UNAVAILABLE", "Login verification is temporarily unavailable") from None
        if self._single(headers, b"transfer-encoding") is not None:
            raise ServiceError(400, "HTTP_REQUEST", "Streaming request framing is unsupported")
        length = self._single(headers, b"content-length")
        if length is not None and (not length.isascii() or not length.isdigit()):
            raise ServiceError(400, "HTTP_REQUEST", "Content-Length must be a nonnegative decimal integer")
        if length is not None and (len(length) > 10 or int(length) > MAX_BODY):
            raise ServiceError(413, "RESOURCE_LIMIT", "Request body exceeds the input byte limit")
        media = self._single(headers, b"content-type")
        key = self._single(headers, b"idempotency-key")
        body = bytearray()
        async with asyncio.timeout(10):
            while True:
                event = await receive()
                if event["type"] == "http.disconnect":
                    return None
                if event["type"] != "http.request":
                    raise ServiceError(400, "HTTP_REQUEST", "Invalid request body event")
                fragment = event.get("body", b"")
                if len(body) + len(fragment) > MAX_BODY:
                    raise ServiceError(413, "RESOURCE_LIMIT", "Request body exceeds the input byte limit")
                body.extend(fragment)
                if not event.get("more_body", False):
                    break
        if length is not None and len(body) != int(length):
            raise ServiceError(400, "HTTP_REQUEST", "Content-Length does not match the body")
        if body and method in {"GET", "HEAD"}:
            raise ServiceError(400, "HTTP_REQUEST", "Read requests do not accept bodies")
        if body and (media is None or media.split(";", 1)[0].strip().lower() != "application/json"):
            raise ServiceError(415, "INPUT_SCHEMA", "Only application/json request bodies are supported")
        return await asyncio.to_thread(self._dispatch, method, path, bytes(body), identity, key)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        admitted = self._active < 32
        if admitted:
            self._active += 1
        try:
            await self._http(scope, receive, send, admitted)
        finally:
            if admitted:
                self._active -= 1

    async def _http(self, scope, receive, send, admitted):
        try:
            if not admitted:
                raise ServiceError(503, "SERVICE_UNAVAILABLE", "The request capacity is temporarily exhausted")
            result = await self._request(scope, receive)
            if result is None:
                return
            status, value, media = result
        except ServiceError as exc:
            status, value, media = exc.status, error_document(exc), None
        except TimeoutError:
            status, value, media = 408, error_document(ServiceError(408, "HTTP_REQUEST", "Request timed out")), None
        except Exception:
            status, value, media = 500, error_document(ServiceError(500, "ENGINE_FAILURE", "The request could not be completed")), None
        raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
        content_type = media or ("application/octet-stream" if isinstance(value, bytes) else "application/json; charset=utf-8")
        headers = [(b"content-type", content_type.encode()), (b"content-length", str(len(raw)).encode()),
                   (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                   (b"content-security-policy", _CSP.encode()), (b"x-frame-options", b"DENY"),
                   (b"referrer-policy", b"no-referrer"), (b"cross-origin-resource-policy", b"same-origin"),
                   (b"cross-origin-opener-policy", b"same-origin")]
        if isinstance(value, bytes):
            headers.append((b"etag", ('"' + hashlib.sha256(raw).hexdigest() + '"').encode()))
        if status == 401:
            headers.append((b"www-authenticate", b"Bearer"))
        try:
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": b"" if scope.get("method") == "HEAD" else raw})
        except OSError:
            pass


def create_app(service, config: AccessConfig, *, verifier=None, worker=None):
    return ProductionApp(service, config, verifier=verifier, worker=worker)
