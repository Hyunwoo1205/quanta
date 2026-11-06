"""Single-worker ASGI transport behind an explicitly authenticated HTTPS origin."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
from importlib import resources
import json
import re
import shutil
import sqlite3
from urllib.parse import urlsplit

from .access_auth import AccessConfig, AccessDenied, AccessVerifier, AuthUnavailable
from .job_store import ServiceError
from .owner_token import OwnerTokenConfig, OwnerTokenDenied, OwnerTokenVerifier
from .parsing import parse_json
from .server import _CSP, _WEB_RESOURCES, error_document
from .worker import JobWorker

MAX_BODY = 1_048_576
MIN_FREE_BYTES = 128 * 1024 * 1024
_OWNER_PUBLIC_SHELL = frozenset({"/", "/index.html", "/assets/app.css", "/assets/app.js", "/assets/view-model.mjs",
    "/assets/dynamics-model.mjs", "/assets/dynamics-evidence.mjs", "/assets/dynamics-viewer.mjs", "/assets/dynamics-viewer.css"})
_COOKIE_NAME = "__Host-quanta_session"
_AUTH_BODY = 8192
_AUTH_PUBLIC_POSTS = frozenset({
    "/auth/signup/request", "/auth/signup/complete", "/auth/login", "/auth/login/verify",
    "/auth/password/reset/request", "/auth/password/reset/complete",
})
_AUTH_PRIVATE_POSTS = frozenset({"/auth/logout", "/auth/mfa/request", "/auth/mfa/confirm"})
_AUTH_ADMIN_POST = "/auth/admin/configure"
_AUTH_POSTS = _AUTH_PUBLIC_POSTS | _AUTH_PRIVATE_POSTS | {_AUTH_ADMIN_POST}
_HEX_SECRET = re.compile(r"[0-9a-f]{64}\Z")


class ProductionApp:
    def __init__(self, service, config: AccessConfig | OwnerTokenConfig, *, verifier=None, worker=None,
                 account_store=None, mailer=None):
        if not isinstance(config, (AccessConfig, OwnerTokenConfig)):
            raise ValueError("A validated production authentication configuration is required")
        self.service = service
        self.config = config
        self.owner_token = isinstance(config, OwnerTokenConfig)
        self.verifier = verifier if verifier is not None else (
            OwnerTokenVerifier(config) if self.owner_token else AccessVerifier(config))
        self.worker = worker if worker is not None else JobWorker(service.directory)
        # Access assertions keep their independent adapter. The owner bearer is
        # retained for operations/bootstrap; normal browser users use accounts.
        self.accounts = None
        self.mailer = None
        if self.owner_token and account_store is not False:
            if mailer is None:
                from .gmail_mailer import GmailMailer
                mailer = GmailMailer(service.directory)
            self.mailer = mailer
            if account_store is None:
                from .account_auth import AccountStore
                account_store = AccountStore(service.directory, config.token, mailer=self.mailer)
            self.accounts = account_store
        elif account_store not in (None, False) or mailer is not None:
            raise ValueError("Local accounts require owner-token authentication")
        self.authority = urlsplit(config.public_origin).netloc.lower()
        self._started = False
        self._active = 0

    def _session(self, identity=None):
        if self.accounts is not None:
            return self.accounts.status()
        if self.owner_token:
            return {"mode": "bearer", "authenticated": False, "authentication": "owner_token"}
        result = {"mode": "access", "authenticated": identity is not None,
                  "login_url": "/", "logout_url": "/cdn-cgi/access/logout"}
        if identity is not None:
            result["principal"] = {"owner": identity["owner"], "email": identity["email"]}
        return result

    def _account_identity(self, token):
        from .account_auth import AuthError
        try:
            return self.accounts.identity(token)
        except AuthError as exc:
            raise ServiceError(exc.status, exc.code, str(exc)) from None

    def _account_status(self, token):
        from .account_auth import AuthError
        try:
            return self.accounts.status(token)
        except AuthError as exc:
            raise ServiceError(exc.status, exc.code, str(exc)) from None

    @staticmethod
    def _cookie(headers):
        raw = ProductionApp._single(headers, b"cookie")
        if raw is None:
            return None
        if len(raw) > 8192 or any(ord(c) < 32 or ord(c) >= 127 for c in raw):
            raise ServiceError(400, "HTTP_REQUEST", "Invalid session cookie header")
        found = []
        for item in raw.split(";"):
            name, separator, value = item.strip().partition("=")
            if name == _COOKIE_NAME:
                if not separator:
                    raise ServiceError(400, "HTTP_REQUEST", "Invalid session cookie header")
                found.append(value)
        if len(found) > 1:
            raise ServiceError(400, "HTTP_REQUEST", "Duplicate session cookie")
        if not found:
            return None
        # An invalid/expired session is anonymous and can be cleared on the
        # discovery response instead of trapping the browser behind bad state.
        return found[0] if _HEX_SECRET.fullmatch(found[0]) else ""

    @staticmethod
    def _cookie_header(token=None):
        if token is None:
            return (b"set-cookie", (_COOKIE_NAME + "=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict").encode())
        if not isinstance(token, str) or not _HEX_SECRET.fullmatch(token):
            raise ServiceError(503, "AUTH_UNAVAILABLE", "Login is temporarily unavailable")
        return (b"set-cookie", (_COOKIE_NAME + "=" + token
            + "; Path=/; Max-Age=604800; Secure; HttpOnly; SameSite=Strict").encode())

    @staticmethod
    def _csrf(headers, identity):
        candidate = ProductionApp._single(headers, b"x-quanta-csrf")
        expected = identity.get("csrf_token") if isinstance(identity, dict) else None
        if (not isinstance(candidate, str) or not _HEX_SECRET.fullmatch(candidate)
                or not isinstance(expected, str) or not _HEX_SECRET.fullmatch(expected)
                or not hmac.compare_digest(candidate, expected)):
            raise ServiceError(403, "HTTP_CSRF", "A valid same-origin session token is required")

    def _account_request(self, path, raw, session_token, owner_authorized):
        from .account_auth import AuthError
        try:
            try:
                body = parse_json(raw) if raw else None
            except ValueError:
                raise ServiceError(422, "INPUT_SCHEMA", "The authentication request must be valid JSON") from None
            fields = {
                "/auth/signup/request": {"email"},
                "/auth/signup/complete": {"challenge_id", "code", "username", "password"},
                "/auth/login": {"username", "password"},
                "/auth/login/verify": {"challenge_id", "code"},
                "/auth/password/reset/request": {"email"},
                "/auth/password/reset/complete": {"challenge_id", "code", "new_password"},
                "/auth/logout": set(),
                "/auth/mfa/request": {"password", "enabled"},
                "/auth/mfa/confirm": {"challenge_id", "code"},
                _AUTH_ADMIN_POST: {"smtp_username", "smtp_password", "owner_email"},
            }
            if not isinstance(body, dict) or set(body) != fields[path]:
                raise ServiceError(422, "INPUT_SCHEMA", "Request members do not match this endpoint")
            if path == _AUTH_ADMIN_POST:
                if not owner_authorized:
                    raise ServiceError(401, "UNAUTHORIZED", "The private owner credential is required for setup")
                try:
                    username, password = self.mailer.validate_credentials(body["smtp_username"], body["smtp_password"])
                except (ValueError, TypeError):
                    raise ServiceError(422, "INPUT_SCHEMA", "Valid Gmail SMTP settings are required") from None
                # Reserve the verified-email owner mapping before mail becomes
                # available. A failed write remains closed and can be retried
                # only for that same owner email with the private owner bearer.
                self.accounts.configure_owner(body["owner_email"], owner_authorized=True)
                try:
                    self.mailer.configure(username, password)
                except Exception:
                    raise ServiceError(503, "AUTH_UNAVAILABLE", "Email delivery settings could not be saved") from None
                return 200, {"configured": True, "mail_configured": True,
                             "message": "Email verification is ready for owner registration"}, None, []
            if path == "/auth/signup/request":
                result = self.accounts.request_signup(body["email"])
            elif path == "/auth/signup/complete":
                result = self.accounts.complete_signup(body["challenge_id"], body["code"], body["username"], body["password"])
            elif path == "/auth/login":
                result = self.accounts.login(body["username"], body["password"])
            elif path == "/auth/login/verify":
                result = self.accounts.complete_login(body["challenge_id"], body["code"])
            elif path == "/auth/password/reset/request":
                result = self.accounts.request_password_reset(body["email"])
            elif path == "/auth/password/reset/complete":
                result = self.accounts.complete_password_reset(body["challenge_id"], body["code"], body["new_password"])
            elif path == "/auth/logout":
                result = self.accounts.logout(session_token)
            elif path == "/auth/mfa/request":
                result = self.accounts.request_mfa(session_token, body["password"], body["enabled"])
            else:
                result = self.accounts.complete_mfa(session_token, body["challenge_id"], body["code"])
            extra = []
            pending_mfa = path == "/auth/login" and result.payload.get("mfa_required") is True
            if session_token and (pending_mfa or result.session_token is not None):
                self.accounts.logout(session_token)
            if result.session_token is not None:
                # The opaque session is deliberately never serialized as JSON.
                if result.session_token in json.dumps(result.payload, ensure_ascii=False):
                    raise ServiceError(503, "AUTH_UNAVAILABLE", "Login is temporarily unavailable")
                extra.append(self._cookie_header(result.session_token))
            elif result.clear_session or pending_mfa:
                extra.append(self._cookie_header())
            status = 202 if "challenge_id" in result.payload else (201 if path == "/auth/signup/complete" else 200)
            return status, result.payload, None, extra
        except AuthError as exc:
            raise ServiceError(exc.status, exc.code, str(exc)) from None

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
            response["execution"]["authentication"] = (
                "server_configured_bearer_principal" if self.owner_token else "cloudflare_access_jwt")
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
        credential = self._single(headers, b"authorization" if self.owner_token else b"cf-access-jwt-assertion")
        session_token = self._cookie(headers) if self.accounts is not None else None
        # These identity/transport headers never establish an authenticated owner.
        public_shell = (self.owner_token and method in {"GET", "HEAD"}
                        and (path == "/ui/auth" or path in _OWNER_PUBLIC_SHELL))
        account_post = self.accounts is not None and method == "POST" and path in _AUTH_POSTS
        public_account_post = account_post and path in _AUTH_PUBLIC_POSTS
        identity = None
        session_identity = None
        owner_authorized = False
        # Explicit credentials never silently fall back to a browser cookie.
        # Even the public shell rejects an explicitly invalid owner bearer.
        if credential is not None or not self.owner_token:
            try:
                identity = await asyncio.to_thread(self.verifier.verify, credential or "")
                owner_authorized = self.owner_token
            except (AccessDenied, OwnerTokenDenied):
                error = ServiceError(401, "UNAUTHORIZED", "A valid permitted login is required")
                return 401, {**error_document(error), **self._session()}, None, []
            except AuthUnavailable:
                raise ServiceError(503, "AUTH_UNAVAILABLE", "Login verification is temporarily unavailable") from None
        if (self.accounts is not None and session_token
                and (not owner_authorized or path in _AUTH_PRIVATE_POSTS)):
            session_identity = await asyncio.to_thread(self._account_identity, session_token)
            if identity is None:
                identity = session_identity
        logout_post = account_post and path == "/auth/logout"
        if not public_shell and not public_account_post and not logout_post and identity is None:
            error = ServiceError(401, "UNAUTHORIZED", "A valid permitted login is required")
            extra = [self._cookie_header()] if session_token is not None else []
            return 401, {**error_document(error), **self._session()}, None, extra
        if account_post:
            if self._single(headers, b"x-quanta-auth") != "1":
                raise ServiceError(403, "HTTP_ORIGIN", "A same-origin account request is required")
            if path == _AUTH_ADMIN_POST and not owner_authorized:
                raise ServiceError(401, "UNAUTHORIZED", "The private owner credential is required for setup")
            if path in _AUTH_PRIVATE_POSTS:
                if session_identity is None and not logout_post:
                    raise ServiceError(401, "UNAUTHORIZED", "A valid account session is required")
                if session_identity is not None:
                    self._csrf(headers, session_identity)
        elif (self.accounts is not None and method not in {"GET", "HEAD"}
              and not owner_authorized and session_identity is not None):
            self._csrf(headers, session_identity)
        if self._single(headers, b"transfer-encoding") is not None:
            raise ServiceError(400, "HTTP_REQUEST", "Streaming request framing is unsupported")
        length = self._single(headers, b"content-length")
        if length is not None and (not length.isascii() or not length.isdigit()):
            raise ServiceError(400, "HTTP_REQUEST", "Content-Length must be a nonnegative decimal integer")
        body_limit = _AUTH_BODY if account_post else MAX_BODY
        if length is not None and (len(length) > 10 or int(length) > body_limit):
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
                if len(body) + len(fragment) > body_limit:
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
        if account_post:
            if not self._ready():
                raise ServiceError(503, "SERVICE_UNAVAILABLE", "The service is not ready")
            if media is None or media.split(";", 1)[0].strip().lower() != "application/json":
                raise ServiceError(415, "INPUT_SCHEMA", "Only application/json request bodies are supported")
            return await asyncio.to_thread(self._account_request, path, bytes(body), session_token, owner_authorized)
        if self.accounts is not None and path == "/ui/auth" and method in {"GET", "HEAD"}:
            value = await asyncio.to_thread(self._account_status, session_token)
            extra = [self._cookie_header()] if session_token is not None and not value["authenticated"] else []
            return 200, value, None, extra
        result = await asyncio.to_thread(self._dispatch, method, path, bytes(body), identity, key)
        if (self.accounts is not None and session_identity is not None and not owner_authorized
                and method == "GET" and path == "/v1/capabilities" and result[0] == 200):
            result[1]["execution"]["authentication"] = "verified_account_session"
        return (*result, [])

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
        extra_headers = []
        try:
            if not admitted:
                raise ServiceError(503, "SERVICE_UNAVAILABLE", "The request capacity is temporarily exhausted")
            result = await self._request(scope, receive)
            if result is None:
                return
            status, value, media, extra_headers = result
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
        headers.extend(extra_headers)
        try:
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": b"" if scope.get("method") == "HEAD" else raw})
        except OSError:
            pass


def create_app(service, config: AccessConfig | OwnerTokenConfig, *, verifier=None, worker=None,
               account_store=None, mailer=None):
    return ProductionApp(service, config, verifier=verifier, worker=worker,
                         account_store=account_store, mailer=mailer)
