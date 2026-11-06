"""Small authenticated loopback HTTP adapter for the single-host prototype."""
from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
import json
import socket
import threading

from .job_store import ServiceError
from .parsing import parse_json

_WEB_RESOURCES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/view-model.mjs": ("view-model.mjs", "text/javascript; charset=utf-8"),
    "/assets/dynamics-model.mjs": ("dynamics-model.mjs", "text/javascript; charset=utf-8"),
    "/assets/dynamics-evidence.mjs": ("dynamics-evidence.mjs", "text/javascript; charset=utf-8"),
    "/assets/dynamics-viewer.mjs": ("dynamics-viewer.mjs", "text/javascript; charset=utf-8"),
    "/assets/dynamics-viewer.css": ("dynamics-viewer.css", "text/css; charset=utf-8"),
    "/ui/examples": ("examples.json", "application/json; charset=utf-8"),
}
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data: blob:; font-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'; object-src 'none'")


def error_document(error: ServiceError) -> dict:
    from .job_store import _error
    registered = _error(error.code, str(error))
    category = registered["category"] if error.code in {
        "RESOURCE_LIMIT", "QUEUE_TIMEOUT", "MODEL_UNSUPPORTED", "PORT_INCOMPATIBLE",
        "REPRESENTATION_UNSUPPORTED", "REGISTRY_SNAPSHOT_UNAVAILABLE", "EXPRESSION_DOMAIN",
        "NUM_NOT_CONVERGED", "NUM_GRID_NOT_CONVERGED", "ENGINE_FAILURE"} else "input"
    return {"errors": [{"code": error.code, "category": category,
            "message": str(error), "path": None, "step_id": None, "branch_index": None,
            "retryable": error.status in {429, 503}, "details": error.details}]}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    request_queue_size = 32

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def create_server(service, *, token: str, owner: str = "local", host: str = "127.0.0.1", port: int = 0):
    """Create an unstarted server; the caller owns worker and HTTP lifecycles."""
    if not isinstance(token, str) or len(token) < 32 or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("The API token must contain at least 32 visible ASCII characters")
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("The prototype HTTP adapter binds to loopback only")
    if not isinstance(owner, str) or not owner or len(owner) > 200:
        raise ValueError("A fixed authenticated owner is required")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = "Quanta"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format, *args):
            # Never log bearer tokens, paths, input definitions or calculations.
            pass

        def _send(self, status, value, *, content_type=None):
            raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type or ("application/octet-stream" if isinstance(value, bytes) else "application/json; charset=utf-8"))
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Connection", "close")
            if isinstance(value, bytes):
                self.send_header("ETag", '"' + hashlib.sha256(value).hexdigest() + '"')
            if status == 401:
                self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                self.wfile.write(raw)

        def send_error(self, code, message=None, explain=None):
            self._send(code, error_document(ServiceError(code, "HTTP_REQUEST", "Invalid HTTP request")))

        def _request(self):
            try:
                hosts = self.headers.get_all("Host", [])
                allowed_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
                if len(hosts) != 1 or hosts[0].lower() not in allowed_hosts:
                    raise ServiceError(400, "HTTP_HOST", "The request must target this loopback server")
                if self.command in {"GET", "HEAD"} and self.path == "/ui/auth":
                    if (self.headers.get_all("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) > 1
                            or self.headers.get("Content-Length", "0") != "0"):
                        raise ServiceError(400, "HTTP_REQUEST", "Session discovery does not accept bodies")
                    self._send(200, {"mode": "bearer", "authenticated": False})
                    return
                # A public application shell contains no private state or token.
                # Every scientific-data endpoint still requires bearer auth.
                if self.command in {"GET", "HEAD"} and self.path in _WEB_RESOURCES:
                    if (self.headers.get_all("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) > 1
                            or self.headers.get("Content-Length", "0") != "0"):
                        raise ServiceError(400, "HTTP_REQUEST", "Static resource requests do not accept bodies")
                    name, media = _WEB_RESOURCES[self.path]
                    try:
                        raw = resources.files("quanta").joinpath("web", name).read_bytes()
                    except (FileNotFoundError, IsADirectoryError, ModuleNotFoundError):
                        raise ServiceError(404, "NOT_FOUND", "Resource not found") from None
                    self._send(200, raw, content_type=media)
                    return
                auth = self.headers.get_all("Authorization", [])
                if len(auth) != 1 or not hmac.compare_digest(auth[0].encode("utf-8"), ("Bearer " + token).encode("utf-8")):
                    raise ServiceError(401, "UNAUTHORIZED", "A valid bearer token is required")
                if self.path.startswith("/v1"):
                    origins = self.headers.get_all("Origin", [])
                    if len(origins) > 1 or (origins and origins[0] != "http://" + hosts[0].lower()):
                        raise ServiceError(403, "HTTP_ORIGIN", "Browser API requests must use the same origin")
                if len(self.path) > 4096:
                    raise ServiceError(414, "RESOURCE_LIMIT", "Request target exceeds the byte limit")
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get_all("Transfer-Encoding") or len(lengths) > 1:
                    raise ServiceError(400, "HTTP_REQUEST", "Ambiguous or streaming request framing is unsupported")
                if lengths and (not lengths[0].isascii() or not lengths[0].isdigit()):
                    raise ServiceError(400, "HTTP_REQUEST", "Content-Length must be a nonnegative decimal integer")
                if lengths and len(lengths[0]) > 10:
                    raise ServiceError(413, "RESOURCE_LIMIT", "Request body exceeds the input byte limit")
                size = int(lengths[0]) if lengths else 0
                if size > 1_048_576:
                    raise ServiceError(413, "RESOURCE_LIMIT", "Request body exceeds the input byte limit")
                body = None
                if size:
                    media = self.headers.get("Content-Type", "application/json").split(";", 1)[0].strip().lower()
                    if media != "application/json":
                        raise ServiceError(415, "INPUT_SCHEMA", "Only application/json request bodies are supported")
                    raw = self.rfile.read(size)
                    if len(raw) != size:
                        raise ServiceError(400, "HTTP_REQUEST", "Incomplete request body")
                    try:
                        body = parse_json(raw)
                    except ValueError as exc:
                        raise ServiceError(422, "INPUT_SCHEMA", str(exc)) from exc
                keys = self.headers.get_all("Idempotency-Key", [])
                if len(keys) > 1:
                    raise ServiceError(400, "HTTP_REQUEST", "Duplicate Idempotency-Key headers")
                status, response = service.request(owner, self.command, self.path, body,
                                                   idempotency_key=keys[0] if keys else None)
                self._send(status, response)
            except ServiceError as exc:
                self._send(exc.status, error_document(exc))
            except (TimeoutError, socket.timeout):
                self._send(408, error_document(ServiceError(408, "HTTP_REQUEST", "Request timed out")))
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            except Exception:
                self._send(500, error_document(ServiceError(500, "ENGINE_FAILURE", "The request could not be completed")))

        do_GET = _request
        do_POST = _request
        do_PUT = _request
        do_PATCH = _request
        do_DELETE = _request
        do_OPTIONS = _request
        do_HEAD = _request

    return _Server((host, port), Handler)
