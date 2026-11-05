#!/usr/bin/env python3
"""Exercise the optional Caddy proxy against a loopback-only dummy upstream.

Requires a separately verified Caddy binary and curl with HTTP/2 support. No
Python dependencies, public CA requests, production credentials, or OCI access.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from queue import Empty, Queue
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
HOST = "caddy-check.example.invalid"
ORIGIN = "https://" + HOST
AUTHORIZATION = "Bearer local-framing-fixture"
MAX_BODY = 1_048_576


def find_handler(value, name):
    if isinstance(value, dict):
        if value.get("handler") == name:
            return value
        for item in value.values():
            result = find_handler(item, name)
            if result is not None:
                return result
    elif isinstance(value, list):
        for item in value:
            result = find_handler(item, name)
            if result is not None:
                return result
    return None


def run_check(caddy: str) -> dict:
    curl = shutil.which("curl")
    if curl is None or "HTTP2" not in subprocess.run(
            [curl, "--version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("curl with HTTP/2 support is required")
    version = subprocess.run([caddy, "version"], check=True, capture_output=True,
                             text=True, timeout=10).stdout.strip()
    observed = Queue()

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            lengths = self.headers.get_all("Content-Length", [])
            transfer = self.headers.get_all("Transfer-Encoding", [])
            # Match Quanta's framing boundary. Do not consume an unknown stream.
            if transfer or len(lengths) != 1:
                observed.put({"framing_error": True, "transfer_encoding": transfer})
                self.send_error(400)
                self.close_connection = True
                return
            body = self.rfile.read(int(lengths[0]))
            observed.put({
                "version": self.request_version,
                "content_length": lengths,
                "transfer_encoding": transfer,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "host": self.headers.get_all("Host", []),
                "origin": self.headers.get_all("Origin", []),
                "authorization": self.headers.get_all("Authorization", []),
            })
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    upstream.daemon_threads = True
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="quanta-caddy-check-") as temporary:
            directory = Path(temporary)
            environment = dict(os.environ, QUANTA_PUBLIC_HOST=HOST,
                               XDG_DATA_HOME=str(directory / "data"),
                               XDG_CONFIG_HOME=str(directory / "config"))
            adapted = subprocess.run([
                caddy, "adapt", "--config", str(ROOT / "deploy/oci/Caddyfile.example"),
                "--adapter", "caddyfile", "--validate"], check=True,
                capture_output=True, text=True, env=environment, timeout=20)
            base = json.loads(adapted.stdout)
            server = base["apps"]["http"]["servers"]["srv0"]
            limiter = find_handler(server, "request_body")
            template_proxy = find_handler(server, "reverse_proxy")
            if (server["protocols"] != ["h1"]
                    or limiter != {"handler": "request_body", "max_size": MAX_BODY}
                    or template_proxy["request_buffers"] != 2 * MAX_BODY
                    or template_proxy["transport"]["versions"] != ["1.1"]
                    or template_proxy["upstreams"] != [{"dial": "127.0.0.1:8765"}]):
                raise RuntimeError("The optional proxy template changed; review this framing probe")

            # Retain the adapted handlers. Change only test addresses, admin,
            # storage and certificate issuer; a local CA never touches OS trust.
            configuration = copy.deepcopy(base)
            configuration["admin"] = {"disabled": True}
            configuration["storage"] = {"module": "file_system", "root": str(directory / "storage")}
            configuration["logging"] = {"logs": {"default": {"level": "ERROR"}}}
            server = configuration["apps"]["http"]["servers"]["srv0"]
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            server["listen"] = [f"127.0.0.1:{port}"]
            server["tls_connection_policies"] = [{}]
            server["automatic_https"] = {"disable_redirects": True}
            proxy = find_handler(server, "reverse_proxy")
            proxy["upstreams"] = [{"dial": f"127.0.0.1:{upstream.server_port}"}]
            configuration["apps"]["tls"] = {"automation": {"policies": [
                {"subjects": [HOST], "issuers": [{"module": "internal"}]}]}}
            configuration["apps"]["pki"] = {"certificate_authorities": {
                "local": {"install_trust": False}}}
            config_path = directory / "caddy.json"
            config_path.write_text(json.dumps(configuration))
            ca = directory / "storage/pki/authorities/local/root.crt"
            with (directory / "caddy.log").open("wb") as log:
                process = subprocess.Popen([caddy, "run", "--config", str(config_path)],
                                           stdout=log, stderr=log, env=environment)
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("Local Caddy exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            if ca.is_file():
                                break
                    except OSError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Local Caddy startup timed out")
                    time.sleep(0.05)

                small = b'{"framing":true}'
                cases = [
                    ("http1_known_length", "--http1.1", [], small, 200),
                    ("http1_empty_mutation", "--http1.1", [], b"", 200),
                    ("http1_chunked", "--http1.1", ["Transfer-Encoding: chunked", "Content-Length:"], small, 400),
                    ("http1_chunked_trailer", "--http1.1", ["Transfer-Encoding: chunked", "Content-Length:", "Trailer: X-Framing-Check"], small, 400),
                    ("http2_offer_falls_back_to_http1", "--http2", [], small, 200),
                    ("http1_exact_limit", "--http1.1", [], b"x" * MAX_BODY, 200),
                    ("http1_over_limit", "--http1.1", [], b"x" * (MAX_BODY + 1), 413),
                ]
                results = []
                for name, protocol, extra_headers, body, expected_status in cases:
                    command = [curl, "--silent", "--show-error", "--max-time", "20",
                               # This synthetic hostname resolves only to the local dummy proxy.
                               "--noproxy", HOST, "--resolve", f"{HOST}:{port}:127.0.0.1",
                               "--cacert", str(ca), protocol, "--request", "POST",
                               "--header", "Host: " + HOST, "--header", "Origin: " + ORIGIN,
                               "--header", "Authorization: " + AUTHORIZATION,
                               "--header", "Content-Type: application/json", "--header", "Expect:",
                               "--data-binary", "@-", "--output", str(directory / "response"),
                               "--write-out", "%{http_code} %{http_version}"]
                    for header in extra_headers:
                        command += ["--header", header]
                    command += [f"https://{HOST}:{port}/probe"]
                    response = subprocess.run(command, input=body, capture_output=True, timeout=25)
                    if response.returncode:
                        raise RuntimeError(name + ": curl failed")
                    status, frontend_version = response.stdout.decode("ascii").split()
                    if int(status) != expected_status:
                        raise RuntimeError(name + ": unexpected response " + status)
                    if frontend_version != "1.1":
                        raise RuntimeError(name + ": expected HTTP/1.1")
                    if expected_status == 200:
                        record = observed.get(timeout=2)
                        expected = {
                            "version": "HTTP/1.1", "content_length": [str(len(body))],
                            "transfer_encoding": [], "bytes": len(body),
                            "sha256": hashlib.sha256(body).hexdigest(), "host": [HOST],
                            "origin": [ORIGIN], "authorization": [AUTHORIZATION],
                        }
                        if record != expected:
                            raise RuntimeError(name + ": upstream framing or header preservation failed")
                    elif not observed.empty():
                        raise RuntimeError(name + ": rejected body reached the upstream")
                    results.append({"case": name, "status": int(status),
                                    "frontend_http": frontend_version, "passed": True})
                context = ssl.create_default_context(cafile=ca)
                context.set_alpn_protocols(["h2"])
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                        with context.wrap_socket(raw, server_hostname=HOST):
                            raise RuntimeError("An HTTP/2-only client was not rejected")
                except ssl.SSLError as exc:
                    if "no application protocol" not in str(exc).lower():
                        raise
                if not observed.empty():
                    raise RuntimeError("Unsupported HTTP/2 reached the upstream")
                results.append({"case": "http2_only_alpn_rejected",
                                "result": "tls_no_application_protocol", "passed": True})
                return {"caddy": version, "template_validation": "passed",
                        "local_tls": "temporary_internal_ca", "public_tls_verified": False,
                        "cases": results}
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy", required=True, help="Path to a separately verified Caddy binary")
    args = parser.parse_args()
    try:
        print(json.dumps(run_check(str(Path(args.caddy).resolve())), indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, Empty, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
