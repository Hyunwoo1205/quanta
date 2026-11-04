#!/usr/bin/env python3
"""Measure verified-session ASGI requests and a real bounded numerical child.

The signing key and JWKS are generated in memory for this measurement. Requests
use real loopback HTTP through Uvicorn; external Cloudflare login, HTTPS, browser
rendering and OCI deployment are deliberately separate verification scopes.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import uvicorn

import quanta
from quanta import __version__
from quanta.access_auth import AccessConfig, AccessVerifier
from quanta.hashing import canonical_bytes
from quanta.job_store import ServiceError
from quanta.production import create_app
from quanta.service import ExecutionService
from quanta.worker import JobWorker
from verify_numerics import locked_environment

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://quanta.example.com"
HOST = "quanta.example.com"


def source_record() -> dict:
    package = Path(quanta.__file__).resolve().parent
    files = {"src/quanta/" + path.name: path for path in package.glob("*.py")}
    for path in (package / "web").rglob("*"):
        if path.is_file() and path.suffix in {".html", ".css", ".js", ".mjs", ".json"}:
            files["src/quanta/" + str(path.relative_to(package))] = path
    for name in ("verify_production.py", "verify_numerics.py"):
        files["scripts/" + name] = Path(__file__).resolve().with_name(name)
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(files.items())}
    result = {"files_sha256": hashes, "source_set_sha256": hashlib.sha256(canonical_bytes(hashes)).hexdigest(),
              "source_set_hash_rule": "RFC 8785 of relative alias to actual imported source/asset raw SHA256; report excluded"}
    try:
        result["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL).strip()
        result["git_worktree_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.CalledProcessError):
        result.update(git_head=None, git_worktree_dirty=None)
    return result


def definition() -> dict:
    """Two independent harmonic particles: U/E0=(2/2)*(1.2-1)^2=0.04."""
    return {"unit_system": "SI", "scales": {"length_m": 1e-9, "energy_j": 1e-19},
        "system": {"representation": "particles_3d", "module_id": "quanta.pair_static",
            "module_version": "0.1.0", "boundary": "nonperiodic", "min_distance_m": 1e-17,
            "particles": [{"id": "anchor", "position_m": [-0.0, 0.0, 0.0], "fixed": [True, True, True]},
                          {"id": "probe", "position_m": [1.2e-9, 0.0, 0.0], "fixed": [False, True, True]}],
            "potential": {"expression": {"op": "mul", "args": [{"op": "const", "value": 0.5},
                {"op": "param", "name": "k"}, {"op": "pow", "arg": {"op": "sub", "args": [
                    {"op": "var", "name": "rho"}, {"op": "param", "name": "rho0"}]}, "exponent": 2}]},
                "parameters": {"k": 2.0, "rho0": 1.0}}},
        "numerics": {"solver": "lbfgsb_forward_ad", "gradient_tolerance": 1e-6,
            "energy_ftol": 1e-12, "max_iterations": 2000, "max_evaluations": 10000},
        "protocol": {"steps": [{"step_id": "measure", "operation": "energy_forces", "source": "initial", "overrides": []}],
                     "sweep": {"axes": []}}, "observables": ["energy", "forces", "final_positions"], "extensions": {}}


class Measurements:
    def __init__(self, directory):
        self.service = ExecutionService(directory)
        self.config = AccessConfig(public_origin=ORIGIN, team_domain="quanta.cloudflareaccess.com",
                                   audience="measurement-app", allowed_email="owner@example.com", owner="local")
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        public.update(kid="ephemeral-production-measurement", alg="RS256", use="sig")
        verifier = AccessVerifier(self.config, fetch_keys=lambda: {"keys": [public]})
        self.app = create_app(self.service, self.config, verifier=verifier)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port,
            workers=1, lifespan="on", proxy_headers=False, access_log=False, log_level="critical",
            server_header=False, http="h11", ws="none", limit_concurrency=32,
            timeout_graceful_shutdown=20))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.listener]}, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started and self.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self.server.started:
            self.close()
            raise RuntimeError("The production ASGI server did not start")
        self.input = definition()
        self.experiment = self.revision = self.run = self.result = None
        self.expired_attempt_status = None

    def close(self):
        self.server.should_exit = True
        self.thread.join(timeout=25)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError("The production ASGI server did not stop")

    def token(self, *, key=None, **changes):
        now = int(time.time())
        claims = {"iss": self.config.issuer, "aud": [self.config.audience],
                  "email": self.config.allowed_email, "sub": "verified-measurement-owner", "type": "app",
                  "iat": now - 1, "nbf": now - 1, "exp": now + 600}
        claims.update(changes)
        return jwt.encode(claims, self.key if key is None else key, algorithm="RS256",
                          headers={"kid": "ephemeral-production-measurement"})

    def http(self, method, path, body=None, *, authenticated=True, assertion=None, key=None, origin=ORIGIN, host=HOST):
        headers = {"Host": host}
        if authenticated:
            headers["Cf-Access-Jwt-Assertion"] = self.token() if assertion is None else assertion
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = "application/json"
        if key:
            headers["Idempotency-Key"] = key
        raw_body = (body.encode() if isinstance(body, str) else
                    json.dumps(body, ensure_ascii=False, allow_nan=False).encode() if body is not None else None)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, body=raw_body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            value = json.loads(raw) if "application/json" in response_headers.get("content-type", "") else raw
            return response.status, value, response_headers, raw
        finally:
            connection.close()

    def wait(self, run_id):
        started, samples = time.monotonic(), []
        while time.monotonic() - started < 45:
            status, current, _, _ = self.http("GET", "/v1/runs/" + run_id)
            if status != 200:
                raise ValueError("The authenticated run could not be read")
            sample = {"execution_status": current["execution_status"], "progress": current["progress"]}
            if not samples or samples[-1] != sample:
                samples.append(sample)
            if current["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                return current, samples
            time.sleep(0.05)
        raise TimeoutError("The authenticated calculation did not finish within 45 seconds")

    @staticmethod
    def case(ident, checks, **evidence):
        return {"id": ident, "status": "passed" if checks and all(checks.values()) else "failed", "checks": checks, **evidence}

    def p01(self):
        session_status, session, headers, raw = self.http("GET", "/ui/auth")
        unauthorized, no_session, _, _ = self.http("GET", "/ui/auth", authenticated=False)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rejected = {}
        for name, token in {
            "wrong_signature": self.token(key=other_key),
            "expired_assertion": self.token(iat=1, nbf=1, exp=2),
            "foreign_email": self.token(email="foreign@example.com"),
            "wrong_audience": self.token(aud=["foreign-app"]),
        }.items():
            rejected[name] = self.http("GET", "/v1/experiments", assertion=token)[0]
        shell_status, _, _, shell = self.http("GET", "/")
        shell_unauthorized = self.http("GET", "/", authenticated=False)[0]
        wrong_host = self.http("GET", "/v1/experiments", host="other.example.com")[0]
        cross_origin = self.http("POST", "/v1/experiments", {"title": "blocked"}, origin="https://other.example.com")[0]
        checks = {"verified_session_maps_to_configured_owner": session_status == 200 and session["mode"] == "access"
                and session["authenticated"] and session["principal"]["owner"] == "local",
            "unauthenticated_session_not_authorized": unauthorized == 401 and no_session["authenticated"] is False
                and "principal" not in no_session,
            "untrusted_assertions_rejected": all(status == 401 for status in rejected.values()),
            "shell_uses_same_identity_boundary": shell_status == 200 and b"<html" in shell.lower() and shell_unauthorized == 401,
            "public_host_and_origin_enforced": wrong_host == 400 and cross_origin == 403,
            "credentials_not_returned_and_private_responses_not_cached": self.token().encode() not in raw + shell
                and headers.get("cache-control") == "no-store"}
        return self.case("P01", checks, reference_method="Real Uvicorn HTTP with ephemeral RSA signatures and rejected identity variants",
                         rejected_assertion_statuses=rejected, wrong_host_status=wrong_host, cross_origin_status=cross_origin)

    def p02(self):
        validation_status, validation, _, _ = self.http("POST", "/v1/validate", {"schema_version": "0.2.0", "definition": self.input})
        status, self.experiment, _, _ = self.http("POST", "/v1/experiments", {"title": "Verified-session harmonic reference"})
        request = {"schema_version": "0.2.0", "title": "Verified-session harmonic reference", "definition": self.input}
        raw_definition = json.dumps(request, separators=(",", ":"), allow_nan=False).replace("-0.0", "-0", 1)
        revision_status, self.revision, _, _ = self.http("POST", f"/v1/experiments/{self.experiment['experiment_id']}/revisions", raw_definition)
        reread_status, reread, _, _ = self.http("GET", "/v1/revisions/" + self.revision["revision_id"])
        submit_status, self.run, _, _ = self.http("POST", "/v1/runs", {"revision_id": self.revision["revision_id"]}, key="production-reference-submit")
        retry_status, retry, _, _ = self.http("POST", "/v1/runs", {"revision_id": self.revision["revision_id"]}, key="production-reference-submit")
        # An expired assertion is rejected while the independently accepted job
        # remains owned by the service; it does not issue a cancellation request.
        self.expired_attempt_status = self.http("GET", "/v1/runs/" + self.run["run_id"],
            assertion=self.token(iat=1, nbf=1, exp=2))[0]
        history_status, history, _, _ = self.http("GET", "/v1/runs")
        checks = {"input_validated": validation_status == 200 and validation["valid"],
            "immutable_revision_saved_and_reread": status == 201 and revision_status == 201 and reread_status == 200 and reread == self.revision,
            "raw_negative_zero_preserved": math.copysign(1, reread["definition"]["system"]["particles"][0]["position_m"][0]) == -1,
            "idempotent_retry_keeps_one_run": submit_status == 202 and retry_status == 202 and self.run["run_id"] == retry["run_id"]
                and history_status == 200 and len(history["items"]) == 1,
            "expired_session_cannot_read_accepted_run": self.expired_attempt_status == 401}
        return self.case("P02", checks, reference_method="Raw signed-zero JSON, immutable reread and repeated authenticated submission",
                         revision_id=self.revision["revision_id"], run_id=self.run["run_id"], history_count=len(history["items"]))

    def p03(self):
        terminal, samples = self.wait(self.run["run_id"])
        status, self.result, _, _ = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/result")
        if status != 200:
            raise ValueError("The actual numerical child did not produce a validated result")
        payload = self.result["steps"][0]["payload"]
        reference_energy = 0.04
        reference_forces = [[0.4, 0.0, 0.0], [-0.4, 0.0, 0.0]]
        energy_error = abs(payload["energy_j"] / 1e-19 - reference_energy)
        force_error = max(abs(actual / 1e-10 - expected)
            for row, reference in zip(payload["forces_n"], reference_forces) for actual, expected in zip(row, reference))
        checks = {"real_numerical_child_succeeded": terminal["execution_status"] == "SUCCEEDED" and self.result["execution_status"] == "SUCCEEDED",
            "independent_harmonic_energy": math.isfinite(energy_error) and energy_error <= 1e-12,
            "independent_cartesian_forces_and_fixed_reaction": math.isfinite(force_error) and force_error <= 1e-12,
            "fixed_negative_zero_retained": math.copysign(1, payload["final_positions_m"][0][0]) == -1,
            "status_axes_are_separate": self.result["numerical_status"] == "not_applicable"
                and self.result["resolution_status"] == "not_applicable" and self.result["physical_validation_status"] == "unvalidated"}
        return self.case("P03", checks, reference_method="U/E0=(2/2)*(1.2-1)^2; anchor force/(E0/L0)=2*(1.2-1), probe opposite",
            energy_actual_j=payload["energy_j"], energy_reference_j=4e-21, energy_error_reduced=energy_error,
            forces_actual_n=payload["forces_n"], forces_reference_n=[[4e-11, 0, 0], [-4e-11, 0, 0]],
            force_error_reduced=force_error, tolerance_reduced=1e-12, observed_progress=samples)

    def p04(self):
        status, manifest, _, _ = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/artifacts")
        transfers = []
        for item in manifest["artifacts"]:
            path = "/v1/artifacts/" + item["artifact_id"]
            code, _, headers, raw = self.http("GET", path)
            transfers.append({"artifact_id": item["artifact_id"], "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(), "passed": code == 200 and len(raw) == item["size_bytes"]
                    and hashlib.sha256(raw).hexdigest() == item["sha256"] and headers.get("cache-control") == "no-store"})
        protected = self.http("GET", "/v1/artifacts/" + manifest["artifacts"][0]["artifact_id"], authenticated=False)[0]
        return self.case("P04", {"every_authenticated_artifact_matches_original_bytes": status == 200 and bool(transfers)
            and all(row["passed"] for row in transfers), "downloads_require_verified_session": protected == 401},
            reference_method="Every actual downloaded artifact size and SHA-256 compared with its immutable manifest",
            download_count=len(transfers), transfers=transfers, unauthenticated_download_status=protected)

    def p05(self):
        fresh = self.token(jti="fresh-measurement-session")
        session_status, session, _, _ = self.http("GET", "/ui/auth", assertion=fresh)
        status, result, _, _ = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/result", assertion=fresh)
        history_status, history, _, _ = self.http("GET", "/v1/runs", assertion=fresh)
        reopened = ExecutionService(self.service.directory)
        _, durable = reopened.request("local", "GET", "/v1/runs/" + self.run["run_id"])
        checks = {"fresh_assertion_maps_to_same_owner": session_status == 200 and session["authenticated"]
                and session["principal"]["owner"] == "local",
            "expired_assertion_did_not_cancel_job": self.expired_attempt_status == 401 and durable["execution_status"] == "SUCCEEDED",
            "fresh_session_reads_unchanged_result": status == 200 and result == self.result,
            "fresh_session_does_not_resubmit": history_status == 200 and len(history["items"]) == 1
                and history["items"][0]["run_id"] == self.run["run_id"]}
        return self.case("P05", checks, reference_method="Fresh synthetic session and reopened SQLite records after rejected expired assertion",
                         durable_run_id=durable["run_id"], durable_execution_status=durable["execution_status"])

    def p06(self):
        healthy = self.http("GET", "/health/ready")[0]
        unauthenticated = self.http("GET", "/health/ready", authenticated=False)[0]
        competing_status = None
        try:
            other = JobWorker(self.service.directory).start()
        except ServiceError as exc:
            competing_status = exc.status
        else:
            other.stop()
        previous = self.app.worker.error
        try:
            self.app.worker.error = "MeasurementInjectedSupervisorFailure"
            failed_health = self.http("GET", "/health/ready")[0]
            blocked = self.http("POST", "/v1/runs", {"revision_id": self.revision["revision_id"]}, key="must-not-admit")[0]
            readable = self.http("GET", "/v1/runs/" + self.run["run_id"])[0]
        finally:
            self.app.worker.error = previous
        return self.case("P06", {"healthy_supervisor_is_ready": healthy == 200,
            "readiness_is_authenticated": unauthenticated == 401,
            "second_actual_worker_refused": competing_status == 409,
            "observed_fatal_worker_error_blocks_readiness_and_admission": failed_health == 503 and blocked == 503,
            "durable_record_reads_remain_available": readable == 200},
            reference_method="Actual exclusive supervisor lock and explicitly injected supervisor error flag; no process crash claim",
            initial_health_status=healthy, competing_worker_status=competing_status,
            failed_health_status=failed_health, blocked_submission_status=blocked, durable_read_status=readable)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    before, environment, cases = source_record(), locked_environment(), []
    with tempfile.TemporaryDirectory(prefix="quanta-production-verification-") as directory:
        measurement = None
        try:
            measurement = Measurements(directory)
            for method in (measurement.p01, measurement.p02, measurement.p03, measurement.p04, measurement.p05, measurement.p06):
                try:
                    case = method()
                    json.dumps(case, allow_nan=False)
                except Exception as exc:
                    case = {"id": method.__name__.upper(), "status": "failed", "error_type": type(exc).__name__,
                            "error": str(exc)[:300]}
                cases.append(case)
        except Exception as exc:
            cases.append({"id": "P00", "status": "failed", "error_type": type(exc).__name__, "error": str(exc)[:300]})
        finally:
            if measurement is not None:
                try:
                    measurement.close()
                except Exception as exc:
                    cases.append({"id": "SHUTDOWN", "status": "failed", "error_type": type(exc).__name__, "error": str(exc)[:300]})
    after = source_record()
    stable = before["source_set_sha256"] == after["source_set_sha256"]
    passed = environment["valid"] and stable and len(cases) == 6 and all(case["status"] == "passed" for case in cases)
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if passed else "failed", "package_version": __version__,
        "scope": "Verified Access assertions over actual Uvicorn HTTP, immutable inputs and actual numerical child",
        "measurement_metadata": {"origin": "actual_executed_checks", "case_namespace": "P01--P06",
            "source_unchanged_during_measurement": stable, "signing_keys": "ephemeral in-memory measurement fixtures",
            "external_cloudflare_login_verified": False, "public_tls_verified": False,
            "browser_rendering_verified": False, "oci_deployment_verified": False},
        "cases": cases, "environment": environment, "code_source": after, "physical_validation_status": "unvalidated",
        "limitations": ["Synthetic signed assertions verify the origin boundary; they are not external Cloudflare login sessions.",
            "Transport is actual loopback HTTP behind the configured HTTPS-origin policy; public TLS and Tunnel are not exercised.",
            "Session-expiry and renewed-session cases use synthetic timestamps; browser cookies and rendered UI require separate QA.",
            "The readiness failure case injects the supervisor error flag and does not claim a process crash or OCI recovery test."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output),
                          "cases": {case["id"]: case["status"] for case in cases}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
