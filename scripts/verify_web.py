#!/usr/bin/env python3
"""Measure the packaged web shell and its authenticated HTTP calculation flow.

These checks use the same requests as the browser UI. Browser rendering and
interaction are verified separately; this script never substitutes mock results.
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
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode

import quanta
from quanta import __version__
from quanta.hashing import canonical_bytes
from quanta.job_store import ServiceError
from quanta.server import create_server
from quanta.service import ExecutionService
from quanta.worker import JobWorker
from verify_numerics import locked_environment

ROOT = Path(__file__).resolve().parents[1]


def source_record() -> dict:
    """Hash the actual imported package plus browser assets, including wheel use."""
    package = Path(quanta.__file__).resolve().parent
    files = {"src/quanta/" + path.name: path for path in package.glob("*.py")}
    for path in (package / "web").rglob("*"):
        if path.is_file() and path.suffix in {".html", ".css", ".js", ".mjs", ".json"}:
            files["src/quanta/" + str(path.relative_to(package))] = path
    files["scripts/verify_web.py"] = Path(__file__).resolve()
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(files.items())}
    record = {"files_sha256": hashes,
              "source_set_sha256": hashlib.sha256(canonical_bytes(hashes)).hexdigest(),
              "source_set_hash_rule": "RFC 8785 of relative alias to actual imported source/asset raw SHA256; report excluded"}
    try:
        record["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
            text=True, stderr=subprocess.DEVNULL).strip()
        record["git_worktree_dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip())
    except (OSError, subprocess.CalledProcessError):
        record.update(git_head=None, git_worktree_dirty=None)
    return record


def definition() -> dict:
    """Independent harmonic input: L0=1 nm, E0=1e-19 J, k=3, rho0=1."""
    return {"unit_system": "SI", "scales": {"length_m": 1e-9, "energy_j": 1e-19},
        "system": {"representation": "particles_3d", "module_id": "quanta.pair_static",
            "module_version": "0.1.0", "boundary": "nonperiodic", "min_distance_m": 1e-17,
            "particles": [{"id": "fixed", "position_m": [-0.0, 0.0, 0.0], "fixed": [True, True, True]},
                          {"id": "probe", "position_m": [1.25e-9, 0.0, 0.0], "fixed": [False, True, True]}],
            "potential": {"expression": {"op": "mul", "args": [{"op": "const", "value": 0.5},
                {"op": "param", "name": "k"}, {"op": "pow", "arg": {"op": "sub", "args": [
                    {"op": "var", "name": "rho"}, {"op": "param", "name": "rho0"}]}, "exponent": 2}]},
                "parameters": {"k": 3.0, "rho0": 1.0}}},
        "numerics": {"solver": "lbfgsb_forward_ad", "gradient_tolerance": 1e-6,
            "energy_ftol": 1e-12, "max_iterations": 2000, "max_evaluations": 10000},
        "protocol": {"steps": [{"step_id": "measure", "operation": "energy_forces", "source": "initial", "overrides": []}],
                     "sweep": {"axes": []}}, "observables": ["energy", "forces", "final_positions"], "extensions": {}}


class Measurements:
    def __init__(self, directory):
        self.service = ExecutionService(directory)
        self.token = secrets.token_urlsafe(48)
        self.owner = "web-verification-owner"
        self.server = create_server(self.service, token=self.token, owner=self.owner)
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.worker = None
        self.input = definition()
        self.experiment = self.revision = self.run = self.result = None

    def close(self):
        if self.worker:
            self.worker.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def http(self, method, path, body=None, *, authenticated=True, key=None, origin=None, host=None):
        headers = {"Content-Type": "application/json", "Origin": self.origin if origin is None else origin}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if key:
            headers["Idempotency-Key"] = key
        if host:
            headers["Host"] = host
        raw_body = (body.encode("utf-8") if isinstance(body, str) else
                    json.dumps(body, allow_nan=False).encode("utf-8") if body is not None else None)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            connection.request(method, path, body=raw_body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            value = json.loads(raw) if "application/json" in response.getheader("Content-Type", "") else raw
            return response.status, value, dict(response.getheaders()), raw
        finally:
            connection.close()

    def counts(self):
        with sqlite3.connect(self.service.store.path) as db:
            return {name: db.execute("SELECT count(*) FROM " + name).fetchone()[0]
                    for name in ("experiments", "revisions", "runs", "artifacts")}

    def wait(self, run_id):
        before = time.monotonic()
        samples = []
        while time.monotonic() - before < 45:
            status, run, _, _ = self.http("GET", "/v1/runs/" + run_id)
            if status != 200:
                raise ValueError("Execution history did not expose the accepted run")
            sample = {"execution_status": run["execution_status"], "progress": run["progress"]}
            if not samples or samples[-1] != sample:
                samples.append(sample)
            if run["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                return run, samples
            time.sleep(0.05)
        raise TimeoutError("The web-flow calculation did not finish within 45 seconds")

    @staticmethod
    def case(ident, checks, **evidence):
        return {"id": ident, "status": "passed" if all(checks.values()) else "failed", "checks": checks, **evidence}

    def w01(self):
        status, shell, headers, raw_shell = self.http("GET", "/", authenticated=False)
        assets = []
        for path in ("/assets/app.css", "/assets/app.js", "/assets/view-model.mjs"):
            asset_status, _, asset_headers, raw = self.http("GET", path, authenticated=False)
            assets.append({"path": path, "status": asset_status, "size_bytes": len(raw),
                           "sha256": hashlib.sha256(raw).hexdigest(), "mime_type": asset_headers.get("Content-Type")})
        example_status, examples, _, raw_examples = self.http("GET", "/ui/examples", authenticated=False)
        example_rows = examples.get("examples", []) if isinstance(examples, dict) else examples
        unauthorized, _, _, _ = self.http("GET", "/v1/capabilities", authenticated=False)
        cross_origin, _, _, _ = self.http("GET", "/v1/capabilities", origin="https://unrelated.invalid")
        rebound, _, _, _ = self.http("GET", "/v1/capabilities", host="unrelated.invalid")
        csp = headers.get("Content-Security-Policy", "")
        checks = {"public_shell_served": status == 200 and b"<html" in raw_shell.lower(),
            "local_assets_served": all(row["status"] == 200 and row["size_bytes"] > 0 for row in assets),
            "trusted_examples_available": example_status == 200 and isinstance(example_rows, list) and bool(example_rows),
            "no_token_in_public_document_or_examples": self.token.encode() not in raw_shell + raw_examples,
            "api_still_requires_bearer": unauthorized == 401,
            "same_origin_boundary": cross_origin == 403 and rebound in {400, 403},
            "security_headers": "script-src 'self'" in csp and "'unsafe-eval'" not in csp
                and headers.get("X-Content-Type-Options") == "nosniff" and headers.get("X-Frame-Options") == "DENY"}
        return self.case("W01", checks, reference_method="Actual shell, asset and example HTTP responses plus browser-origin rejection",
            assets=assets, example_count=len(example_rows), public_document_sha256=hashlib.sha256(raw_shell).hexdigest(),
            cross_origin_status=cross_origin, rebinding_status=rebound)

    def w02(self):
        before = self.counts()
        validation_status, validation, _, _ = self.http("POST", "/v1/validate", {"schema_version": "0.2.0", "definition": self.input})
        after_validation = self.counts()
        title = "Independent browser-flow reference <script>not executable</script>"
        status, self.experiment, _, _ = self.http("POST", "/v1/experiments", {"title": title})
        raw_definition = json.dumps(self.input, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        body = '{"schema_version":"0.2.0","title":' + json.dumps(title) + ',"definition":' + raw_definition + '}'
        revision_status, self.revision, _, raw_revision = self.http("POST", f"/v1/experiments/{self.experiment['experiment_id']}/revisions", body)
        reread_status, reread, _, _ = self.http("GET", "/v1/revisions/" + self.revision["revision_id"])
        bad = deepcopy(self.input)
        bad["system"]["particles"][1]["position_m"] = [0.0, 0.0, 0.0]
        invalid_status, invalid, _, _ = self.http("POST", "/v1/validate", {"schema_version": "0.2.0", "definition": bad})
        checks = {"validated_without_storage_effect": validation_status == 200 and validation["valid"] and before == after_validation,
            "saved_immutable_revision": status == 201 and revision_status == 201 and reread_status == 200 and reread == self.revision,
            "negative_zero_carrier_preserved": math.copysign(1, reread["definition"]["system"]["particles"][0]["position_m"][0]) == -1
                and b"-0.0" in raw_revision,
            "title_remains_json_data": reread["title"] == title,
            "invalid_input_has_pointer_and_code": invalid_status == 200 and not invalid["valid"] and bool(invalid["errors"])
                and all("code" in e and "path" in e for e in invalid["errors"])}
        return self.case("W02", checks, reference_method="Browser-equivalent validate and raw JSON revision requests, separate immutable reread",
            experiment_id=self.experiment["experiment_id"], revision_id=self.revision["revision_id"],
            validation_storage_before=before, validation_storage_after=after_validation,
            invalid_errors=invalid["errors"])

    def w03(self):
        body = {"revision_id": self.revision["revision_id"]}
        status, self.run, _, _ = self.http("POST", "/v1/runs", body, key="web-reference-submit")
        retry_status, retry, _, _ = self.http("POST", "/v1/runs", body, key="web-reference-submit")
        pending_result, _, _, _ = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/result")
        self.worker = JobWorker(self.service.directory).start()
        terminal, samples = self.wait(self.run["run_id"])
        result_status, self.result, _, _ = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/result")
        if result_status != 200:
            raise ValueError("No verified calculation result: " + str(terminal["diagnostics"]))
        payload = self.result["steps"][0]["payload"]
        # Independent closed form: U/E0 = (3/2)*(1.25-1)^2,
        # anchor force/(E0/L0)=+3*(1.25-1), probe has the opposite force.
        expected_energy_reduced = 0.09375
        expected_forces_reduced = [[0.75, 0, 0], [-0.75, 0, 0]]
        energy_error = abs(payload["energy_j"] / 1e-19 - expected_energy_reduced)
        force_error = max(abs(value / 1e-10 - expected) for row, ref in zip(payload["forces_n"], expected_forces_reduced)
                          for value, expected in zip(row, ref))
        history_status, history, _, _ = self.http("GET", "/v1/runs?" + urlencode({"experiment_id": self.experiment["experiment_id"], "limit": 1}))
        checks = {"asynchronous_submit_and_idempotent_retry": status == 202 and self.run["execution_status"] == "QUEUED"
                and retry_status == 202 and retry["run_id"] == self.run["run_id"],
            "pending_does_not_fabricate_result": pending_result == 409,
            "actual_worker_result": terminal["execution_status"] == "SUCCEEDED" and self.result["execution_status"] == "SUCCEEDED",
            "independent_energy": math.isfinite(energy_error) and energy_error <= 1e-12,
            "independent_forces_and_fixed_reaction": math.isfinite(force_error) and force_error <= 1e-12,
            "separate_status_axes": self.result["numerical_status"] == "not_applicable"
                and self.result["resolution_status"] == "not_applicable" and self.result["physical_validation_status"] == "unvalidated",
            "experiment_history_lists_result": history_status == 200 and len(history["items"]) == 1
                and history["items"][0]["run_id"] == self.run["run_id"]}
        return self.case("W03", checks, reference_method="Actual numerical child and independent two-particle analytic energy/Cartesian forces",
            energy_actual_j=payload["energy_j"], energy_reference_j=9.375e-21, energy_error_reduced=energy_error,
            forces_actual_n=payload["forces_n"], forces_reference_n=[[7.5e-11, 0, 0], [-7.5e-11, 0, 0]],
            force_error_reduced=force_error, tolerance_reduced=1e-12, observed_progress=samples)

    def w04(self):
        reopened = ExecutionService(self.service.directory)
        _, revision = reopened.request(self.owner, "GET", "/v1/revisions/" + self.revision["revision_id"])
        _, result = reopened.request(self.owner, "GET", "/v1/runs/" + self.run["run_id"] + "/result")
        _, history = reopened.request(self.owner, "GET", "/v1/runs?experiment_id=" + self.experiment["experiment_id"])
        manifest_status, manifest, _, _ = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/artifacts")
        transfers = []
        for metadata in manifest["artifacts"]:
            status, _, _, raw = self.http("GET", "/v1/artifacts/" + metadata["artifact_id"])
            transfers.append({"artifact_id": metadata["artifact_id"], "passed": status == 200
                and len(raw) == metadata["size_bytes"] and hashlib.sha256(raw).hexdigest() == metadata["sha256"]})
        foreign_status = None
        try:
            reopened.request("foreign-owner", "GET", "/v1/runs?experiment_id=" + self.experiment["experiment_id"])
        except ServiceError as exc:
            foreign_status = exc.status
        checks = {"revision_reload_unchanged": revision == self.revision,
            "result_reload_unchanged": result == self.result,
            "history_reload_unchanged": len(history["items"]) == 1 and history["items"][0]["run_id"] == self.run["run_id"],
            "authenticated_downloads_match_manifests": manifest_status == 200 and bool(transfers) and all(row["passed"] for row in transfers),
            "foreign_experiment_history_hidden": foreign_status == 404}
        return self.case("W04", checks, reference_method="Reopened durable store and every authenticated artifact raw-byte digest",
            download_count=len(transfers), transfers=transfers, foreign_history_status=foreign_status)

    def w05(self):
        self.worker.stop()
        self.worker = None
        status, queued, _, _ = self.http("POST", "/v1/runs", {"revision_id": self.revision["revision_id"]}, key="web-reference-cancel")
        cancel_status, cancelled, _, _ = self.http("POST", "/v1/runs/" + queued["run_id"] + "/cancel")
        missing_result, _, _, _ = self.http("GET", "/v1/runs/" + queued["run_id"] + "/result")
        query = {"experiment_id": self.experiment["experiment_id"], "limit": 1}
        page_status, page, _, _ = self.http("GET", "/v1/runs?" + urlencode(query))
        query["cursor"] = page["next_cursor"]
        next_status, following, _, _ = self.http("GET", "/v1/runs?" + urlencode(query))
        all_ids = [row["run_id"] for row in page["items"] + following["items"]]
        checks = {"queued_cancel_is_terminal": status == 202 and queued["execution_status"] == "QUEUED"
                and cancel_status in {200, 202} and cancelled["execution_status"] == "CANCELLED",
            "no_cancelled_payload_invented": missing_result == 409 and cancelled["artifacts"] == [] and cancelled["progress"]["completed_steps"] == 0,
            "history_cursor_visits_each_saved_run_once": page_status == 200 and next_status == 200
                and len(all_ids) == len(set(all_ids)) == 2 and set(all_ids) == {self.run["run_id"], queued["run_id"]}}
        return self.case("W05", checks, reference_method="Queued cancellation and two actual durable records across one-item cursor pages",
            cancelled_run_id=queued["run_id"], result_http_status=missing_result, history_run_ids=all_ids)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    before = source_record()
    environment = locked_environment()
    cases = []
    with tempfile.TemporaryDirectory(prefix="quanta-web-verification-") as directory:
        measurement = Measurements(directory)
        try:
            for method in (measurement.w01, measurement.w02, measurement.w03, measurement.w04, measurement.w05):
                try:
                    result = method()
                    json.dumps(result, allow_nan=False)
                except Exception as exc:
                    result = {"id": method.__name__.upper(), "status": "failed", "error_type": type(exc).__name__, "error": str(exc)[:500]}
                cases.append(result)
        finally:
            measurement.close()
    after = source_record()
    stable = before["source_set_sha256"] == after["source_set_sha256"]
    passed = environment["valid"] and stable and all(case["status"] == "passed" for case in cases)
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if passed else "failed", "package_version": __version__,
        "scope": "Packaged web assets, browser-origin authenticated HTTP workflow, immutable revisions and actual numerical child",
        "measurement_metadata": {"origin": "actual_executed_checks", "case_namespace": "W01--W05",
            "source_unchanged_during_measurement": stable, "browser_rendering_tested_by_this_script": False},
        "cases": cases, "environment": environment, "code_source": after, "physical_validation_status": "unvalidated",
        "limitations": ["This measurement exercises the HTTP protocol used by the UI, not rendered DOM interactions; browser QA is separate.",
            "Pure JavaScript number transport, formatting and chart mapping have independent Node regression tests.",
            "No public deployment, external account, distributed execution or new physical model is certified."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output), "cases": {case["id"]: case["status"] for case in cases}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
