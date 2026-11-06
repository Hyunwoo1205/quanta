#!/usr/bin/env python3
"""Measure the web dynamics boundary with real HTTP, SQLite and solver children.

This deliberately does not claim browser rendering/interaction, public HTTPS,
OCI deployment, actual email or physical validation. An optional synthetic
fixture contains actual returned result bytes plus independent frame references
for a separate browser parity check.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import http.client
from importlib import resources
import json
from pathlib import Path
import secrets
import tempfile
import threading
import time

import quanta
from quanta import __version__
from quanta.environment import environment_report
from quanta.hashing import canonical_bytes
from quanta.server import create_server
from quanta.service import ExecutionService
from quanta.worker import JobWorker

ASSETS = {
    "/assets/dynamics-evidence.mjs": ("dynamics-evidence.mjs", "text/javascript"),
    "/assets/dynamics-model.mjs": ("dynamics-model.mjs", "text/javascript"),
    "/assets/dynamics-viewer.mjs": ("dynamics-viewer.mjs", "text/javascript"),
    "/assets/dynamics-viewer.css": ("dynamics-viewer.css", "text/css"),
}


class WebMeasurements:
    """A temporary loopback service; credentials are never serialized."""
    def __init__(self, directory):
        self.service = ExecutionService(directory)
        self.owner = "synthetic-web-dynamics-verification"
        self.token = secrets.token_urlsafe(48)
        self.server = create_server(self.service, token=self.token, owner=self.owner, port=0)
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def http(self, method, path, body=None, *, authenticated=True, key=None):
        headers = {"Origin": self.origin, "Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if key is not None:
            headers["Idempotency-Key"] = key
        raw = body if isinstance(body, (str, bytes)) else (
            json.dumps(body, ensure_ascii=False, allow_nan=False) if body is not None else None)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            connection.request(method, path, raw, headers)
            response = connection.getresponse()
            payload = response.read()
            media = response.getheader("Content-Type", "")
            value = json.loads(payload) if "application/json" in media else payload
            return response.status, value, dict(response.getheaders()), payload
        finally:
            connection.close()

    def submit(self, example, *, key):
        title = "Synthetic browser dynamics reference"
        status, experiment, _, _ = self.http("POST", "/v1/experiments", {"title": title})
        if status != 201:
            raise ValueError("Experiment admission failed")
        body = {"schema_version": example["schema_version"], "title": title,
                "definition": deepcopy(example["definition"])}
        status, revision, _, revision_raw = self.http("POST",
            f"/v1/experiments/{experiment['experiment_id']}/revisions", body)
        if status != 201:
            raise ValueError("Revision admission failed")
        status, run, _, _ = self.http("POST", "/v1/runs", {"revision_id": revision["revision_id"]}, key=key)
        if status != 202:
            raise ValueError("Run admission failed")
        return revision, run, revision_raw

    def completed(self, run_id):
        expires = time.monotonic() + 60
        while time.monotonic() < expires:
            status, run, _, _ = self.http("GET", f"/v1/runs/{run_id}")
            if status != 200:
                raise ValueError("Saved run could not be reopened")
            if run["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                status, result, _, raw = self.http("GET", f"/v1/runs/{run_id}/result")
                if status != 200:
                    raise ValueError("Completed run did not publish a result")
                return run, result, raw
            time.sleep(0.02)
        raise TimeoutError("Web dynamics child did not finish within sixty seconds")


def case(identifier, checks, **evidence):
    return {"id": identifier, "status": "passed" if all(checks.values()) else "failed",
            "checks": checks, **evidence}


def source_record():
    package = Path(quanta.__file__).resolve().parent
    files = {"src/quanta/" + str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in package.rglob("*") if p.is_file() and p.suffix in {".py", ".html", ".css", ".js", ".mjs", ".json"}}
    files["scripts/verify_dynamics_web.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return {"files_sha256": dict(sorted(files.items())),
            "source_set_sha256": hashlib.sha256(canonical_bytes(files)).hexdigest(),
            "source_set_hash_rule": "RFC8785 of relative imported package/source asset names to raw SHA256; report excluded"}


def measure(directory, *, fixture_path=None):
    m = WebMeasurements(directory)
    cases = []
    try:
        assets = []
        credentials_absent_assets = True
        for path, (name, media) in ASSETS.items():
            status, _, headers, raw = m.http("GET", path, authenticated=False)
            expected = resources.files("quanta").joinpath("web", name).read_bytes()
            credentials_absent_assets &= m.token.encode() not in raw
            assets.append({"path": path, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "passed": status == 200 and raw == expected and headers.get("Content-Type", "").startswith(media)
                    and headers.get("X-Content-Type-Options") == "nosniff"})
        status, examples, _, examples_raw = m.http("GET", "/ui/examples", authenticated=False)
        rows = examples.get("examples", [])
        dynamic = [e for e in rows if e.get("schema_version") == "0.4.0"]
        legacy = [e for e in rows if e.get("schema_version") == "0.2.0"]
        validations = []
        for row in rows:
            result_status, report, _, _ = m.http("POST", "/v1/validate",
                {"schema_version": row["schema_version"], "definition": row["definition"]})
            validations.append({"id": row["id"], "schema_version": row["schema_version"],
                                "passed": result_status == 200 and report.get("valid") is True})
        cases.append(case("DWEB01", {
            "exact_packaged_assets": all(a["passed"] for a in assets),
            "both_versioned_example_families": status == 200 and len(dynamic) == 2 and len(legacy) == 5,
            "all_examples_validate": bool(validations) and all(v["passed"] for v in validations),
            "api_authentication_still_required": m.http("GET", "/v1/capabilities", authenticated=False)[0] == 401,
            "no_credential_in_assets_or_examples": credentials_absent_assets and m.token.encode() not in examples_raw,
        }, scope="Actual same-origin package assets and version-specific example validation; no browser rendering",
            assets=assets, examples=validations))

        free = next(e for e in dynamic if e["definition"]["system"]["potential"]["expression"] == {"op": "const", "value": 0})
        selected = deepcopy(free)
        # Nonuniform final interval exercises physical-time selection in the viewer.
        selected["definition"]["numerics"].update(dt_s=0.125, steps=8, sample_stride=3)
        particles = selected["definition"]["system"]["particles"]
        revision, run, _ = m.submit(selected, key="web-free-dynamics")
        with JobWorker(m.service.directory) as worker:
            terminal, result, result_raw = m.completed(run["run_id"])
            step = result["steps"][0]
            payload = step["payload"]
            frames = payload["legs"][0]["sampled_frames"]
            references = []
            correct = True
            observables_correct = True
            for frame in frames:
                t = float(Fraction("0.125") * frame["step_index"])
                expected_positions = [[float(Fraction(p["position_m"][axis]) + Fraction(p["velocity_m_per_s"][axis]) * Fraction(t))
                                       for axis in range(3)] for p in particles]
                expected_velocities = [p["velocity_m_per_s"] for p in particles]
                correct &= (frame["time_s"] == t and frame["positions_m"] == expected_positions
                    and frame["velocities_m_per_s"] == expected_velocities
                    and frame["forces_n"] == [[0, 0, 0] for _ in particles])
                momentum = [sum(Fraction(p["mass_kg"]) * Fraction(p["velocity_m_per_s"][axis]) for p in particles)
                            for axis in range(3)]
                kinetic = sum(Fraction(p["mass_kg"]) * sum(Fraction(v) ** 2 for v in p["velocity_m_per_s"]) / 2
                              for p in particles)
                angular = [sum(Fraction(p["mass_kg"]) * (Fraction(x[a]) * Fraction(p["velocity_m_per_s"][b])
                             - Fraction(x[b]) * Fraction(p["velocity_m_per_s"][a]))
                             for p, x in zip(particles, expected_positions)) for a, b in ((1, 2), (2, 0), (0, 1))]
                observables_correct &= (frame["kinetic_energy_j"] == float(kinetic)
                    and frame["potential_energy_j"] == 0 and frame["total_energy_j"] == float(kinetic)
                    and frame["linear_momentum_kg_m_per_s"] == [float(v) for v in momentum]
                    and frame["angular_momentum_kg_m2_per_s"] == [float(v) for v in angular])
                references.append({"step_index": frame["step_index"], "time_s": t,
                    "positions_m": expected_positions, "velocities_m_per_s": expected_velocities,
                    "kinetic_energy_j": float(kinetic), "potential_energy_j": 0, "total_energy_j": float(kinetic),
                    "linear_momentum_kg_m_per_s": [float(v) for v in momentum],
                    "angular_momentum_kg_m2_per_s": [float(v) for v in angular]})
            final = next((s for s in result["states"] if s["state_id"] == step["state_ref"]), None)
            cases.append(case("DWEB02", {
                "real_child_succeeded": terminal["execution_status"] == "SUCCEEDED" and worker.error is None,
                "general_and_solver_versions_preserved": result["schema_version"] == "0.4.0" and payload["contract_version"] == "0.3.1",
                "every_retained_frame_matches_closed_form": bool(frames) and correct,
                "synchronized_energy_momentum_angular_values": observables_correct,
                "nonuniform_retained_grid": [f["step_index"] for f in frames] == [0, 3, 6, 8],
                "particle_identity_and_mass_order": payload["particle_ids"] == [p["id"] for p in particles]
                    and payload["masses_kg"] == [p["mass_kg"] for p in particles],
                "physical_unvalidated": result["physical_validation_status"] == "unvalidated",
                "successful_final_time_and_phase_state": final is not None and final["physical_time"] == {"value": 1, "unit": "s"}
                    and final["data"]["time_s"] == 1 and payload["partial"] is False and step["partial"] is False,
            }, scope="Actual HTTP/SQLite/numerical child, independent x(t)=x0+v0t on every retained frame",
                frames_checked=len(frames), saved_step_indices=[f["step_index"] for f in frames],
                final_time_s=frames[-1]["time_s"], result_size_bytes=len(result_raw),
                result_sha256=hashlib.sha256(result_raw).hexdigest()))

            status, manifest, _, _ = m.http("GET", f"/v1/runs/{run['run_id']}/artifacts")
            transfers = []
            for meta in manifest["artifacts"]:
                downloaded, _, _, raw = m.http("GET", f"/v1/artifacts/{meta['artifact_id']}")
                transfers.append(downloaded == 200 and len(raw) == meta["size_bytes"]
                    and hashlib.sha256(raw).hexdigest() == meta["sha256"])
            reopened = ExecutionService(m.service.directory)
            status_revision, stored_revision = reopened.request(m.owner, "GET", f"/v1/revisions/{revision['revision_id']}")
            status_result, stored_result = reopened.request(m.owner, "GET", f"/v1/runs/{run['run_id']}/result")
            cases.append(case("DWEB03", {
                "all_artifact_bytes_verified": status == 200 and bool(transfers) and all(transfers),
                "immutable_revision_reopened_exact": status_revision == 200 and stored_revision == revision,
                "result_reopened_exact": status_result == 200 and stored_result == result,
            }, scope="Fresh SQLite service reopen and all downloaded artifact byte sizes/SHA256",
                artifacts_checked=len(transfers)))

            old_results = []
            for op in ("energy_forces", "eigenstates"):
                old = next(e for e in legacy if len(e["definition"]["protocol"]["steps"]) == 1
                           and e["definition"]["protocol"]["steps"][0]["operation"] == op)
                _, old_run, _ = m.submit(old, key="web-legacy-" + op)
                done, old_result, _ = m.completed(old_run["run_id"])
                old_results.append({"operation": op, "passed": done["execution_status"] == "SUCCEEDED"
                    and old_result["schema_version"] == "0.2.0"})
            cases.append(case("DWEB04", {"legacy_static_and_quantum_real_children": all(x["passed"] for x in old_results)},
                scope="Actual existing default0.2 static and quantum web examples through the same worker/API", runs=old_results))
        if fixture_path is not None:
            fixture = {"scope": "synthetic_actual_http_result_for_separate_browser_parity", "production_data": False,
                "browser_verified": False, "physical_validation_status": "unvalidated", "schema_version": "0.4.0",
                "input": selected, "result": result, "result_raw_utf8": result_raw.decode("utf-8"),
                "result_raw_sha256": hashlib.sha256(result_raw).hexdigest(), "result_size_bytes": len(result_raw),
                "closed_form_reference": references}
            path = Path(fixture_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(fixture, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        return cases
    finally:
        m.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixture")
    args = parser.parse_args(argv)
    report = {"verification_kind": "web_dynamics_http_storage_artifact_boundary",
        "created_at": datetime.now(timezone.utc).isoformat(), "package_version": __version__,
        "contract_version": "0.4.0", "solver_contract_version": "0.3.1",
        "physical_validation_status": "unvalidated", "browser_verified": False,
        "not_claimed": ["actual browser trajectory parity", "OCI deployment", "public HTTPS", "actual email", "physical validation"],
        "cases": []}
    try:
        report["environment"] = environment_report()
        report["source"] = source_record()
        if not report["environment"]["valid"]:
            raise ValueError("Locked execution environment is not valid")
        with tempfile.TemporaryDirectory(prefix="quanta-web-dynamics-") as directory:
            report["cases"] = measure(directory, fixture_path=args.fixture)
        report["status"] = "passed" if report["cases"] and all(c["status"] == "passed" for c in report["cases"]) else "failed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)[:600]})
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "cases": {c["id"]: c["status"] for c in report["cases"]},
                      "error": report.get("error"), "output": str(path)}))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
