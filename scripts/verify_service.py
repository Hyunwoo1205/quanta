#!/usr/bin/env python3
"""Measure the authenticated execution service over real loopback HTTP."""
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
import tempfile
import threading
import time
import uuid

from verify_numerics import locked_environment, source_record as numeric_source_record
from quanta import __version__
from quanta.hashing import canonical_bytes
from quanta.job_store import ServiceError
from quanta.server import create_server
from quanta.service import ExecutionService
from quanta.worker import JobWorker

ROOT = Path(__file__).resolve().parents[1]
L0, E0 = 2e-9, 4e-20


def definition() -> dict:
    """An independently authored two-particle harmonic problem, with SI output."""
    return {"unit_system": "SI", "scales": {"length_m": L0, "energy_j": E0},
        "system": {"representation": "particles_3d", "module_id": "quanta.pair_static",
            "module_version": "0.1.0", "boundary": "nonperiodic", "min_distance_m": 1e-17,
            "particles": [{"id": "anchor", "position_m": [0.0, 0.0, 0.0], "fixed": [True, True, True]},
                          {"id": "probe", "position_m": [3e-9, 0.0, 0.0], "fixed": [False, True, True]}],
            "potential": {"expression": {"op": "mul", "args": [{"op": "const", "value": 0.5},
                {"op": "param", "name": "k"}, {"op": "pow", "arg": {"op": "sub", "args": [
                    {"op": "var", "name": "rho"}, {"op": "param", "name": "rho0"}]}, "exponent": 2}]},
                "parameters": {"k": 3.0, "rho0": 0.75}}},
        "numerics": {"solver": "lbfgsb_forward_ad", "gradient_tolerance": 1e-6,
            "energy_ftol": 1e-12, "max_iterations": 2000, "max_evaluations": 10000},
        "protocol": {"steps": [{"step_id": "measure", "operation": "energy_forces", "source": "initial", "overrides": []}],
                     "sweep": {"axes": []}}, "observables": ["energy", "forces", "pair_energies", "final_positions"],
        "extensions": {}}


def source_record() -> dict:
    result = numeric_source_record()
    result["files_sha256"]["scripts/verify_service.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["source_set_sha256"] = hashlib.sha256(canonical_bytes(result["files_sha256"])).hexdigest()
    return result


class Measurements:
    def __init__(self, directory: str):
        self.service = ExecutionService(directory)
        self.token = secrets.token_urlsafe(48)
        self.server = create_server(self.service, token=self.token, owner="verification-owner")
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.worker = None
        self.input = definition()
        self.revision = None
        self.run = None
        self.result = None

    def close(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker = None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def http(self, method: str, path: str, body=None, *, key: str | None = None, authenticated=True):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if key:
            headers["Idempotency-Key"] = key
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            connection.request(method, path, body=None if body is None else json.dumps(body, allow_nan=False), headers=headers)
            response = connection.getresponse()
            raw = response.read()
            value = raw if response.getheader("Content-Type", "").startswith("application/octet-stream") else json.loads(raw)
            return response.status, value
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
            status, record = self.http("GET", "/v1/runs/" + run_id)
            if status != 200:
                raise ValueError("Run status was not available")
            sample = {"execution_status": record["execution_status"], "progress": record["progress"]}
            if not samples or samples[-1] != sample:
                samples.append(sample)
            if record["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
                return record, samples, time.monotonic() - before
            time.sleep(0.05)
        raise TimeoutError("The bounded service measurement did not reach a terminal state")

    @staticmethod
    def case(ident, checks, **measurements):
        return {"id": ident, "status": "passed" if all(checks.values()) else "failed", "checks": checks, **measurements}

    def s01(self):
        before = self.counts()
        unauthenticated, _ = self.http("GET", "/v1/capabilities", authenticated=False)
        capability_status, capability = self.http("GET", "/v1/capabilities")
        validation_status, validation = self.http("POST", "/v1/validate", {"schema_version": "0.2.0", "definition": self.input})
        after = self.counts()
        checks = {"unauthenticated_request_rejected": unauthenticated == 401,
            "authenticated_capabilities": capability_status == 200 and capability["package_version"] == __version__,
            "validated_without_compute": validation_status == 200 and validation["valid"] and not validation.get("simulation_executed", False),
            "validation_has_no_storage_effects": before == after,
            "physical_validation_separate": capability["physical_validation_status"] == "unvalidated"}
        return self.case("S01", checks, reference_method="Real authenticated HTTP and storage counts before/after validation",
                         stored_counts_before=before, stored_counts_after=after)

    def s02(self):
        status, experiment = self.http("POST", "/v1/experiments", {"title": "Independent service verification"})
        body = {"schema_version": "0.2.0", "title": "Harmonic service reference", "definition": deepcopy(self.input)}
        original = deepcopy(body)
        rev_status, self.revision = self.http("POST", f"/v1/experiments/{experiment['experiment_id']}/revisions", body)
        body["definition"]["system"]["potential"]["parameters"]["k"] = 99.0
        read_status, reread = self.http("GET", "/v1/revisions/" + self.revision["revision_id"])
        invalid_status, _ = self.http("POST", f"/v1/experiments/{experiment['experiment_id']}/revisions",
                                      {**original, "revision_id": str(uuid.uuid4())})
        detail_status, detail = self.http("GET", "/v1/experiments/" + experiment["experiment_id"])
        checks = {"created_experiment_and_revision": status == 201 and rev_status == 201,
            "server_assigned_v4_ids": all(uuid.UUID(self.revision[name]).version == 4 for name in ("experiment_id", "revision_id")),
            "revision_roundtrip_immutable": read_status == 200 and reread == self.revision and reread["definition"] == original["definition"],
            "client_cannot_assign_revision_id": invalid_status == 422,
            "experiment_links_revision": detail_status == 200 and detail["revision_ids"] == [self.revision["revision_id"]]}
        return self.case("S02", checks, reference_method="Submitted copy compared with durable server envelope; no update route",
                         experiment_id=experiment["experiment_id"], revision_id=self.revision["revision_id"], input=original)

    def s03(self):
        body = {"revision_id": self.revision["revision_id"]}
        first_status, self.run = self.http("POST", "/v1/runs", body, key="service-reference-submit")
        retry_status, retry = self.http("POST", "/v1/runs", body, key="service-reference-submit")
        alternate_body = {"schema_version": "0.2.0", "title": "A distinct immutable revision", "definition": self.input}
        _, alternate = self.http("POST", f"/v1/experiments/{self.revision['experiment_id']}/revisions", alternate_body)
        conflict_status, conflict = self.http("POST", "/v1/runs", {"revision_id": alternate["revision_id"]}, key="service-reference-submit")
        foreign = {}
        for name, method, path in (
            ("revision", "GET", "/v1/revisions/" + self.revision["revision_id"]),
            ("run", "GET", "/v1/runs/" + self.run["run_id"]),
            ("cancel", "POST", "/v1/runs/" + self.run["run_id"] + "/cancel"),
            ("replay", "POST", "/v1/runs/" + self.run["run_id"] + "/replay"),
            ("artifacts", "GET", "/v1/runs/" + self.run["run_id"] + "/artifacts")):
            try:
                self.service.request("another-owner", method, path, idempotency_key="foreign")
                foreign[name] = None
            except ServiceError as exc:
                foreign[name] = exc.status
        checks = {"queued_asynchronously": first_status == 202 and self.run["execution_status"] == "QUEUED",
            "idempotent_retry_same_run": retry_status == 202 and retry["run_id"] == self.run["run_id"],
            "one_accepted_queue_record": self.counts()["runs"] == 1,
            "different_body_conflict": conflict_status == 409 and conflict["errors"][0]["code"] == "IDEMPOTENCY_CONFLICT",
            "foreign_resources_return_404": all(value == 404 for value in foreign.values())}
        return self.case("S03", checks, reference_method="HTTP retry and conflicting body inside the configured 86400-second window; second-principal access attempts",
                         run_id=self.run["run_id"], configured_idempotency_seconds=self.service.store.idempotency_seconds,
                         foreign_statuses=foreign)

    def s04(self):
        self.worker = JobWorker(self.service.directory).start()
        exclusive = False
        other = JobWorker(self.service.directory)
        try:
            other.start()
        except ServiceError as exc:
            exclusive = exc.status == 409 and exc.code == "WORKER_ACTIVE"
        else:
            other.stop()
        terminal, samples, elapsed = self.wait(self.run["run_id"])
        result_status, self.result = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/result")
        if result_status != 200:
            raise ValueError("No verified result: " + str(terminal["diagnostics"]))
        payload = self.result["steps"][0]["payload"]
        reference_energy_reduced = 0.5 * 3.0 * (1.5 - 0.75) ** 2
        reference_forces_reduced = [[2.25, 0.0, 0.0], [-2.25, 0.0, 0.0]]
        actual_energy_reduced = payload["energy_j"] / E0
        actual_forces_reduced = [[number / (E0 / L0) for number in row] for row in payload["forces_n"]]
        energy_error = abs(actual_energy_reduced - reference_energy_reduced)
        force_error = max(abs(a - b) for ar, br in zip(actual_forces_reduced, reference_forces_reduced) for a, b in zip(ar, br))
        manifest_status, manifest = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/artifacts")
        transfers = []
        for artifact in manifest["artifacts"]:
            status, raw = self.http("GET", "/v1/artifacts/" + artifact["artifact_id"])
            transfers.append({"artifact_id": artifact["artifact_id"], "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(), "passed": status == 200 and len(raw) == artifact["size_bytes"]
                    and hashlib.sha256(raw).hexdigest() == artifact["sha256"]})
        foreign_artifact = None
        try:
            self.service.request("another-owner", "GET", "/v1/artifacts/" + manifest["artifacts"][0]["artifact_id"])
        except ServiceError as exc:
            foreign_artifact = exc.status
        checks = {"exclusive_worker": exclusive, "actual_subprocess_succeeded": terminal["execution_status"] == "SUCCEEDED",
            "expected_state_order": [event["execution_status"] for event in terminal["events"]] == ["QUEUED", "RUNNING", "SUCCEEDED"],
            "energy_closed_form": math.isfinite(energy_error) and energy_error <= 1e-12,
            "forces_closed_form_and_fixed_reaction": math.isfinite(force_error) and force_error <= 1e-12,
            "progress_complete": terminal["progress"] == {"completed_steps": 1, "total_steps": 1, "active_step": None, "active_branch": None},
            "manifest_and_raw_hashes": manifest_status == 200 and bool(transfers) and all(row["passed"] for row in transfers),
            "foreign_raw_artifact_404": foreign_artifact == 404,
            "physical_validation_unvalidated": self.result["physical_validation_status"] == "unvalidated"}
        return self.case("S04", checks, reference_method="Actual worker process, HTTP results and analytic two-particle harmonic reference; every manifest raw transfer checked",
            elapsed_seconds=elapsed, observed_progress=samples, reference_energy_j=reference_energy_reduced * E0,
            actual_energy_j=payload["energy_j"], energy_error_reduced=energy_error,
            reference_forces_n=[[value * E0 / L0 for value in row] for row in reference_forces_reduced],
            actual_forces_n=payload["forces_n"], force_max_absolute_error_reduced=force_error, tolerance_reduced=1e-12,
            artifacts=transfers)

    def s05(self):
        status, replay = self.http("POST", "/v1/runs/" + self.run["run_id"] + "/replay", {}, key="service-reference-replay")
        if status != 202:
            raise ValueError("Replay was not accepted: " + str(replay))
        retry_status, retry = self.http("POST", "/v1/runs/" + self.run["run_id"] + "/replay", {}, key="service-reference-replay")
        terminal, samples, elapsed = self.wait(replay["run_id"])
        result_status, result = self.http("GET", "/v1/runs/" + replay["run_id"] + "/result")
        if result_status != 200:
            raise ValueError("No verified replay result: " + str(terminal["diagnostics"]))
        reopened = ExecutionService(self.service.directory)
        original_report = reopened.store.get_report("verification-owner", self.run["run_id"])
        reread_status, revision = reopened.request("verification-owner", "GET", "/v1/revisions/" + self.revision["revision_id"])
        hashes = ("input_sha256", "resolved_input_sha256", "execution_fingerprint")
        checks = {"accepted_new_run": status == 202 and replay["run_id"] != self.run["run_id"],
            "replay_idempotent": retry_status == 202 and retry["run_id"] == replay["run_id"],
            "replay_succeeded": terminal["execution_status"] == "SUCCEEDED",
            "same_scientific_and_execution_hashes": all(result[name] == self.result[name] for name in hashes),
            "same_computed_payload": result["steps"][0]["payload"] == self.result["steps"][0]["payload"],
            "source_provenance": result["provenance"]["replay_of"] == self.run["run_id"],
            "reopened_result_unchanged": original_report["result"] == self.result,
            "reopened_revision_unchanged": reread_status == 200 and revision == self.revision}
        return self.case("S05", checks, reference_method="Actual new subprocess replay and reopened SQLite records",
            replay_run_id=replay["run_id"], source_run_id=self.run["run_id"],
            preserved_hashes={name: result[name] for name in hashes}, observed_progress=samples, elapsed_seconds=elapsed)

    def s06(self):
        self.worker.stop()
        self.worker = None
        body = {"revision_id": self.revision["revision_id"]}
        status, queued = self.http("POST", "/v1/runs", body, key="service-reference-cancel")
        cancel_status, cancelled = self.http("POST", "/v1/runs/" + queued["run_id"] + "/cancel")
        again_status, again = self.http("POST", "/v1/runs/" + queued["run_id"] + "/cancel")
        retry_status, retry = self.http("POST", "/v1/runs", body, key="service-reference-cancel")
        done_status, done = self.http("POST", "/v1/runs/" + self.run["run_id"] + "/cancel")
        source_result_status, _ = self.http("GET", "/v1/runs/" + queued["run_id"] + "/result")
        replay_status, replay = self.http("POST", "/v1/runs/" + queued["run_id"] + "/replay", {}, key="service-reference-no-result")
        if replay_status != 202:
            raise ValueError("Terminal-input replay was not accepted: " + str(replay))
        replay_result_status, _ = self.http("GET", "/v1/runs/" + replay["run_id"] + "/result")
        cleanup_status, replay_cancelled = self.http("POST", "/v1/runs/" + replay["run_id"] + "/cancel")
        result_status, final_result = self.http("GET", "/v1/runs/" + self.run["run_id"] + "/result")
        checks = {"queued_then_cancelled": status == 202 and queued["execution_status"] == "QUEUED" and cancel_status == 200 and cancelled["execution_status"] == "CANCELLED",
            "cancel_is_terminal_and_repeatable": again_status == 200 and again == cancelled,
            "cancelled_retry_same_run": retry_status == 202 and retry["run_id"] == queued["run_id"] and retry["execution_status"] == "CANCELLED",
            "cancelled_without_computation": cancelled["progress"]["completed_steps"] == 0 and cancelled["artifacts"] == [],
            "committed_success_is_immutable": done_status == 200 and done["execution_status"] == "SUCCEEDED" and result_status == 200 and final_result == self.result,
            "terminal_input_replay_accepted": replay_status == 202 and replay["run_id"] != queued["run_id"]
                and replay["execution_status"] == "QUEUED" and replay["replay_of"] == queued["run_id"]
                and replay["revision_id"] == queued["revision_id"] and replay["resolved_input_sha256"] == queued["resolved_input_sha256"],
            "no_fabricated_source_or_replay_result": source_result_status == 409 and replay_result_status == 409
                and replay["artifacts"] == [] and replay["progress"]["completed_steps"] == 0,
            "queued_replay_cleanly_cancelled": cleanup_status == 200 and replay_cancelled["execution_status"] == "CANCELLED"}
        return self.case("S06", checks, reference_method="HTTP queued cancellation, repeated cancellation/idempotent retry, terminal success immutability and new replay from immutable cancelled input",
            cancelled_run_id=queued["run_id"], cancellation_events=cancelled["events"], cancelled_progress=cancelled["progress"],
            input_replay_run_id=replay["run_id"], input_replay_source_run_id=replay["replay_of"],
            source_result_http_status=source_result_status, queued_replay_result_http_status=replay_result_status,
            race_coverage="These measurements exercise both committed state orderings. Simultaneous transaction races and running cooperative cancellation are separate regression tests.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    before = source_record()
    environment = locked_environment()
    cases = []
    with tempfile.TemporaryDirectory(prefix="quanta-service-verification-") as directory:
        measurements = Measurements(directory)
        try:
            for method in (measurements.s01, measurements.s02, measurements.s03,
                           measurements.s04, measurements.s05, measurements.s06):
                try:
                    case = method()
                    json.dumps(case, allow_nan=False)
                except Exception as exc:
                    case = {"id": method.__name__.upper(), "status": "failed", "error_type": type(exc).__name__, "error": str(exc)[:500]}
                cases.append(case)
        finally:
            measurements.close()
    after = source_record()
    stable = before["source_set_sha256"] == after["source_set_sha256"]
    passed = environment["valid"] and stable and all(case["status"] == "passed" for case in cases)
    plan_path = ROOT / "contracts/v0.2.0/validation_manifest.json"
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if passed else "failed", "package_version": __version__,
        "scope": "Single-host authenticated HTTP API, durable queue, actual subprocess calculation, artifacts and replay",
        "acceptance_plan": {"path": str(plan_path.relative_to(ROOT)), "sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            "coverage": {"C01": "Partial: server-assigned immutable revisions, durable result/replay and finite JSON",
                "C03": "Partial actual HTTP measurement: configured 24h-window idempotent retry/conflict, queued cancellation and terminal immutability; running cancellation/concurrent races are regression tests",
                "C04": "Partial: authenticated ownership boundaries and no fabricated numerical result when replaying terminal immutable input"}},
        "measurement_metadata": {"origin": "actual_executed_checks", "case_namespace": "S01--S06",
            "reference_policy": "Independent two-particle harmonic closed form, actual HTTP status transitions and raw-byte SHA256",
            "source_unchanged_during_measurement": stable}, "cases": cases, "environment": environment,
        "code_source": after, "physical_validation_status": "unvalidated",
        "limitations": ["These service checks cover one host and one configured bearer principal; no public deployment or account provider is tested.",
            "Retry is observed inside the configured 86400-second retention window; this measurement does not wait 24 hours.",
            "Simultaneous cancel/publication transactions, running cooperative cancellation, queue expiry and crash recovery have separate regression tests.",
            "No checkpoint resume, distributed execution, new physical model or experimental accuracy is certified."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output), "cases": {row["id"]: row["status"] for row in cases}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
