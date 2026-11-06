"""Owner-scoped execution service; HTTP and workers share this trusted boundary."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit
import uuid

from . import __version__
from .hashing import canonical_bytes
from .job_store import JobStore, ServiceError, public_account_limits
from .parsing import ensure_json_value
from .planning import plan_experiment
from .registry import ContractRegistry
from .validation import validate_experiment

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


def _body(value: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ServiceError(422, "INPUT_SCHEMA", "Request members do not match this endpoint")
    try:
        value = ensure_json_value(value)
        size = len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ServiceError(422, "INPUT_SCHEMA", "Request must be finite UTF-8 JSON") from exc
    if size > 1_048_576:
        raise ServiceError(413, "RESOURCE_LIMIT", "Request body exceeds the input byte limit")
    return value


def _title(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200:
        raise ServiceError(422, "INPUT_SCHEMA", "Title must contain 1 to 200 characters")
    return value


def _envelope(body: dict, experiment_id: str | None = None) -> dict:
    return {**deepcopy(body), "experiment_id": experiment_id or str(uuid.uuid4()),
            "revision_id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat()}


def _valid_plan(revision: dict) -> dict:
    plan = plan_experiment(revision)
    if not plan["valid"]:
        raise ServiceError(422, plan["errors"][0]["code"], "Revision cannot be executed by the installed engine",
                           details={"errors": plan["errors"]})
    return plan


def same_plan(left: dict, right: dict) -> bool:
    """Compare only frozen identities, never future results or wall-clock progress."""
    keys = ("input_sha256", "resolved_input_sha256", "frozen_plan", "execution_manifests")
    return all(canonical_bytes(left[key]) == canonical_bytes(right[key]) for key in keys)


class ExecutionService:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).resolve()
        self.store = JobStore(self.directory)

    def _submit(self, owner: str, body: dict, key: str | None, *, source: str | None = None) -> dict:
        endpoint = f"/v1/runs/{source}/replay" if source else "/v1/runs"
        # Verify ownership before returning even an existing idempotent response.
        if source:
            original = self.store.get_run(owner, source)
            revision = self.store.get_revision(owner, original["revision_id"])
        else:
            revision = self.store.get_revision(owner, body["revision_id"])
        cached = self.store.lookup_idempotency(owner, endpoint, key, body)
        if cached is not None:
            return cached
        plan = _valid_plan(revision)
        if source:
            from .run_store import validate_run_report
            from .job_store import TERMINAL
            if original["execution_status"] not in TERMINAL:
                raise ServiceError(409, "REPLAY_UNAVAILABLE", "Replay requires a terminal source execution")
            report = self.store.get_report(owner, source)
            if report is not None and not validate_run_report(report)["valid"]:
                raise ServiceError(409, "REPLAY_UNAVAILABLE", "Stored computation evidence failed verification")
            original_plan = report["plan"] if report is not None else self.store.get_job(source)["plan"]
            if not same_plan(original_plan, plan):
                raise ServiceError(409, "REGISTRY_SNAPSHOT_UNAVAILABLE", "Frozen replay implementation is unavailable")
        run, _ = self.store.submit(owner, revision["revision_id"], plan,
            idempotency_key=key, endpoint=endpoint, body=body, replay_of=source)
        return run

    def capabilities(self) -> dict:
        registry = ContractRegistry()
        if registry.validate_integrity():
            raise ServiceError(409, "REGISTRY_SNAPSHOT_UNAVAILABLE", "The bundled registry failed integrity verification")
        return {"service_version": "0.1.0", "package_version": __version__, "contract_version": "0.2.0",
            "scope": "single_host_owner_scoped_service", "physical_validation_status": "unvalidated",
            "implemented_operations": {"quanta.pair_static@0.1.0": ["energy_forces", "relax"],
                                       "quanta.quantum_stationary@0.1.0": ["eigenstates"]},
            "registry": deepcopy(registry.data), "resource_policy": deepcopy(registry.resource_policy),
            "execution": {"workers": 1, "threads_per_worker": 1, "idempotency_seconds": 86400,
                          "checkpoint_resume": False, "authentication": "server_configured_bearer_principal",
                          "local_account_limits": public_account_limits()}}

    def request(self, owner: str, method: str, path: str, body: object = None,
                idempotency_key: str | None = None) -> tuple[int, dict | bytes]:
        if not isinstance(owner, str) or not owner or len(owner) > 200:
            raise ServiceError(401, "UNAUTHORIZED", "An authenticated principal is required")
        split = urlsplit(path)
        route = split.path
        if split.fragment or split.scheme or split.netloc:
            raise ServiceError(404, "NOT_FOUND", "Resource not found")
        try:
            query = parse_qs(split.query, keep_blank_values=True, max_num_fields=8)
        except ValueError as exc:
            raise ServiceError(422, "INPUT_SCHEMA", "Too many query parameters") from exc
        if split.query and not (method == "GET" and route in {"/v1/experiments", "/v1/runs"}):
            raise ServiceError(422, "INPUT_SCHEMA", "This endpoint does not accept query parameters")
        if method == "GET" and body is not None:
            raise ServiceError(422, "INPUT_SCHEMA", "GET requests do not accept a body")
        if method == "GET" and route == "/v1/capabilities":
            return 200, self.capabilities()
        if method == "POST" and route == "/v1/experiments":
            value = _body(body, {"title"})
            return 201, self.store.create_experiment(owner, _title(value["title"]))
        if method == "GET" and route == "/v1/experiments":
            if query.keys() - {"limit", "cursor"} or any(len(v) != 1 for v in query.values()):
                raise ServiceError(422, "INPUT_SCHEMA", "Invalid pagination parameters")
            try:
                limit = int(query.get("limit", ["50"])[0])
                if not 1 <= limit <= 100:
                    raise ValueError
            except ValueError as exc:
                raise ServiceError(422, "INPUT_SCHEMA", "Limit must be an integer from 1 to 100") from exc
            return 200, self.store.list_experiments(owner, limit=limit, cursor=query.get("cursor", [None])[0])
        match = re.fullmatch(f"/v1/experiments/({_UUID})", route)
        if method == "GET" and match:
            return 200, self.store.get_experiment(owner, match[1])
        match = re.fullmatch(f"/v1/experiments/({_UUID})/revisions", route)
        if method == "POST" and match:
            self.store.get_experiment(owner, match[1])
            value = _body(body, {"schema_version", "title", "definition"})
            _title(value["title"])
            validation = validate_experiment(_envelope(value, match[1]))
            if not validation["valid"]:
                raise ServiceError(422, validation["errors"][0]["code"], "Invalid revision",
                                   details={"errors": validation["errors"]})
            return 201, self.store.create_revision(owner, match[1], value)
        match = re.fullmatch(f"/v1/revisions/({_UUID})", route)
        if method == "GET" and match:
            return 200, self.store.get_revision(owner, match[1])
        if method == "POST" and route == "/v1/validate":
            value = _body(body, {"schema_version", "definition"})
            return 200, validate_experiment(_envelope({**value, "title": "Validation only"}))
        if method == "POST" and route == "/v1/runs":
            value = _body(body, {"revision_id"})
            if not isinstance(value["revision_id"], str) or not re.fullmatch(_UUID, value["revision_id"]):
                raise ServiceError(404, "NOT_FOUND", "Resource not found")
            return 202, self._submit(owner, value, idempotency_key)
        if method == "GET" and route == "/v1/runs":
            if query.keys() - {"limit", "cursor", "experiment_id"} or any(len(v) != 1 for v in query.values()):
                raise ServiceError(422, "INPUT_SCHEMA", "Invalid run-history parameters")
            try:
                limit = int(query.get("limit", ["50"])[0])
                if not 1 <= limit <= 100:
                    raise ValueError
            except ValueError as exc:
                raise ServiceError(422, "INPUT_SCHEMA", "Limit must be an integer from 1 to 100") from exc
            return 200, self.store.list_runs(owner, experiment_id=query.get("experiment_id", [None])[0],
                limit=limit, cursor=query.get("cursor", [None])[0])
        match = re.fullmatch(f"/v1/runs/({_UUID})(?:/(cancel|replay|artifacts|result))?", route)
        if match:
            run_id, action = match.groups()
            if method == "GET" and action is None:
                return 200, self.store.get_run(owner, run_id)
            if method == "POST" and action == "cancel":
                _body({} if body is None else body, set())
                result, changed = self.store.cancel(owner, run_id)
                return (202 if result["execution_status"] == "CANCEL_REQUESTED" else 200), result
            if method == "POST" and action == "replay":
                _body({} if body is None else body, set())
                return 202, self._submit(owner, {}, idempotency_key, source=run_id)
            if method == "GET" and action == "artifacts":
                return 200, {"run_id": run_id, "artifacts": self.store.get_artifacts(owner, run_id)}
            if method == "GET" and action == "result":
                report = self.store.get_report(owner, run_id)
                if report is None:
                    raise ServiceError(409, "RESULT_UNAVAILABLE", "No verified computation result is available")
                return 200, report["result"]
        match = re.fullmatch(f"/v1/artifacts/({_UUID})", route)
        if method == "GET" and match:
            _, raw = self.store.get_artifact(owner, match[1])
            return 200, raw
        raise ServiceError(404, "NOT_FOUND", "Resource not found")
