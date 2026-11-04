"""Synchronous, hash-bound execution of a frozen multi-step experiment plan.

Only completed successful outputs become continuation states. Scientific source
snapshots and prepared inputs have separate identities, and dependency failures
skip their consumers without stopping unrelated steps or branches.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import time
import uuid

from . import __version__
from .autodiff import CalculationError
from .environment import environment_report
from .hashing import canonical_bytes
from .parsing import parse_json
from .planning import plan_experiment, prepare_step
from .registry import ContractRegistry

_ERROR_DETAIL_BYTES = 2048
_TERMINAL_RESERVE_PER_STEP = 8192
_TERMINAL_RESERVE_PER_RUN = 4096


class _WorkflowLimit(CalculationError):
    def __init__(self, message: str, *, global_limit: bool, details: dict):
        super().__init__(message, code="RESOURCE_LIMIT", path=None, details=details)
        self.global_limit = global_limit


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())


def _issue(code: str, message: str, *, path: str | None = None, step_id: str | None = None,
           branch_index: int | None = None, details: dict | None = None) -> dict:
    if not isinstance(code, str) or not code or len(code.encode("utf-8", errors="backslashreplace")) > 64:
        code = "ENGINE_FAILURE"
    if path is not None and (not isinstance(path, str) or not path.startswith("/") or
                             len(path.encode("utf-8", errors="backslashreplace")) > 512):
        path = None
    try:
        if details is not None and not isinstance(details, dict):
            raise ValueError("Diagnostic details must be an object")
        encoded = canonical_bytes(details or {})
        if len(encoded) > _ERROR_DETAIL_BYTES:
            details = {"detail_retention": "omitted because diagnostic details exceed the retained byte limit",
                       "original_detail_bytes": len(encoded), "retained_detail_byte_limit": _ERROR_DETAIL_BYTES}
    except (TypeError, ValueError, OverflowError):
        details = {"detail_retention": "omitted because diagnostic details are not finite canonical JSON"}
    category = ("resource" if code == "RESOURCE_LIMIT" else "numerical" if code in
                {"NUM_NOT_CONVERGED", "NUM_GRID_NOT_CONVERGED", "EXPRESSION_DOMAIN"} else "support" if code in
                {"MODEL_UNSUPPORTED", "PORT_INCOMPATIBLE", "REGISTRY_SNAPSHOT_UNAVAILABLE", "REPRESENTATION_UNSUPPORTED"}
                else "runtime" if code == "ENGINE_FAILURE" else "input")
    text = str(message).encode("utf-8", errors="backslashreplace")[:300].decode("utf-8", errors="ignore")
    return {"code": code, "category": category, "message": text, "path": path,
            "step_id": step_id, "branch_index": branch_index, "retryable": code == "ENGINE_FAILURE",
            "details": details or {}}


def _warning(value: dict) -> dict:
    return {key: value[key] for key in ("code", "message", "step_id", "branch_index")}


def _dispatch(definition: dict, operation: str, registry: ContractRegistry, check_deadline) -> dict:
    """Call only the statically enabled implementations with the same budget guard."""
    if operation == "energy_forces":
        from .pair import evaluate_pair
        return evaluate_pair(definition, registry=registry, deadline_check=check_deadline)
    if operation == "relax":
        from .relaxation import relax_pair
        return relax_pair(definition, registry=registry, deadline_check=check_deadline)
    if operation == "eigenstates":
        from .quantum import eigenstates
        return eigenstates(definition, registry=registry, deadline_check=check_deadline)
    raise CalculationError("The planned operation has no enabled implementation", code="MODEL_UNSUPPORTED",
                           path="/definition/protocol")


def _locked_environment(plan: dict, assets: dict[str, str]) -> dict:
    """Observe every captured locked distribution before asserting an execution identity."""
    observed = copy.deepcopy(environment_report())
    dependency_sha = plan["execution_manifests"]["dependency_manifest_sha256"]
    dependency = parse_json(assets[dependency_sha])
    versions = {}
    for distribution in dependency["locked_distributions"]:
        name, expected = distribution["name"], distribution["version"]
        try:
            actual = metadata.version(name)
        except metadata.PackageNotFoundError:
            actual = None
            observed["errors"].append({"code": "ENV_DEPENDENCY", "path": "/locked_distribution_versions/" + name,
                                       "message": f"Locked distribution is not installed: {name}"})
        versions[name] = actual
        if actual is not None and actual != expected:
            observed["errors"].append({"code": "ENV_LOCK_VERSION", "path": "/locked_distribution_versions/" + name,
                                       "message": f"Expected locked {name} {expected}, observed {actual}"})
    observed["locked_distribution_versions"] = versions
    package = "quanta-research-contracts"
    try:
        actual_package = metadata.version(package)
    except metadata.PackageNotFoundError:
        actual_package = None
    observed["package_distribution"] = {"name": package, "expected_version": __version__, "version": actual_package}
    if actual_package != __version__:
        observed["errors"].append({"code": "ENV_PACKAGE_VERSION", "path": "/package_distribution/version",
                                   "message": f"Expected installed {package} {__version__}, observed {actual_package}"})
    observed["valid"] = bool(observed["valid"]) and not observed["errors"]
    return observed


def _metadata(module: dict, data: dict, *, output: bool) -> dict:
    precision = copy.deepcopy(module["precision_contract"])
    common = {"coordinate_system": "cartesian", "boundary": data.get("boundary", "dirichlet_zero"),
              "precision": precision}
    if module["module_id"] == "quanta.pair_static":
        return {**common, "state_role": "configuration", "spatial_dimension": 3,
                "coordinate_labels": ["x", "y", "z"], "length_unit": "m",
                "position_shape": [len(data["particles"]), 3]}
    if not output:
        return {**common, "state_role": "configuration", "spatial_dimension": 1,
                "coordinate_label": "x", "coordinate_convention": "absolute_SI", "length_unit": "m"}
    return {**common, "state_role": "stationary_solution", "spatial_dimension": 1,
            "grid_unit": "m", "state_unit": "m^-1/2", "density_unit": "m^-1",
            "grid_shape": [len(data["x_m"])], "state_shape": [len(data["energies_j"]), len(data["x_m"])],
            "axis_order": ["state", "position"], "integration_rule": "uniform_interior_rectangle",
            "normalization": "sum_delta_x_abs_psi_squared_equals_one"}


def _port(module: dict, operation: str, direction: str) -> dict:
    ports = [p for p in module["ports"] if p["direction"] == direction and operation in p["operations"]]
    if len(ports) != 1:
        raise CalculationError("The operation has no unique registered port", code="PORT_INCOMPATIBLE")
    return ports[0]


def _state(module: dict, port: dict, data: dict, producer: dict, parents: list[str],
           resolved_sha: str, registry: ContractRegistry) -> dict:
    state = {"contract_version": "0.2.0", "state_id": _id(), "module_id": module["module_id"],
             "module_version": module["module_version"], "representation": port["representation"],
             "representation_version": port["representation_version"], "time_kind": "static", "physical_time": None,
             "data_schema_ref": port["data_schema_ref"], "data": copy.deepcopy(data),
             "metadata_schema_ref": port["metadata_schema_ref"],
             "metadata": _metadata(module, data, output=port["direction"] == "output"),
             "producer": producer, "resolved_input_sha256": resolved_sha, "parent_state_refs": parents}
    registry.validator("state.schema.json").validate(state)
    registry.validator(state["data_schema_ref"]).validate(state["data"])
    registry.validator(state["metadata_schema_ref"]).validate(state["metadata"])
    return state


def _state_projection(state: dict, definition: dict) -> dict:
    names = ("module_id", "module_version", "representation", "representation_version", "time_kind", "physical_time",
             "data_schema_ref", "data", "metadata_schema_ref", "metadata")
    projection = {name: copy.deepcopy(state[name]) for name in names}
    projection["unit_context"] = {key: copy.deepcopy(definition[key]) for key in ("unit_system", "scales")}
    return projection


def _axes(operation: str, payload: dict | None = None, error: Exception | None = None) -> tuple[str, str]:
    numerical = "not_applicable" if operation == "energy_forces" else "not_checked"
    resolution = "not_checked" if operation == "eigenstates" else "not_applicable"
    if error is not None:
        return getattr(error, "numerical_status", numerical), getattr(error, "resolution_status", resolution)
    if payload is not None:
        numerical = "not_applicable" if operation == "energy_forces" else "pass"
        if operation == "relax":
            check = next((check for check in payload["diagnostics"]["checks"]
                          if check["id"] == "free_gradient_tolerance"), None)
            numerical = ("not_checked" if check is None else
                         "pass" if payload["free_gradient_inf"] <= check["tolerance"] else "not_converged")
        if operation == "eigenstates":
            resolution = next(check["status"] for check in payload["diagnostics"]["checks"]
                              if check["id"] == "grid_energy_convergence")
    return numerical, resolution


def _aggregate(values: list[str]) -> str:
    applicable = [value for value in values if value != "not_applicable"]
    if not applicable:
        return "not_applicable"
    for status in ("not_converged", "not_checked", "pass"):
        if status in applicable:
            return status
    return "not_checked"


def _validate_payload(payload: dict, definition: dict, operation: str, module: dict,
                      registry: ContractRegistry) -> None:
    if payload.get("operation") != operation:
        raise CalculationError("The kernel returned another operation's payload", code="ENGINE_FAILURE", path="/payload/operation")
    if operation in {"energy_forces", "relax"}:
        from .pair import _check_payload
        particles = definition["system"]["particles"]
        _check_payload(payload, [p["position_m"] for p in particles], registry, module["payload_schema_ref"],
                       "pair_energies" in definition["observables"], [p["fixed"] for p in particles])
    else:
        from .quantum import _check_payload
        _check_payload(payload, registry=registry, schema_ref=module["payload_schema_ref"], definition=definition,
                       completed_grids=len(payload["grid_results"]),
                       max_bytes=int(registry.resource_policy["common_execution"]["max_artifact_bytes_per_run"]))


def run_experiment(data: bytes | str | dict, *, registry: ContractRegistry | None = None,
                   replay_of: str | None = None) -> dict:
    """Freeze and execute a finite synchronous workflow, retaining inspectable evidence.

    ``valid`` describes input and symbolic-plan validity. The nested ``result``
    carries the registered execution envelope. Resource rejection before run
    acceptance has ``result=None`` and a structured wrapper error.
    """
    plan = plan_experiment(data, registry=registry)
    report = {"report_version": "0.1.0", "scope": "synchronous_workflow", "valid": plan["valid"],
              "errors": copy.deepcopy(plan["errors"]), "warnings": copy.deepcopy(plan["warnings"]),
              "result": None, "plan": plan, "resolved_record": None, "state_content_hashes": {},
              "captured_artifacts": copy.deepcopy(plan["captured_artifacts"]), "artifact_contents": {}}
    if not plan["valid"]:
        return report
    if replay_of is not None:
        try:
            reference = uuid.UUID(replay_of)
            if reference.version != 4 or str(reference) != replay_of:
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            report["errors"].append(_issue("INPUT_SEMANTIC", "Replay provenance must reference a canonical version-4 run UUID"))
            return report
    registry = registry or ContractRegistry()
    frozen = plan["frozen_plan"]
    module_binding = frozen["frozen_bindings"]["module_bindings"][0]
    module = registry.get_module(module_binding["module_id"], module_binding["module_version"])
    policy = registry.resource_policy["common_execution"]
    byte_limit = int(policy["max_artifact_bytes_per_run"])
    assets = report["captured_artifacts"]

    def capture(value: dict) -> str:
        raw = canonical_bytes(value).decode("utf-8")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if digest in assets and assets[digest] != raw:
            raise CalculationError("Immutable captured content changed", code="ENGINE_FAILURE")
        assets[digest] = raw
        return digest

    terminal_reserve = _TERMINAL_RESERVE_PER_RUN + _TERMINAL_RESERVE_PER_STEP * len(frozen["expanded_steps"])

    def budget(*, final: bool = False) -> None:
        from .run_store import report_storage_bytes
        size = report_storage_bytes(report)
        reserve = 0 if final else terminal_reserve
        if size + reserve > byte_limit:
            raise _WorkflowLimit("The accumulated run evidence exceeds the storage byte limit", global_limit=True,
                                 details={"scope": "run", "bytes": size, "terminal_reserve_bytes": reserve, "limit": byte_limit,
                                          "stop_reason": "artifact_byte_limit"})

    capture(frozen)
    try:
        observed = _locked_environment(plan, assets)
        environment_sha = capture(observed)
        fingerprint_projection = {"contract_version": "0.2.0", "run_resolved_input_sha256": plan["resolved_input_sha256"],
                                  **plan["execution_manifests"], "environment_manifest_sha256": environment_sha}
        fingerprint = capture(fingerprint_projection) if observed["valid"] else None
        budget()
    except Exception as exc:
        report["errors"].append(_issue(getattr(exc, "code", "ENGINE_FAILURE"), str(exc),
            path=getattr(exc, "path", None), details=getattr(exc, "details", {})))
        return report

    run_id = _id()
    result = {"schema_version": "0.2.0", "run_id": run_id, "revision_id": plan["experiment"]["revision_id"],
              "input_sha256": plan["input_sha256"], "resolved_input_sha256": plan["resolved_input_sha256"],
              "execution_fingerprint": fingerprint, "execution_status": "FAILED", "numerical_status": "not_checked",
              "resolution_status": "not_checked", "physical_validation_status": "unvalidated", "steps": [], "states": [],
              "warnings": [_warning(value) for value in plan["warnings"]], "errors": [], "artifacts": [],
              "provenance": {"registry_snapshot_sha256": frozen["frozen_bindings"]["registry_binding"]["registry_snapshot_sha256"],
                  "module_manifest_sha256": module_binding["manifest_sha256"],
                  "implementation_manifest_sha256": plan["execution_manifests"]["implementation_manifest_sha256"],
                  "environment_manifest_sha256": environment_sha,
                  "constants_manifest_sha256": plan["execution_manifests"]["constants_manifest_sha256"],
                  "resource_policy_version": registry.resource_policy["version"], "replay_of": replay_of,
                  "started_at": None, "finished_at": None}, "partial": True, "physical_validation_evidence_refs": []}
    for expanded in frozen["expanded_steps"]:
        numerical, resolution = _axes(expanded["operation"])
        result["steps"].append({"branch_index": expanded["branch_index"], "step_id": expanded["step_id"],
            "module_id": module["module_id"], "module_version": module["module_version"], "resolved_input_sha256": None,
            "state_ref": None, "source_binding": None, "outcome": "SKIPPED", "partial": True,
            "numerical_status": numerical, "resolution_status": resolution, "diagnostics": {"reason": "not_executed"},
            "payload_schema_ref": module["payload_schema_ref"], "payload": None, "artifacts": []})
    result["numerical_status"] = _aggregate([step["numerical_status"] for step in result["steps"]])
    result["resolution_status"] = _aggregate([step["resolution_status"] for step in result["steps"]])
    runtime = {"effective_step_inputs": [], "typed_states": result["states"], "port_bindings": [],
               "state_content_hashes": report["state_content_hashes"], "initial_state_refs": [], "state_unit_contexts": {}}
    record = {"contract_version": "0.2.0", "run_id": run_id, "revision_id": result["revision_id"],
              "input_sha256": result["input_sha256"], "resolved_input_sha256": result["resolved_input_sha256"],
              "registry_snapshot_sha256": result["provenance"]["registry_snapshot_sha256"], "frozen_plan": copy.deepcopy(frozen),
              "runtime_evidence": runtime, "engine_bindings": copy.deepcopy(frozen["frozen_bindings"]["engine_bindings"])}
    report.update(result=result, resolved_record=record)
    registered_assets: set[str] = set()

    def artifact(raw: str, *, schema_ref: str | None = None) -> dict:
        encoded = raw.encode("utf-8")
        metadata = {"contract_version": "0.2.0", "artifact_id": _id(),
                    "kind": "config" if schema_ref else "text", "sha256": hashlib.sha256(encoded).hexdigest(),
                    "mime_type": "application/json" if schema_ref else "text/plain; charset=utf-8", "size_bytes": len(encoded)}
        metadata.update({"format": "json", "schema_ref": schema_ref} if schema_ref else {"encoding": "UTF-8"})
        registry.validator("artifact.schema.json").validate(metadata)
        result["artifacts"].append(metadata)
        report["artifact_contents"][metadata["artifact_id"]] = raw
        return metadata

    def sync_assets() -> None:
        for sha, raw in list(assets.items()):
            if sha not in registered_assets:
                artifact(raw)
                registered_assets.add(sha)

    def publish_state(state: dict, definition: dict) -> None:
        state_id = state["state_id"]
        content_sha = capture(_state_projection(state, definition))
        if state_id in report["state_content_hashes"]:
            raise CalculationError("A state identity is already published", code="ENGINE_FAILURE")
        result["states"].append(state)
        report["state_content_hashes"][state_id] = content_sha
        runtime["state_unit_contexts"][state_id] = {name: copy.deepcopy(definition[name]) for name in ("unit_system", "scales")}

    def snapshot() -> tuple:
        return (set(assets), set(report["artifact_contents"]), len(result["artifacts"]), len(result["states"]),
                len(runtime["effective_step_inputs"]), len(runtime["port_bindings"]), len(runtime["initial_state_refs"]),
                set(report["state_content_hashes"]), set(registered_assets))

    def rollback(saved: tuple) -> None:
        a, ids, artifacts, states, inputs, bindings, initials, state_ids, registered = saved
        for sha in set(assets) - a:
            del assets[sha]
        for ident in set(report["artifact_contents"]) - ids:
            del report["artifact_contents"][ident]
        del result["artifacts"][artifacts:]
        del result["states"][states:]
        del runtime["effective_step_inputs"][inputs:]
        del runtime["port_bindings"][bindings:]
        del runtime["initial_state_refs"][initials:]
        for ident in set(report["state_content_hashes"]) - state_ids:
            del report["state_content_hashes"][ident]
            del runtime["state_unit_contexts"][ident]
        registered_assets.clear()
        registered_assets.update(registered)

    try:
        sync_assets()
        budget()
    except Exception as exc:
        # A valid plan can be too large even before an accepted run exists.
        report.update(result=None, resolved_record=None)
        report["state_content_hashes"].clear()
        report["artifact_contents"].clear()
        report["errors"].append(_issue(getattr(exc, "code", "ENGINE_FAILURE"), str(exc),
            path=getattr(exc, "path", None), details=getattr(exc, "details", {})))
        return report
    if not observed["valid"]:
        result["errors"].append(_issue("MODEL_UNSUPPORTED", "The selected numerical environment baseline does not match",
                                      details={"environment_errors": observed["errors"]}))
        result["provenance"]["finished_at"] = _now()
        result["steps"].clear()
        result.update(numerical_status="not_checked", resolution_status="not_checked")
        return report

    result["provenance"]["started_at"] = _now()
    started = time.monotonic()
    run_limit = min(120.0, float(policy["wall_seconds_per_run"]))
    step_limit = min(60.0, float(policy["wall_seconds_per_step"]))
    initial_states: dict[int, dict] = {}
    completed: dict[tuple[int, str], tuple[dict, dict]] = {}
    global_stop: str | None = None

    def run_deadline() -> None:
        elapsed = time.monotonic() - started
        if elapsed >= run_limit:
            raise _WorkflowLimit("The workflow exceeded its run wall-time limit", global_limit=True,
                                 details={"scope": "run", "elapsed_seconds": elapsed, "limit_seconds": run_limit,
                                          "stop_reason": "run_wall_time_limit"})

    for expanded, step in zip(frozen["expanded_steps"], result["steps"]):
        branch, step_id, operation = expanded["branch_index"], expanded["step_id"], expanded["operation"]
        if global_stop or (expanded["source_alias"] != "initial" and (branch, expanded["source_alias"]) not in completed):
            step["diagnostics"] = {"reason": global_stop or "source_not_successful", "source_alias": expanded["source_alias"]}
            continue
        step_started = time.monotonic()

        def deadline() -> None:
            run_deadline()
            elapsed = time.monotonic() - step_started
            if elapsed >= step_limit:
                raise _WorkflowLimit("The workflow step exceeded its wall-time limit", global_limit=False,
                                     details={"scope": "step", "elapsed_seconds": elapsed, "limit_seconds": step_limit,
                                              "stop_reason": "step_wall_time_limit"})

        definition = None
        candidate_payload = None
        try:
            deadline()
            base = plan["branch_definitions"][branch]
            input_port = _port(module, operation, "input")
            if branch not in initial_states:
                saved = snapshot()
                try:
                    initial = _state(module, input_port, base["system"], {"kind": "initial", "revision_id": result["revision_id"]},
                                     [], plan["resolved_input_sha256"], registry)
                    publish_state(initial, base)
                    runtime["initial_state_refs"].append({"branch_index": branch, "state_ref": initial["state_id"]})
                    sync_assets()
                    deadline()
                    budget()
                    initial_states[branch] = initial
                except Exception:
                    rollback(saved)
                    raise
            if expanded["source_alias"] == "initial":
                source, source_definition = initial_states[branch], None
            else:
                source_definition, source = completed[(branch, expanded["source_alias"])]
            prepared = prepare_step(base, expanded, source_definition=source_definition, source_state=source,
                source_content_sha256=report["state_content_hashes"][source["state_id"]],
                frozen_bindings=frozen["frozen_bindings"], registry=registry)
            definition = prepared["definition"]
            saved = snapshot()
            try:
                digest = capture(prepared["step_projection"])
                if digest != prepared["resolved_input_sha256"]:
                    raise CalculationError("The effective-input projection hash changed", code="ENGINE_FAILURE")
                state = _state(module, input_port, definition["system"], {"kind": "prepared_input", "run_id": run_id,
                    "branch_index": branch, "step_id": step_id}, [source["state_id"]], digest, registry)
                publish_state(state, definition)
                binding = {"branch_index": branch, "step_id": step_id, "source_alias": expanded["source_alias"],
                    "source_state_ref": source["state_id"], "source_output_port": expanded["source_output_port"],
                    "target_input_port": input_port["port_id"], "representation": input_port["representation"],
                    "representation_version": input_port["representation_version"], "conversion_ref": None,
                    "effective_input_state_ref": state["state_id"]}
                registry.validator("state.schema.json#/$defs/portBinding").validate(binding)
                runtime["port_bindings"].append(binding)
                runtime["effective_step_inputs"].append({"branch_index": branch, "step_id": step_id,
                    "resolved_input_sha256": digest, "definition": copy.deepcopy(definition),
                    "projection": copy.deepcopy(prepared["step_projection"])})
                sync_assets()
                deadline()
                budget()
                step.update(resolved_input_sha256=digest, source_binding=binding)
            except Exception:
                rollback(saved)
                raise
            payload = _dispatch(definition, operation, registry, deadline)
            _validate_payload(payload, definition, operation, module, registry)
            candidate_payload = payload
            numerical, resolution = _axes(operation, payload)
            if ((operation == "relax" and payload["free_gradient_inf"] > definition["numerics"]["gradient_tolerance"])
                    or resolution == "not_converged"):
                raise CalculationError("The kernel returned a nonconverged success", code="ENGINE_FAILURE")
            if operation == "eigenstates" and len(payload["grid_results"]) != definition["numerics"]["refinement_levels"] + 1:
                raise CalculationError("The kernel did not complete the requested grids", code="ENGINE_FAILURE")
            deadline()
            saved = snapshot()
            try:
                output_port = _port(module, operation, "output")
                output_data = copy.deepcopy(definition["system"])
                if operation in {"energy_forces", "relax"}:
                    for particle, position in zip(output_data["particles"], payload["final_positions_m"]):
                        particle["position_m"] = copy.deepcopy(position)
                else:
                    output_data = payload
                output = _state(module, output_port, output_data, {"kind": "step", "run_id": run_id,
                    "branch_index": branch, "step_id": step_id, "output_port": output_port["port_id"]},
                    [state["state_id"]], digest, registry)
                publish_state(output, definition)
                payload_sha = capture(payload)
                payload_artifact = artifact(assets[payload_sha], schema_ref=module["payload_schema_ref"])
                sync_assets()
                step.update(payload=copy.deepcopy(payload), artifacts=[payload_artifact], state_ref=output["state_id"],
                            outcome="SUCCEEDED", partial=False, numerical_status=numerical, resolution_status=resolution,
                            diagnostics=copy.deepcopy(payload["diagnostics"]))
                deadline()
                budget()
                completed[(branch, step_id)] = (copy.deepcopy(definition), output)
            except Exception:
                rollback(saved)
                step.update(payload=None, artifacts=[], state_ref=None, outcome="FAILED", partial=True)
                raise
        except Exception as exc:
            step.update(outcome="FAILED", partial=True, state_ref=None)
            error = _issue(getattr(exc, "code", "ENGINE_FAILURE"), str(exc)[:300], path=getattr(exc, "path", None),
                step_id=step_id, branch_index=branch, details=getattr(exc, "details", {}))
            result["errors"].append(error)
            partial_payload = getattr(exc, "partial_payload", None) or candidate_payload
            numerical, resolution = (_axes(operation, partial_payload) if partial_payload is not None
                                     else _axes(operation, error=exc))
            if getattr(exc, "partial_payload", None) is not None:
                numerical, resolution = _axes(operation, error=exc)
            step.update(numerical_status=numerical, resolution_status=resolution,
                        diagnostics={"error": copy.deepcopy(error)})
            if partial_payload is not None and definition is not None and step["resolved_input_sha256"] is not None:
                saved = snapshot()
                try:
                    _validate_payload(partial_payload, definition, operation, module, registry)
                    payload_sha = capture(partial_payload)
                    row = artifact(assets[payload_sha], schema_ref=module["payload_schema_ref"])
                    sync_assets()
                    step.update(payload=copy.deepcopy(partial_payload), artifacts=[row])
                    budget()
                except Exception as partial_exc:
                    rollback(saved)
                    step.update(payload=None, artifacts=[])
                    if isinstance(partial_exc, _WorkflowLimit):
                        global_stop = "artifact_byte_limit"
                        result["errors"].append(_issue(partial_exc.code, str(partial_exc), step_id=step_id,
                            branch_index=branch, details=partial_exc.details))
            if ((isinstance(exc, _WorkflowLimit) and exc.global_limit) or
                    (getattr(exc, "code", None) == "RESOURCE_LIMIT" and getattr(exc, "details", {}).get("scope") == "run")):
                reason = exc.details.get("stop_reason")
                global_stop = (reason if isinstance(reason, str) and reason in {"run_wall_time_limit", "artifact_byte_limit"}
                               else "run_resource_limit")

    result["execution_status"] = "SUCCEEDED" if all(step["outcome"] == "SUCCEEDED" for step in result["steps"]) else "FAILED"
    result["partial"] = result["execution_status"] != "SUCCEEDED"
    result["numerical_status"] = _aggregate([step["numerical_status"] for step in result["steps"]])
    result["resolution_status"] = _aggregate([step["resolution_status"] for step in result["steps"]])
    result["provenance"]["finished_at"] = _now()
    try:
        run_deadline()
        registry.validator("result.schema.json").validate(result)
        budget(final=True)
    except Exception as exc:
        result.update(execution_status="FAILED", partial=True)
        result["errors"].append(_issue(getattr(exc, "code", "ENGINE_FAILURE"), str(exc)[:300],
            path=getattr(exc, "path", None), details=getattr(exc, "details", {})))
    from .run_store import validate_run_report
    verification = validate_run_report(report, registry=registry)
    if not verification["valid"]:
        result.update(execution_status="FAILED", partial=True)
        result["errors"].append(_issue("ENGINE_FAILURE", "The workflow evidence failed its final integrity checks",
                                     details={"validation_errors": verification["errors"][:3]}))
    try:
        run_deadline()
        budget(final=True)
    except CalculationError as exc:
        result.update(execution_status="FAILED", partial=True)
        if not any(error["code"] == exc.code and error["details"].get("stop_reason") == exc.details.get("stop_reason")
                   for error in result["errors"]):
            result["errors"].append(_issue(exc.code, str(exc), path=exc.path, details=exc.details))
    result["provenance"]["finished_at"] = _now()
    return report
