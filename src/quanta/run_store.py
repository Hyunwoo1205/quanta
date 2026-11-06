"""Content-addressed local execution bundles; saved text is never executed."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import tempfile

from .hashing import canonical_bytes
from .parsing import ensure_json_value, parse_json
from .registry import ContractRegistry

MAX_BUNDLE_BYTES = 33_554_432
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class BundleError(ValueError):
    """A bundle is incomplete, incompatible, or fails an integrity check."""

    def __init__(self, message: str, *, code: str = "BUNDLE_INTEGRITY", details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _metadata_bytes(value: dict) -> bytes:
    # JCS is required for scientific identities, but a record transport also
    # preserves the signed-zero carrier used by fixed-coordinate checks.
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _check_dynamics_solver_record(request: dict, solver_report: dict, raw_report: bytes,
                                  *, registry: ContractRegistry, engine: dict,
                                  implementation: dict, dependency_files: dict,
                                  lock: dict, observed: dict) -> None:
    """Verify retained solver evidence as bytes, never against current Python.

    A previous implementation's internally consistent bundle remains readable.
    Only replay compares its captured implementation to currently trusted code.
    """
    def require(condition, message):
        if not condition:
            raise BundleError(message)

    from .dynamics_results import build_phase_state, check_payload, transport_bytes, _same_tree
    registry.validator("dynamics_request.schema.json").validate(request)
    registry.validator("dynamics_report.schema.json").validate(solver_report)
    require(transport_bytes(solver_report) == raw_report,
            "Standalone dynamics report transport changed its exact carriers")
    payload = solver_report["payload"]
    success = solver_report["execution_status"] == "SUCCEEDED"
    validated = solver_report["input_validation_status"] == "pass"
    require(solver_report["input_sha256"] == (_digest(canonical_bytes(request)) if validated else None),
            "Standalone dynamics request hash differs from its mapped input")
    require(solver_report["partial"] == (payload is not None and not success),
            "Standalone dynamics partial flag differs from its payload")
    # This contract is immutable and independently frozen by the engine binding;
    # semantic checks do not evaluate forces or import captured source text.
    solver_registry = ContractRegistry(contract_version="0.3.1")
    require(not solver_registry.validate_integrity(), "The immutable solver contract is unavailable")
    expected_files = {name: _digest(raw) for name, raw in solver_registry.raw_bytes.items()}
    expected_manifest = _digest(solver_registry._manifest_path.read_bytes())
    binding = engine["solver_contract_binding"]
    require(binding == {"contract_version": "0.3.1", "registry_snapshot_sha256": expected_files["registry.json"],
                        "resource_policy_sha256": expected_files["resource_policy.json"],
                        "digest_manifest_sha256": expected_manifest,
                        "files_sha256": {**expected_files, "SHA256SUMS.json": expected_manifest}},
            "Standalone solver binding differs from its immutable contract")
    for name, raw in solver_registry.raw_bytes.items():
        if name.startswith("dynamics_") and name.endswith(".schema.json"):
            require(registry.raw_bytes[name] == raw,
                    "Generic dynamics science schema differs from its solver contract")
    if payload is not None:
        require(solver_report["initial_force_evaluation_performed"] is True,
                "Retained dynamics trajectory has no initial force evaluation")
        require(not any(leg["completed_steps"] > 0 for leg in payload["legs"])
                or solver_report["dynamics_simulation_executed"] is True,
                "Retained dynamics steps contradict the execution flag")
        check_payload(request, payload, registry=solver_registry,
                      execution_status=solver_report["execution_status"],
                      numerical_status=solver_report["numerical_status"],
                      resolution_status=solver_report["resolution_status"])
    else:
        require(solver_report["numerical_status"] == solver_report["resolution_status"] == "not_checked",
                "Absent dynamics trajectory has an invented assessment")
    if success:
        require(payload is not None and solver_report["numerical_status"] == "pass",
                "Successful dynamics report has no converged trajectory")
        require(_same_tree(solver_report["final_state"],
                           build_phase_state(request, payload, registry=solver_registry)),
                "Standalone final phase state differs from its primary trajectory")
    else:
        require(solver_report["final_state"] is None,
                "Failed dynamics execution publishes a successful final state")
    provenance = solver_report["provenance"]
    if provenance is None:
        require(not success and payload is None,
                "Retained successful or partial dynamics output has no provenance")
        return
    require(validated, "An unvalidated dynamics input has an execution provenance")
    contents = provenance["captured_utf8_contents"]
    require(all(isinstance(sha, str) and _SHA.fullmatch(sha) and isinstance(text, str)
                and _digest(text.encode("utf-8")) == sha for sha, text in contents.items()),
            "Captured standalone provenance bytes differ from their hashes")

    def captured(sha):
        require(sha in contents, "Standalone provenance references unavailable content")
        return contents[sha].encode("utf-8")

    from .dynamics_workflow import initial_phase_data
    initial = initial_phase_data({"scales": request["scales"],
                                  "system": request["system"], "numerics": request["numerics"]})
    require(provenance["provenance_version"] == "0.1.0" and provenance["contract_version"] == "0.3.1"
            and provenance["solver"] == {"id": "velocity_verlet_forward_ad", "version": "0.1.0"},
            "Standalone dynamics provenance identity differs")
    require(provenance["package_version"] == implementation["package_version"]
            and provenance["source_files_sha256"] == implementation["source_files_sha256"],
            "Standalone solver implementation differs from the workflow capture")
    require(provenance["implementation_manifest_sha256"] == _digest(canonical_bytes({
                "package_version": provenance["package_version"], "files": provenance["source_files_sha256"]})),
            "Standalone implementation manifest hash differs")
    require(provenance["dependency_lock_files_sha256"] == dependency_files
            and provenance["contract_files_sha256"] == expected_files
            and provenance["contract_digest_manifest_sha256"] == expected_manifest
            and provenance["registry_snapshot_sha256"] == expected_files["registry.json"],
            "Standalone contract or dependency snapshot differs from its workflow binding")
    expected_distributions = [{"name": item["name"], "expected_version": item["version"],
                              "observed_version": item["version"], "locked_filename": item["filename"],
                              "locked_wheel_sha256": item["sha256"]} for item in lock["packages"]]
    require(provenance["observed_locked_distributions"] == expected_distributions,
            "Standalone dependency observations differ from the captured lock")
    baseline_observation = {key: value for key, value in observed.items()
                            if key not in {"locked_distribution_versions", "package_distribution"}}
    require(canonical_bytes(provenance["environment"]) == canonical_bytes(baseline_observation)
            and provenance["environment_sha256"] == _digest(canonical_bytes(provenance["environment"])),
            "Standalone environment differs from the workflow observation")
    require(provenance["instrumentation_present"] is False
            and provenance["instrumentation_identity_captured"] is False
            and provenance["original_input_encoding"] == "detached_dictionary_json",
            "Standalone workflow execution has an unsupported instrumentation or source claim")
    require(captured(provenance["authored_request_canonical_sha256"]) == canonical_bytes(request)
            and captured(provenance["original_input_sha256"]) == transport_bytes(request)
            and captured(provenance["initial_state_canonical_sha256"]) == canonical_bytes(initial)
            and captured(provenance["initial_state_transport_sha256"]) == transport_bytes(initial),
            "Standalone authored input or initial phase bytes differ")
    for sha in (*provenance["source_files_sha256"].values(), *expected_files.values(),
                expected_manifest, *dependency_files.values()):
        captured(sha)
    publication = provenance["publication"]
    require(set(publication) == {"serialization", "artifact_byte_limit", "report_transport_bytes",
                                "report_projection_sha256", "payload_canonical_sha256",
                                "payload_transport_sha256", "payload_transport_bytes"}
            and all(type(publication[key]) is int for key in
                    ("artifact_byte_limit", "report_transport_bytes", "payload_transport_bytes")),
            "Standalone publication has malformed counts or unregistered fields")
    projection = copy.deepcopy(solver_report)
    del projection["provenance"]["publication"]
    require(publication["serialization"] == "compact_utf8_json_preserving_signed_zero"
            and publication["report_transport_bytes"] == len(raw_report)
            and len(raw_report) <= publication["artifact_byte_limit"] <= MAX_BUNDLE_BYTES
            and publication["report_projection_sha256"] == _digest(canonical_bytes(projection)),
            "Standalone publication bytes or projection differ")
    require(publication["payload_transport_bytes"] == (len(transport_bytes(payload)) if payload is not None else 0)
            and publication["payload_transport_sha256"] == (_digest(transport_bytes(payload)) if payload is not None else None)
            and publication["payload_canonical_sha256"] == (_digest(canonical_bytes(payload)) if payload is not None else None),
            "Standalone publication payload hashes differ")


def _bundle_parts(report: dict) -> tuple[dict, dict[str, bytes]]:
    metadata = copy.deepcopy(report)
    assets: dict[str, bytes] = {}

    def capture(store: dict) -> list[str]:
        keys = []
        for sha, text in store.items():
            if not isinstance(sha, str) or not _SHA.fullmatch(sha) or not isinstance(text, str):
                raise BundleError("Invalid captured artifact entry")
            raw = text.encode("utf-8", errors="strict")
            if _digest(raw) != sha:
                raise BundleError("Captured artifact bytes do not match their digest", details={"sha256": sha})
            assets[sha] = raw
            keys.append(sha)
        return sorted(keys)

    captured = capture(metadata.pop("captured_artifacts", {}))
    plan = metadata.get("plan")
    plan_captured = capture(plan.pop("captured_artifacts", {})) if isinstance(plan, dict) else []
    artifact_refs = {}
    for artifact_id, text in metadata.pop("artifact_contents", {}).items():
        if not isinstance(artifact_id, str) or not isinstance(text, str):
            raise BundleError("Invalid artifact byte entry")
        raw = text.encode("utf-8", errors="strict")
        sha = _digest(raw)
        assets[sha] = raw
        artifact_refs[artifact_id] = sha
    document = {"bundle_version": "0.1.0", "report": metadata,
                "captured_artifact_hashes": captured, "plan_captured_artifact_hashes": plan_captured,
                "artifact_content_hashes": artifact_refs}
    document["bundle_content_sha256"] = _digest(canonical_bytes(document))
    return document, assets


def report_storage_bytes(report: dict) -> int:
    """Exact bytes of bundle metadata plus deduplicated UTF-8 content assets."""
    document, assets = _bundle_parts(report)
    return len(_metadata_bytes(document)) + 65 + sum(len(data) for data in assets.values())


def write_bundle(report: dict, directory: str | Path, *, registry: ContractRegistry | None = None) -> Path:
    """Publish a new local bundle, refusing an existing destination."""
    checked = validate_run_report(report, registry=registry)
    if not checked["valid"]:
        raise BundleError("Execution report failed validation", details={"errors": checked["errors"]})
    document, assets = _bundle_parts(report)
    if report_storage_bytes(report) > MAX_BUNDLE_BYTES:
        raise BundleError("Bundle exceeds the byte ceiling", code="RESOURCE_LIMIT")
    target = Path(directory).absolute()
    if target.exists() or target.is_symlink():
        raise BundleError("Bundle destination already exists", code="BUNDLE_EXISTS")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Prepare all bytes before reserving the output name. Readers require the
    # manifest, published last, so an interrupted write is never a valid bundle.
    with tempfile.TemporaryDirectory(prefix=".quanta-bundle-", dir=target.parent) as temp:
        staged = Path(temp)
        staged_assets = staged / "assets"
        staged_assets.mkdir()
        for sha, data in assets.items():
            (staged_assets / sha).write_bytes(data)
        encoded = _metadata_bytes(document)
        (staged / "bundle.json").write_bytes(encoded)
        (staged / "bundle.sha256").write_text(_digest(encoded) + "\n", encoding="ascii")
        target.mkdir(exist_ok=False)
        os.rename(staged_assets, target / "assets")
        os.rename(staged / "bundle.sha256", target / "bundle.sha256")
        os.rename(staged / "bundle.json", target / "bundle.json")
    return target


def read_bundle(directory: str | Path, *, registry: ContractRegistry | None = None) -> dict:
    """Read bounded local assets, verify every byte, and validate the report."""
    root = Path(directory)
    manifest = root / "bundle.json"
    checksum = root / "bundle.sha256"
    assets_dir = root / "assets"
    if (not manifest.is_file() or manifest.is_symlink() or not checksum.is_file() or checksum.is_symlink()
            or checksum.stat().st_size != 65 or not assets_dir.is_dir()
            or assets_dir.is_symlink() or manifest.stat().st_size > MAX_BUNDLE_BYTES):
        raise BundleError("Incomplete or invalid bundle directory")
    try:
        raw_manifest = manifest.read_bytes()
        if checksum.read_text(encoding="ascii") != _digest(raw_manifest) + "\n":
            raise BundleError("Bundle metadata bytes differ from their checksum")
        document = parse_json(raw_manifest, max_bytes=MAX_BUNDLE_BYTES)
        expected_keys = {"bundle_version", "report", "captured_artifact_hashes", "plan_captured_artifact_hashes",
                         "artifact_content_hashes", "bundle_content_sha256"}
        if set(document) != expected_keys or document["bundle_version"] != "0.1.0":
            raise BundleError("Unsupported bundle format")
        projection = {key: value for key, value in document.items() if key != "bundle_content_sha256"}
        if _digest(canonical_bytes(projection)) != document["bundle_content_sha256"]:
            raise BundleError("Bundle metadata digest differs")
        hashes = set(document["captured_artifact_hashes"]) | set(document["plan_captured_artifact_hashes"]) | set(document["artifact_content_hashes"].values())
        if any(not isinstance(sha, str) or not _SHA.fullmatch(sha) for sha in hashes):
            raise BundleError("Invalid content-addressed asset name")
        if {p.name for p in assets_dir.iterdir()} != hashes:
            raise BundleError("Bundle asset set is incomplete or has unreferenced files")
        sizes = manifest.stat().st_size + 65
        texts = {}
        for sha in sorted(hashes):
            path = assets_dir / sha
            if path.is_symlink() or not path.is_file():
                raise BundleError("Bundle assets must be regular local files")
            sizes += path.stat().st_size
            if sizes > MAX_BUNDLE_BYTES:
                raise BundleError("Bundle exceeds the byte ceiling", code="RESOURCE_LIMIT")
            raw = path.read_bytes()
            if _digest(raw) != sha:
                raise BundleError("Stored asset digest differs", details={"sha256": sha})
            texts[sha] = raw.decode("utf-8", errors="strict")
        report = document["report"]
        report["captured_artifacts"] = {sha: texts[sha] for sha in document["captured_artifact_hashes"]}
        if isinstance(report.get("plan"), dict):
            report["plan"]["captured_artifacts"] = {sha: texts[sha] for sha in document["plan_captured_artifact_hashes"]}
        report["artifact_contents"] = {key: texts[sha] for key, sha in document["artifact_content_hashes"].items()}
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise BundleError("Bundle could not be decoded", details={"reason": str(exc)[:180]}) from exc
    checked = validate_run_report(report, registry=registry)
    if not checked["valid"]:
        raise BundleError("Stored execution report failed validation", details={"errors": checked["errors"]})
    return report


def validate_run_report(report: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Check schemas, exact stored bytes, scientific projections and state links.

    This verifies local record consistency, not a signature or a replacement for
    scientific validation. Captured Python text is inspected only as bytes.
    """
    def require(condition: bool, message: str, path: str = "/") -> None:
        if not condition:
            raise BundleError(message, details={"path": path})

    def equal(left, right) -> bool:
        return canonical_bytes(left) == canonical_bytes(right)

    def record_equal(left, right) -> bool:
        """Compare record carriers without changing JCS scientific identities."""
        if not equal(left, right):
            return False

        def same_zero_signs(a, b) -> bool:
            if isinstance(a, dict):
                return all(same_zero_signs(value, b[key]) for key, value in a.items())
            if isinstance(a, list):
                return all(same_zero_signs(value, other) for value, other in zip(a, b))
            if isinstance(a, (int, float)) and not isinstance(a, bool) and a == 0:
                return math.copysign(1, a) == math.copysign(1, b)
            return True

        return same_zero_signs(left, right)

    try:
        report = ensure_json_value(report)
        require(report.get("report_version") == "0.1.0" and report.get("scope") == "synchronous_workflow",
                "Unsupported execution report")
        plan = report["plan"]
        require(type(report["valid"]) is bool and report["valid"] == plan["valid"], "Plan validity differs")
        # Also verifies raw content digests before any content is interpreted.
        size = report_storage_bytes(report)
        require(size <= MAX_BUNDLE_BYTES, "Bundle exceeds the storage ceiling")
        store = report["captured_artifacts"]
        for sha, text in plan["captured_artifacts"].items():
            require(store.get(sha) == text, "Plan artifact differs from captured execution content")

        def asset(sha: str) -> bytes:
            require(sha in store, "Referenced immutable content is unavailable")
            return store[sha].encode("utf-8")

        def json_asset(sha: str):
            return parse_json(asset(sha), max_bytes=MAX_BUNDLE_BYTES)

        def projection(value: dict, sha: str) -> None:
            encoded = canonical_bytes(value)
            require(_digest(encoded) == sha and asset(sha) == encoded, "Projection bytes or digest differ")

        result = report["result"]
        if not plan["valid"]:
            require(result is None and report["resolved_record"] is None and bool(report["errors"]),
                    "An invalid plan has an execution record")
            require(not report["state_content_hashes"] and not report["artifact_contents"],
                    "An invalid plan contains published results")
            return {"valid": True, "errors": []}

        from .registry import experiment_registry
        registry = experiment_registry(plan["experiment"], registry)
        contract_version = registry.contract_version

        from .planning import _schema_bindings, _schema_refs
        from .validation import _assign, validate_definition, validate_experiment

        experiment = plan["experiment"]
        validation = validate_experiment(experiment, registry=registry)
        require(validation["valid"], "Saved authored input is invalid")
        authored = experiment["definition"]
        projection(authored, plan["input_sha256"])
        require(validation["input_sha256"] == plan["input_sha256"], "Authored input identity differs")
        frozen = plan["frozen_plan"]
        require(set(frozen) == {"contract_version", "input_sha256", "branch_bases", "expanded_steps", "frozen_bindings"},
                "Frozen plan contains a non-projected member")
        require(frozen["contract_version"] == contract_version and frozen["input_sha256"] == plan["input_sha256"],
                "Frozen plan input link differs")
        projection(frozen, plan["resolved_input_sha256"])
        bindings = frozen["frozen_bindings"]
        require(set(bindings) == {"registry_binding", "module_bindings", "observable_bindings", "schema_bindings", "engine_bindings"},
                "Frozen binding set differs from its whitelist")
        require(bindings["registry_binding"] == {"registry_version": registry.data["registry_version"],
                    "registry_snapshot_sha256": _digest(registry.raw_bytes["registry.json"])},
                "The captured registry is unavailable or differs")
        require(asset(bindings["registry_binding"]["registry_snapshot_sha256"]) == registry.raw_bytes["registry.json"],
                "Captured registry bytes differ")
        system = authored["system"]
        dynamics = system["module_id"] == "quanta.pair_dynamics"
        module = registry.get_module(system["module_id"], system["module_version"])
        require(module is not None, "Saved module registration is unavailable")
        module_sha = _digest(canonical_bytes(module))
        require(bindings["module_bindings"] == [{"module_id": system["module_id"], "module_version": system["module_version"],
                                                "manifest_sha256": module_sha}], "Module binding differs")
        projection(module, module_sha)
        descriptors = [registry.get_observable(system["module_id"], system["module_version"], name)
                       for name in authored["observables"]]
        observable_refs = []
        for descriptor in descriptors:
            require(descriptor is not None, "Saved observable registration is unavailable")
            sha = _digest(canonical_bytes(descriptor))
            projection(descriptor, sha)
            observable_refs.append({key: descriptor[key] for key in ("module_id", "module_version", "observable_id", "observable_version")} | {"manifest_sha256": sha})
        observable_refs.sort(key=lambda x: (x["module_id"], x["module_version"], x["observable_id"], x["observable_version"]))
        require(bindings["observable_bindings"] == observable_refs, "Observable bindings differ")
        require(bindings["schema_bindings"] == _schema_bindings(registry, _schema_refs(registry, module, descriptors)),
                "Schema bindings differ or are incomplete")
        for item in bindings["schema_bindings"]:
            filename = item["schema_ref"].split("#", 1)[0]
            require(asset(item["schema_sha256"]) == registry.raw_bytes[filename], "Captured schema bytes differ")
        manifests = plan["execution_manifests"]
        require(set(manifests) == {"implementation_manifest_sha256", "dependency_manifest_sha256", "constants_manifest_sha256",
                                   "resource_policy_sha256", "effective_resource_profile_sha256"}, "Execution manifest references differ")
        for sha in manifests.values():
            asset(sha)
        implementation = json_asset(manifests["implementation_manifest_sha256"])
        for path, sha in implementation["source_files_sha256"].items():
            require(path.startswith("src/quanta/") and path.endswith(".py"), "Unexpected captured code path")
            asset(sha)
        dependencies = json_asset(manifests["dependency_manifest_sha256"])
        dependency_files = dependencies["files_sha256"]
        require(set(dependency_files) == {"requirements.in", "requirements.lock.txt", "requirements.lock.json"},
                "Dependency capture is incomplete")
        lock = json_asset(dependency_files["requirements.lock.json"])
        require(_digest(asset(dependency_files["requirements.in"])) == lock["direct_requirements_sha256"]
                and _digest(asset(dependency_files["requirements.lock.txt"])) == lock["requirements_lock_sha256"]
                and equal(dependencies["locked_distributions"], lock["packages"]), "Dependency locks disagree")
        profile = json_asset(manifests["effective_resource_profile_sha256"])
        require(size <= int(profile["common_execution"]["max_artifact_bytes_per_run"]), "Captured resource byte limit exceeded")
        resource_policy = json_asset(manifests["resource_policy_sha256"])
        require(resource_policy == registry.resource_policy, "Captured resource policy is unavailable or differs")
        profile_ref = module["capabilities"]["resource_policy_ref"] + "#" + module["capabilities"]["resource_profile_pointer"]
        require(equal(profile, {"manifest_version": "1.0.0", "policy_version": resource_policy["version"],
            "module_id": module["module_id"], "module_version": module["module_version"], "profile_ref": profile_ref,
            "profile": registry.resolve_schema(profile_ref), "common_execution": resource_policy["common_execution"]}),
            "Effective resource profile differs from its captured policy")
        constants = []
        if module["module_id"] == "quanta.quantum_stationary":
            constants = [{"name": "h", "value": 6.62607015e-34, "unit": "J s", "definition": "SI defining value, binary64 carrier"},
                         {"name": "hbar", "value": 6.62607015e-34 / (2 * math.pi), "unit": "J s",
                          "definition": "h/(2*pi), binary64 math.pi"}]
        require(equal(json_asset(manifests["constants_manifest_sha256"]), {"manifest_version": "1.0.0",
            "module_id": module["module_id"], "module_version": module["module_version"], "constants": constants}),
            "Constants manifest differs from the selected module")
        operations = sorted({step["operation"] for step in authored["protocol"]["steps"]})
        engines = bindings["engine_bindings"]
        require([(e["module_id"], e["module_version"], e["operation"]) for e in engines]
                == [(system["module_id"], system["module_version"], op) for op in operations], "Engine binding set differs")
        for engine in engines:
            value = json_asset(engine["implementation_manifest_sha256"])
            require(all(value[key] == engine[key] for key in ("module_id", "module_version", "operation"))
                    and value["implementation_manifest_sha256"] == manifests["implementation_manifest_sha256"],
                    "Operation implementation manifest differs")
            if dynamics:
                from .planning import _dynamics_bindings
                adapter_binding, solver_binding = _dynamics_bindings(registry)
                require(value.get("adapter_binding") == adapter_binding
                        and value.get("solver_contract_binding") == solver_binding,
                        "Dynamics adapter or solver contract binding differs")
                require(asset(adapter_binding["manifest_sha256"]) == registry.raw_bytes["dynamics_adapter.json"],
                        "Captured dynamics adapter registration differs")
                for filename, sha in solver_binding["files_sha256"].items():
                    asset(sha)

        science = ("unit_system", "scales", "system", "numerics", "extensions")
        def scientific(value):
            return {key: copy.deepcopy(value[key]) for key in science if key in value}

        def port(operation, direction):
            candidates = [p for p in module["ports"] if p["direction"] == direction and operation in p["operations"]]
            require(len(candidates) == 1, "No unique compatible operation port")
            return candidates[0]

        expected_bases, branches, expanded = [], [], []
        axes = authored["protocol"]["sweep"]["axes"]
        previous_steps = {step["step_id"]: step for step in authored["protocol"]["steps"]}
        for branch_index, indices in enumerate(itertools.product(*(range(len(a["values"])) for a in axes))):
            base = copy.deepcopy(authored)
            assignments = []
            for axis_index, (axis, value_index) in enumerate(zip(axes, indices)):
                _assign(base, axis["path"], axis["values"][value_index])
                assignments.append({"axis_index": axis_index, "value_index": value_index, "path": axis["path"], "value": axis["values"][value_index]})
            branches.append(base)
            expected_bases.append({"branch_index": branch_index, "sweep_assignments": assignments, "definition": scientific(base)})
            for step_index, step in enumerate(authored["protocol"]["steps"]):
                eligible = {d["observable_id"] for d in descriptors if step["operation"] in d["eligible_operations"]}
                expanded.append({"branch_index": branch_index, "step_index": step_index, "step_id": step["step_id"],
                    "operation": step["operation"], "source_alias": step["source"],
                    "source_output_port": None if step["source"] == "initial" else port(previous_steps[step["source"]]["operation"], "output")["port_id"],
                    "target_input_port": port(step["operation"], "input")["port_id"], "overrides": step["overrides"],
                    "active_observable_refs": [ref for ref in observable_refs if ref["observable_id"] in eligible]})
        require(equal(expected_bases, frozen["branch_bases"]) and record_equal(branches, plan["branch_definitions"])
                and equal(expanded, frozen["expanded_steps"]), "Plan does not resolve the authored branches and steps")
        if result is None:
            require(bool(report["errors"]) and report["resolved_record"] is None and not report["state_content_hashes"],
                    "A pre-execution refusal has unexplained execution data")
            return {"valid": True, "errors": []}

        registry.validator("result.schema.json").validate(result)
        require(result["execution_status"] in {"SUCCEEDED", "FAILED", "CANCELLED"},
                "Saved execution evidence must have a terminal status")
        require(not any(step["outcome"] == "CANCELLED" for step in result["steps"])
                or result["execution_status"] == "CANCELLED", "Cancelled steps contradict the terminal status")
        if result["execution_status"] == "CANCELLED":
            require(any(error["code"] == "CANCELLED" for error in result["errors"]),
                    "Cancelled execution has no cancellation diagnostic")
        require(result["input_sha256"] == plan["input_sha256"] and result["resolved_input_sha256"] == plan["resolved_input_sha256"]
                and result["revision_id"] == experiment["revision_id"], "Result input links differ")
        require(result["physical_validation_status"] == "unvalidated" and result["physical_validation_evidence_refs"] == [],
                "Unsupported physical validation claim")
        provenance = result["provenance"]
        require(provenance["registry_snapshot_sha256"] == bindings["registry_binding"]["registry_snapshot_sha256"]
                and provenance["module_manifest_sha256"] == module_sha
                and provenance["implementation_manifest_sha256"] == manifests["implementation_manifest_sha256"]
                and provenance["constants_manifest_sha256"] == manifests["constants_manifest_sha256"]
                and provenance["resource_policy_version"] == resource_policy["version"], "Execution provenance differs")
        observed = json_asset(provenance["environment_manifest_sha256"])
        if result["execution_fingerprint"] is not None:
            from .profiles import target_matches_observation
            require(target_matches_observation(lock["target"], observed),
                    "Executed platform observation contradicts the captured lock target")
            require(observed["valid"] and observed["locked_distribution_versions"] == {
                package["name"]: package["version"] for package in lock["packages"]},
                "Executed dependency observation contradicts the captured lock")
            package_observation = observed["package_distribution"]
            require(package_observation["name"] == "quanta-research-contracts"
                    and package_observation["expected_version"] == package_observation["version"] == implementation["package_version"],
                    "Executed package observation differs from its implementation")
            fingerprint = {"contract_version": contract_version, "run_resolved_input_sha256": plan["resolved_input_sha256"],
                           **manifests, "environment_manifest_sha256": provenance["environment_manifest_sha256"]}
            projection(fingerprint, result["execution_fingerprint"])
        else:
            require(provenance["started_at"] is None and not observed["valid"], "Unexplained unavailable execution fingerprint")

        artifacts = {row["artifact_id"]: row for row in result["artifacts"]}
        require(len(artifacts) == len(result["artifacts"]) and set(artifacts) == set(report["artifact_contents"]),
                "Artifact identities or byte records differ")
        for ident, artifact in artifacts.items():
            raw = report["artifact_contents"][ident].encode("utf-8")
            require(_digest(raw) == artifact["sha256"] and len(raw) == artifact["size_bytes"], "Artifact byte identity differs")
            if artifact["kind"] == "config":
                registry.validator(artifact["schema_ref"]).validate(parse_json(raw, max_bytes=MAX_BUNDLE_BYTES))
        record = report["resolved_record"]
        for key in ("run_id", "revision_id", "input_sha256", "resolved_input_sha256"):
            require(record[key] == result[key], "Resolved record identity differs")
        require(record["contract_version"] == contract_version and equal(record["frozen_plan"], frozen)
                and record["registry_snapshot_sha256"] == provenance["registry_snapshot_sha256"]
                and record["engine_bindings"] == engines, "Resolved support record differs")
        runtime = record["runtime_evidence"]
        require(record_equal(runtime["typed_states"], result["states"])
                and runtime["state_content_hashes"] == report["state_content_hashes"], "Runtime state evidence differs")
        states = {state["state_id"]: state for state in result["states"]}
        require(len(states) == len(result["states"]) and set(states) == set(report["state_content_hashes"])
                == set(runtime["state_unit_contexts"]), "State identities and content mappings differ")
        state_members = ("module_id", "module_version", "representation", "representation_version", "time_kind", "physical_time",
                         "data_schema_ref", "data", "metadata_schema_ref", "metadata")
        for ident, state in states.items():
            registry.validator(state["data_schema_ref"]).validate(state["data"])
            registry.validator(state["metadata_schema_ref"]).validate(state["metadata"])
            require(state["module_id"] == system["module_id"] and state["module_version"] == system["module_version"],
                    "State module context differs")
            if dynamics:
                from .dynamics_workflow import phase_metadata
                require(state["time_kind"] == "evolving" and state["data"]["time_kind"] == "evolving"
                        and record_equal(state["physical_time"], {"value": state["data"]["time_s"], "unit": "s"})
                        and record_equal(state["metadata"], phase_metadata(state["data"])),
                        "Dynamics state time or phase metadata differs")
            else:
                require(state["time_kind"] == "static" and state["physical_time"] is None
                        and state["metadata"]["precision"] == module["precision_contract"], "State scientific context differs")
            require(all(parent in states for parent in state["parent_state_refs"]), "State parent is unavailable")
            producer = state["producer"]
            if producer["kind"] == "initial":
                state_port = port(authored["protocol"]["steps"][0]["operation"], "input")
            else:
                planned_state_step = next(p for p in expanded if (p["branch_index"], p["step_id"]) == (producer["branch_index"], producer["step_id"]))
                state_port = port(planned_state_step["operation"], "output" if producer["kind"] == "step" else "input")
            require(all(state[name] == state_port[name] for name in ("representation", "representation_version", "data_schema_ref", "metadata_schema_ref")),
                    "State representation differs from its registered producer port")
            if module["module_id"] == "quanta.pair_static":
                require(state["metadata"]["position_shape"] == [len(state["data"]["particles"]), 3], "Position metadata shape differs")
            elif not dynamics and producer["kind"] == "step":
                grid_size = len(state["data"]["x_m"])
                require(state["metadata"]["grid_shape"] == [grid_size]
                        and state["metadata"]["state_shape"] == [len(state["data"]["energies_j"]), grid_size], "Quantum metadata shape differs")
            content = {key: state[key] for key in state_members}
            content["unit_context"] = runtime["state_unit_contexts"][ident]
            projection(content, report["state_content_hashes"][ident])
        initial_refs = runtime["initial_state_refs"]
        initial_map = {row["branch_index"]: row["state_ref"] for row in initial_refs}
        require(len(initial_map) == len(initial_refs), "A branch has duplicate initial states")
        seen_states = set()
        for branch, ident in initial_map.items():
            state = states[ident]
            if dynamics:
                from .dynamics_workflow import initial_phase_data
                expected_initial = initial_phase_data(branches[branch])
            else:
                expected_initial = branches[branch]["system"]
            require(0 <= branch < len(branches) and state["producer"] == {"kind": "initial", "revision_id": result["revision_id"]}
                    and state["parent_state_refs"] == [] and state["resolved_input_sha256"] == plan["resolved_input_sha256"]
                    and record_equal(state["data"], expected_initial), "Initial state does not match its swept branch")
            require(runtime["state_unit_contexts"][ident] == {key: branches[branch][key] for key in ("unit_system", "scales")},
                    "Initial unit context differs")
            seen_states.add(ident)

        inputs = runtime["effective_step_inputs"]
        input_map = {(row["branch_index"], row["step_id"]): row for row in inputs}
        require(len(inputs) == len(input_map), "Duplicate effective step inputs")
        steps = result["steps"]
        solver_rows = runtime.get("dynamics_solver_reports", [])
        require(isinstance(solver_rows, list) and (dynamics or not solver_rows),
                "Unexpected standalone solver evidence in a static workflow")
        if dynamics:
            require("dynamics_solver_reports" in runtime, "Dynamics runtime evidence list is unavailable")
        solver_map = {}
        for row in solver_rows:
            require(set(row) == {"branch_index", "step_id", "request", "solver_report_sha256", "control_error"},
                    "Standalone dynamics evidence has an unregistered member")
            require(type(row["branch_index"]) is int and isinstance(row["step_id"], str),
                    "Standalone dynamics evidence has an invalid branch or step identity")
            key = (row["branch_index"], row["step_id"])
            require(key not in solver_map, "Duplicate standalone dynamics evidence")
            solver_map[key] = row
        if provenance["started_at"] is None:
            require(not steps and not states and result["execution_status"] == "FAILED" and bool(result["errors"]),
                    "An unstarted execution contains scientific work")
        else:
            require(len(steps) == len(expanded), "Expanded step results are incomplete")
        completed, consumed_inputs, observed_bindings, consumed_solver_rows = {}, set(), [], set()
        cancellation_seen = False
        for step, planned in zip(steps, expanded):
            branch, step_id = planned["branch_index"], planned["step_id"]
            key = (branch, step_id)
            require((step["branch_index"], step["step_id"]) == key and step["module_id"] == module["module_id"]
                    and step["module_version"] == module["module_version"]
                    and step["payload_schema_ref"] == module["payload_schema_ref"], "Step identity or schema differs")
            binding = step["source_binding"]
            if cancellation_seen:
                require(step["outcome"] in {"CANCELLED", "SKIPPED"} and binding is None,
                        "Execution continued after cancellation")
            cancellation_seen = cancellation_seen or step["outcome"] == "CANCELLED"
            if binding is None:
                require(step["outcome"] != "SUCCEEDED" and step["resolved_input_sha256"] is None and key not in input_map
                        and step["payload"] is None and step["diagnostics"], "Unprepared step has invented scientific evidence")
                require(key not in solver_map, "Unprepared step has standalone solver evidence")
                if dynamics:
                    require(step["numerical_status"] == step["resolution_status"] == "not_checked",
                            "Unprepared dynamics step has an invented numerical assessment")
                continue
            require(key in input_map and step["outcome"] != "SKIPPED", "Prepared step input is absent")
            row = input_map[key]
            consumed_inputs.add(key)
            observed_bindings.append(binding)
            source_id = initial_map[branch] if planned["source_alias"] == "initial" else completed[(branch, planned["source_alias"])]["state_ref"]
            source = states[source_id]
            input_port = port(planned["operation"], "input")
            require(binding == {"branch_index": branch, "step_id": step_id, "source_alias": planned["source_alias"],
                "source_state_ref": source_id, "source_output_port": planned["source_output_port"],
                "target_input_port": input_port["port_id"], "representation": input_port["representation"],
                "representation_version": input_port["representation_version"], "conversion_ref": None,
                "effective_input_state_ref": binding["effective_input_state_ref"]}, "Source port binding differs")
            effective = copy.deepcopy(branches[branch] if planned["source_alias"] == "initial" else input_map[(branch, planned["source_alias"])]["definition"])
            if planned["source_alias"] != "initial":
                effective["system"] = copy.deepcopy(source["data"])
            for patch in planned["overrides"]:
                _assign(effective, patch["path"], patch["value"])
            refs = planned["active_observable_refs"]
            effective["observables"] = [ref["observable_id"] for ref in refs] or (["trajectory"] if dynamics else
                (["energy"] if module["module_id"] == "quanta.pair_static" else ["energies"]))
            effective["protocol"] = {"steps": [{"step_id": step_id, "operation": planned["operation"], "source": "initial", "overrides": []}], "sweep": {"axes": []}}
            require(record_equal(effective, row["definition"]) and validate_definition(effective, registry=registry)["valid"],
                    "Effective input does not match source inheritance and overrides")
            relevant = [d for d in descriptors if d["observable_id"] in {ref["observable_id"] for ref in refs}]
            step_bindings = {"registry_binding": bindings["registry_binding"], "module_bindings": bindings["module_bindings"],
                "observable_bindings": refs, "schema_bindings": _schema_bindings(registry, _schema_refs(registry, module, relevant)),
                "engine_bindings": [engine for engine in engines if engine["operation"] == planned["operation"]]}
            expected_projection = {"contract_version": contract_version, "effective_definition": scientific(effective), "operation": planned["operation"],
                "active_observable_refs": refs, "frozen_bindings": step_bindings,
                "source_scientific_content_sha256": report["state_content_hashes"][source_id]}
            if dynamics:
                from .dynamics_workflow import solver_request
                dynamic_engine = json_asset(step_bindings["engine_bindings"][0]["implementation_manifest_sha256"])
                expected_projection.update(solver_request_sha256=_digest(canonical_bytes(solver_request(effective))),
                                           adapter_binding=dynamic_engine["adapter_binding"])
            require(equal(row["projection"], expected_projection) and row["resolved_input_sha256"] == step["resolved_input_sha256"],
                    "Effective step projection differs")
            projection(expected_projection, step["resolved_input_sha256"])
            prepared_id = binding["effective_input_state_ref"]
            prepared = states[prepared_id]
            context = {name: effective[name] for name in ("unit_system", "scales")}
            expected_prepared = initial_phase_data(effective) if dynamics else effective["system"]
            require(prepared_id != source_id and prepared["producer"] == {"kind": "prepared_input", "run_id": result["run_id"], "branch_index": branch, "step_id": step_id}
                    and prepared["parent_state_refs"] == [source_id] and prepared["resolved_input_sha256"] == step["resolved_input_sha256"]
                    and record_equal(prepared["data"], expected_prepared) and runtime["state_unit_contexts"][prepared_id] == context,
                    "Prepared state identity or content differs")
            for state in (source, prepared):
                require(all(state[name] == input_port[name] for name in ("representation", "representation_version", "data_schema_ref", "metadata_schema_ref")),
                        "Source representation is incompatible")
            seen_states.add(prepared_id)
            payload = step["payload"]
            inner_report = None
            if dynamics:
                if key in solver_map:
                    solver_row = solver_map[key]
                    consumed_solver_rows.add(key)
                    require(record_equal(solver_row["request"], solver_request(effective)),
                            "Retained standalone request differs from its effective generic input")
                    raw_solver_report = asset(solver_row["solver_report_sha256"])
                    inner_report = parse_json(raw_solver_report, max_bytes=MAX_BUNDLE_BYTES)
                    _check_dynamics_solver_record(solver_row["request"], inner_report, raw_solver_report,
                        registry=registry, engine=dynamic_engine, implementation=implementation,
                        dependency_files=dependency_files, lock=lock, observed=observed)
                    require(step["diagnostics"].get("solver_report_sha256") == solver_row["solver_report_sha256"],
                            "Step diagnostics do not reference its retained standalone report")
                    control_error = solver_row["control_error"]
                    if control_error is not None:
                        require(isinstance(control_error, dict) and inner_report["execution_status"] == "CANCELLED"
                                and step["outcome"] != "SUCCEEDED"
                                and all(control_error.get(name) == step["diagnostics"]["error"].get(name)
                                        for name in ("code", "message", "path", "details")),
                                "Host control reason contradicts the cancelled inner solver")
                        require(step["outcome"] == ("CANCELLED" if control_error["code"] == "CANCELLED" else "FAILED"),
                                "Host control category differs from the outer step outcome")
                    elif inner_report["execution_status"] == "CANCELLED":
                        require(step["outcome"] == "CANCELLED",
                                "Standalone cancellation was relabelled without a host control refusal")
                    require(record_equal(payload, inner_report["payload"]),
                            "Step trajectory differs from its retained standalone report")
                    require(step["numerical_status"] == inner_report["numerical_status"]
                            and step["resolution_status"] == inner_report["resolution_status"],
                            "Step numerical axes differ from the retained solver assessment")
                    require(step["outcome"] != "SUCCEEDED" or inner_report["execution_status"] == "SUCCEEDED",
                            "A failed standalone solver became a successful workflow step")
                    require(step["outcome"] != "CANCELLED" or inner_report["execution_status"] == "CANCELLED",
                            "Cancellation retained an unpublished successful solver trajectory")
                    require(len(step["artifacts"]) == (2 if payload is not None else 1),
                            "Dynamics step does not retain its exact payload/report artifacts")
                    report_artifact = step["artifacts"][-1]
                    require(artifacts[report_artifact["artifact_id"]] == report_artifact
                            and report_artifact.get("schema_ref") == "dynamics_report.schema.json"
                            and report_artifact["sha256"] == solver_row["solver_report_sha256"]
                            and report["artifact_contents"][report_artifact["artifact_id"]].encode("utf-8") == raw_solver_report,
                            "Standalone report artifact does not preserve its captured transport")
                else:
                    require(payload is None and step["state_ref"] is None and not step["artifacts"]
                            and step["outcome"] != "SUCCEEDED"
                            and step["numerical_status"] == step["resolution_status"] == "not_checked",
                            "Dynamics output has no retained standalone execution proof")
            if payload is not None:
                registry.validator(step["payload_schema_ref"]).validate(payload)
                if dynamics:
                    pass  # Request-relative semantics were checked with the inner assessment above.
                elif planned["operation"] in {"energy_forces", "relax"}:
                    from .pair import _check_payload
                    particles = effective["system"]["particles"]
                    _check_payload(payload, [p["position_m"] for p in particles], registry, module["payload_schema_ref"],
                                   "pair_energies" in effective["observables"], [p["fixed"] for p in particles])
                else:
                    from .quantum import _check_payload
                    _check_payload(payload, registry=registry, schema_ref=module["payload_schema_ref"], definition=effective,
                                   completed_grids=len(payload["grid_results"]), max_bytes=MAX_BUNDLE_BYTES)
                require(payload["operation"] == planned["operation"] and len(step["artifacts"]) == (2 if dynamics else 1), "Step payload identity differs")
                if planned["operation"] == "relax":
                    require(step["numerical_status"] == ("pass" if payload["free_gradient_inf"] <= effective["numerics"]["gradient_tolerance"] else "not_converged")
                            and step["resolution_status"] == "not_applicable", "Relaxation axes contradict the preserved criterion")
                elif planned["operation"] == "eigenstates":
                    checks = {check["id"]: check for check in payload["diagnostics"]["checks"]}
                    require(step["numerical_status"] == "pass" and step["resolution_status"] == checks["grid_energy_convergence"]["status"]
                            and 1 <= len(payload["grid_results"]) <= effective["numerics"]["refinement_levels"] + 1,
                            "Quantum axes contradict the preserved diagnostics")
                    for check_id, tolerance in (("weighted_normalization", 1e-10), ("weighted_orthogonality", 1e-10), ("eigen_residual", 1e-12)):
                        require(checks[check_id]["status"] == "pass" and checks[check_id]["tolerance"] == tolerance
                                and 0 <= checks[check_id]["value"] <= tolerance, "Preserved quantum state failed a numerical criterion")
                elif not dynamics:
                    require(step["numerical_status"] == step["resolution_status"] == "not_applicable", "Single evaluation has an iterative status")
                payload_artifact = step["artifacts"][0]
                require(artifacts[payload_artifact["artifact_id"]] == payload_artifact
                        and (record_equal if dynamics else equal)(parse_json(report["artifact_contents"][payload_artifact["artifact_id"]], max_bytes=MAX_BUNDLE_BYTES), payload),
                        "Step artifact does not preserve its payload")
            else:
                require((dynamics and inner_report is not None and len(step["artifacts"]) == 1)
                        or not step["artifacts"], "A step without payload has unexplained result artifacts")
            if step["outcome"] == "SUCCEEDED":
                output = states[step["state_ref"]]
                output_port = port(planned["operation"], "output")
                expected_data = copy.deepcopy(effective["system"])
                if dynamics:
                    require(inner_report is not None and inner_report["execution_status"] == "SUCCEEDED",
                            "Successful dynamics state has no successful solver proof")
                    expected_data = inner_report["final_state"]["data"]
                elif planned["operation"] in {"energy_forces", "relax"}:
                    for particle, position in zip(expected_data["particles"], payload["final_positions_m"]):
                        particle["position_m"] = copy.deepcopy(position)
                else:
                    expected_data = payload
                    require(len(payload["grid_results"]) == effective["numerics"]["refinement_levels"] + 1
                            and step["resolution_status"] == ("pass" if effective["numerics"]["refinement_levels"] else "not_checked"),
                            "Successful quantum step has incomplete refinement")
                require(step["numerical_status"] == ("not_applicable" if planned["operation"] == "energy_forces" else "pass"),
                        "Successful step numerical criterion is not met")
                if planned["operation"] == "relax":
                    require(payload["free_gradient_inf"] <= effective["numerics"]["gradient_tolerance"], "Successful relaxation did not converge")
                require(output["producer"] == {"kind": "step", "run_id": result["run_id"], "branch_index": branch, "step_id": step_id, "output_port": output_port["port_id"]}
                        and output["parent_state_refs"] == [prepared_id] and output["resolved_input_sha256"] == step["resolved_input_sha256"]
                        and record_equal(output["data"], expected_data) and runtime["state_unit_contexts"][output["state_id"]] == context
                        and all(output[name] == output_port[name] for name in ("representation", "representation_version", "data_schema_ref", "metadata_schema_ref")),
                        "Produced state does not match the successful step")
                seen_states.add(output["state_id"])
                completed[key] = step
            else:
                require(step["state_ref"] is None and step["diagnostics"], "Incomplete output was admitted as a state")
        require(consumed_inputs == set(input_map) and observed_bindings == runtime["port_bindings"] and seen_states == set(states)
                and consumed_solver_rows == set(solver_map),
                "Unreferenced or incomplete runtime evidence exists")
        if provenance["started_at"] is not None:
            for field in ("numerical_status", "resolution_status"):
                values = [s[field] for s in steps if s[field] != "not_applicable"]
                expected = next((status for status in ("not_converged", "not_checked", "pass") if status in values), "not_applicable")
                require(result[field] == expected, "Overall status does not aggregate the step evidence")
        if result["execution_status"] == "SUCCEEDED":
            require(len(initial_map) == len(branches) and all(step["outcome"] == "SUCCEEDED" for step in steps),
                    "An incomplete workflow was marked successful")
        else:
            require(result["errors"], "Failed execution has no diagnostic")
        return {"valid": True, "errors": []}
    except Exception as exc:
        return {"valid": False, "errors": [{"code": getattr(exc, "code", "BUNDLE_INTEGRITY"),
            "message": str(exc)[:300], "path": getattr(exc, "details", {}).get("path", "/")}]}


def replay_bundle(directory: str | Path, *, registry: ContractRegistry | None = None) -> dict:
    """Replay through current trusted code only when all frozen bindings match."""
    original = read_bundle(directory, registry=registry)
    if original["result"] is None:
        raise BundleError("A pre-execution refusal cannot be replayed")
    from .planning import plan_experiment
    from .workflow import run_experiment

    current = plan_experiment(original["plan"]["experiment"], registry=registry)
    if (not current["valid"] or current["resolved_input_sha256"] != original["plan"]["resolved_input_sha256"]
            or current["execution_manifests"] != original["plan"]["execution_manifests"]):
        raise BundleError("The frozen implementation, dependency or contract snapshot is unavailable",
                          code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    # The new actual environment is observed by the runner. Its fingerprint may
    # differ, while the original record remains unchanged and new IDs are real.
    return run_experiment(original["plan"]["experiment"], registry=registry,
                          replay_of=original["result"]["run_id"])
