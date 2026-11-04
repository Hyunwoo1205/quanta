"""Deterministic symbolic workflow plans and validated effective step inputs.

Every digest follows the frozen 0.2.0 projections. Generated states, storage
identifiers and calculation outputs are deliberately absent from a run plan.
Captured manifest strings are the exact UTF-8 contents addressed by their keys.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
import math
from pathlib import Path
import re
import sys
from urllib.parse import urldefrag

from . import __version__
from .autodiff import CalculationError
from .hashing import canonical_bytes
from .parsing import parse_json
from .registry import ContractRegistry
from .validation import _Validation, _assign, validate_definition, validate_experiment

_SCIENCE = ("unit_system", "scales", "system", "numerics", "extensions")
_COMMON_SCHEMAS = ("experiment.schema.json", "module_manifest.schema.json",
                   "observable_manifest.schema.json", "state.schema.json",
                   "result.schema.json", "artifact.schema.json")
_IMPLEMENTATIONS = {
    ("quanta.pair_static", "0.1.0", "energy_forces"): "quanta.pair.evaluate_pair",
    ("quanta.pair_static", "0.1.0", "relax"): "quanta.relaxation.relax_pair",
    ("quanta.quantum_stationary", "0.1.0", "eigenstates"): "quanta.quantum.eigenstates",
}


class PlanningError(CalculationError):
    """A plan or effective input cannot be prepared without changing its meaning."""


def _digest(value: dict) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def definition_projection(definition: dict) -> dict:
    """Take only the explicitly whitelisted scientific definition members."""
    return {name: copy.deepcopy(definition[name]) for name in _SCIENCE if name in definition}


def _capture(contents: dict[str, str], raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8", errors="strict")
    if digest in contents and contents[digest] != text:
        raise PlanningError("Captured content identity changed", code="ENGINE_FAILURE", path=None)
    contents[digest] = text
    return digest


def _capture_json(contents: dict[str, str], value: dict) -> str:
    return _capture(contents, canonical_bytes(value))


def _manifest_refs(value: object) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key.endswith("schema_ref") and isinstance(child, str):
                refs.add(child)
            refs.update(_manifest_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(_manifest_refs(child))
    return refs


def _schema_refs(registry: ContractRegistry, module: dict, observables: list[dict]) -> list[str]:
    pending = set(_COMMON_SCHEMAS) | _manifest_refs(module)
    for observable in observables:
        pending.update(_manifest_refs(observable))
    found: set[str] = set()
    while pending:
        ref = pending.pop()
        filename, fragment = urldefrag(ref)
        filename = registry.schema_ids.get(filename, filename)
        ref = filename + ("#" + fragment if fragment else "")
        if ref in found:
            continue
        resolved = registry.resolve_schema(ref)
        found.add(ref)

        def visit(node):
            if isinstance(node, dict):
                target = node.get("$ref")
                if isinstance(target, str):
                    pending.add(filename + target if target.startswith("#") else target)
                for child in node.values():
                    visit(child)
            elif isinstance(node, list):
                for child in node:
                    visit(child)

        visit(resolved)
    return sorted(found)


def _schema_bindings(registry: ContractRegistry, refs: list[str]) -> list[dict]:
    return [{"schema_ref": ref, "schema_sha256": hashlib.sha256(
        registry.raw_bytes[urldefrag(ref)[0]]).hexdigest()} for ref in refs]


def _lock_files() -> dict[str, bytes]:
    names = ("requirements.in", "requirements.lock.txt", "requirements.lock.json")
    candidates = (Path(__file__).resolve().parents[2], Path(sys.prefix) / "share" / "quanta")
    root = next((path for path in candidates if all((path / name).is_file() for name in names)), None)
    if root is None:
        raise PlanningError("The exact dependency lock artifacts are unavailable", code="REGISTRY_SNAPSHOT_UNAVAILABLE",
                            path=None)
    try:
        result = {name: (root / name).read_bytes() for name in names}
        lock = parse_json(result["requirements.lock.json"])
        if (hashlib.sha256(result["requirements.in"]).hexdigest() != lock["direct_requirements_sha256"]
                or hashlib.sha256(result["requirements.lock.txt"]).hexdigest() != lock["requirements_lock_sha256"]):
            raise ValueError("Dependency lock content differs from its provenance")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise PlanningError("The dependency lock artifacts are invalid", code="REGISTRY_SNAPSHOT_UNAVAILABLE",
                            path=None, details={"reason": str(exc)[:160]}) from exc
    return result


def _implementation_capture(contents: dict[str, str]) -> str:
    sources = {}
    for path in sorted(Path(__file__).resolve().parent.glob("*.py")):
        sources["src/quanta/" + path.name] = _capture(contents, path.read_bytes())
    return _capture_json(contents, {"manifest_version": "1.0.0", "package_version": __version__,
                                     "source_files_sha256": sources})


def _engine_manifest(module_id: str, module_version: str, operation: str, implementation_sha: str) -> dict:
    return {"manifest_version": "1.0.0", "module_id": module_id,
            "module_version": module_version, "operation": operation,
            "entry_point": _IMPLEMENTATIONS[(module_id, module_version, operation)],
            "implementation_manifest_sha256": implementation_sha}


def _port(module: dict, direction: str, operation: str) -> dict:
    ports = [port for port in module["ports"] if port["direction"] == direction and operation in port["operations"]]
    if len(ports) != 1:
        raise PlanningError("An operation has no unique registered port", code="PORT_INCOMPATIBLE",
                            path="/definition/protocol")
    return ports[0]


def _observable_ref(descriptor: dict, contents: dict[str, str]) -> dict:
    return {"module_id": descriptor["module_id"], "module_version": descriptor["module_version"],
            "observable_id": descriptor["observable_id"], "observable_version": descriptor["observable_version"],
            "manifest_sha256": _capture_json(contents, descriptor)}


def _sort_observables(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda x: (x["module_id"], x["module_version"], x["observable_id"], x["observable_version"]))


def _build_plan(experiment: dict, registry: ContractRegistry, contents: dict[str, str]) -> dict:
    definition = experiment["definition"]
    system, protocol = definition["system"], definition["protocol"]
    module_id, module_version = system["module_id"], system["module_version"]
    module = registry.get_module(module_id, module_version)
    if module is None:
        raise PlanningError("The exact module registration is unavailable", code="MODEL_UNSUPPORTED", path="/definition/system")
    operations = sorted({step["operation"] for step in protocol["steps"]})
    if any((module_id, module_version, op) not in _IMPLEMENTATIONS for op in operations):
        raise PlanningError("A requested operation has no enabled implementation", code="MODEL_UNSUPPORTED",
                            path="/definition/protocol")
    # Preserve the original raw allowlist, including its normative hashing rules.
    for raw in registry.raw_bytes.values():
        _capture(contents, raw)
    implementation_sha = _implementation_capture(contents)
    locks = _lock_files()
    lock_refs = {name: _capture(contents, raw) for name, raw in locks.items()}
    dependency_sha = _capture_json(contents, {"manifest_version": "1.0.0", "files_sha256": lock_refs,
        "locked_distributions": parse_json(locks["requirements.lock.json"])["packages"]})
    constants = []
    if module_id == "quanta.quantum_stationary":
        constants = [{"name": "h", "value": 6.62607015e-34, "unit": "J s", "definition": "SI defining value, binary64 carrier"},
                     {"name": "hbar", "value": 6.62607015e-34 / (2 * math.pi), "unit": "J s",
                      "definition": "h/(2*pi), binary64 math.pi"}]
    constants_sha = _capture_json(contents, {"manifest_version": "1.0.0", "module_id": module_id,
        "module_version": module_version, "constants": constants})
    profile_ref = module["capabilities"]["resource_policy_ref"] + "#" + module["capabilities"]["resource_profile_pointer"]
    effective_sha = _capture_json(contents, {"manifest_version": "1.0.0", "policy_version": registry.resource_policy["version"],
        "module_id": module_id, "module_version": module_version, "profile_ref": profile_ref,
        "profile": registry.resolve_schema(profile_ref), "common_execution": copy.deepcopy(registry.resource_policy["common_execution"])})
    descriptors = [registry.get_observable(module_id, module_version, name) for name in definition["observables"]]
    if any(item is None for item in descriptors):
        raise PlanningError("An observable registration is unavailable", code="MODEL_UNSUPPORTED", path="/definition/observables")
    observable_refs = _sort_observables([_observable_ref(item, contents) for item in descriptors])
    engine_bindings = []
    for operation in operations:
        sha = _capture_json(contents, _engine_manifest(module_id, module_version, operation, implementation_sha))
        engine_bindings.append({"module_id": module_id, "module_version": module_version,
                                "operation": operation, "implementation_manifest_sha256": sha})
    frozen_bindings = {
        "registry_binding": {"registry_version": registry.data["registry_version"],
                             "registry_snapshot_sha256": hashlib.sha256(registry.raw_bytes["registry.json"]).hexdigest()},
        "module_bindings": [{"module_id": module_id, "module_version": module_version,
                             "manifest_sha256": _capture_json(contents, module)}],
        "observable_bindings": observable_refs,
        "schema_bindings": _schema_bindings(registry, _schema_refs(registry, module, descriptors)),
        "engine_bindings": engine_bindings,
    }
    branches, branch_definitions, expanded = [], [], []
    axes = protocol["sweep"]["axes"]
    for branch_index, indices in enumerate(itertools.product(*(range(len(axis["values"])) for axis in axes))):
        branch = copy.deepcopy(definition)
        assignments = []
        for axis_index, (axis, value_index) in enumerate(zip(axes, indices)):
            _assign(branch, axis["path"], axis["values"][value_index])
            assignments.append({"axis_index": axis_index, "value_index": value_index,
                                "path": axis["path"], "value": copy.deepcopy(axis["values"][value_index])})
        branch_definitions.append(branch)
        branches.append({"branch_index": branch_index, "sweep_assignments": assignments,
                         "definition": definition_projection(branch)})
        previous = {}
        for step_index, step in enumerate(protocol["steps"]):
            input_port = _port(module, "input", step["operation"])
            source_port = None
            if step["source"] != "initial":
                source_port = _port(module, "output", previous[step["source"]]["operation"])
                if ("previous_success_same_branch" not in input_port["allowed_sources"] or
                        any(source_port[key] != input_port[key] for key in
                            ("representation", "representation_version", "data_schema_ref", "metadata_schema_ref", "time_kind"))):
                    raise PlanningError("Selected source and receiving port are incompatible", code="PORT_INCOMPATIBLE",
                                        path="/definition/protocol")
            elif "initial" not in input_port["allowed_sources"]:
                raise PlanningError("This port does not admit an initial source", code="PORT_INCOMPATIBLE",
                                    path="/definition/protocol")
            eligible = {item["observable_id"] for item in descriptors if step["operation"] in item["eligible_operations"]}
            expanded.append({"branch_index": branch_index, "step_index": step_index, "step_id": step["step_id"],
                "operation": step["operation"], "source_alias": step["source"],
                "source_output_port": source_port["port_id"] if source_port else None,
                "target_input_port": input_port["port_id"], "overrides": copy.deepcopy(step["overrides"]),
                "active_observable_refs": [copy.deepcopy(ref) for ref in observable_refs if ref["observable_id"] in eligible]})
            previous[step["step_id"]] = step
    input_sha = hashlib.sha256(canonical_bytes(definition)).hexdigest()
    projection = {"contract_version": "0.2.0", "input_sha256": input_sha, "branch_bases": branches,
                  "expanded_steps": expanded, "frozen_bindings": frozen_bindings}
    _capture_json(contents, definition)
    resolved_sha = _capture_json(contents, projection)
    return {"input_sha256": input_sha, "resolved_input_sha256": resolved_sha,
            "frozen_plan": projection, "branch_definitions": branch_definitions,
            "execution_manifests": {"implementation_manifest_sha256": implementation_sha,
                "dependency_manifest_sha256": dependency_sha, "constants_manifest_sha256": constants_sha,
                "resource_policy_sha256": hashlib.sha256(registry.raw_bytes["resource_policy.json"]).hexdigest(),
                "effective_resource_profile_sha256": effective_sha}}


def plan_experiment(data: bytes | str | dict, *, registry: ContractRegistry | None = None) -> dict:
    """Validate authored input and freeze only its deterministic symbolic plan."""
    result = {"valid": False, "errors": [], "warnings": [], "input_sha256": None,
              "resolved_input_sha256": None, "frozen_plan": None, "branch_definitions": [],
              "experiment": None, "captured_artifacts": {}, "execution_manifests": {}}
    try:
        registry = registry or ContractRegistry()
        validation = validate_experiment(data, registry=registry)
        result.update(errors=validation["errors"], warnings=[w for w in validation["warnings"]
                                                           if w["code"] != "CONTRACT_VALIDATION_ONLY"],
                      input_sha256=validation["input_sha256"])
        if not validation["valid"]:
            return result
        experiment = parse_json(data)
        captured = {}
        result.update(_build_plan(experiment, registry, captured))
        result.update(valid=True, experiment=experiment, captured_artifacts=captured)
    except (CalculationError, OSError, ValueError, TypeError, KeyError) as exc:
        code = getattr(exc, "code", "REGISTRY_SNAPSHOT_UNAVAILABLE")
        category = ("support" if code in {"MODEL_UNSUPPORTED", "REGISTRY_SNAPSHOT_UNAVAILABLE", "PORT_INCOMPATIBLE"}
                    else "resource" if code == "RESOURCE_LIMIT" else "runtime" if code == "ENGINE_FAILURE"
                    else "numerical" if code in {"EXPRESSION_DOMAIN", "NUM_NOT_CONVERGED", "NUM_GRID_NOT_CONVERGED"} else "input")
        result["errors"].append({"code": code, "category": category,
            "message": str(exc)[:240], "path": getattr(exc, "path", None), "step_id": None,
            "branch_index": None, "retryable": False, "details": getattr(exc, "details", {})})
    return result


def step_bindings(frozen_bindings: dict, expanded_step: dict, *, registry: ContractRegistry | None = None) -> dict:
    """Restrict captured bindings to the exact one-module operation and observables."""
    registry = registry or ContractRegistry()
    modules = frozen_bindings["module_bindings"]
    if len(modules) != 1:
        raise PlanningError("This runner requires one registered module per definition", code="MODEL_UNSUPPORTED")
    binding = modules[0]
    module = registry.get_module(binding["module_id"], binding["module_version"])
    if module is None:
        raise PlanningError("Captured module registration is unavailable", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    expected_registry = {"registry_version": registry.data["registry_version"],
        "registry_snapshot_sha256": hashlib.sha256(registry.raw_bytes["registry.json"]).hexdigest()}
    expected_module = {"module_id": module["module_id"], "module_version": module["module_version"],
                       "manifest_sha256": _digest(module)}
    if frozen_bindings["registry_binding"] != expected_registry or binding != expected_module:
        raise PlanningError("A registry or module manifest differs from its frozen binding", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    descriptors = [registry.get_observable(binding["module_id"], binding["module_version"], ref["observable_id"])
                   for ref in expanded_step["active_observable_refs"]]
    if any(item is None for item in descriptors):
        raise PlanningError("A captured observable registration is unavailable", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    expected_refs = _sort_observables([_observable_ref(item, {}) for item in descriptors])
    if (expected_refs != expanded_step["active_observable_refs"] or
            len({(item["module_id"], item["module_version"], item["observable_id"], item["observable_version"])
                 for item in expected_refs}) != len(expected_refs) or
            any(expanded_step["operation"] not in item["eligible_operations"] for item in descriptors)):
        raise PlanningError("An observable differs from its captured identity or operation", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    expected_schemas = _schema_bindings(registry, _schema_refs(registry, module, descriptors))
    if any(item not in frozen_bindings["schema_bindings"] for item in expected_schemas):
        raise PlanningError("A required schema differs from its frozen binding", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    engines = [copy.deepcopy(item) for item in frozen_bindings["engine_bindings"]
               if item["module_id"] == binding["module_id"] and item["module_version"] == binding["module_version"]
               and item["operation"] == expanded_step["operation"]]
    if len(engines) != 1 or any(ref not in frozen_bindings["observable_bindings"] for ref in expanded_step["active_observable_refs"]):
        raise PlanningError("An operation or observable binding is unavailable", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    ident = (binding["module_id"], binding["module_version"], expanded_step["operation"])
    expected_engine = {"module_id": ident[0], "module_version": ident[1], "operation": ident[2],
                       "implementation_manifest_sha256": _digest(_engine_manifest(*ident, _implementation_capture({})))} if ident in _IMPLEMENTATIONS else None
    if engines[0] != expected_engine:
        raise PlanningError("The selected implementation differs from its frozen binding", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    return {"registry_binding": copy.deepcopy(frozen_bindings["registry_binding"]),
            "module_bindings": copy.deepcopy(modules), "observable_bindings": copy.deepcopy(expanded_step["active_observable_refs"]),
            "schema_bindings": expected_schemas, "engine_bindings": engines}


def prepare_step(branch_base: dict, expanded_step: dict, *, source_definition: dict | None = None,
                 source_state: dict | None = None, source_content_sha256: str,
                 frozen_bindings: dict, registry: ContractRegistry | None = None) -> dict:
    """Resolve a real source plus overrides, then hash and validate this actual input.

    A pair step with no eligible optional requests uses its mandatory energy
    carrier solely to satisfy the module's pre-existing definition schema.
    The active observable binding list remains empty in its scientific identity.
    """
    registry = registry or ContractRegistry()
    if not isinstance(source_content_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", source_content_sha256):
        raise PlanningError("The original source content digest is unavailable", code="INPUT_SEMANTIC")
    if expanded_step["source_alias"] == "initial":
        effective = copy.deepcopy(branch_base)
    else:
        if source_definition is None or source_state is None:
            raise PlanningError("The earlier successful source is unavailable", code="PORT_INCOMPATIBLE")
        effective = copy.deepcopy(source_definition)
        if (source_state["module_id"], source_state["module_version"]) != (
                effective["system"]["module_id"], effective["system"]["module_version"]):
            raise PlanningError("The source state belongs to another module", code="PORT_INCOMPATIBLE")
        if source_state["representation"] != effective["system"]["representation"]:
            raise PlanningError("The source state is not a compatible configuration", code="PORT_INCOMPATIBLE")
        effective["system"] = copy.deepcopy(source_state["data"])
    module_id, module_version = effective["system"]["module_id"], effective["system"]["module_version"]
    if (effective["unit_system"] != branch_base["unit_system"] or effective["scales"] != branch_base["scales"]
            or module_id != branch_base["system"]["module_id"] or module_version != branch_base["system"]["module_version"]):
        raise PlanningError("The inherited source changes the branch's scientific context", code="PORT_INCOMPATIBLE")
    patch_validation = _Validation(registry)
    patch_validation.patches(effective, expanded_step["overrides"], module_id, "/definition/protocol/steps/overrides", sweep=False)
    if patch_validation.errors:
        error = patch_validation.errors[0]
        raise PlanningError(error["message"], code=error["code"], path=error["path"], details=error["details"])
    for patch in expanded_step["overrides"]:
        _assign(effective, patch["path"], patch["value"])
    names = [ref["observable_id"] for ref in expanded_step["active_observable_refs"]]
    effective["observables"] = names or (["energy"] if effective["system"]["module_id"] == "quanta.pair_static" else ["energies"])
    effective["protocol"] = {"steps": [{"step_id": expanded_step["step_id"], "operation": expanded_step["operation"],
        "source": "initial", "overrides": []}], "sweep": {"axes": []}}
    validation = validate_definition(effective, registry=registry)
    if not validation["valid"]:
        error = validation["errors"][0]
        raise PlanningError(error["message"], code=error["code"], path=error["path"], details=error["details"])
    bindings = step_bindings(frozen_bindings, expanded_step, registry=registry)
    projection = {"contract_version": "0.2.0", "effective_definition": definition_projection(effective),
        "operation": expanded_step["operation"], "active_observable_refs": copy.deepcopy(expanded_step["active_observable_refs"]),
        "frozen_bindings": bindings, "source_scientific_content_sha256": source_content_sha256}
    return {"definition": effective, "step_projection": projection, "resolved_input_sha256": _digest(projection),
            "frozen_bindings": bindings}
