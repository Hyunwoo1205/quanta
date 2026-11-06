"""Hash-checked contract loading and exclusively offline schema resolution."""
from __future__ import annotations

import copy
import hashlib
import importlib.resources
import itertools
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import urldefrag

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from .parsing import parse_json, pointer


_DYNAMICS_ADAPTER_MAPPING = {
    "adapter_id": "quanta.pair_dynamics.generic_adapter", "adapter_version": "0.1.0",
    "generic_contract_version": "0.4.0", "solver_contract_version": "0.3.1",
    "module_id": "quanta.pair_dynamics", "module_version": "0.1.0", "operation": "integrate",
    "solver_entry_point": "quanta.dynamics.integrate_dynamics_request",
    "fixed_request_members": {"contract_version": "0.3.1", "operation": "integrate", "initial_time_s": 0},
    "definition_members_to_request": ["scales", "system", "numerics"], "required_unit_system": "SI",
    "allowed_protocol": {"steps": 1, "source": "initial", "overrides": False, "sweep_axes": 0},
}
_DYNAMICS_PHASE_PORTS = [
    {"port_id": name, "direction": direction, "representation": "particles_phase_space_3d",
     "representation_version": "0.1.0", "data_schema_ref": "dynamics_state.schema.json",
     "metadata_schema_ref": "dynamics_metadata.schema.json", "time_kind": "evolving", "required": True,
     "operations": ["integrate"], "allowed_sources": sources}
    for name, direction, sources in (("phase_in", "input", ["initial"]),
                                      ("phase_out", "output", ["not_applicable"]))
]
_DYNAMICS_EXPRESSION_CAPABILITIES = {
    "variables": ["rho"],
    "allowed_ops": ["const", "var", "param", "add", "sub", "mul", "div", "neg", "pow", "exp", "log", "sqrt", "sin", "cos"],
    "dimensionless": True, "max_depth": 16, "max_nodes": 128, "max_parameters": 32,
    "integer_power_min": -12, "integer_power_max": 12,
}
_DYNAMICS_PROTOCOL_CAPABILITIES = {
    "max_steps": 1, "max_sweep_axes": 0, "max_expanded_steps": 1,
    "source_policy": "initial_only", "physical_coupling": False,
}
_DYNAMICS_IMPLEMENTED_LIMITS = {
    "min_particles": 2, "max_particles": 128, "max_base_steps": 10000,
    "max_total_force_evaluations": 10000, "max_pair_evaluations": 1000000,
    "max_total_output_frames": 512, "max_ast_depth": 16, "max_ast_nodes": 128,
    "max_parameters": 32, "max_protocol_steps": 1, "max_expanded_steps": 1, "max_sweep_axes": 0,
}


def _error(message: str, path: str | None = None, **details) -> dict:
    return {"code": "REGISTRY_SNAPSHOT_UNAVAILABLE", "category": "support", "message": message,
            "path": path, "step_id": None, "branch_index": None, "retryable": False, "details": details}


def experiment_registry(value, registry: ContractRegistry | None = None) -> ContractRegistry:
    """Select a generic bundle from an already parsed experiment envelope.

    The default remains 0.2.0.  Unknown or malformed version markers are left
    for the selected envelope schema to reject; they never opt into 0.4.0.
    Standalone solver bundles cannot be supplied as generic registries.
    """
    marker = value.get("schema_version") if isinstance(value, dict) else None
    known = isinstance(marker, str) and marker in {"0.2.0", "0.4.0"}
    if registry is not None:
        if not isinstance(registry, ContractRegistry) or registry.contract_version not in {"0.2.0", "0.4.0"}:
            raise ValueError("A generic experiment requires its exact supported generic registry")
        if known and marker != registry.contract_version:
            raise ValueError("Experiment schema version differs from the supplied generic registry")
        return registry
    return ContractRegistry(contract_version="0.4.0" if marker == "0.4.0" else "0.2.0")


def _same_snapshot(left, right) -> bool:
    """Compare captured rules without Python's boolean/number equality alias."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_snapshot(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_snapshot(a, b) for a, b in zip(left, right))
    return left == right


class ContractRegistry:
    """Load only files listed in the frozen bundle's digest manifest.

    ``validate_integrity`` returns error dictionaries and never claims physical
    validation. Resolution errors raise ``ValueError``; network retrieval is
    disabled even if a malicious schema attempts to request a remote URI.
    """

    def __init__(self, contract_dir: Path | str | None = None, *,
                 contract_version: str | None = None):
        # Version selection is explicit: merely installing a new bundle never
        # changes validation or replay of existing 0.2 inputs.
        if contract_version is not None and (not isinstance(contract_version, str)
                                             or contract_version not in {"0.2.0", "0.3.0", "0.3.1", "0.4.0"}):
            raise ValueError("Unsupported bundled contract version")
        selected_version = contract_version or "0.2.0"
        enforce_selected_version = contract_dir is None or contract_version is not None
        if contract_dir is None:
            bundle_name = "v" + selected_version
            candidates = [Path(__file__).resolve().parents[2] / "contracts" / bundle_name,
                          Path(sys.prefix) / "share" / "quanta" / "contracts" / bundle_name]
            try:
                candidates.append(Path(str(importlib.resources.files("quanta").joinpath("contracts", bundle_name))))
            except (ModuleNotFoundError, TypeError):
                pass
            contract_dir = next((p for p in candidates if p.is_dir()), candidates[0])
        self.contract_dir = Path(contract_dir).resolve()
        self._manifest_path = self.contract_dir / "SHA256SUMS.json"
        self.manifest = parse_json(self._manifest_path.read_bytes())
        if not isinstance(self.manifest, dict):
            raise ValueError("Contract digest manifest must be an object")
        self.documents: dict[str, dict] = {}
        self.raw_bytes: dict[str, bytes] = {}
        self._load_errors: list[dict] = []
        for name, digest in self.manifest.items():
            try:
                path = self._allowed_path(name)
                raw = path.read_bytes()
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError("Invalid digest value")
                if hashlib.sha256(raw).hexdigest() != digest:
                    self._load_errors.append(_error("Contract file digest mismatch", name))
                self.raw_bytes[name] = raw
                if name.endswith(".json"):
                    value = parse_json(raw)
                    if not isinstance(value, dict):
                        raise ValueError("Contract document must be an object")
                    self.documents[name] = value
            except (OSError, ValueError) as exc:
                self._load_errors.append(_error(str(exc), str(name)))
        self.data = self.documents.get("registry.json", {})
        self.contract_version = self.data.get("contract_version")
        if enforce_selected_version and self.contract_version != selected_version:
            raise ValueError("Selected contract version differs from the loaded registry")
        if self.contract_version not in {"0.2.0", "0.3.0", "0.3.1", "0.4.0"}:
            self._load_errors.append(_error("Unsupported registry contract version", "registry.json"))
        self.resource_policy = self.documents.get("resource_policy.json", {})
        self.schema_ids: dict[str, str] = {}
        for name, doc in self.documents.items():
            if "$schema" not in doc or "$id" not in doc:
                continue
            schema_id = doc["$id"]
            if not isinstance(schema_id, str):
                self._load_errors.append(_error("Schema identifiers must be strings", name))
            elif schema_id in self.schema_ids:
                self._load_errors.append(_error("Duplicate bundled schema identifier", name))
            else:
                self.schema_ids[schema_id] = name

        def deny_remote(uri: str):
            raise NoSuchResource(ref=uri)

        offline = Registry(retrieve=deny_remote)
        for name, doc in self.documents.items():
            if "$schema" not in doc:
                continue
            try:
                resource = Resource.from_contents(doc)
            except Exception as exc:
                self._load_errors.append(_error("Invalid bundled schema resource: " + str(exc)[:160], name))
                continue
            for alias in (name, "https://quanta.invalid/contracts/v" + str(self.contract_version) + "/" + name, doc.get("$id")):
                if isinstance(alias, str) and alias:
                    offline = offline.with_resource(alias, resource)
        self.offline_registry = offline

    def _allowed_path(self, name: str) -> Path:
        if not isinstance(name, str) or not name or "\\" in name or "%" in name:
            raise ValueError("Invalid local contract path")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != name or ":" in name:
            raise ValueError("Only exact local allowlisted contract paths are permitted")
        path = (self.contract_dir / name).resolve()
        if not path.is_relative_to(self.contract_dir):
            raise ValueError("Contract path escapes the bundle")
        return path

    def resolve_schema(self, ref: str) -> dict:
        """Resolve a bundled document plus JSON Pointer; never retrieve a URI."""
        if not isinstance(ref, str):
            raise ValueError("A schema reference must be text")
        name, fragment = urldefrag(ref)
        if name in self.schema_ids:
            name = self.schema_ids[name]
        if name not in self.documents:
            raise ValueError("Schema reference is not in the frozen allowlist: " + ref)
        self._allowed_path(name)
        value = self.documents[name]
        if fragment:
            if not fragment.startswith("/") or "%" in fragment or re.search(r"~(?![01])", fragment):
                raise ValueError("Only literal local JSON Pointer fragments are supported")
            for token in fragment[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                try:
                    value = value[int(token)] if isinstance(value, list) else value[token]
                except (KeyError, IndexError, ValueError, TypeError) as exc:
                    raise ValueError("Unresolved schema fragment: " + ref) from exc
        if not isinstance(value, dict):
            raise ValueError("Reference does not identify an object contract")
        return copy.deepcopy(value)

    def validator(self, ref: str) -> Draft202012Validator:
        self.resolve_schema(ref)
        return Draft202012Validator({"$ref": ref}, registry=self.offline_registry, format_checker=FormatChecker())

    def get_module(self, module_id: str, module_version: str) -> dict | None:
        items = self.data.get("modules", [])
        if not isinstance(items, list):
            return None
        matches = [m for m in items if isinstance(m, dict) and m.get("module_id") == module_id and m.get("module_version") == module_version]
        return copy.deepcopy(matches[0]) if len(matches) == 1 else None

    def get_observable(self, module_id: str, module_version: str, observable_id: str) -> dict | None:
        items = self.data.get("observables", [])
        if not isinstance(items, list):
            return None
        matches = [o for o in items if isinstance(o, dict) and (o.get("module_id"), o.get("module_version"), o.get("observable_id")) == (module_id, module_version, observable_id)]
        return copy.deepcopy(matches[0]) if len(matches) == 1 else None

    def validate_integrity(self) -> list[dict]:
        errors = copy.deepcopy(self._load_errors)
        if not self.data:
            errors.append(_error("The frozen registry document is unavailable"))
            return errors
        if self.contract_version == "0.4.0":
            errors.extend(self._generic_dynamics_snapshot_errors())
        if self.contract_version in {"0.3.0", "0.3.1", "0.4.0"}:
            bindings = [("registry.json", "registry.schema.json"),
                        ("resource_policy.json", "resource_policy.schema.json")]
            if self.contract_version == "0.4.0":
                bindings.append(("dynamics_adapter.json", "dynamics_adapter.schema.json"))
            for name, schema in bindings:
                try:
                    for error in itertools.islice(self.validator(schema).iter_errors(self.documents.get(name)), 100 - len(errors)):
                        errors.append(_error(error.message[:240], name + pointer(tuple(error.absolute_path))))
                except Exception as exc:
                    errors.append(_error(str(exc)[:240], name))
        for name, doc in self.documents.items():
            if len(errors) >= 100:
                return errors[:100]
            if "$schema" not in doc:
                continue
            try:
                Draft202012Validator.check_schema(doc)
            except Exception as exc:
                errors.append(_error("Invalid schema: " + str(exc)[:180], name))
            def refs(item):
                if isinstance(item, dict):
                    if "$ref" in item:
                        yield item["$ref"]
                    for v in item.values():
                        yield from refs(v)
                elif isinstance(item, list):
                    for v in item:
                        yield from refs(v)
            for ref in refs(doc):
                try:
                    self.resolve_schema((name if isinstance(ref, str) and ref.startswith("#") else "") + ref)
                except (ValueError, TypeError) as exc:
                    errors.append(_error(str(exc), name))
        for kind, schema in (("modules", "module_manifest.schema.json"), ("observables", "observable_manifest.schema.json")):
            seen = set()
            items = self.data.get(kind)
            if not isinstance(items, list):
                errors.append(_error("Registry manifest collection must be an array", "/" + kind))
                continue
            for i, manifest in enumerate(items):
                if len(errors) >= 100:
                    return errors[:100]
                if not isinstance(manifest, dict):
                    errors.append(_error("Registry manifest entry must be an object", "/" + kind + "/" + str(i)))
                    continue
                try:
                    manifest_errors = list(itertools.islice(self.validator(schema).iter_errors(manifest), 100 - len(errors)))
                except Exception as exc:
                    errors.append(_error(str(exc)[:240], "/" + kind + "/" + str(i)))
                    continue
                if manifest_errors:
                    for error in manifest_errors:
                        errors.append(_error(error.message[:240], "/" + kind + "/" + str(i) + pointer(tuple(error.absolute_path))))
                    continue
                ident = (manifest.get("module_id"), manifest.get("module_version"))
                if kind == "observables":
                    ident += (manifest.get("observable_id"),)
                if ident in seen:
                    errors.append(_error("Duplicate registered identity", "/" + kind + "/" + str(i)))
                seen.add(ident)
                try:
                    self._check_manifest_refs(manifest)
                except Exception as exc:
                    errors.append(_error(str(exc)[:240], "/" + kind + "/" + str(i)))
        return errors

    def _generic_dynamics_snapshot_errors(self) -> list[dict]:
        """Bind executable generic rules and explicit science imports to bytes."""
        try:
            disk_manifest = parse_json(self._manifest_path.read_bytes())
            if not _same_snapshot(disk_manifest, self.manifest) or set(self.raw_bytes) != set(self.manifest):
                raise ValueError("Generic contract manifest changed after capture")
            for name, raw in self.raw_bytes.items():
                if hashlib.sha256(raw).hexdigest() != self.manifest[name] or self._allowed_path(name).read_bytes() != raw:
                    raise ValueError("Generic contract bytes differ from their captured manifest: " + name)
            documents = {name: parse_json(raw) for name, raw in self.raw_bytes.items() if name.endswith(".json")}
            if (not _same_snapshot(documents, self.documents) or
                    not _same_snapshot(self.data, documents["registry.json"]) or
                    not _same_snapshot(self.resource_policy, documents["resource_policy.json"])):
                raise ValueError("Active generic contract rules differ from captured bytes")
            schema_ids = {doc["$id"]: name for name, doc in documents.items() if "$schema" in doc and "$id" in doc}
            if self.schema_ids != schema_ids or documents["registry.json"]["schema_ids"] != schema_ids:
                raise ValueError("Generic schema identity map differs from the captured allowlist")
            for name, doc in documents.items():
                if "$schema" not in doc:
                    continue
                aliases = (name, "https://quanta.invalid/contracts/v0.4.0/" + name, doc["$id"])
                if any(not _same_snapshot(self.offline_registry.contents(alias), doc) for alias in aliases):
                    raise ValueError("Active offline schema resource differs from captured bytes: " + name)
            adapter = documents["dynamics_adapter.json"]
            if not _same_snapshot({key: adapter.get(key) for key in _DYNAMICS_ADAPTER_MAPPING}, _DYNAMICS_ADAPTER_MAPPING):
                raise ValueError("Registered dynamics adapter mapping differs from the compiled supported mapping")
            imported = adapter["imported_scientific_schemas_sha256"]
            names = {"dynamics_request.schema.json", "dynamics_payload.schema.json", "dynamics_state.schema.json",
                     "dynamics_metadata.schema.json", "dynamics_report.schema.json"}
            if set(imported) != names or any(hashlib.sha256(self.raw_bytes[name]).hexdigest() != imported[name] for name in names):
                raise ValueError("Explicit standalone scientific schema imports differ from their frozen hashes")
            source = ContractRegistry(contract_version="0.3.1")
            if source._load_errors or any(source.raw_bytes[name] != self.raw_bytes[name] for name in names):
                raise ValueError("Scientific imports are not the exact installed standalone 0.3.1 schemas")
            modules = documents["registry.json"]["modules"]
            if len(modules) != 1 or (modules[0]["module_id"], modules[0]["module_version"], modules[0]["operations"]) != ("quanta.pair_dynamics", "0.1.0", ["integrate"]):
                raise ValueError("Generic dynamics bundle declares an unsupported module or operation")
            if modules[0]["capabilities"].get("execution_adapter_ref") != "dynamics_adapter.json":
                raise ValueError("Generic dynamics module is not bound to its registered adapter")
            module = modules[0]
            expected_refs = {"definition_schema_ref": "dynamics_definition.schema.json",
                             "input_schema_ref": "dynamics_request.schema.json#/properties/system",
                             "numerics_schema_ref": "dynamics_request.schema.json#/properties/numerics",
                             "payload_schema_ref": "dynamics_payload.schema.json"}
            if not _same_snapshot({key: module.get(key) for key in expected_refs}, expected_refs):
                raise ValueError("Registered dynamics scientific schema bindings differ from the supported adapter")
            if not _same_snapshot(module.get("precision_contract"), {"real_dtype": "float64", "complex_encoding": "none", "finite_only": True}):
                raise ValueError("Registered dynamics precision differs from the compiled binary64 implementation")
            if (module.get("unit_contract", {}).get("interchange_system") != "SI" or
                    module.get("unit_contract", {}).get("scaling_quantities") != ["length", "energy", "time"]):
                raise ValueError("Registered dynamics units differ from the compiled SI adapter")
            if not _same_snapshot(module.get("ports"), _DYNAMICS_PHASE_PORTS):
                raise ValueError("Registered dynamics phase ports differ from the compiled supported bindings")
            if (module["capabilities"].get("time_kind") != "evolving" or
                    module["capabilities"].get("spatial_dimensions") != [3] or
                    module["capabilities"].get("boundaries") != ["nonperiodic"]):
                raise ValueError("Registered dynamics geometry or time semantics differ from the compiled implementation")
            if not _same_snapshot(module["capabilities"].get("expression"), _DYNAMICS_EXPRESSION_CAPABILITIES):
                raise ValueError("Registered dynamics expression capabilities differ from the compiled implementation")
            if not _same_snapshot(module["capabilities"].get("protocol"), _DYNAMICS_PROTOCOL_CAPABILITIES):
                raise ValueError("Registered dynamics protocol capabilities differ from the compiled supported mapping")
            if not _same_snapshot(module["capabilities"].get("limits"), _DYNAMICS_IMPLEMENTED_LIMITS):
                raise ValueError("Registered dynamics implementation ceilings differ; tighten the resource policy instead")
            if (module["capabilities"].get("resource_policy_ref") != "resource_policy.json" or
                    module["capabilities"].get("resource_profile_pointer") != "/profiles/pair_dynamics_cpu" or
                    not _same_snapshot(module["capabilities"].get("expression_formats"), [
                        {"format_id": "quanta.scalar_ast", "format_version": "0.1.0",
                         "schema_ref": "dynamics_request.schema.json#/$defs/expression"}])):
                raise ValueError("Registered dynamics expression format or resource binding differs from the supported adapter")
        except Exception as exc:
            return [_error("Generic dynamics contract snapshot is unavailable", reason=str(exc)[:240])]
        return []

    def _check_manifest_refs(self, manifest: dict) -> None:
        def walk(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if key.endswith("schema_ref") and isinstance(value, str):
                        self.resolve_schema(value)
                    walk(value)
            elif isinstance(item, list):
                for value in item:
                    walk(value)
        walk(manifest)
        if "ports" in manifest:
            ports = [p["port_id"] for p in manifest["ports"]]
            if len(ports) != len(set(ports)):
                raise ValueError("Duplicate module port identity")
            operations = set(manifest.get("operations", []))
            if any(set(p.get("operations", [])) - operations for p in manifest["ports"]):
                raise ValueError("Port names an undeclared operation")
            caps = manifest.get("capabilities", {})
            policy = self.resolve_schema(caps["resource_policy_ref"] + "#" + caps["resource_profile_pointer"])
            identity = manifest["module_id"] + "@" + manifest["module_version"]
            if identity not in policy.get("module_versions", []):
                raise ValueError("Module is not bound to its declared resource profile")
