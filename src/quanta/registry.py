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


def _error(message: str, path: str | None = None, **details) -> dict:
    return {"code": "REGISTRY_SNAPSHOT_UNAVAILABLE", "category": "support", "message": message,
            "path": path, "step_id": None, "branch_index": None, "retryable": False, "details": details}


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
                                             or contract_version not in {"0.2.0", "0.3.0"}):
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
        if self.contract_version not in {"0.2.0", "0.3.0"}:
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
        if self.contract_version == "0.3.0":
            for name, schema in (("registry.json", "registry.schema.json"),
                                 ("resource_policy.json", "resource_policy.schema.json")):
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
