"""A single, explicit configuration evaluation; no protocol runner or fake states."""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import __version__
from .environment import environment_report
from .hashing import canonical_bytes
from .parsing import parse_json
from .registry import ContractRegistry
from .validation import validate_experiment


def _issue(code: str, message: str, path: str | None = None, *, details: dict | None = None,
           category: str = "support") -> dict:
    return {"code": code, "category": category, "message": message, "path": path,
            "step_id": None, "branch_index": None, "retryable": False, "details": details or {}}


def _provenance(registry: ContractRegistry, observed: dict) -> dict:
    root = Path(__file__).resolve().parent
    code = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.py"))}
    return {"package_version": __version__, "contract_version": "0.2.0",
            "implementation_source_sha256": hashlib.sha256(canonical_bytes(code)).hexdigest(),
            "source_file_sha256": code,
            "registry_snapshot_sha256": hashlib.sha256(registry.raw_bytes["registry.json"]).hexdigest(),
            "environment": {"baseline_matches": observed["valid"], "versions": observed["versions"],
                "implementation": observed["implementation"], "platform": observed["platform"],
                "thread_environment": observed["thread_environment"],
                "threadpools": [{k: pool.get(k) for k in ("user_api", "internal_api", "version", "num_threads", "architecture")}
                                for pool in observed["threadpools"]]}}


def evaluate_experiment(data: bytes | str | dict, *, registry: ContractRegistry | None = None) -> dict:
    """Evaluate one initial energy/force step, rejecting unimplemented execution.

    This versioned report is deliberately distinct from the future run-result
    envelope. It creates neither run/state IDs nor an execution fingerprint.
    """
    report = {"report_version": "0.1.0", "scope": "single_configuration_energy_forces",
              "evaluation_status": "FAILED", "input_validation_status": "failed",
              "numerical_status": "not_applicable", "resolution_status": "not_applicable",
              "physical_validation_status": "unvalidated", "calculation_executed": False,
              "input_sha256": None, "module_ref": None, "payload": None,
              "warnings": [], "errors": [], "provenance": None}
    try:
        registry = registry or ContractRegistry()
        validation = validate_experiment(data, registry=registry)
    except (OSError, ValueError, TypeError) as exc:
        report["errors"].append(_issue("REGISTRY_SNAPSHOT_UNAVAILABLE", "The frozen registry could not be loaded.",
                                       details={"reason": str(exc)[:180]}))
        return report
    report["errors"] = validation["errors"]
    report["warnings"] = [w for w in validation["warnings"] if w["code"] != "CONTRACT_VALIDATION_ONLY"]
    report["input_sha256"] = validation["input_sha256"]
    report["module_ref"] = validation["module_ref"]
    if not validation["valid"]:
        return report
    report["input_validation_status"] = "pass"
    experiment = parse_json(data)
    definition = experiment["definition"]
    protocol = definition["protocol"]
    steps = protocol["steps"]
    supported = (definition["system"]["module_id"] == "quanta.pair_static"
                 and definition["system"]["module_version"] == "0.1.0"
                 and len(steps) == 1 and steps[0]["operation"] == "energy_forces"
                 and steps[0]["source"] == "initial" and not steps[0]["overrides"]
                 and not protocol["sweep"]["axes"])
    if not supported:
        report["errors"].append(_issue("MODEL_UNSUPPORTED",
            "Single evaluation requires exactly one pair energy_forces step, initial source, no overrides and no sweep.",
            "/definition/protocol"))
        return report
    observed = environment_report()
    report["provenance"] = _provenance(registry, observed)
    if not observed["valid"]:
        report["errors"].append(_issue("MODEL_UNSUPPORTED", "The selected numerical environment baseline does not match.",
                                       details={"environment_errors": observed["errors"]}))
        return report
    from .autodiff import CalculationError
    from .pair import evaluate_pair
    try:
        payload = evaluate_pair(definition, registry=registry)
    except CalculationError as exc:
        category = {"EXPRESSION_DOMAIN": "numerical", "RESOURCE_LIMIT": "resource",
                    "MODEL_UNSUPPORTED": "support", "ENGINE_FAILURE": "runtime"}.get(exc.code, "input")
        report["errors"].append(_issue(exc.code, str(exc), getattr(exc, "path", None),
            details=getattr(exc, "details", {}), category=category))
        return report
    except Exception as exc:
        report["errors"].append(_issue("ENGINE_FAILURE", "Single evaluation failed unexpectedly.",
                                       details={"exception_type": type(exc).__name__}, category="runtime"))
        return report
    report.update(evaluation_status="SUCCEEDED", calculation_executed=True, payload=payload)
    report["module_ref"] = {**report["module_ref"], "operation": "energy_forces"}
    report["particle_ids"] = [p["id"] for p in definition["system"]["particles"]]
    return report
