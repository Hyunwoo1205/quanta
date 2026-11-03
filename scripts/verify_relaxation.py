#!/usr/bin/env python3
"""Measure A04 against an independent constrained harmonic reference."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import struct

from verify_numerics import locked_environment, source_record as energy_source_record
import numpy as np

from quanta import __version__
from quanta.hashing import canonical_bytes, definition_sha256
from quanta.registry import ContractRegistry
from quanta.validation import validate_definition

ROOT = Path(__file__).resolve().parents[1]
L0, E0, K, RHO0 = 1e-9, 1e-19, 2.0, 1.0


def definition() -> dict:
    """Declare the A04 input separately from implementation and CLI examples."""
    return {
        "unit_system": "SI", "scales": {"length_m": L0, "energy_j": E0},
        "system": {
            "representation": "particles_3d", "module_id": "quanta.pair_static",
            "module_version": "0.1.0", "boundary": "nonperiodic", "min_distance_m": 1e-17,
            "particles": [
                {"id": "p1", "position_m": [0.0, 0.0, 0.0], "fixed": [True, True, True]},
                {"id": "p2", "position_m": [1.2 * L0, 0.0, 0.0], "fixed": [False, True, True]}],
            "potential": {"expression": {"op": "mul", "args": [
                {"op": "const", "value": 0.5}, {"op": "param", "name": "k"},
                {"op": "pow", "arg": {"op": "sub", "args": [
                    {"op": "var", "name": "rho"}, {"op": "param", "name": "rho0"}]},
                 "exponent": 2}]}, "parameters": {"k": K, "rho0": RHO0}}},
        "numerics": {"solver": "lbfgsb_forward_ad", "gradient_tolerance": 1e-6,
                     "energy_ftol": 1e-12, "max_iterations": 2000, "max_evaluations": 10000},
        "protocol": {"steps": [{"step_id": "relax", "operation": "relax", "source": "initial",
                                  "overrides": []}], "sweep": {"axes": []}},
        "observables": ["energy", "forces", "pair_energies", "final_positions", "optimization_history"],
        "extensions": {}}


def bits(value: float) -> str:
    return struct.pack(">d", float(value)).hex()


def reference(positions: np.ndarray) -> dict:
    """Closed form without production AST, kernel or optimizer helpers."""
    delta = positions[1] - positions[0]
    distance = math.hypot(*(float(x) for x in delta))
    rho = distance / L0
    slope = K * (rho - RHO0)
    force_p2 = -slope * delta / distance
    forces = np.stack((-force_p2, force_p2))
    return {"distance_m": distance, "distance_reduced": rho,
            "energy_reduced": 0.5 * K * (rho - RHO0) ** 2,
            "forces_reduced": forces.tolist(), "free_gradient_inf": abs(float(force_p2[0]))}


def component_comparison(actual: np.ndarray | float, expected: np.ndarray | float) -> dict:
    actual, expected = np.asarray(actual), np.asarray(expected)
    error = np.abs(actual - expected)
    # Independent payload consistency uses the existing A01 reduced-unit rule.
    atol = rtol = 1e-10
    return {"actual": actual.tolist(), "reference": expected.tolist(), "absolute_error": error.tolist(),
            "max_absolute_error": float(np.max(error)), "atol": atol, "rtol": rtol,
            "passed": bool(np.all(error <= atol + rtol * np.abs(expected)))}


def measure(base: dict, target: dict) -> dict:
    from quanta.relaxation import relax_pair

    authored = deepcopy(base)
    before = canonical_bytes(authored)
    registry = ContractRegistry()
    validation = validate_definition(base, registry=registry)
    if not validation["valid"]:
        raise ValueError(f"A04 definition is invalid: {validation['errors']}")
    payload = relax_pair(base, registry=registry)
    module = registry.get_module("quanta.pair_static", "0.1.0")
    schema_ref = module["payload_schema_ref"]
    schema_errors = [{"path": list(error.absolute_path), "message": error.message}
                     for error in registry.validator(schema_ref).iter_errors(payload)]
    initial = np.array([p["position_m"] for p in authored["system"]["particles"]], dtype=float)
    final = np.asarray(payload["final_positions_m"], dtype=float)
    forces = np.asarray(payload["forces_n"], dtype=float)
    if final.shape != (2, 3) or forces.shape != (2, 3):
        raise ValueError("A04 returned an inconsistent coordinate or force shape")
    if not np.isfinite(final).all() or not np.isfinite(forces).all():
        raise ValueError("A04 returned a nonfinite coordinate or force")
    for name in ("energy_j", "free_gradient_inf"):
        if not math.isfinite(payload[name]):
            raise ValueError(f"A04 returned nonfinite {name}")
    ref = reference(final)
    initial_ref = reference(initial)
    distance_error = abs(ref["distance_reduced"] - RHO0)
    comparisons = {
        "final_energy_reduced": component_comparison(payload["energy_j"] / E0, ref["energy_reduced"]),
        "final_forces_reduced": component_comparison(forces / (E0 / L0), ref["forces_reduced"]),
        "free_gradient_inf": component_comparison(payload["free_gradient_inf"], ref["free_gradient_inf"])}
    fixed = [{"particle_index": i, "axis": axis,
              "initial_bits_be": bits(initial[i, axis]), "final_bits_be": bits(final[i, axis]),
              "unchanged": bits(initial[i, axis]) == bits(final[i, axis])}
             for i, particle in enumerate(authored["system"]["particles"])
             for axis, fixed in enumerate(particle["fixed"]) if fixed]
    iterations, evaluations = payload["iterations"], payload["evaluations"]
    history = payload.get("optimization_history", [])
    history_indices = [entry["iteration"] for entry in history]
    history_finite = all(math.isfinite(entry[name]) for entry in history
                         for name in ("energy_j", "free_gradient_inf"))
    history_last_matches = bool(history) and all(bits(history[-1][name]) == bits(payload[name])
                                                for name in ("energy_j", "free_gradient_inf"))
    history_first = {
        "energy_reduced": component_comparison(history[0]["energy_j"] / E0, initial_ref["energy_reduced"]),
        "free_gradient_inf": component_comparison(history[0]["free_gradient_inf"], initial_ref["free_gradient_inf"])
    } if history else {}
    counters_valid = (type(iterations) is int and type(evaluations) is int
                      and 1 <= iterations <= authored["numerics"]["max_iterations"]
                      and iterations + 1 <= evaluations <= authored["numerics"]["max_evaluations"])
    history_valid = (bool(history) and history_finite and len(history) == iterations + 1
                     and history_indices == list(range(iterations + 1)) and history_last_matches
                     and all(check["passed"] for check in history_first.values()))
    input_unchanged = before == canonical_bytes(base)
    initial_output_unchanged = all(bits(payload["initial_positions_m"][i][axis]) == bits(initial[i, axis])
                                   for i in range(2) for axis in range(3))
    gradient_checks = [check for check in payload["diagnostics"]["checks"]
                       if check["id"] == "free_gradient_tolerance"]
    fixed_checks = [check for check in payload["diagnostics"]["checks"]
                    if check["id"] == "fixed_coordinates_unchanged"]
    gradient_diagnostic_consistent = (len(gradient_checks) == 1 and gradient_checks[0]["status"] == "pass"
        and bits(gradient_checks[0]["value"]) == bits(payload["free_gradient_inf"])
        and bits(gradient_checks[0]["tolerance"]) == bits(authored["numerics"]["gradient_tolerance"]))
    pairs = payload.get("pair_energies", [])
    pair_indices_valid = len(pairs) == 1 and (pairs[0]["i"], pairs[0]["j"]) == (0, 1)
    pair_comparisons = {
        "distance_reduced": component_comparison(pairs[0]["distance_m"] / L0, ref["distance_reduced"]),
        "energy_reduced": component_comparison(pairs[0]["energy_j"] / E0, ref["energy_reduced"])
    } if pair_indices_valid else {}
    checks = {
        "registered_payload_schema": not schema_errors, "operation_relax": payload["operation"] == "relax",
        "distance_tolerance": distance_error <= 1e-6,
        "reported_free_gradient_tolerance": payload["free_gradient_inf"] <= target["threshold"],
        "independent_free_gradient_tolerance": ref["free_gradient_inf"] <= target["threshold"],
        "independent_payload_agreement": all(check["passed"] for check in comparisons.values()),
        "fixed_coordinate_bits_unchanged": all(check["unchanged"] for check in fixed),
        "authored_definition_unchanged": input_unchanged, "initial_output_unchanged": initial_output_unchanged,
        "counter_limits": counters_valid, "accepted_history_consistent": history_valid,
        "explicit_gradient_termination": payload["stop_reason"] == "gradient_tolerance",
        "gradient_diagnostic_consistent": gradient_diagnostic_consistent,
        "fixed_coordinate_diagnostic": (len(fixed_checks) == 1 and fixed_checks[0]["status"] == "pass"
                                         and fixed_checks[0]["value"] == 0 and fixed_checks[0]["tolerance"] == 0),
        "requested_pair_table_complete": pair_indices_valid,
        "requested_pair_table_agreement": bool(pair_comparisons) and all(check["passed"] for check in pair_comparisons.values()),
        "minimum_not_certified": payload["minimum_confirmed"] is False}
    return {"id": "A04", "status": "passed" if all(checks.values()) else "failed",
            "input_sha256": definition_sha256(authored), "checks": checks,
            "thresholds": {"free_gradient_inf": target["threshold"], "rest_distance_reduced_error": 1e-6},
            "reference": {"method": "Independent two-point constrained harmonic closed form",
                          "formula": "u=k/2*(rho-rho0)^2; F2_reduced=-k*(rho-rho0)*(x2_reduced-x1_reduced)/rho; F1=-F2",
                          "stationary_distance_reduced": RHO0, "stationary_energy_reduced": 0.0,
                          "one_reference_configuration_m": [[0.0, 0.0, 0.0], [RHO0 * L0, 0.0, 0.0]],
                          "branch_note": "Both signs of the free separation can be stationary; acceptance uses rest distance.",
                          "at_final_configuration": ref},
            "measurements": {"distance_m": ref["distance_m"], "distance_reduced": ref["distance_reduced"],
                             "rest_distance_reduced_error": distance_error,
                             "reported_free_gradient_inf": payload["free_gradient_inf"],
                             "independent_free_gradient_inf": ref["free_gradient_inf"],
                             "payload_comparisons": comparisons, "fixed_coordinates": fixed,
                             "pair_table_comparisons": pair_comparisons,
                             "iterations": iterations, "evaluations": evaluations,
                             "history_entries": len(history), "history_indices": history_indices,
                             "history_initial_comparisons": history_first,
                             "history_last_matches_payload_bits": history_last_matches,
                             "convergence_diagnostic": gradient_checks,
                             "stop_reason": payload["stop_reason"]},
            "registered_payload_schema": {"path": "contracts/v0.2.0/" + schema_ref,
                                          "sha256": hashlib.sha256((ROOT / "contracts/v0.2.0" / schema_ref).read_bytes()).hexdigest(),
                                          "errors": schema_errors},
            "actual_payload": payload}


def source_record() -> dict:
    record = energy_source_record()
    path = Path(__file__).resolve()
    record["files_sha256"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    record["source_set_sha256"] = hashlib.sha256(canonical_bytes(record["files_sha256"])).hexdigest()
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write actual A04 measurements to this JSON file")
    args = parser.parse_args()
    base = definition()
    plan_path = ROOT / "contracts/v0.2.0/validation_manifest.json"
    target = next(case for case in json.loads(plan_path.read_text())["cases"] if case["id"] == "A04")
    environment = locked_environment()
    try:
        result = measure(base, target)
        json.dumps(result, allow_nan=False)
    except Exception as exc:
        result = {"id": "A04", "status": "failed", "error_type": type(exc).__name__, "error": str(exc),
                  "error_code": getattr(exc, "code", None)}
        partial = getattr(exc, "partial_payload", None)
        if isinstance(partial, dict):
            try:
                json.dumps(partial, allow_nan=False)
                result["partial_payload"] = partial
            except (TypeError, ValueError):
                result["partial_payload_serializable"] = False
    passed = environment["valid"] and result["status"] == "passed"
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
              "status": "passed" if passed else "failed", "package_version": __version__,
              "scope": "A04 constrained two-point harmonic local stationarity search only",
              "baseline_definition": definition(), "baseline_input_sha256": definition_sha256(definition()),
              "acceptance_plan": {"path": str(plan_path.relative_to(ROOT)), "sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
                                  "case_at_plan_snapshot": target},
              "measurement_metadata": {"origin": "actual_executed_benchmark", "target_source": "src/quanta/relaxation.py",
                                       "target_module": "quanta.pair_static@0.1.0", "operation": "relax",
                                       "solver": "lbfgsb_forward_ad", "energy_scale_j": E0, "force_scale_n": E0 / L0,
                                       "history_semantics": "Initial accepted point and accepted iterations; trial evaluations are counted separately"},
              "cases": [result], "environment": environment, "code_source": source_record(),
              "physical_validation_status": "unvalidated", "minimum_certification": "not_performed",
              "limitations": ["Acceptance applies to this smooth constrained harmonic input only.",
                              "Stationarity does not certify a minimum, a global solution, or agreement with physical experiments.",
                              "Other modules, multistep execution, and future runtime features are outside this report."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output), "cases": {"A04": result["status"]}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
