#!/usr/bin/env python3
"""Measure B01--B06 against independent finite-interval reference problems."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

from verify_numerics import locked_environment, source_record as energy_source_record
import numpy as np

from quanta import __version__
from quanta.hashing import canonical_bytes, definition_sha256
from quanta.registry import ContractRegistry
from quanta.validation import validate_definition

ROOT = Path(__file__).resolve().parents[1]
PLANCK_J_S = 6.62607015e-34
HBAR = PLANCK_J_S / (2 * math.pi)
L0, E0 = 1e-9, 1e-20
K = 4


def definition(n: int = 255, *, harmonic: bool = False, half_width: float = 8.0) -> dict:
    """Independent benchmark inputs, without relying on an application example."""
    alpha = 0.5
    mass = HBAR * HBAR / (2 * alpha * L0 * L0 * E0)
    if harmonic:
        a, b = -half_width * L0, half_width * L0
        potential = {
            "expression": {"op": "mul", "args": [{"op": "const", "value": 0.5},
                {"op": "pow", "arg": {"op": "sub", "args": [
                    {"op": "var", "name": "xi"}, {"op": "param", "name": "center"}]},
                 "exponent": 2}]}, "parameters": {"center": half_width}}
    else:
        a, b = 0.0, L0
        potential = {"expression": {"op": "const", "value": 0.0}, "parameters": {}}
    return {
        "unit_system": "SI", "scales": {"length_m": L0, "energy_j": E0},
        "system": {"representation": "quantum_grid_1d", "module_id": "quanta.quantum_stationary",
                   "module_version": "0.1.0", "domain": {"a_m": a, "b_m": b},
                   "mass_kg": mass, "boundary": "dirichlet_zero", "potential": potential},
        "numerics": {"solver": "symmetric_tridiagonal_lowest", "n_points": n, "states": K,
                     "refinement_levels": 0, "grid_energy_atol": 1e-10, "grid_energy_rtol": 1e-8},
        "protocol": {"steps": [{"step_id": "spectrum", "operation": "eigenstates",
                                  "source": "initial", "overrides": []}], "sweep": {"axes": []}},
        "observables": ["energies", "states", "density", "x_mean", "x2_mean",
                        "kinetic_mean", "potential_mean"], "extensions": {}}


def reduced_constants(value: dict) -> tuple[float, float, float]:
    """Reference constants; deliberately do not call production coefficient helpers."""
    system, scales = value["system"], value["scales"]
    width = (system["domain"]["b_m"] - system["domain"]["a_m"]) / scales["length_m"]
    alpha = HBAR ** 2 / (2 * system["mass_kg"] * scales["length_m"] ** 2 * scales["energy_j"])
    spacing = width / (value["numerics"]["n_points"] + 1)
    return alpha, width, spacing


def exact_discrete_energies(value: dict) -> np.ndarray:
    alpha, _, spacing = reduced_constants(value)
    j = np.arange(1, value["numerics"]["states"] + 1)
    n = value["numerics"]["n_points"]
    return 4 * alpha / spacing ** 2 * np.sin(j * math.pi / (2 * (n + 1))) ** 2


def exact_continuum_energies(value: dict) -> np.ndarray:
    alpha, width, _ = reduced_constants(value)
    j = np.arange(1, value["numerics"]["states"] + 1)
    return alpha * (j * math.pi / width) ** 2


def hash_value(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class Benchmarks:
    def __init__(self):
        self.registry = ContractRegistry()
        self.cache: dict[str, tuple[dict, dict]] = {}

    def run(self, value: dict) -> tuple[dict, dict]:
        from quanta.quantum import eigenstates

        key = definition_sha256(value)
        if key in self.cache:
            return self.cache[key]
        authored = deepcopy(value)
        validation = validate_definition(value, registry=self.registry)
        if not validation["valid"]:
            raise ValueError(f"Invalid benchmark input: {validation['errors']}")
        payload = eigenstates(value, registry=self.registry)
        module = self.registry.get_module("quanta.quantum_stationary", "0.1.0")
        schema_ref = module["payload_schema_ref"]
        schema_errors = [{"path": list(error.absolute_path), "message": error.message}
                         for error in self.registry.validator(schema_ref).iter_errors(payload)]
        n, k = value["numerics"]["n_points"], value["numerics"]["states"]
        x = np.asarray(payload["x_m"], dtype=float)
        real, imag = (np.asarray(payload["states"][name], dtype=float) for name in ("real", "imag"))
        energies = np.asarray(payload["energies_j"], dtype=float)
        if x.shape != (n + 2,) or real.shape != (k, n + 2) or imag.shape != real.shape or energies.shape != (k,):
            raise ValueError("Calculated payload has inconsistent array shapes")
        if not all(np.isfinite(array).all() for array in (x, real, imag, energies)):
            raise ValueError("Calculated payload has nonfinite mandatory values")
        domain, scales = value["system"]["domain"], value["scales"]
        dx_m = (domain["b_m"] - domain["a_m"]) / (n + 1)
        expected_x = np.linspace(domain["a_m"], domain["b_m"], n + 2)
        density = np.asarray(payload["density_per_m"], dtype=float)
        x_mean, x2_mean = np.asarray(payload["x_mean_m"]), np.asarray(payload["x2_mean_m2"])
        kinetic, potential = np.asarray(payload["kinetic_mean_j"]), np.asarray(payload["potential_mean_j"])
        if density.shape != real.shape or any(array.shape != (k,) for array in (x_mean, x2_mean, kinetic, potential)):
            raise ValueError("Calculated optional observables have inconsistent shapes")
        expected_density = real ** 2 + imag ** 2
        expected_x_mean = np.sum(expected_density[:, 1:-1] * x[1:-1], axis=1) * dx_m
        expected_x2_mean = np.sum(expected_density[:, 1:-1] * x[1:-1] ** 2, axis=1) * dx_m
        checks = {
            "registered_payload_schema": not schema_errors,
            "operation_eigenstates": payload["operation"] == "eigenstates",
            "definition_unchanged": canonical_bytes(value) == canonical_bytes(authored),
            "ascending_energies": bool(np.all(np.diff(energies) > 0)),
            "monotone_uniform_grid": bool(np.all(np.diff(x) > 0))
                and float(np.max(np.abs(x - expected_x)) / scales["length_m"]) <= 1e-12,
            "domain_endpoints": bool(x[0] == domain["a_m"] and x[-1] == domain["b_m"]),
            "zero_boundary_states": bool(np.all(real[:, [0, -1]] == 0)) and bool(np.all(imag[:, [0, -1]] == 0)),
            "real_carrier": bool(np.all(imag == 0)),
            "finite_optional_values": all(np.isfinite(array).all() for array in (density, x_mean, x2_mean, kinetic, potential)),
            "density_agreement": float(np.max(np.abs(density - expected_density)) * scales["length_m"]) <= 1e-10,
            "position_mean_agreement": float(np.max(np.abs(x_mean - expected_x_mean)) / scales["length_m"]) <= 1e-10,
            "position_squared_mean_agreement": float(np.max(np.abs(x2_mean - expected_x2_mean)) / scales["length_m"] ** 2) <= 1e-10,
            "energy_decomposition": float(np.max(np.abs(kinetic + potential - energies)) / scales["energy_j"]) <= 1e-8,
            "one_grid_result": len(payload["grid_results"]) == 1
                and payload["grid_results"][0]["n_points"] == n
                and payload["grid_results"][0]["energies_j"] == payload["energies_j"]
                and payload["grid_results"][0]["atol"] == value["numerics"]["grid_energy_atol"]
                and payload["grid_results"][0]["rtol"] == value["numerics"]["grid_energy_rtol"],
        }
        summary = {"definition": authored, "input_sha256": key, "payload_sha256": hash_value(payload),
                   "registered_payload_schema": {"path": "contracts/v0.2.0/" + schema_ref,
                       "sha256": hashlib.sha256((ROOT / "contracts/v0.2.0" / schema_ref).read_bytes()).hexdigest(),
                       "errors": schema_errors},
                   "common_checks": checks, "energies_j": payload["energies_j"],
                   "energies_reduced": (energies / scales["energy_j"]).tolist(),
                   "x_m_sha256": hash_value(payload["x_m"]), "states_sha256": hash_value(payload["states"]),
                   "grid_results": payload["grid_results"], "diagnostics": payload["diagnostics"]}
        self.cache[key] = payload, summary
        return payload, summary

    @staticmethod
    def all_common(summaries: list[dict]) -> bool:
        return all(all(run["common_checks"].values()) for run in summaries)

    def b01(self, target: dict) -> dict:
        value = definition()
        payload, run = self.run(value)
        actual = np.asarray(payload["energies_j"]) / E0
        reference = exact_discrete_energies(value)
        errors = np.abs(actual - reference)
        bounds = target["atol"] + target["rtol"] * np.abs(reference)
        passed = bool(np.all(errors <= bounds)) and self.all_common([run])
        return {"id": "B01", "status": "passed" if passed else "failed", "runs": [run],
                "reference_method": "Closed-form discrete zero-potential Dirichlet eigenvalues; no eigensolver in reference",
                "formula": target["formula"], "atol": target["atol"], "rtol": target["rtol"],
                "actual_reduced": actual.tolist(), "reference_reduced": reference.tolist(),
                "absolute_errors": errors.tolist(), "max_error_to_tolerance": float(np.max(errors / bounds))}

    def b02(self, target: dict) -> dict:
        value = definition()
        payload, run = self.run(value)
        psi = np.asarray(payload["states"]["real"]) + 1j * np.asarray(payload["states"]["imag"])
        dx_m = (value["system"]["domain"]["b_m"] - value["system"]["domain"]["a_m"]) / (value["numerics"]["n_points"] + 1)
        gram = (psi[:, 1:-1].conj() @ psi[:, 1:-1].T) * dx_m
        normalization_error = float(np.max(np.abs(np.diag(gram) - 1)))
        off_diagonal = gram - np.diag(np.diag(gram))
        orthogonality_error = float(np.max(np.abs(off_diagonal)))
        passed = max(normalization_error, orthogonality_error) <= target["threshold"] and self.all_common([run])
        return {"id": "B02", "status": "passed" if passed else "failed", "runs": [run],
                "reference_method": "SI interior-weighted complex Gram matrix, independently integrated from returned states",
                "threshold": target["threshold"], "grid_weight_m": dx_m,
                "gram_matrix": {"real": gram.real.tolist(), "imag": gram.imag.tolist()},
                "max_normalization_error": normalization_error, "max_off_diagonal_overlap": orthogonality_error}

    def b03(self, target: dict) -> dict:
        value = definition()
        payload, run = self.run(value)
        alpha, _, dx = reduced_constants(value)
        energies = np.asarray(payload["energies_j"]) / E0
        phi = np.asarray(payload["states"]["real"]) * math.sqrt(L0)
        # A declared zero potential makes this an independent closed-form
        # three-point operator check of the exported SI state, not a call to H.
        operated = -alpha * (phi[:, 2:] - 2 * phi[:, 1:-1] + phi[:, :-2]) / dx ** 2
        residual = operated - energies[:, None] * phi[:, 1:-1]
        h_norm_inf = 4 * alpha / dx ** 2
        ratios = np.linalg.norm(residual, axis=1) / ((h_norm_inf + np.abs(energies)) * np.linalg.norm(phi[:, 1:-1], axis=1))
        max_ratio = float(np.max(ratios))
        passed = max_ratio <= target["threshold"] and self.all_common([run])
        return {"id": "B03", "status": "passed" if passed else "failed", "runs": [run],
                "reference_method": "Independent zero-potential second-difference action on exported states",
                "metric": target["metric"], "threshold": target["threshold"],
                "operator_infinity_norm_reduced": h_norm_inf, "backward_residuals": ratios.tolist(),
                "max_backward_residual": max_ratio}

    def b04(self, target: dict) -> dict:
        value = definition(1023)
        payload, run = self.run(value)
        actual = np.asarray(payload["energies_j"]) / E0
        reference = exact_continuum_energies(value)
        errors = np.abs(actual - reference) / np.abs(reference)
        max_error = float(np.max(errors))
        passed = max_error <= target["threshold"] and self.all_common([run])
        return {"id": "B04", "status": "passed" if passed else "failed", "runs": [run],
                "reference_method": "Continuum zero-potential Dirichlet spectrum on exactly the same finite interval",
                "formula": "epsilon_j=alpha*(j*pi/B)^2", "threshold": target["threshold"],
                "actual_reduced": actual.tolist(), "continuum_reference_reduced": reference.tolist(),
                "relative_errors": errors.tolist(), "max_relative_error": max_error,
                "error_scope": "Grid discretization of the stated finite-interval continuum problem"}

    def b05(self, target: dict) -> dict:
        values = [definition(n, harmonic=True) for n in (127, 255, 511)]
        solved = [self.run(value) for value in values]
        runs = [run for _, run in solved]
        energies = np.asarray([payload["energies_j"] for payload, _ in solved]) / E0
        numerator, denominator = np.abs(energies[0] - energies[1]), np.abs(energies[1] - energies[2])
        roundoff_floor = 100 * np.finfo(np.float64).eps * np.maximum(1.0, np.max(np.abs(energies), axis=0))
        state_records = []
        for state, (coarse, fine, floor) in enumerate(zip(numerator, denominator, roundoff_floor)):
            limited = bool(coarse <= floor or fine <= floor)
            order = None if limited else math.log2(float(coarse / fine))
            accepted = limited or target["range"][0] <= order <= target["range"][1]
            state_records.append({"state_index": state, "coarse_difference_reduced": float(coarse),
                "fine_difference_reduced": float(fine), "roundoff_floor_reduced": float(floor),
                "order_status": "roundoff_limited" if limited else "measured", "observed_order": order,
                "passed": accepted})
        passed = all(row["passed"] for row in state_records) and self.all_common(runs)
        return {"id": "B05", "status": "passed" if passed else "failed", "runs": runs,
                "reference_method": "Second-order convergence of a smooth centered quadratic potential at fixed finite domain",
                "metric": target["metric"], "accepted_order_range": target["range"],
                "roundoff_policy": target["additional"], "grids": [127, 255, 511],
                "energies_reduced_by_grid": energies.tolist(), "state_measurements": state_records}

    def b06(self, target: dict) -> dict:
        values = [definition(1023, harmonic=True, half_width=8),
                  definition(1279, harmonic=True, half_width=10)]
        solved = [self.run(value) for value in values]
        runs = [run for _, run in solved]
        energies = np.asarray([payload["energies_j"] for payload, _ in solved]) / E0
        alpha = reduced_constants(values[0])[0]
        reference = math.sqrt(2 * alpha) * (np.arange(K) + 0.5)
        errors = np.abs(energies - reference) / np.abs(reference)
        spacings = [reduced_constants(value)[2] for value in values]
        same_spacing = spacings[0] == spacings[1]
        domain_delta = np.abs(energies[1] - energies[0])
        max_error = float(np.max(errors))
        passed = same_spacing and max_error <= target["threshold"] and self.all_common(runs)
        return {"id": "B06", "status": "passed" if passed else "failed", "runs": runs,
                "reference_method": "Harmonic continuum reference with finite-domain enlargement at constant spacing",
                "formula": "epsilon_s=sqrt(2*alpha)*(s+1/2) for V=1/2*(xi-center)^2",
                "threshold": target["threshold"], "continuum_reference_reduced": reference.tolist(),
                "energies_reduced_by_domain": energies.tolist(), "relative_errors_by_domain": errors.tolist(),
                "max_relative_error": max_error, "grid_spacings_reduced": spacings,
                "same_grid_spacing": same_spacing, "center_parameters": [8, 10],
                "fixed_spacing_domain_energy_difference_reduced": domain_delta.tolist(),
                "error_separation": {
                    "total_error": "Each finite-grid result compared with the infinite-domain harmonic reference",
                    "domain_sensitivity": "Difference between domains at the same grid spacing and physical centered potential",
                    "grid_error": "Fixed-domain grid dependence measured separately by B05",
                    "limitation": "Domain sensitivity is a measurement, not a rigorous bound on finite-domain truncation error"}}


def source_record() -> dict:
    record = energy_source_record()
    path = Path(__file__).resolve()
    record["files_sha256"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    record["source_set_sha256"] = hashlib.sha256(canonical_bytes(record["files_sha256"])).hexdigest()
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write actual B01--B06 measurements to this JSON file")
    args = parser.parse_args()
    plan_path = ROOT / "contracts/v0.2.0/validation_manifest.json"
    plan = json.loads(plan_path.read_text())
    targets = {case["id"]: case for case in plan["cases"]}
    environment = locked_environment()
    benchmarks = Benchmarks()
    cases = []
    for case_id, measure in (("B01", benchmarks.b01), ("B02", benchmarks.b02), ("B03", benchmarks.b03),
                             ("B04", benchmarks.b04), ("B05", benchmarks.b05), ("B06", benchmarks.b06)):
        try:
            result = measure(targets[case_id])
            json.dumps(result, allow_nan=False)
        except Exception as exc:
            result = {"id": case_id, "status": "failed", "error_type": type(exc).__name__,
                      "error": str(exc)[:500], "error_code": getattr(exc, "code", None)}
            partial = getattr(exc, "partial_payload", None)
            if isinstance(partial, dict):
                try:
                    json.dumps(partial, allow_nan=False)
                    result["partial_payload_sha256"] = hash_value(partial)
                    result["partial_diagnostics"] = partial.get("diagnostics")
                except (TypeError, ValueError, OverflowError):
                    result["partial_payload_serializable"] = False
        cases.append(result)
    passed = environment["valid"] and all(case["status"] == "passed" for case in cases)
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
              "status": "passed" if passed else "failed", "package_version": __version__,
              "scope": "B01--B06 finite-interval stationary-state numerical benchmarks only",
              "acceptance_plan": {"path": str(plan_path.relative_to(ROOT)),
                  "sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
                  "cases_at_plan_snapshot": [targets[f"B{i:02d}"] for i in range(1, 7)]},
              "measurement_metadata": {"origin": "actual_executed_benchmarks",
                  "target_source": "src/quanta/quantum.py", "target_module": "quanta.quantum_stationary@0.1.0",
                  "operation": "eigenstates", "solver": "symmetric_tridiagonal_lowest",
                  "constants": {"planck_j_s": PLANCK_J_S, "planck_exact_in_SI": True, "hbar_j_s": HBAR,
                      "hbar_rule": "h/(2*pi), binary64 pi", "source": "https://www.nist.gov/pml/special-publication-330/sp-330-section-2"},
                  "state_storage": "Report retains input definitions, energies, diagnostics and payload hashes; full states are reproducible from inputs"},
              "cases": cases, "environment": environment, "code_source": source_record(),
              "physical_validation_status": "unvalidated",
              "limitations": ["Acceptance applies only to the declared smooth, well-scaled reference inputs.",
                  "Discrete eigensolver correctness, grid convergence, and domain truncation are distinct checks.",
                  "No agreement with measured physical experiments or unsupported model is certified.",
                  "Grid-refinement control-flow cases are covered by the separate automated test suite."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output),
                          "cases": {case["id"]: case["status"] for case in cases}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
