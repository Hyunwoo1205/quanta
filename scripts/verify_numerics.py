#!/usr/bin/env python3
"""Measure the named pair benchmarks; do not change historical validation plans."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
import math
import os
from pathlib import Path
import subprocess
import sys

for _name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ.setdefault(_name, "1")

import numpy as np

from quanta import __version__
from quanta.environment import environment_report
from quanta.hashing import canonical_bytes, definition_sha256
from quanta.pair import evaluate_pair
from quanta.validation import validate_definition as validate_definition_contract

ROOT = Path(__file__).resolve().parents[1]
POSITIONS = np.array([[0.1, -0.2, 0.3], [1.3, 0.4, -0.1],
                      [-0.4, 1.2, 0.7], [0.8, -0.9, 1.4]], dtype=float)
L0, E0, K, RHO0 = 2e-9, 3e-20, 2.3, 0.9


def definition() -> dict:
    """Declare an independent smooth, well-scaled benchmark input."""
    return {
        "unit_system": "SI", "scales": {"length_m": L0, "energy_j": E0},
        "system": {
            "representation": "particles_3d", "module_id": "quanta.pair_static",
            "module_version": "0.1.0", "boundary": "nonperiodic", "min_distance_m": 1e-17,
            "particles": [{"id": f"p{i+1}", "position_m": position.tolist(),
                           "fixed": [i == 0] * 3} for i, position in enumerate(POSITIONS * L0)],
            "potential": {
                "expression": {"op": "mul", "args": [
                    {"op": "const", "value": 0.5}, {"op": "param", "name": "k"},
                    {"op": "pow", "arg": {"op": "sub", "args": [
                        {"op": "var", "name": "rho"}, {"op": "param", "name": "rho0"}]},
                     "exponent": 2}]},
                "parameters": {"k": K, "rho0": RHO0}}},
        "numerics": {"solver": "lbfgsb_forward_ad", "gradient_tolerance": 1e-6,
                     "energy_ftol": 1e-12, "max_iterations": 2000, "max_evaluations": 10000},
        "protocol": {"steps": [{"step_id": "evaluate", "operation": "energy_forces",
                                  "source": "initial", "overrides": []}], "sweep": {"axes": []}},
        "observables": ["energy", "forces", "pair_energies", "final_positions"], "extensions": {}}


def validate_definition(value: dict) -> None:
    report = validate_definition_contract(value)
    if not report["valid"]:
        raise ValueError(f"Benchmark definition is invalid: {report['errors']}")


def actual(value: dict) -> tuple[float, np.ndarray]:
    payload = evaluate_pair(value)
    energy = float(payload["energy_j"])
    forces = np.asarray(payload["forces_n"], dtype=float)
    if not math.isfinite(energy) or forces.shape != (4, 3) or not np.isfinite(forces).all():
        raise ValueError("The evaluated energy or force array is nonfinite or has the wrong shape")
    return energy, forces


def independent_harmonic(value: dict) -> tuple[float, np.ndarray]:
    """Vectorized closed form, independent of production AST/force helpers."""
    scale = value["scales"]
    points = np.array([p["position_m"] for p in value["system"]["particles"]]) / scale["length_m"]
    parameters = value["system"]["potential"]["parameters"]
    differences = points[:, None, :] - points[None, :, :]
    distances = np.linalg.norm(differences, axis=2)
    i, j = np.triu_indices(len(points), 1)
    extension = distances[i, j] - parameters["rho0"]
    energy = float(0.5 * parameters["k"] * np.dot(extension, extension))
    safe_distances = distances + np.eye(len(points))
    coefficients = -parameters["k"] * (distances - parameters["rho0"]) / safe_distances
    np.fill_diagonal(coefficients, 0.0)
    forces = np.sum(coefficients[:, :, None] * differences, axis=1)
    return energy, forces


def comparison(got: np.ndarray | float, expected: np.ndarray | float, atol: float, rtol: float) -> dict:
    got, expected = np.asarray(got), np.asarray(expected)
    errors = np.abs(got - expected)
    tolerances = atol + rtol * np.abs(expected)
    return {"actual": got.tolist(), "reference": expected.tolist(), "absolute_error": errors.tolist(),
            "max_absolute_error": float(np.max(errors)),
            "max_tolerance_ratio": float(np.max(errors / tolerances)),
            "passed": bool(np.all(errors <= tolerances))}


def analytic_case(base: dict, target: dict) -> dict:
    energy, forces = actual(base)
    reference_energy, reference_forces = independent_harmonic(base)
    results = {"energy_reduced": comparison(energy / E0, reference_energy, target["atol"], target["rtol"]),
               "forces_reduced": comparison(forces / (E0 / L0), reference_forces, target["atol"], target["rtol"])}
    return {"id": "A01", "status": "passed" if all(x["passed"] for x in results.values()) else "failed",
            "input_sha256": definition_sha256(base), "atol": target["atol"], "rtol": target["rtol"],
            "reference_method": "Independent vectorized harmonic energy and Cartesian force closed form",
            "formula": "u=sum(i<j, k/2*(rho_ij-rho0)^2); F_i=-sum(j!=i,k*(rho_ij-rho0)*(x_i-x_j)/rho_ij)",
            "measurements": results}


def finite_difference_case(base: dict, target: dict) -> dict:
    _, forces = actual(base)
    reduced_forces = forces / (E0 / L0)
    normalizer = max(1.0, float(np.max(np.abs(reduced_forces))))
    measurements = []
    for step in target["steps"]:
        gradient = np.empty((4, 3))
        inputs = []
        for i in range(4):
            for axis in range(3):
                minus, plus = deepcopy(base), deepcopy(base)
                minus["system"]["particles"][i]["position_m"][axis] -= step * L0
                plus["system"]["particles"][i]["position_m"][axis] += step * L0
                e_minus, _ = actual(minus)
                e_plus, _ = actual(plus)
                gradient[i, axis] = (e_plus / E0 - e_minus / E0) / (2 * step)
                inputs.append({"particle_index": i, "axis": axis,
                               "minus_input_sha256": definition_sha256(minus),
                               "plus_input_sha256": definition_sha256(plus)})
        residual = float(np.max(np.abs(reduced_forces + gradient)) / normalizer)
        measurements.append({"step_reduced": step, "gradient_fd_reduced": gradient.tolist(),
                             "force_plus_gradient_fd_reduced": (reduced_forces + gradient).tolist(),
                             "normalized_max_residual": residual, "passed": residual <= target["threshold"],
                             "perturbed_inputs": inputs})
    adjacent = any(a["passed"] and b["passed"] for a, b in zip(measurements, measurements[1:]))
    return {"id": "A02", "status": "passed" if adjacent else "failed", "input_sha256": definition_sha256(base),
            "threshold": target["threshold"], "metric": target["metric"],
            "acceptance_rule": "At least two adjacent declared step sizes pass",
            "normalizer_reduced": normalizer, "actual_forces_reduced": reduced_forces.tolist(),
            "measurements": measurements}


def transformed_positions(base: dict, points: np.ndarray) -> dict:
    changed = deepcopy(base)
    for particle, point in zip(changed["system"]["particles"], points):
        particle["position_m"] = point.tolist()
    return changed


def invariance_case(base: dict, target: dict) -> dict:
    energy, forces = actual(base)
    u, f = energy / E0, forces / (E0 / L0)
    points = np.array([p["position_m"] for p in base["system"]["particles"]])
    energy_normalizer = max(1.0, abs(u))
    force_normalizer = max(1.0, float(np.max(np.abs(f))))
    axis = np.array([1.0, 2.0, -1.0]) / math.sqrt(6.0)
    cross = np.array([[0.0, -axis[2], axis[1]], [axis[2], 0.0, -axis[0]], [-axis[1], axis[0], 0.0]])
    angle = 0.713
    rotation = math.cos(angle) * np.eye(3) + (1 - math.cos(angle)) * np.outer(axis, axis) + math.sin(angle) * cross
    translation = np.array([2.1, -1.3, 0.7]) * L0
    permutation = [2, 0, 3, 1]
    permuted = deepcopy(base)
    permuted["system"]["particles"] = [deepcopy(base["system"]["particles"][i]) for i in permutation]
    variants = [("translation", transformed_positions(base, points + translation), f),
                ("rotation", transformed_positions(base, points @ rotation.T), f @ rotation.T),
                ("permutation", permuted, f[permutation])]
    measurements = []
    for name, changed, expected_forces in variants:
        changed_energy, changed_forces = actual(changed)
        energy_residual = abs(changed_energy / E0 - u) / energy_normalizer
        force_delta = changed_forces / (E0 / L0) - expected_forces
        force_residual = float(np.max(np.abs(force_delta))) / force_normalizer
        measurements.append({"name": name, "input_sha256": definition_sha256(changed),
                             "actual_energy_reduced": changed_energy / E0, "reference_energy_reduced": u,
                             "actual_forces_reduced": (changed_forces / (E0 / L0)).tolist(),
                             "reference_forces_reduced": expected_forces.tolist(),
                             "force_residual_reduced": force_delta.tolist(),
                             "normalized_energy_residual": energy_residual,
                             "normalized_force_residual": force_residual,
                             "passed": max(energy_residual, force_residual) <= target["threshold"]})
    net_force = np.sum(forces, axis=0) / (E0 / L0)
    net_torque = np.sum(np.cross(points, forces), axis=0) / E0
    for name, residual in (("net_internal_force", net_force), ("net_internal_torque", net_torque)):
        value = float(np.max(np.abs(residual)))
        measurements.append({"name": name, "actual_reduced": residual.tolist(), "reference_reduced": [0.0] * 3,
                             "normalized_max_residual": value, "passed": value <= target["threshold"]})
    return {"id": "A03", "status": "passed" if all(x["passed"] for x in measurements) else "failed",
            "input_sha256": definition_sha256(base), "threshold": target["threshold"],
            "energy_normalizer_reduced": energy_normalizer, "force_normalizer_reduced": force_normalizer,
            "net_force_scale_n": E0 / L0, "net_torque_scale_j": E0,
            "translation_reduced": (translation / L0).tolist(), "rotation_matrix": rotation.tolist(),
            "permutation": permutation, "measurements": measurements}


def unit_case(base: dict, target: dict) -> dict:
    changed = deepcopy(base)
    changed["scales"] = {"length_m": 2 * L0, "energy_j": 5 * E0}
    changed["system"]["potential"]["parameters"] = {"k": K * 4 / 5, "rho0": RHO0 / 2}
    validate_definition(changed)
    energy, forces = actual(base)
    new_energy, new_forces = actual(changed)
    measurements = {"energy_in_baseline_units": comparison(new_energy / E0, energy / E0, target["atol"], target["rtol"]),
                    "forces_in_baseline_units": comparison(new_forces / (E0 / L0), forces / (E0 / L0), target["atol"], target["rtol"])}
    return {"id": "SI_EQUIVALENCE", "status": "passed" if all(x["passed"] for x in measurements.values()) else "failed",
            "baseline_input_sha256": definition_sha256(base), "equivalent_input_sha256": definition_sha256(changed),
            "equivalent_definition": changed, "atol": target["atol"], "rtol": target["rtol"],
            "reference_method": "Same SI coordinates with L0'=2*L0, E0'=5*E0, k'=4*k/5, rho0'=rho0/2",
            "common_energy_scale_j": E0, "common_force_scale_n": E0 / L0,
            "measurements": measurements}


def source_record() -> dict:
    files = sorted((ROOT / "src" / "quanta").glob("*.py")) + [Path(__file__).resolve()]
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    record = {"files_sha256": hashes, "source_set_sha256": hashlib.sha256(canonical_bytes(hashes)).hexdigest(),
              "source_set_hash_rule": "RFC 8785 of the relative-path to raw-file-SHA256 map; report excluded"}
    try:
        record["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).splitlines()
        record["git_worktree_dirty"] = bool(status)
        record["git_worktree_status"] = status
    except (OSError, subprocess.CalledProcessError):
        record["git_head"] = None
        record["git_worktree_dirty"] = None
    return record


def locked_environment() -> dict:
    """Record all locked distributions, beyond the numerical library baseline."""
    observed = environment_report()
    lock = json.loads((ROOT / "requirements.lock.json").read_text())
    installed = {}
    for package in lock["packages"]:
        try:
            installed[package["name"]] = version(package["name"])
        except PackageNotFoundError:
            installed[package["name"]] = None
        if installed[package["name"]] != package["version"]:
            observed["errors"].append({"code": "ENV_LOCK", "path": "/locked_distributions/" + package["name"],
                                       "message": "Installed version differs from the exact dependency lock."})
    for filename, field in (("requirements.in", "direct_requirements_sha256"),
                            ("requirements.lock.txt", "requirements_lock_sha256")):
        if hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() != lock[field]:
            observed["errors"].append({"code": "ENV_LOCK", "path": "/" + filename,
                                       "message": "Dependency input or lock changed after lock generation."})
    observed["locked_distributions"] = installed
    observed["requirements_lock_sha256"] = lock["requirements_lock_sha256"]
    observed["valid"] = not observed["errors"]
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write actual measurements to this JSON file")
    args = parser.parse_args()
    base = definition()
    plan = json.loads((ROOT / "contracts/v0.2.0/validation_manifest.json").read_text())
    targets = {case["id"]: case for case in plan["cases"]}
    environment = locked_environment()
    results = []
    for case_id, measure, target in (("A01", analytic_case, targets["A01"]),
                                     ("A02", finite_difference_case, targets["A02"]),
                                     ("A03", invariance_case, targets["A03"]),
                                     ("SI_EQUIVALENCE", unit_case, targets["A01"])):
        try:
            validate_definition(base)
            result = measure(base, target)
            json.dumps(result, allow_nan=False)
        except Exception as exc:
            result = {"id": case_id, "status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
        results.append(result)
    passed = environment["valid"] and all(case["status"] == "passed" for case in results)
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
              "status": "passed" if passed else "failed", "package_version": __version__,
              "scope": "Named smooth harmonic pair benchmarks for one-configuration energy_forces only",
              "baseline_definition": base, "baseline_input_sha256": definition_sha256(base),
              "acceptance_plan": {"path": "contracts/v0.2.0/validation_manifest.json",
                                  "sha256": hashlib.sha256((ROOT / "contracts/v0.2.0/validation_manifest.json").read_bytes()).hexdigest()},
              "cases": results, "environment": environment, "code_source": source_record(),
              "physical_validation_status": "unvalidated", "A04_status": "not_executed",
              "limitations": ["Thresholds apply to the declared smooth, well-scaled inputs only.",
                              "This report does not verify all AST operations, optimization, other modules, or agreement with experiments."]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(args.output),
                          "cases": {case["id"]: case["status"] for case in results}}))
    else:
        print(encoded, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
