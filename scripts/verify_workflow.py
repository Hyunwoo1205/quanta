#!/usr/bin/env python3
"""Measure synchronous workflow execution against declared independent oracles."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import itertools
import json
import math
from pathlib import Path
import tempfile

import rfc8785

from verify_numerics import locked_environment, source_record as numeric_source_record
from quanta import __version__
from quanta.registry import ContractRegistry

ROOT = Path(__file__).resolve().parents[1]
L0, E0 = 1e-9, 1e-19
SCIENCE = ("unit_system", "scales", "system", "numerics", "extensions")
STATE_SCIENCE = ("module_id", "module_version", "representation", "representation_version",
                 "time_kind", "physical_time", "data_schema_ref", "data", "metadata_schema_ref", "metadata")
FP_MANIFESTS = ("implementation_manifest_sha256", "dependency_manifest_sha256", "constants_manifest_sha256",
                "resource_policy_sha256", "effective_resource_profile_sha256")


def digest(value: object) -> str:
    """Use the vetted JCS library, with independent projection assembly below."""
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def projection(value: dict) -> dict:
    return {name: deepcopy(value[name]) for name in SCIENCE if name in value}


def envelope(definition: dict, title: str) -> dict:
    return {"schema_version": "0.2.0", "experiment_id": "77e77777-7777-4777-8777-777777777777",
            "revision_id": "88e88888-8888-4888-8888-888888888888", "title": title,
            "created_at": "2026-11-04T00:00:00+09:00", "definition": definition}


def pair_definition() -> dict:
    """A separate authored problem, independent of application example files."""
    return {"unit_system": "SI", "scales": {"length_m": L0, "energy_j": E0},
        "system": {"representation": "particles_3d", "module_id": "quanta.pair_static", "module_version": "0.1.0",
            "boundary": "nonperiodic", "min_distance_m": 1e-17,
            "particles": [{"id": "p1", "position_m": [0.0, 0.0, 0.0], "fixed": [True, True, True]},
                          {"id": "p2", "position_m": [1.4 * L0, 0.0, 0.0], "fixed": [False, True, True]}],
            "potential": {"expression": {"op": "mul", "args": [{"op": "const", "value": 0.5},
                {"op": "param", "name": "k"}, {"op": "pow", "arg": {"op": "sub", "args": [
                    {"op": "var", "name": "rho"}, {"op": "param", "name": "rho0"}]}, "exponent": 2}]},
                "parameters": {"k": 2.0, "rho0": 1.0}}},
        "numerics": {"solver": "lbfgsb_forward_ad", "gradient_tolerance": 1e-6,
            "energy_ftol": 1e-12, "max_iterations": 2000, "max_evaluations": 10000},
        "protocol": {"steps": [{"step_id": "measure", "operation": "energy_forces", "source": "initial", "overrides": []}],
                     "sweep": {"axes": []}},
        "observables": ["energy", "forces", "pair_energies", "final_positions", "optimization_history"],
        "extensions": {}}


def branching_experiment() -> dict:
    value = pair_definition()
    value["protocol"] = {"steps": [
        {"step_id": "equilibrate", "operation": "relax", "source": "initial",
         "overrides": [{"path": "/system/potential/parameters/k", "value": 6.0}]},
        {"step_id": "inherit", "operation": "energy_forces", "source": "equilibrate",
         "overrides": [{"path": "/system/particles/1/position_m/0", "value": 1.3 * L0}]},
        {"step_id": "reset", "operation": "energy_forces", "source": "initial", "overrides": []}],
        "sweep": {"axes": [{"path": "/system/potential/parameters/k", "values": [2.0, 4.0]},
                            {"path": "/system/potential/parameters/rho0", "values": [1.0, 1.1]}]}}
    return envelope(value, "Independent two-axis workflow reference")


def quantum_experiment() -> dict:
    value = {"unit_system": "SI", "scales": {"length_m": 1e-9, "energy_j": 1e-20},
        "system": {"representation": "quantum_grid_1d", "module_id": "quanta.quantum_stationary",
            "module_version": "0.1.0", "domain": {"a_m": 0.0, "b_m": 1e-9}, "mass_kg": 1e-30,
            "boundary": "dirichlet_zero", "potential": {"expression": {"op": "const", "value": 0.0}, "parameters": {}}},
        "numerics": {"solver": "symmetric_tridiagonal_lowest", "n_points": 63, "states": 2,
            "refinement_levels": 0, "grid_energy_atol": 1e-8, "grid_energy_rtol": 1e-3},
        "protocol": {"steps": [
            {"step_id": "first", "operation": "eigenstates", "source": "initial", "overrides": []},
            {"step_id": "second", "operation": "eigenstates", "source": "initial",
             "overrides": [{"path": "/system/mass_kg", "value": 2e-30}]}], "sweep": {"axes": []}},
        "observables": ["energies", "states", "density", "x_mean"], "extensions": {}}
    return envelope(value, "Independent stationary workflow reference")


def common_checks(report: dict, authored: dict) -> dict:
    """Reassemble scientific digests and check frozen schemas independently."""
    registry = ContractRegistry()
    result = report["result"]
    frozen = report["resolved_record"]["frozen_plan"]
    evidence = report["resolved_record"]["runtime_evidence"]
    states = {state["state_id"]: state for state in result["states"]}
    prepared = {(row["branch_index"], row["step_id"]): row for row in evidence["effective_step_inputs"]}
    expanded = {(row["branch_index"], row["step_id"]): row for row in frozen["expanded_steps"]}
    bases = {row["branch_index"]: row["definition"] for row in frozen["branch_bases"]}
    initial_refs = {row["state_ref"]: row["branch_index"] for row in evidence["initial_state_refs"]}
    hashes = report["state_content_hashes"]
    assets = report["captured_artifacts"]
    schema_valid = not list(registry.validator("result.schema.json").iter_errors(result))
    state_valid, source_links, content_valid, step_valid, selected_bindings_valid = True, True, True, True, True
    for state_id, state in states.items():
        state_valid &= not list(registry.validator("state.schema.json").iter_errors(state))
        state_valid &= not list(registry.validator(state["data_schema_ref"]).iter_errors(state["data"]))
        state_valid &= not list(registry.validator(state["metadata_schema_ref"]).iter_errors(state["metadata"]))
        producer = state["producer"]
        if producer["kind"] == "initial":
            context = bases[initial_refs[state_id]]
        else:
            context = prepared[(producer["branch_index"], producer["step_id"])]["definition"]
        content = {name: deepcopy(state[name]) for name in STATE_SCIENCE}
        content["unit_context"] = {"unit_system": context["unit_system"], "scales": context["scales"]}
        content_valid &= digest(content) == hashes[state_id]
        content_valid &= evidence["state_content_hashes"][state_id] == hashes[state_id]
        source_links &= all(parent in states for parent in state["parent_state_refs"])
    for step in result["steps"]:
        key = step["branch_index"], step["step_id"]
        if step["payload"] is not None:
            schema_valid &= not list(registry.validator(step["payload_schema_ref"]).iter_errors(step["payload"]))
        binding = step["source_binding"]
        if binding is None:
            step_valid &= step["resolved_input_sha256"] is None and step["outcome"] != "SUCCEEDED"
            continue
        entry, planned = prepared[key], expanded[key]
        source = states[binding["source_state_ref"]]
        effective = states[binding["effective_input_state_ref"]]
        source_links &= source["state_id"] != effective["state_id"]
        source_links &= all(binding[name] == planned[name] for name in
                            ("source_alias", "source_output_port", "target_input_port"))
        source_links &= effective["producer"]["kind"] == "prepared_input"
        source_links &= effective["parent_state_refs"] == [source["state_id"]]
        source_links &= effective["data"] == entry["definition"]["system"]
        supplied_bindings = entry["projection"]["frozen_bindings"]
        selected_bindings_valid &= supplied_bindings["registry_binding"] == frozen["frozen_bindings"]["registry_binding"]
        selected_bindings_valid &= supplied_bindings["observable_bindings"] == planned["active_observable_refs"]
        selected_bindings_valid &= all(item in frozen["frozen_bindings"][name] for name in
            ("module_bindings", "observable_bindings", "schema_bindings", "engine_bindings") for item in supplied_bindings[name])
        selected_bindings_valid &= all(item["operation"] == planned["operation"] for item in supplied_bindings["engine_bindings"])
        independent = {"contract_version": "0.2.0", "effective_definition": projection(entry["definition"]),
            "operation": planned["operation"], "active_observable_refs": planned["active_observable_refs"],
            "frozen_bindings": supplied_bindings, "source_scientific_content_sha256": hashes[source["state_id"]]}
        step_valid &= independent == entry["projection"]
        step_valid &= digest(independent) == step["resolved_input_sha256"] == entry["resolved_input_sha256"] == effective["resolved_input_sha256"]
        if step["outcome"] == "SUCCEEDED":
            produced = states[step["state_ref"]]
            source_links &= produced["producer"]["kind"] == "step"
            source_links &= produced["producer"]["branch_index"] == step["branch_index"]
            source_links &= produced["producer"]["step_id"] == step["step_id"]
            source_links &= produced["resolved_input_sha256"] == step["resolved_input_sha256"]
            source_links &= produced["parent_state_refs"] == [effective["state_id"]]
        else:
            source_links &= step["state_ref"] is None and step["partial"]
    manifest_valid = all(hashlib.sha256(raw.encode("utf-8")).hexdigest() == key for key, raw in assets.items())
    registered_bindings = frozen["frozen_bindings"]
    registered_valid = registered_bindings["registry_binding"]["registry_snapshot_sha256"] == hashlib.sha256(registry.raw_bytes["registry.json"]).hexdigest()
    for item in registered_bindings["module_bindings"]:
        descriptor = registry.get_module(item["module_id"], item["module_version"])
        registered_valid &= digest(descriptor) == item["manifest_sha256"]
    for item in registered_bindings["observable_bindings"]:
        descriptor = registry.get_observable(item["module_id"], item["module_version"], item["observable_id"])
        registered_valid &= digest(descriptor) == item["manifest_sha256"]
    for item in registered_bindings["schema_bindings"]:
        raw = registry.raw_bytes[item["schema_ref"].split("#", 1)[0]]
        registered_valid &= hashlib.sha256(raw).hexdigest() == item["schema_sha256"]
    symbolic = set(frozen) == {"contract_version", "input_sha256", "branch_bases", "expanded_steps", "frozen_bindings"}
    symbolic &= all(set(row) == {"branch_index", "sweep_assignments", "definition"}
                    and set(row["definition"]) == set(SCIENCE) for row in frozen["branch_bases"])
    symbolic &= all(set(row) == {"branch_index", "step_index", "step_id", "operation", "source_alias",
                    "source_output_port", "target_input_port", "overrides", "active_observable_refs"}
                    for row in frozen["expanded_steps"])
    artifact_valid = True
    for artifact in result["artifacts"]:
        raw = report["artifact_contents"][artifact["artifact_id"]].encode("utf-8")
        artifact_valid &= len(raw) == artifact["size_bytes"] and hashlib.sha256(raw).hexdigest() == artifact["sha256"]
    manifests = report["plan"]["execution_manifests"]
    fp_projection = {"contract_version": "0.2.0", "run_resolved_input_sha256": result["resolved_input_sha256"],
        **{name: manifests[name] for name in FP_MANIFESTS},
        "environment_manifest_sha256": result["provenance"]["environment_manifest_sha256"]}
    fp_valid = digest(fp_projection) == result["execution_fingerprint"]
    fp_valid &= all(fp_projection[name] in assets for name in (*FP_MANIFESTS, "environment_manifest_sha256"))
    finite = True
    try:
        json.dumps(report, allow_nan=False)
    except (ValueError, OverflowError):
        finite = False
    return {"accepted_input": report["valid"] is True, "registered_result_and_payload_schemas": bool(schema_valid),
        "registered_state_schemas": bool(state_valid), "input_digest": digest(authored["definition"]) == result["input_sha256"],
        "frozen_plan_digest": digest(frozen) == result["resolved_input_sha256"] == report["plan"]["resolved_input_sha256"],
        "frozen_plan_unchanged": frozen == report["plan"]["frozen_plan"],
        "state_content_digests": bool(content_valid), "effective_step_digests": bool(step_valid),
        "selected_frozen_bindings": bool(selected_bindings_valid), "typed_source_links": bool(source_links),
        "registered_manifest_and_schema_bindings": bool(registered_valid), "symbolic_plan_whitelists": bool(symbolic),
        "captured_exact_byte_digests": bool(manifest_valid), "artifact_exact_bytes": bool(artifact_valid),
        "execution_fingerprint": bool(fp_valid), "finite_json_export": finite,
        "physical_validation_unclaimed": result["physical_validation_status"] == "unvalidated"
            and result["physical_validation_evidence_refs"] == []}


def summary(report: dict) -> dict:
    result = report["result"]
    return {"run_id": result["run_id"], "input_sha256": result["input_sha256"],
        "resolved_input_sha256": result["resolved_input_sha256"], "execution_fingerprint": result["execution_fingerprint"],
        "execution_status": result["execution_status"], "numerical_status": result["numerical_status"],
        "resolution_status": result["resolution_status"], "state_count": len(result["states"]),
        "artifact_count": len(result["artifacts"]),
        "steps": [{"branch_index": s["branch_index"], "step_id": s["step_id"], "outcome": s["outcome"],
            "partial": s["partial"], "resolved_input_sha256": s["resolved_input_sha256"],
            "state_ref": s["state_ref"], "payload_sha256": digest(s["payload"]) if s["payload"] is not None else None}
            for s in result["steps"]]}


def harmonic_check(payload: dict, stiffness: float, rest: float) -> dict:
    delta = [payload["final_positions_m"][1][i] - payload["final_positions_m"][0][i] for i in range(3)]
    distance = math.hypot(*delta)
    rho = distance / L0
    expected_energy = 0.5 * stiffness * (rho - rest) ** 2
    force_p2 = [-stiffness * (rho - rest) * value / distance for value in delta]
    expected_force = [[-v for v in force_p2], force_p2]
    actual_energy = payload["energy_j"] / E0
    actual_force = [[v / (E0 / L0) for v in row] for row in payload["forces_n"]]
    energy_error = abs(actual_energy - expected_energy)
    force_error = max(abs(a-b) for actual, expected in zip(actual_force, expected_force) for a, b in zip(actual, expected))
    passed = energy_error <= 1e-10 + 1e-10 * abs(expected_energy)
    passed &= all(abs(a-b) <= 1e-10 + 1e-10 * abs(b)
                  for actual, expected in zip(actual_force, expected_force) for a, b in zip(actual, expected))
    return {"passed": bool(passed), "distance_reduced": rho, "energy_reduced": actual_energy,
        "reference_energy_reduced": expected_energy, "energy_absolute_error_reduced": energy_error,
        "max_force_error_reduced": force_error, "atol": 1e-10, "rtol": 1e-10}


class Measurements:
    def __init__(self):
        self.branching_input = branching_experiment()
        self.branching_report = None

    def wf01(self) -> dict:
        from quanta.workflow import run_experiment
        from quanta.planning import plan_experiment
        authored = deepcopy(self.branching_input)
        before = digest(authored)
        planned = plan_experiment(authored)
        report = run_experiment(authored)
        self.branching_report = report
        checks = common_checks(report, authored)
        result = report["result"]
        rows = {(s["branch_index"], s["step_id"]): s for s in result["steps"]}
        states = {s["state_id"]: s for s in result["states"]}
        prepared = {(p["branch_index"], p["step_id"]): p["definition"]
                    for p in report["resolved_record"]["runtime_evidence"]["effective_step_inputs"]}
        expected_pairs = list(itertools.product([2.0, 4.0], [1.0, 1.1]))
        measurements = []
        for branch, (stiffness, rest) in enumerate(expected_pairs):
            first, inherited, reset = (rows[(branch, name)] for name in ("equilibrate", "inherit", "reset"))
            source = states[inherited["source_binding"]["source_state_ref"]]
            effective = states[inherited["source_binding"]["effective_input_state_ref"]]
            p_first, p_inherited, p_reset = (prepared[(branch, name)] for name in ("equilibrate", "inherit", "reset"))
            first_check = harmonic_check(first["payload"], 6.0, rest)
            inherit_check = harmonic_check(inherited["payload"], 6.0, rest)
            reset_check = harmonic_check(reset["payload"], stiffness, rest)
            branch_checks = {
                "step_success": all(s["outcome"] == "SUCCEEDED" for s in (first, inherited, reset)),
                "sweep_then_override": p_first["system"]["potential"]["parameters"] == {"k": 6.0, "rho0": rest},
                "definition_inherited": p_inherited["system"]["potential"]["parameters"] == {"k": 6.0, "rho0": rest},
                "initial_resets_overrides": p_reset["system"]["potential"]["parameters"] == {"k": stiffness, "rho0": rest},
                "original_source_retained": source["data"]["particles"][1]["position_m"] == first["payload"]["final_positions_m"][1],
                "prepared_override_distinct": source["state_id"] != effective["state_id"]
                    and effective["data"]["particles"][1]["position_m"][0] == 1.3 * L0,
                "initial_coordinate_reset": reset["payload"]["initial_positions_m"][1][0] == 1.4 * L0,
                "rest_distance": abs(first_check["distance_reduced"] - rest) <= 1e-6,
                "free_gradient": first["payload"]["free_gradient_inf"] <= 1e-6,
                "independent_energy_forces": all(c["passed"] for c in (first_check, inherit_check, reset_check))}
            measurements.append({"branch_index": branch, "swept_parameters": {"k": stiffness, "rho0": rest},
                "checks": branch_checks, "relax": first_check, "inherit": inherit_check, "reset": reset_check})
        actual_pairs = [(b["definition"]["system"]["potential"]["parameters"]["k"],
                         b["definition"]["system"]["potential"]["parameters"]["rho0"])
                        for b in report["resolved_record"]["frozen_plan"]["branch_bases"]]
        prepared_ids = [rows[(branch, "equilibrate")]["source_binding"]["effective_input_state_ref"] for branch in (0, 2)]
        checks.update({"authored_input_unchanged": digest(authored) == before,
            "deterministic_cartesian_order": actual_pairs == expected_pairs,
            "four_branches_twelve_steps": len(actual_pairs) == 4 and len(result["steps"]) == 12,
            "plan_before_execution_same_identity": planned["resolved_input_sha256"] == result["resolved_input_sha256"],
            "equal_effective_content_distinct_provenance": prepared_ids[0] != prepared_ids[1]
                and report["state_content_hashes"][prepared_ids[0]] == report["state_content_hashes"][prepared_ids[1]],
            "original_source_content_retained_in_step_identity": rows[(0, "equilibrate")]["resolved_input_sha256"]
                != rows[(2, "equilibrate")]["resolved_input_sha256"],
            "manual_branch_oracles": all(all(row["checks"].values()) for row in measurements),
            "overall_success": result["execution_status"] == "SUCCEEDED" and not result["partial"]})
        return {"id": "WF01", "status": "passed" if all(checks.values()) else "failed", "checks": checks,
            "reference_method": "Manual Cartesian ordering, explicit inheritance/reset rules and independent harmonic closed form",
            "input": authored, "measurements": measurements, "run": summary(report)}

    def wf02(self) -> dict:
        from quanta.workflow import run_experiment
        value = pair_definition()
        value["observables"] = ["optimization_history"]
        value["protocol"]["steps"] = [
            {"step_id": "first", "operation": "energy_forces", "source": "initial", "overrides": []},
            {"step_id": "second", "operation": "relax", "source": "first", "overrides": []}]
        authored = envelope(value, "Independent empty-active-observable reference")
        report = run_experiment(authored)
        checks = common_checks(report, authored)
        steps = report["result"]["steps"]
        planned = report["resolved_record"]["frozen_plan"]["expanded_steps"]
        checks.update({"empty_active_selection_is_executable": steps[0]["outcome"] == "SUCCEEDED"
            and planned[0]["active_observable_refs"] == [],
            "mandatory_payload_preserved": {"energy_j", "forces_n", "final_positions_m", "diagnostics"} <= steps[0]["payload"].keys(),
            "unrequested_optional_outputs_absent": "optimization_history" not in steps[0]["payload"]
                and "pair_energies" not in steps[0]["payload"],
            "eligible_history_returned": "optimization_history" in steps[1]["payload"],
            "overall_success": report["result"]["execution_status"] == "SUCCEEDED"})
        return {"id": "WF02", "status": "passed" if all(checks.values()) else "failed", "checks": checks,
            "reference_method": "Mandatory core output is independent of the empty per-step optional selection",
            "input": authored, "run": summary(report)}

    def wf03(self) -> dict:
        from quanta.workflow import run_experiment
        value = pair_definition()
        value["numerics"]["max_evaluations"] = 1
        value["protocol"]["steps"] = [
            {"step_id": "limited", "operation": "relax", "source": "initial", "overrides": []},
            {"step_id": "dependent", "operation": "energy_forces", "source": "limited", "overrides": []},
            {"step_id": "independent", "operation": "energy_forces", "source": "initial", "overrides": []}]
        authored = envelope(value, "Independent partial and dependency reference")
        report = run_experiment(authored)
        checks = common_checks(report, authored)
        result = report["result"]
        limited, skipped, independent = result["steps"]
        checks.update({"failed_run_is_partial": result["execution_status"] == "FAILED" and result["partial"],
            "last_valid_partial_payload_kept": limited["outcome"] == "FAILED" and limited["partial"]
                and limited["payload"] is not None and limited["payload"]["evaluations"] == 1,
            "partial_not_promoted": limited["state_ref"] is None
                and not any(s["producer"].get("kind") == "step" and s["producer"].get("step_id") == "limited" for s in result["states"]),
            "dependent_skipped_without_fabricated_preparation": skipped["outcome"] == "SKIPPED"
                and skipped["state_ref"] is None and skipped["source_binding"] is None and skipped["resolved_input_sha256"] is None,
            "independent_initial_step_continues": independent["outcome"] == "SUCCEEDED" and independent["state_ref"] is not None,
            "resource_reason_recorded": any(e["code"] == "RESOURCE_LIMIT" and e["step_id"] == "limited" for e in result["errors"]),
            "independent_energy_forces": harmonic_check(independent["payload"], 2.0, 1.0)["passed"]})
        return {"id": "WF03", "status": "passed" if all(checks.values()) else "failed", "checks": checks,
            "reference_method": "Real one-evaluation budget exhaustion, explicit dependent skip and initial-source continuation",
            "input": authored, "run": summary(report)}

    def wf04(self) -> dict:
        from quanta.workflow import run_experiment
        authored = quantum_experiment()
        report = run_experiment(authored)
        checks = common_checks(report, authored)
        hbar = 6.62607015e-34 / (2 * math.pi)
        n, width, scale = 63, 1e-9, 1e-20
        dx = width / (n + 1)
        observations = []
        for step, mass in zip(report["result"]["steps"], (1e-30, 2e-30)):
            references = [4 * hbar**2 / (2 * mass * dx**2) * math.sin(j * math.pi / (2 * (n + 1)))**2 for j in (1, 2)]
            actual = step["payload"]["energies_j"]
            errors = [abs(a-b) / scale for a, b in zip(actual, references)]
            passed = all(error <= 1e-10 + 1e-8 * abs(ref / scale) for error, ref in zip(errors, references))
            observations.append({"step_id": step["step_id"], "mass_kg": mass, "energies_j": actual,
                "reference_energies_j": references, "absolute_errors_reduced": errors, "passed": passed})
        checks.update({"two_independent_initial_steps": all(s["source_binding"]["source_alias"] == "initial"
            and s["outcome"] == "SUCCEEDED" for s in report["result"]["steps"]),
            "independent_discrete_spectrum": all(o["passed"] for o in observations),
            "resolution_not_claimed_without_refinement": all(s["resolution_status"] == "not_checked" for s in report["result"]["steps"]),
            "overall_success": report["result"]["execution_status"] == "SUCCEEDED"})
        return {"id": "WF04", "status": "passed" if all(checks.values()) else "failed", "checks": checks,
            "reference_method": "Closed-form discrete zero-potential spectrum with independent initial mass override",
            "input": authored, "measurements": observations, "run": summary(report)}

    def wf05(self) -> dict:
        from quanta.run_store import write_bundle, read_bundle, replay_bundle
        report = self.branching_report
        if report is None:
            raise ValueError("WF01 must produce the source run for the replay check")
        with tempfile.TemporaryDirectory(prefix="quanta-workflow-measure-") as temp:
            directory = Path(temp) / "original"
            write_bundle(report, directory)
            restored = read_bundle(directory)
            replayed = replay_bundle(directory)
            checks = common_checks(replayed, self.branching_input)
            original, replay = report["result"], replayed["result"]
            original_content = [report["state_content_hashes"][s["state_id"]] for s in original["states"]]
            replay_content = [replayed["state_content_hashes"][s["state_id"]] for s in replay["states"]]
            checks.update({"bundle_restores_exact_report": restored == report,
                "new_run_identity": original["run_id"] != replay["run_id"],
                "new_state_identities": not ({s["state_id"] for s in original["states"]} & {s["state_id"] for s in replay["states"]}),
                "authored_and_plan_hashes_preserved": original["input_sha256"] == replay["input_sha256"]
                    and original["resolved_input_sha256"] == replay["resolved_input_sha256"],
                "same_actual_environment_same_fingerprint": original["execution_fingerprint"] == replay["execution_fingerprint"],
                "effective_step_hashes_preserved": [s["resolved_input_sha256"] for s in original["steps"]] == [s["resolved_input_sha256"] for s in replay["steps"]],
                "scientific_state_contents_preserved": original_content == replay_content,
                "replay_provenance": replay["provenance"]["replay_of"] == original["run_id"],
                "replay_success": replay["execution_status"] == "SUCCEEDED"})
            assets = sorted(p for p in (directory / "assets").rglob("*") if p.is_file())
            if not assets:
                raise ValueError("Saved bundle did not expose any content-addressed assets")
            chosen = assets[0]
            chosen.write_bytes(chosen.read_bytes() + b"\n")
            rejected = False
            try:
                read_bundle(directory)
            except (ValueError, OSError):
                rejected = True
            checks["tampered_asset_rejected"] = rejected
        return {"id": "WF05", "status": "passed" if all(checks.values()) else "failed", "checks": checks,
            "reference_method": "Persisted exact-byte round trip and actual replay with new IDs but stable scientific identities",
            "original_run": summary(report), "replayed_run": summary(replayed)}

    def wf06(self) -> dict:
        from quanta.workflow import run_experiment
        candidates = []
        cap = pair_definition()
        cap["protocol"]["steps"] = [{"step_id": name, "operation": "energy_forces", "source": "initial", "overrides": []}
                                     for name in ("one", "two")]
        cap["observables"] = ["energy"]
        cap["protocol"]["sweep"]["axes"] = [{"path": "/system/potential/parameters/k", "values": list(range(1, 10))}]
        candidates.append(("eighteen_expanded_steps", envelope(cap, "Resource refusal reference"), "RESOURCE_LIMIT"))
        bad_domain = pair_definition()
        bad_domain["observables"] = ["energy"]
        bad_domain["system"]["particles"][1]["position_m"] = [0.0, 0.0, 0.0]
        candidates.append(("initial_collision", envelope(bad_domain, "Domain refusal reference"), "INPUT_SEMANTIC"))
        unknown = pair_definition()
        unknown["observables"] = ["energy"]
        unknown["system"]["module_version"] = "9.9.9"
        candidates.append(("unknown_exact_version", envelope(unknown, "Support refusal reference"), "MODEL_UNSUPPORTED"))
        incompatible = quantum_experiment()
        incompatible["definition"]["protocol"]["steps"][1]["source"] = "first"
        candidates.append(("solution_is_not_configuration", incompatible, "PORT_INCOMPATIBLE"))
        rows = []
        for name, authored, expected_code in candidates:
            before = digest(authored)
            report = run_experiment(authored)
            errors = report["errors"]
            checks = {"rejected_before_run": report["valid"] is False and report.get("result") is None,
                "expected_reason": any(error["code"] == expected_code for error in errors),
                "authored_input_unchanged": before == digest(authored)}
            rows.append({"case": name, "expected_error_code": expected_code, "checks": checks,
                "errors": errors, "input": authored})
        checks = {"all_preflight_refusals": all(all(row["checks"].values()) for row in rows)}
        return {"id": "WF06", "status": "passed" if all(checks.values()) else "failed", "checks": checks,
            "reference_method": "Invalid input, unsupported version, incompatible source and expanded-step cap refusal before dispatch",
            "measurements": rows}


def source_record() -> dict:
    record = numeric_source_record()
    path = Path(__file__).resolve()
    record["files_sha256"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    record["source_set_sha256"] = digest(record["files_sha256"])
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write actual synchronous workflow measurements to this JSON file")
    args = parser.parse_args()
    environment = locked_environment()
    measurements = Measurements()
    cases = []
    for method in (measurements.wf01, measurements.wf02, measurements.wf03,
                   measurements.wf04, measurements.wf05, measurements.wf06):
        try:
            case = method()
            json.dumps(case, allow_nan=False)
        except Exception as exc:
            case = {"id": method.__name__.upper(), "status": "failed", "error_type": type(exc).__name__, "error": str(exc)[:500]}
        cases.append(case)
    plan_path = ROOT / "contracts/v0.2.0/validation_manifest.json"
    targets = json.loads(plan_path.read_text())["cases"]
    passed = environment["valid"] and all(case["status"] == "passed" for case in cases)
    report = {"report_version": "1.0.0", "measured_at": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if passed else "failed", "package_version": __version__,
        "scope": "Declared synchronous workflow, hash, source and persisted-replay checks only",
        "acceptance_plan": {"path": str(plan_path.relative_to(ROOT)), "sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            "cases_at_plan_snapshot": [case for case in targets if case["id"] in {"C01", "C02", "C03", "C04"}],
            "coverage": {"C01": "Partial: authored immutability, exact scientific identities, persisted replay and finite JSON",
                "C02": "Synchronous source/override/sweep ordering and expanded-step cap",
                "C03": "not_executed: HTTP idempotency, cancellation and races are outside this engine",
                "C04": "Partial: invalid geometry, unknown version, incompatible source, budget and corrupt bundle assets"}},
        "measurement_metadata": {"origin": "actual_executed_checks", "case_namespace": "WF01--WF06",
            "reference_policy": "Independent authored inputs, Cartesian enumeration, closed-form energies/forces and explicit JCS hash projections",
            "state_storage": "Declared inputs, selected observations, IDs and digests; full runs are reproducible from inputs"},
        "cases": cases, "environment": environment, "code_source": source_record(),
        "physical_validation_status": "unvalidated",
        "limitations": ["These checks cover the declared synchronous execution paths only.",
            "HTTP authentication, queues, cancellation, idempotency and checkpoint resume were not executed.",
            "Replay uses matching trusted installed implementations; captured source text is never executed.",
            "No new physical model, implicit conversion, physical coupling or experimental accuracy is certified."]}
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
