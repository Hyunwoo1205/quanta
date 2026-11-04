"""Independent expansion and identity checks for the immutable submission plan."""
import copy
import hashlib
import itertools
import json
import uuid

import pytest
import rfc8785

from quanta.planning import PlanningError, plan_experiment, step_bindings
from quanta.registry import ContractRegistry


SCIENTIFIC = ("unit_system", "scales", "system", "numerics", "extensions")


def digest(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def one_evaluation(pair):
    pair = copy.deepcopy(pair)
    pair["definition"]["protocol"]["steps"] = [
        {"step_id": "measure", "operation": "energy_forces", "source": "initial", "overrides": []}]
    pair["definition"]["observables"] = ["energy"]
    return pair


def test_plan_cartesian_order_and_branch_science_match_manual_assignments(pair):
    authored = one_evaluation(pair)
    axes = [
        {"path": "/system/potential/parameters/k", "values": [2, 4]},
        {"path": "/system/potential/parameters/rho0", "values": [0.8, 1.0]}]
    authored["definition"]["protocol"]["sweep"]["axes"] = axes
    before = copy.deepcopy(authored)
    report = plan_experiment(authored)
    assert report["valid"], report["errors"]
    plan = report["frozen_plan"]
    assert set(plan) == {"contract_version", "input_sha256", "branch_bases", "expanded_steps", "frozen_bindings"}
    assert report["input_sha256"] == digest(before["definition"])
    assert report["resolved_input_sha256"] == digest(plan)
    expected_values = list(itertools.product(axes[0]["values"], axes[1]["values"]))
    assert len(report["branch_definitions"]) == len(plan["branch_bases"]) == len(expected_values)
    for index, ((k, rho0), base, full) in enumerate(zip(expected_values, plan["branch_bases"], report["branch_definitions"])):
        expected = {name: copy.deepcopy(before["definition"][name]) for name in SCIENTIFIC}
        expected["system"]["potential"]["parameters"].update(k=k, rho0=rho0)
        assert base["branch_index"] == index
        assert base["definition"] == expected
        assert {name: full[name] for name in SCIENTIFIC} == expected
        assert base["sweep_assignments"] == [
            {"axis_index": 0, "value_index": index // 2, "path": axes[0]["path"], "value": k},
            {"axis_index": 1, "value_index": index % 2, "path": axes[1]["path"], "value": rho0}]
    assert [(s["branch_index"], s["step_index"], s["step_id"]) for s in plan["expanded_steps"]] == [
        (index, 0, "measure") for index in range(4)]
    assert authored == before


def test_plan_keeps_future_sources_symbolic_and_does_not_inject_step_overrides(pair):
    pair["definition"]["protocol"]["steps"][0]["overrides"] = [
        {"path": "/system/potential/parameters/k", "value": 4}]
    before = copy.deepcopy(pair)
    report = plan_experiment(pair)
    assert report["valid"], report["errors"]
    plan = report["frozen_plan"]
    assert plan["branch_bases"][0]["definition"]["system"]["potential"]["parameters"]["k"] == 2
    assert plan["expanded_steps"][0]["source_alias"] == "initial"
    assert plan["expanded_steps"][0]["source_output_port"] is None
    assert plan["expanded_steps"][1]["source_alias"] == "evaluate"
    assert plan["expanded_steps"][1]["source_output_port"] == "configuration_out"
    expected_fields = {"branch_index", "step_index", "step_id", "operation", "source_alias",
                       "source_output_port", "target_input_port", "overrides", "active_observable_refs"}
    assert all(set(step) == expected_fields for step in plan["expanded_steps"])
    assert not {"states", "run_id", "state_content_hashes", "runtime_evidence", "execution_fingerprint"} & plan.keys()
    assert pair == before


def test_envelope_metadata_does_not_change_scientific_or_plan_identity(pair):
    pair = one_evaluation(pair)
    first = plan_experiment(pair)
    pair.update(title="Different label", experiment_id=str(uuid.uuid4()), revision_id=str(uuid.uuid4()),
                created_at="2026-11-04T12:34:56+09:00")
    second = plan_experiment(pair)
    assert first["valid"] and second["valid"]
    assert first["input_sha256"] == second["input_sha256"]
    assert first["resolved_input_sha256"] == second["resolved_input_sha256"]
    assert first["frozen_plan"] == second["frozen_plan"]
    assert first["experiment"]["revision_id"] != second["experiment"]["revision_id"]


def test_authored_array_order_and_observable_selection_remain_distinct(pair):
    first = one_evaluation(pair)
    first["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": [2, 4]}]
    changed = copy.deepcopy(first)
    changed["definition"]["protocol"]["sweep"]["axes"][0]["values"].reverse()
    a, b = plan_experiment(first), plan_experiment(changed)
    assert a["valid"] and b["valid"]
    assert a["input_sha256"] != b["input_sha256"]
    assert a["resolved_input_sha256"] != b["resolved_input_sha256"]
    changed = copy.deepcopy(first)
    changed["definition"]["observables"] = ["forces"]
    c = plan_experiment(changed)
    assert c["valid"]
    assert a["resolved_input_sha256"] != c["resolved_input_sha256"]
    assert a["frozen_plan"]["branch_bases"] == c["frozen_plan"]["branch_bases"]


def test_empty_active_observables_are_preserved_in_the_plan(pair):
    pair["definition"]["observables"] = ["optimization_history"]
    report = plan_experiment(pair)
    assert report["valid"], report["errors"]
    steps = report["frozen_plan"]["expanded_steps"]
    assert steps[0]["active_observable_refs"] == []
    assert [ref["observable_id"] for ref in steps[1]["active_observable_refs"]] == ["optimization_history"]


def test_plan_bindings_resolve_to_exact_captured_bytes_and_sorted_sets(pair):
    report = plan_experiment(pair)
    assert report["valid"], report["errors"]
    captured = report["captured_artifacts"]
    for sha, text in captured.items():
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == sha
    bindings = report["frozen_plan"]["frozen_bindings"]
    assert set(bindings) == {"registry_binding", "module_bindings", "observable_bindings", "schema_bindings", "engine_bindings"}
    registry = ContractRegistry()
    assert bindings["registry_binding"]["registry_snapshot_sha256"] == hashlib.sha256(registry.raw_bytes["registry.json"]).hexdigest()
    assert captured[bindings["registry_binding"]["registry_snapshot_sha256"]].encode() == registry.raw_bytes["registry.json"]
    sorting = {"module_bindings": ("module_id", "module_version"),
               "observable_bindings": ("module_id", "module_version", "observable_id", "observable_version"),
               "schema_bindings": ("schema_ref",), "engine_bindings": ("module_id", "module_version", "operation")}
    for name, keys in sorting.items():
        assert bindings[name] == sorted(bindings[name], key=lambda item: tuple(item[k] for k in keys))
        for item in bindings[name]:
            sha_key = "schema_sha256" if name == "schema_bindings" else ("implementation_manifest_sha256" if name == "engine_bindings" else "manifest_sha256")
            assert item[sha_key] in captured
            if name == "schema_bindings":
                filename = item["schema_ref"].split("#")[0]
                assert captured[item[sha_key]].encode() == registry.raw_bytes[filename]
            else:
                json.loads(captured[item[sha_key]])
    assert all(sha in captured for sha in report["execution_manifests"].values())


def test_invalid_input_or_excess_expansion_cannot_acquire_a_plan(pair):
    pair["definition"]["protocol"]["sweep"]["axes"] = [
        {"path": "/system/potential/parameters/k", "values": list(range(1, 10))}]
    report = plan_experiment(pair)
    assert not report["valid"]
    assert report["resolved_input_sha256"] is None
    assert report["frozen_plan"] is None
    assert any(error["code"] == "RESOURCE_LIMIT" for error in report["errors"])
    malformed = plan_experiment('{"schema_version":"0.2.0","schema_version":"0.2.0"}')
    assert not malformed["valid"]
    assert malformed["input_sha256"] is None and malformed["resolved_input_sha256"] is None


def test_preparation_cannot_replace_a_captured_module_manifest(pair):
    registry = ContractRegistry()
    report = plan_experiment(pair, registry=registry)
    assert report["valid"], report["errors"]
    frozen = report["frozen_plan"]["frozen_bindings"]
    expanded = report["frozen_plan"]["expanded_steps"][0]
    step_bindings(frozen, expanded, registry=registry)
    registry.data["modules"][0]["description"] += " altered after submission"
    with pytest.raises(PlanningError) as caught:
        step_bindings(frozen, expanded, registry=registry)
    assert caught.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"
