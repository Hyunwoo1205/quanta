"""Generic dynamics plans freeze authored science and explicit solver bindings."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785

from quanta.planning import PlanningError, plan_experiment, prepare_step, step_bindings
from quanta.registry import ContractRegistry


ROOT = Path(__file__).resolve().parents[1]


def sha(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def raw_sha(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def dynamics_experiment():
    request = json.loads((ROOT / "contracts/v0.3.1/examples/free.request.json").read_text())
    return {"schema_version": "0.4.0", "experiment_id": "11111111-1111-4111-8111-111111111111",
            "revision_id": "22222222-2222-4222-8222-222222222222", "title": "Free dynamics",
            "created_at": "2026-11-06T09:00:00Z",
            "definition": {"unit_system": "SI", "scales": request["scales"], "system": request["system"],
                           "numerics": request["numerics"], "extensions": {},
                           "protocol": {"steps": [{"step_id": "motion", "operation": "integrate",
                                                    "source": "initial", "overrides": []}],
                                        "sweep": {"axes": []}},
                           "observables": ["trajectory", "conservation_diagnostics"]}}


def assert_valid(report):
    assert report["valid"], report["errors"]
    return report


def test_explicit_generic_plan_is_single_symbolic_initial_step(dynamics_experiment):
    before = deepcopy(dynamics_experiment)
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    assert frozen["contract_version"] == "0.4.0"
    assert frozen["input_sha256"] == sha(before["definition"])
    assert report["resolved_input_sha256"] == sha(frozen)
    assert len(frozen["branch_bases"]) == len(frozen["expanded_steps"]) == 1
    step = frozen["expanded_steps"][0]
    assert step["operation"] == "integrate" and step["source_alias"] == "initial"
    assert step["target_input_port"] == "phase_in" and step["source_output_port"] is None
    assert step["overrides"] == [] and frozen["branch_bases"][0]["sweep_assignments"] == []
    assert not {"states", "result", "run_id", "runtime_evidence", "execution_fingerprint"} & frozen.keys()
    assert dynamics_experiment == before


def test_metadata_is_not_science_but_velocity_and_duration_are(dynamics_experiment):
    first = assert_valid(plan_experiment(dynamics_experiment))
    changed = deepcopy(dynamics_experiment)
    changed.update(title="Another title", revision_id="33333333-3333-4333-8333-333333333333",
                   created_at="2026-11-06T10:00:00Z")
    renamed = assert_valid(plan_experiment(changed))
    assert first["input_sha256"] == renamed["input_sha256"]
    assert first["resolved_input_sha256"] == renamed["resolved_input_sha256"]
    for change in (lambda d: d["system"]["particles"][0]["velocity_m_per_s"].__setitem__(0, 0.25),
                   lambda d: d["numerics"].__setitem__("dt_s", 0.0625)):
        changed = deepcopy(dynamics_experiment)
        change(changed["definition"])
        actual = assert_valid(plan_experiment(changed))
        assert actual["input_sha256"] != first["input_sha256"]
        assert actual["resolved_input_sha256"] != first["resolved_input_sha256"]


def test_plan_captures_adapter_and_complete_exact_solver_bundle(dynamics_experiment):
    report = assert_valid(plan_experiment(dynamics_experiment))
    captured = report["captured_artifacts"]
    engine_ref = report["frozen_plan"]["frozen_bindings"]["engine_bindings"][0]["implementation_manifest_sha256"]
    engine = json.loads(captured[engine_ref])
    assert engine["entry_point"] == "quanta.dynamics_workflow.execute_dynamics"
    adapter = engine["adapter_binding"]
    assert adapter["adapter_id"] == "quanta.pair_dynamics.generic_adapter"
    assert adapter["adapter_version"] == "0.1.0"
    registry = ContractRegistry(contract_version="0.4.0")
    assert captured[adapter["manifest_sha256"]].encode() == registry.raw_bytes["dynamics_adapter.json"]
    solver = ContractRegistry(contract_version="0.3.1")
    expected = {**solver.raw_bytes, "SHA256SUMS.json": solver._manifest_path.read_bytes()}
    binding = engine["solver_contract_binding"]
    assert binding["contract_version"] == "0.3.1"
    assert binding["files_sha256"] == {name: raw_sha(raw) for name, raw in expected.items()}
    for name, digest in binding["files_sha256"].items():
        assert captured[digest].encode() == expected[name]
    assert binding["registry_snapshot_sha256"] == raw_sha(expected["registry.json"])
    assert binding["resource_policy_sha256"] == raw_sha(expected["resource_policy.json"])
    assert binding["digest_manifest_sha256"] == raw_sha(expected["SHA256SUMS.json"])


def test_prepared_input_binds_explicit_derived_request_and_adapter(dynamics_experiment):
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    prepared = prepare_step(report["branch_definitions"][0], frozen["expanded_steps"][0],
                            source_content_sha256="a" * 64, frozen_bindings=frozen["frozen_bindings"])
    definition = prepared["definition"]
    expected_request = {"contract_version": "0.3.1", "operation": "integrate", "initial_time_s": 0,
                        **{name: deepcopy(definition[name]) for name in ("scales", "system", "numerics")}}
    projection = prepared["step_projection"]
    assert projection["contract_version"] == "0.4.0"
    assert projection["solver_request_sha256"] == sha(expected_request)
    assert projection["source_scientific_content_sha256"] == "a" * 64
    assert prepared["resolved_input_sha256"] == sha(projection)
    engine_ref = projection["frozen_bindings"]["engine_bindings"][0]["implementation_manifest_sha256"]
    engine = json.loads(report["captured_artifacts"][engine_ref])
    assert projection["adapter_binding"] == engine["adapter_binding"]


def test_plan_and_preparation_do_not_evaluate_ad_forces(dynamics_experiment, monkeypatch):
    from quanta.pair_kernel import PairForceKernel
    def no_force(*args, **kwargs):
        raise AssertionError("An authored plan must not run a force engine")
    monkeypatch.setattr(PairForceKernel, "evaluate", no_force)
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    prepare_step(report["branch_definitions"][0], frozen["expanded_steps"][0],
                 source_content_sha256="b" * 64, frozen_bindings=frozen["frozen_bindings"])


@pytest.mark.parametrize("mutation", [
    lambda e: e.__setitem__("schema_version", "0.2.0"),
    lambda e: e.__setitem__("schema_version", "0.3.1"),
    lambda e: e["definition"]["protocol"]["steps"][0].__setitem__("source", "previous"),
    lambda e: e["definition"]["protocol"]["steps"][0]["overrides"].append({"path": "/numerics/dt_s", "value": 0.1}),
    lambda e: e["definition"]["protocol"]["steps"].append({"step_id": "again", "operation": "integrate", "source": "initial", "overrides": []}),
    lambda e: e["definition"]["protocol"]["sweep"]["axes"].append({"path": "/numerics/dt_s", "values": [0.1, 0.2]}),
    lambda e: e["definition"]["system"]["particles"][0].pop("velocity_m_per_s"),
    lambda e: e["definition"]["numerics"].__setitem__("steps", 10001),
])
def test_unsupported_inputs_do_not_acquire_a_frozen_plan(dynamics_experiment, mutation):
    mutation(dynamics_experiment)
    report = plan_experiment(dynamics_experiment)
    assert not report["valid"] and report["errors"]
    assert report["frozen_plan"] is None and report["resolved_input_sha256"] is None


def test_explicit_registry_mismatch_and_changed_frozen_engine_are_rejected(dynamics_experiment):
    mismatch = plan_experiment(dynamics_experiment, registry=ContractRegistry())
    assert not mismatch["valid"] and mismatch["errors"]
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    altered = deepcopy(frozen["frozen_bindings"])
    altered["engine_bindings"][0]["implementation_manifest_sha256"] = "0" * 64
    with pytest.raises(PlanningError) as caught:
        step_bindings(altered, frozen["expanded_steps"][0])
    assert caught.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"


def test_integral_float_numerical_carriers_remain_authored(dynamics_experiment):
    dynamics_experiment["definition"]["numerics"].update(steps=8.0, sample_stride=1.0)
    report = assert_valid(plan_experiment(dynamics_experiment))
    assert type(report["experiment"]["definition"]["numerics"]["steps"]) is float
    assert type(report["branch_definitions"][0]["numerics"]["sample_stride"]) is float


@pytest.mark.parametrize("change", [
    lambda engine: engine["solver_contract_binding"].__setitem__("resource_policy_sha256", "0" * 64),
    lambda engine: engine["solver_contract_binding"]["files_sha256"].pop("SHA256SUMS.json"),
])
def test_rehashed_solver_binding_forgery_cannot_prepare(dynamics_experiment, change):
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    bindings = deepcopy(frozen["frozen_bindings"])
    engine_binding = bindings["engine_bindings"][0]
    engine = json.loads(report["captured_artifacts"][engine_binding["implementation_manifest_sha256"]])
    change(engine)
    engine_binding["implementation_manifest_sha256"] = sha(engine)
    with pytest.raises(PlanningError) as caught:
        step_bindings(bindings, frozen["expanded_steps"][0])
    assert caught.value.code == "REGISTRY_SNAPSHOT_UNAVAILABLE"


def test_optional_observables_do_not_rewrite_solver_science(dynamics_experiment):
    first = assert_valid(plan_experiment(dynamics_experiment))
    changed = deepcopy(dynamics_experiment)
    changed["definition"]["observables"] = ["trajectory"]
    second = assert_valid(plan_experiment(changed))
    assert first["input_sha256"] != second["input_sha256"]
    requests = []
    for report in (first, second):
        frozen = report["frozen_plan"]
        prepared = prepare_step(report["branch_definitions"][0], frozen["expanded_steps"][0],
                                source_content_sha256="c" * 64, frozen_bindings=frozen["frozen_bindings"])
        request_sha = prepared["step_projection"]["solver_request_sha256"]
        assert request_sha in report["captured_artifacts"]
        requests.append(request_sha)
    assert requests[0] == requests[1]


@pytest.mark.parametrize("change", [
    lambda base, step: step["overrides"].append({"path": "/system/potential/parameters/k", "value": 2}),
    lambda base, step: step.__setitem__("operation", "relax"),
    lambda base, step: step.__setitem__("source_alias", "earlier"),
    lambda base, step: step.__setitem__("target_input_port", "configuration_in"),
    lambda base, step: step.__setitem__("step_id", "unplanned"),
    lambda base, step: step.__setitem__("branch_index", 1),
    lambda base, step: base["protocol"]["sweep"]["axes"].append({"path": "/numerics/dt_s", "values": [0.1]}),
])
def test_direct_preparation_rejects_forged_scope(dynamics_experiment, change):
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    base, step = deepcopy(report["branch_definitions"][0]), deepcopy(frozen["expanded_steps"][0])
    change(base, step)
    with pytest.raises(PlanningError):
        prepare_step(base, step, source_content_sha256="d" * 64,
                     frozen_bindings=frozen["frozen_bindings"])


@pytest.mark.parametrize("field,value", [("source_alias", "earlier"), ("overrides", [{"path": "/numerics/dt_s", "value": 0.1}]),
                                         ("target_input_port", "configuration_in"), ("branch_index", True)])
def test_direct_binding_selection_rejects_unsupported_scope(dynamics_experiment, field, value):
    report = assert_valid(plan_experiment(dynamics_experiment))
    frozen = report["frozen_plan"]
    step = deepcopy(frozen["expanded_steps"][0])
    step[field] = value
    with pytest.raises(PlanningError) as caught:
        step_bindings(frozen["frozen_bindings"], step)
    assert caught.value.code == "MODEL_UNSUPPORTED"

