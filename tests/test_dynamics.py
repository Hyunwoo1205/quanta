"""Accepted full-step boundaries, explicit failure, and trusted callback behavior."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from quanta.autodiff import CalculationError
import quanta.dynamics as dynamics
import quanta.dynamics_results as results


ROOT = Path(__file__).resolve().parents[1]


def request(name="free"):
    return json.loads((ROOT/"contracts/v0.3.1/examples"/(name+".request.json")).read_text())


def codes(report):
    return {issue["code"] for issue in report["errors"]}


def assert_failed(report, code):
    assert report["execution_status"] == "FAILED", report["errors"]
    assert code in codes(report), report["errors"]
    assert report["final_state"] is None


def test_old_validation_only_request_cannot_be_silently_integrated():
    value = request()
    value["contract_version"] = "0.3.0"
    report = dynamics.integrate_dynamics_request(value)
    assert_failed(report, "MODEL_UNSUPPORTED")
    assert report["input_validation_status"] == "failed"
    assert not report["initial_force_evaluation_performed"]
    assert not report["dynamics_simulation_executed"]
    assert report["payload"] is None


def test_free_motion_publishes_synchronized_state_without_mutating_input():
    value = request()
    before = copy.deepcopy(value)
    report = dynamics.integrate_dynamics_request(value)
    assert report["execution_status"] == "SUCCEEDED", report["errors"]
    assert value == before
    assert not report["partial"]
    assert report["numerical_status"] == "pass"
    assert report["resolution_status"] == "not_checked"
    assert report["physical_validation_status"] == "unvalidated"
    leg = report["payload"]["legs"][0]
    assert leg["completed_steps"] == 8
    assert leg["force_evaluations"] == leg["completed_force_evaluations"] == 9
    last = leg["sampled_frames"][-1]
    expected = [[q+v for q,v in zip(p["position_m"],p["velocity_m_per_s"])]
                for p in value["system"]["particles"]]
    assert last["positions_m"] == expected
    assert last["velocities_m_per_s"] == [p["velocity_m_per_s"] for p in value["system"]["particles"]]
    assert last["time_s"] == 1
    assert report["final_state"]["data"]["time_s"] == 1
    assert report["final_state"]["data"]["system"]["particles"][0]["position_m"] == expected[0]
    assert not {"run_id","state_id"} & report["final_state"].keys()


def test_refinement_preserves_primary_and_exact_sampled_clocks():
    value = request()
    value["numerics"].update(refinement="halving_2",sample_stride=3)
    report = dynamics.integrate_dynamics_request(value)
    assert report["execution_status"] == "SUCCEEDED", report["errors"]
    legs = report["payload"]["legs"]
    assert [leg["refinement_factor"] for leg in legs] == [1,2,4]
    assert sum(leg["force_evaluations"] for leg in legs) == 7*8+3
    for factor,leg in zip([1,2,4],legs):
        assert [frame["step_index"] for frame in leg["sampled_frames"]] == [factor*j for j in [0,3,6,8]]
        assert [frame["time_s"] for frame in leg["sampled_frames"]] == [0,.375,.75,1]
    assert report["final_state"]["data"]["system"]["particles"][0]["position_m"] == legs[0]["sampled_frames"][-1]["positions_m"][0]


def test_safe_endpoints_do_not_hide_a_drift_segment_crossing():
    value = request()
    value["numerics"].update(dt_s=1,steps=1)
    for p,x,v in zip(value["system"]["particles"],[-1,1],[2,-2]):
        p["position_m"],p["velocity_m_per_s"] = [x,0,0],[v,0,0]
    report = dynamics.integrate_dynamics_request(value)
    assert_failed(report,"EXPRESSION_DOMAIN")
    assert report["partial"] and report["dynamics_simulation_executed"]
    leg = report["payload"]["legs"][0]
    assert leg["completed_steps"] == 0
    assert leg["force_evaluations"] == 1
    assert [frame["step_index"] for frame in leg["sampled_frames"]] == [0]
    assert leg["sampled_frames"][0]["positions_m"] == [[-1,0,0],[1,0,0]]
    assert report["errors"][0]["details"]["guard"] == "numerical_drift_segment_not_physical_collision_time"


def test_initial_domain_failure_has_no_trajectory_or_final_state():
    value = request()
    value["system"]["potential"]["expression"] = {"op":"log","arg":{"op":"const","value":-1}}
    report = dynamics.integrate_dynamics_request(value)
    assert_failed(report,"EXPRESSION_DOMAIN")
    assert report["payload"] is None and not report["partial"]
    assert not report["dynamics_simulation_executed"]


def test_force_failure_retains_only_last_full_step_with_reserved_terminal_frame(monkeypatch):
    value = request()
    value["numerics"]["sample_stride"] = 3
    factory = dynamics._kernel
    def failing_factory(authored):
        kernel = factory(authored)
        evaluate = kernel.evaluate
        calls = 0
        def failing_evaluate(*args,**kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise CalculationError("Injected trial-domain failure",code="EXPRESSION_DOMAIN",path="/system/potential")
            return evaluate(*args,**kwargs)
        return SimpleNamespace(evaluate=failing_evaluate)
    monkeypatch.setattr(dynamics,"_kernel",failing_factory)
    report = dynamics.integrate_dynamics_request(value)
    assert_failed(report,"EXPRESSION_DOMAIN")
    assert report["partial"]
    leg = report["payload"]["legs"][0]
    assert leg["completed_steps"] == 1
    assert leg["force_evaluations"] == 3
    assert leg["completed_force_evaluations"] == 2
    assert [frame["step_index"] for frame in leg["sampled_frames"]] == [0,1]
    assert leg["sampled_frames"][-1]["time_s"] == .125
    assert leg["sampled_frames"][-1]["velocities_m_per_s"] == [p["velocity_m_per_s"] for p in value["system"]["particles"]]


def test_conservation_failure_waits_for_all_finite_legs_then_refuses_final_state():
    value = request("harmonic-refinement")
    value["numerics"]["energy_drift_atol"] = 0
    report = dynamics.integrate_dynamics_request(value)
    assert_failed(report,"NUM_NOT_CONVERGED")
    assert report["numerical_status"] == "not_converged"
    assert report["partial"]
    assert [leg["completed_steps"] for leg in report["payload"]["legs"]] == [20,40,80]
    assert all(leg["stop_reason"] == "completed" for leg in report["payload"]["legs"])


def test_refinement_tolerance_failure_cannot_replace_primary_with_fine_trajectory():
    value = request("harmonic-refinement")
    value["numerics"].update(state_atol=1e-15,state_rtol=0)
    report = dynamics.integrate_dynamics_request(value)
    assert_failed(report,"NUM_GRID_NOT_CONVERGED")
    assert report["numerical_status"] == "pass"
    assert report["resolution_status"] == "not_converged"
    assert report["payload"]["primary_refinement_factor"] == 1
    assert len(report["payload"]["legs"]) == 3


def test_failed_refinement_prevents_publishing_completed_primary():
    value = request()
    value["numerics"]["refinement"] = "halving_2"
    def observer(factor,frame):
        if factor == 2 and frame["step_index"] == 1:
            raise RuntimeError("trusted observer refuses refinement")
    report = dynamics.integrate_dynamics_request(value,step_observer=observer)
    assert_failed(report,"ENGINE_FAILURE")
    assert report["partial"]
    assert [leg["completed_steps"] for leg in report["payload"]["legs"]] == [8,1]
    assert report["numerical_status"] == report["resolution_status"] == "not_checked"


def test_observer_receives_every_step_and_mutations_are_detached():
    value = request()
    value["numerics"]["sample_stride"] = 3
    seen = []
    def observer(factor,frame):
        seen.append((factor,frame["step_index"]))
        frame["positions_m"][0][0] = 999
        frame["velocities_m_per_s"].clear()
        frame["forces_n"][0][0] = 999
    report = dynamics.integrate_dynamics_request(value,step_observer=observer)
    assert report["execution_status"] == "SUCCEEDED", report["errors"]
    assert seen == [(1,j) for j in range(9)]
    frames = report["payload"]["legs"][0]["sampled_frames"]
    assert [frame["step_index"] for frame in frames] == [0,3,6,8]
    assert all(frame["positions_m"][0][0] != 999 and len(frame["velocities_m_per_s"]) == 2 for frame in frames)


@pytest.mark.parametrize("where",["initial","final"])
def test_observer_failure_keeps_last_accepted_full_state(where):
    value = request()
    def observer(factor,frame):
        if frame["step_index"] == (0 if where == "initial" else 8):
            raise ValueError("trusted callback failure")
    report = dynamics.integrate_dynamics_request(value,step_observer=observer)
    assert_failed(report,"ENGINE_FAILURE")
    assert report["partial"]
    leg = report["payload"]["legs"][0]
    assert leg["completed_steps"] == (0 if where == "initial" else 8)
    assert leg["stop_reason"] == "engine_failure"
    assert report["numerical_status"] == "not_checked"


def test_cancellation_discards_unpublished_standalone_payload():
    value = request()
    cancelled = False
    def observer(factor,frame):
        nonlocal cancelled
        cancelled = frame["step_index"] == 3
    report = dynamics.integrate_dynamics_request(value,step_observer=observer,check_cancel=lambda:cancelled)
    assert report["execution_status"] == "CANCELLED"
    assert codes(report) == {"CANCELLED"}
    assert report["payload"] is None and report["final_state"] is None and not report["partial"]
    assert report["dynamics_simulation_executed"]


@pytest.mark.parametrize("callback",[lambda: "cancel",lambda: (_ for _ in ()).throw(RuntimeError("failure"))])
def test_invalid_cancellation_callback_fails_closed(callback):
    report = dynamics.integrate_dynamics_request(request(),check_cancel=callback)
    assert_failed(report,"ENGINE_FAILURE")
    assert report["payload"] is None
    assert not report["dynamics_simulation_executed"]


def test_runtime_byte_refusal_does_not_run_solver_or_publish_partial(monkeypatch):
    prepare = dynamics._prepare_dynamics_request
    def tiny_budget(*args,**kwargs):
        report,prepared = prepare(*args,**kwargs)
        prepared["budgets"]["artifact_byte_limit"] = 1
        return report,prepared
    monkeypatch.setattr(dynamics,"_prepare_dynamics_request",tiny_budget)
    report = dynamics.integrate_dynamics_request(request())
    assert_failed(report,"RESOURCE_LIMIT")
    assert not report["dynamics_simulation_executed"]
    assert report["payload"] is None and not report["partial"]


def test_runtime_force_budget_retains_initial_accepted_state(monkeypatch):
    prepare = dynamics._prepare_dynamics_request
    def limited_budget(*args,**kwargs):
        report,prepared = prepare(*args,**kwargs)
        prepared["budgets"]["limits"]["max_total_force_evaluations"] = 1
        return report,prepared
    monkeypatch.setattr(dynamics,"_prepare_dynamics_request",limited_budget)
    report = dynamics.integrate_dynamics_request(request())
    assert_failed(report,"RESOURCE_LIMIT")
    assert report["partial"] and report["dynamics_simulation_executed"]
    leg = report["payload"]["legs"][0]
    assert leg["completed_steps"] == 0
    assert leg["force_evaluations"] == 2 and leg["completed_force_evaluations"] == 1
    assert [frame["step_index"] for frame in leg["sampled_frames"]] == [0]


def test_refinement_legs_share_one_standalone_wall_deadline(monkeypatch):
    value = request()
    value["numerics"]["refinement"] = "halving_2"
    clock = [time.monotonic()]
    monkeypatch.setattr(dynamics,"time",SimpleNamespace(monotonic=lambda:clock[0]))
    def observer(factor,frame):
        if frame["step_index"] == 0:
            clock[0] += 22
    report = dynamics.integrate_dynamics_request(value,step_observer=observer)
    assert_failed(report,"RESOURCE_LIMIT")
    assert report["partial"]
    assert [leg["completed_steps"] for leg in report["payload"]["legs"]] == [8,16,0]


@pytest.mark.parametrize("terminal",[3,8])
def test_wall_timeout_preserves_accepted_failure_evidence(monkeypatch,terminal):
    clock = [time.monotonic()]
    monkeypatch.setattr(dynamics,"time",SimpleNamespace(monotonic=lambda:clock[0]))
    def observer(factor,frame):
        if frame["step_index"] == terminal:
            clock[0] += 61
    report = dynamics.integrate_dynamics_request(request(),step_observer=observer)
    assert_failed(report,"RESOURCE_LIMIT")
    assert report["partial"]
    leg = report["payload"]["legs"][0]
    assert leg["completed_steps"] == terminal
    assert leg["sampled_frames"][-1]["step_index"] == terminal
    assert leg["stop_reason"] == "resource_limit"


def test_deadline_expiring_during_publication_cannot_return_success(monkeypatch):
    clock = [time.monotonic()]
    monkeypatch.setattr(dynamics,"time",SimpleNamespace(monotonic=lambda:clock[0]))
    finalise = results.finalise_report
    def delayed(*args,**kwargs):
        report = finalise(*args,**kwargs)
        clock[0] += 61
        return report
    monkeypatch.setattr(results,"finalise_report",delayed)
    report = dynamics.integrate_dynamics_request(request())
    assert_failed(report,"RESOURCE_LIMIT")
    assert report["partial"] and report["payload"]["legs"][0]["completed_steps"] == 8


def test_second_publication_refusal_discards_unpublished_assessments(monkeypatch):
    clock = [time.monotonic()]
    monkeypatch.setattr(dynamics,"time",SimpleNamespace(monotonic=lambda:clock[0]))
    finalise = results.finalise_report
    calls = 0
    def delayed_then_refused(*args,**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CalculationError("Failure evidence exceeds bytes",code="RESOURCE_LIMIT",
                                   details={"resource":"artifact_bytes"})
        report = finalise(*args,**kwargs)
        clock[0] += 61
        return report
    monkeypatch.setattr(results,"finalise_report",delayed_then_refused)
    report = dynamics.integrate_dynamics_request(request())
    assert_failed(report,"RESOURCE_LIMIT")
    assert calls == 2
    assert report["payload"] is None and report["final_state"] is None
    assert report["provenance"] is None and not report["partial"]
    assert report["numerical_status"] == report["resolution_status"] == "not_checked"
    from quanta.registry import ContractRegistry
    registry = ContractRegistry(contract_version="0.3.1")
    assert not list(registry.validator("dynamics_report.schema.json").iter_errors(report))


def test_cancellation_during_publication_discards_candidate_final_state(monkeypatch):
    cancelled = False
    finalise = results.finalise_report
    def delayed(*args,**kwargs):
        nonlocal cancelled
        report = finalise(*args,**kwargs)
        cancelled = True
        return report
    monkeypatch.setattr(results,"finalise_report",delayed)
    report = dynamics.integrate_dynamics_request(request(),check_cancel=lambda:cancelled)
    assert report["execution_status"] == "CANCELLED"
    assert report["payload"] is None and report["final_state"] is None and not report["partial"]


def test_unexpected_publication_exception_is_a_structured_failure(monkeypatch):
    def broken(*args,**kwargs):
        raise ValueError("bad publication")
    monkeypatch.setattr(results,"finalise_report",broken)
    report = dynamics.integrate_dynamics_request(request())
    assert_failed(report,"ENGINE_FAILURE")
    assert report["payload"] is None and not report["partial"]
