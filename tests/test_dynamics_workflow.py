"""Single initial-value dynamics through the existing generic execution engine."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from quanta.dynamics_results import transport_bytes
from quanta.dynamics_workflow import initial_phase_data, solver_request
from quanta.hashing import canonical_bytes
from quanta.registry import ContractRegistry
from quanta.run_store import validate_run_report
from quanta.workflow import WorkflowCancelled, _WorkflowLimit, run_experiment

ROOT = Path(__file__).resolve().parents[1]


def example(name="free"):
    return json.loads((ROOT/f"contracts/v0.4.0/examples/{name}_revision.json").read_text())


def checked(report, expected="SUCCEEDED"):
    assert report["valid"], report["errors"]
    result=report["result"]
    assert result["execution_status"] == expected, result["errors"]
    assert result["schema_version"] == "0.4.0"
    assert result["physical_validation_status"] == "unvalidated"
    validation=validate_run_report(report)
    assert validation["valid"], validation["errors"]
    return result


def proof(report):
    entries=report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"]
    assert len(entries)==1
    entry=entries[0]
    raw=report["captured_artifacts"][entry["solver_report_sha256"]]
    assert hashlib.sha256(raw.encode()).hexdigest()==entry["solver_report_sha256"]
    return entry,json.loads(raw)


def test_success_has_full_phase_time_and_independently_bound_solver_transport():
    authored=example()
    before=deepcopy(authored)
    progress=[]
    report=run_experiment(authored,progress_callback=progress.append)
    result=checked(report)
    assert authored==before
    assert result["numerical_status"]=="pass" and result["resolution_status"]=="not_checked"
    states=result["states"]
    assert [s["producer"]["kind"] for s in states]==["initial","prepared_input","step"]
    assert [s["physical_time"] for s in states]==[{"value":0,"unit":"s"},{"value":0,"unit":"s"},{"value":1.0,"unit":"s"}]
    assert all(s["time_kind"]=="evolving" and s["data"]["time_s"]==s["physical_time"]["value"] for s in states)
    assert states[0]["data"]==initial_phase_data(authored["definition"])
    entry,solver=proof(report)
    assert entry["request"]==solver_request(authored["definition"]) and entry["control_error"] is None
    assert solver["execution_status"]=="SUCCEEDED"
    assert solver["provenance"]["publication"]["report_transport_bytes"]==len(transport_bytes(solver))
    step=result["steps"][0]
    assert step["payload"]["legs"][0]["force_evaluations"]==9
    assert states[-1]["data"]==solver["final_state"]["data"]
    assert step["state_ref"]==states[-1]["state_id"]
    assert len(step["artifacts"])==2
    for row in step["artifacts"]:
        raw=report["artifact_contents"][row["artifact_id"]]
        target=solver if row["schema_ref"]=="dynamics_report.schema.json" else step["payload"]
        assert raw.encode()==transport_bytes(target)
        assert row["size_bytes"]==len(raw.encode())
    assert progress[-1]=={"completed_steps":1,"total_steps":1,"active_step":None,"active_branch":None}
    projection=report["resolved_record"]["runtime_evidence"]["effective_step_inputs"][0]["projection"]
    assert projection["contract_version"]=="0.4.0"
    assert projection["solver_request_sha256"]==hashlib.sha256(canonical_bytes(entry["request"])).hexdigest()


def test_refinement_retains_primary_h_and_all_leg_counts():
    value=example("harmonic_refinement")
    report=run_experiment(value)
    result=checked(report)
    assert result["resolution_status"]=="pass"
    _,solver=proof(report)
    legs=solver["payload"]["legs"]
    n=value["definition"]["numerics"]["steps"]
    assert [leg["refinement_factor"] for leg in legs]==[1,2,4]
    assert sum(leg["force_evaluations"] for leg in legs)==7*n+3
    state=next(s for s in result["states"] if s["state_id"]==result["steps"][0]["state_ref"])
    assert state["data"]["time_s"]==legs[0]["sampled_frames"][-1]["time_s"]
    assert [p["position_m"] for p in state["data"]["system"]["particles"]]==legs[0]["sampled_frames"][-1]["positions_m"]


def test_whole_workflow_does_not_hide_extra_force_preflights(monkeypatch):
    from quanta.pair_kernel import PairForceKernel
    original=PairForceKernel.evaluate
    calls=0
    def measured(self,*args,**kwargs):
        nonlocal calls
        calls+=1
        return original(self,*args,**kwargs)
    monkeypatch.setattr(PairForceKernel,"evaluate",measured)
    report=run_experiment(example())
    result=checked(report)
    assert calls==9
    assert result["steps"][0]["payload"]["legs"][0]["force_evaluations"]==calls


def test_drift_failure_preserves_accepted_frame_without_output_state():
    value=example()
    definition=value["definition"]
    for p,q,v in zip(definition["system"]["particles"],[[-1,0,0],[1,0,0]],[[2,0,0],[-2,0,0]]):
        p["position_m"],p["velocity_m_per_s"]=q,v
    definition["numerics"].update(dt_s=1,steps=1,sample_stride=1)
    report=run_experiment(value)
    result=checked(report,"FAILED")
    step=result["steps"][0]
    assert step["outcome"]=="FAILED" and step["state_ref"] is None
    assert step["payload"]["partial"] is True
    assert step["payload"]["legs"][0]["completed_steps"]==0
    assert len(step["payload"]["legs"][0]["sampled_frames"])==1
    assert all(s["producer"]["kind"]!="step" for s in result["states"])
    _,solver=proof(report)
    assert solver["execution_status"]=="FAILED" and solver["final_state"] is None
    assert solver["errors"][0]["code"]=="EXPRESSION_DOMAIN"


def test_completed_numerical_failure_is_partial_not_a_successful_phase():
    value=example("harmonic")
    value["definition"]["numerics"]["energy_drift_atol"]=0
    report=run_experiment(value)
    result=checked(report,"FAILED")
    assert result["numerical_status"]=="not_converged"
    step=result["steps"][0]
    assert step["state_ref"] is None and step["payload"]["partial"]
    assert step["payload"]["legs"][0]["completed_steps"]==value["definition"]["numerics"]["steps"]
    _,solver=proof(report)
    assert solver["numerical_status"]=="not_converged" and solver["final_state"] is None


def test_initial_force_domain_failure_has_report_only():
    value=example()
    value["definition"]["system"]["potential"]["expression"]={"op":"log","arg":{"op":"const","value":-1}}
    report=run_experiment(value)
    result=checked(report,"FAILED")
    step=result["steps"][0]
    assert step["payload"] is None and step["state_ref"] is None
    assert len(step["artifacts"])==1
    _,solver=proof(report)
    assert solver["input_validation_status"]=="failed" and solver["payload"] is None
    assert solver["errors"][0]["code"]=="EXPRESSION_DOMAIN"


def test_cancel_before_dispatch_has_no_published_state_or_solver_proof():
    def cancel():
        raise WorkflowCancelled()
    report=run_experiment(example(),control_check=cancel)
    result=checked(report,"CANCELLED")
    assert result["states"]==[]
    assert report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"]==[]


@pytest.mark.parametrize("host_kind",["cancel","resource"])
def test_bridge_keeps_original_host_reason_and_discards_unpublished_solver_work(monkeypatch,host_kind):
    import quanta.workflow as workflow
    original=workflow.execute_dynamics
    def wrapped(definition,deadline):
        count=0
        def guard():
            nonlocal count
            deadline()
            count+=1
            if count>=8:
                if host_kind=="cancel":
                    raise WorkflowCancelled()
                raise _WorkflowLimit("Injected host deadline",global_limit=True,
                    details={"scope":"run","stop_reason":"run_wall_time_limit"})
        return original(definition,guard)
    monkeypatch.setattr(workflow,"execute_dynamics",wrapped)
    report=run_experiment(example())
    result=checked(report,"CANCELLED" if host_kind=="cancel" else "FAILED")
    entry,solver=proof(report)
    assert solver["execution_status"]=="CANCELLED" and solver["payload"] is None and solver["final_state"] is None
    assert entry["control_error"]["code"]==("CANCELLED" if host_kind=="cancel" else "RESOURCE_LIMIT")
    assert any(e["code"]==entry["control_error"]["code"] for e in result["errors"])
    assert result["steps"][0]["payload"] is None and result["steps"][0]["state_ref"] is None


@pytest.mark.parametrize("host_kind",["cancel","resource"])
def test_host_refusal_after_solver_completion_never_promotes_unpublished_phase(monkeypatch,host_kind):
    import quanta.workflow as workflow
    original=workflow.execute_dynamics
    finished=False
    def wrapped(definition,deadline):
        nonlocal finished
        result=original(definition,deadline)
        finished=True
        return result
    def control():
        if finished:
            if host_kind=="cancel":
                raise WorkflowCancelled()
            raise _WorkflowLimit("Injected publication deadline",global_limit=True,
                details={"scope":"run","stop_reason":"run_wall_time_limit"})
    monkeypatch.setattr(workflow,"execute_dynamics",wrapped)
    report=run_experiment(example(),control_check=control)
    result=checked(report,"CANCELLED" if host_kind=="cancel" else "FAILED")
    step=result["steps"][0]
    assert step["state_ref"] is None
    assert all(s["producer"]["kind"]!="step" for s in result["states"])
    entries=report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"]
    if host_kind=="cancel":
        assert step["payload"] is None and entries==[]
    else:
        _,solver=proof(report)
        assert solver["execution_status"]=="SUCCEEDED" and solver["payload"]["partial"] is False
        assert step["payload"]==solver["payload"] and step["partial"] is True


def test_global_cancel_after_completed_protocol_keeps_completed_evidence():
    finished=False
    def progress(value):
        nonlocal finished
        finished=value["completed_steps"]==1
    def control():
        if finished:
            raise WorkflowCancelled()
    report=run_experiment(example(),control_check=control,progress_callback=progress)
    result=checked(report,"CANCELLED")
    step=result["steps"][0]
    assert step["outcome"]=="SUCCEEDED" and step["state_ref"] is not None
    _,solver=proof(report)
    assert solver["execution_status"]=="SUCCEEDED"


def test_generic_whole_report_cap_can_discard_solver_evidence_without_fabricated_axes(monkeypatch):
    import quanta.run_store as store
    original=store.report_storage_bytes
    def measured(report):
        proofs=(report.get("resolved_record") or {}).get("runtime_evidence",{}).get("dynamics_solver_reports",[])
        return 33*1024*1024 if proofs else original(report)
    monkeypatch.setattr(store,"report_storage_bytes",measured)
    report=run_experiment(example())
    result=checked(report,"FAILED")
    step=result["steps"][0]
    assert step["payload"] is None and step["artifacts"]==[] and step["state_ref"] is None
    assert step["numerical_status"]==step["resolution_status"]=="not_checked"
    assert "solver_report_sha256" not in step["diagnostics"]
    assert report["resolved_record"]["runtime_evidence"]["dynamics_solver_reports"]==[]
    assert any(e["code"]=="RESOURCE_LIMIT" for e in result["errors"])
