"""Standalone conservative pair dynamics with explicit full-step state boundaries.

This is a solver for immutable 0.3.1 requests, not a workflow, queue or restart
engine.  Local compound products/sums are evaluated exactly then rounded once
per binary64 component.  No step-size, velocity or force correction is applied.
"""
from __future__ import annotations

import copy
from fractions import Fraction
import json
import math
import time
from typing import Callable

from .autodiff import CalculationError, _fraction_float
from .dynamics_validation import _initial_diagnostics, _prepare_dynamics_request
from .environment import environment_report
from .pair_kernel import PairForceKernel
from .parsing import StrictJSONError, parse_json
from .registry import ContractRegistry


_CONTRACT = "0.3.1"
_PATH = "/system/particles"


class _Cancelled(CalculationError):
    def __init__(self):
        super().__init__("Standalone dynamics cancellation requested", code="CANCELLED", path="/numerics")


def _issue(code, message, path=None, details=None):
    category = {"RESOURCE_LIMIT":"resource", "MODEL_UNSUPPORTED":"support",
                "REGISTRY_SNAPSHOT_UNAVAILABLE":"support", "ENGINE_FAILURE":"runtime",
                "CANCELLED":"runtime", "EXPRESSION_DOMAIN":"numerical",
                "NUM_NOT_CONVERGED":"numerical", "NUM_GRID_NOT_CONVERGED":"numerical"}.get(code, "input")
    return {"code":code, "category":category, "message":message, "path":path,
            "step_id":None, "branch_index":None, "retryable":False, "details":details or {}}


def _number(value, quantity, path="/numerics"):
    return _fraction_float(value, path, quantity)


def _kernel(request):
    system = request["system"]
    return PairForceKernel(count=len(system["particles"]),
        length_m=request["scales"]["length_m"], energy_j=request["scales"]["energy_j"],
        min_distance_m=system["min_distance_m"], expression=system["potential"]["expression"],
        parameters=system["potential"]["parameters"], particles_path=_PATH,
        payload_path="/payload", scales_path="/scales", potential_path="/system/potential")


def _drift_guard(before, after, minimum, control):
    """Exact finite-segment minimum, not an interpolated physical collision time."""
    minimum_squared = Fraction(minimum)**2
    for i in range(len(before)):
        for j in range(i+1, len(before)):
            control()
            start = [Fraction(before[i][k])-Fraction(before[j][k]) for k in range(3)]
            finish = [Fraction(after[i][k])-Fraction(after[j][k]) for k in range(3)]
            change = [b-a for a,b in zip(start,finish)]
            denom = sum((x*x for x in change), Fraction())
            if denom:
                fraction = -sum((a*b for a,b in zip(start,change)), Fraction())/denom
                fraction = min(Fraction(1), max(Fraction(0), fraction))
            else:
                fraction = Fraction(0)
            distance_squared = sum(((a+fraction*b)**2 for a,b in zip(start,change)), Fraction())
            if distance_squared <= minimum_squared:
                raise CalculationError("Numerical drift segment reaches the minimum pair distance",
                    code="EXPRESSION_DOMAIN", path=_PATH,
                    details={"pair_indices":[i,j], "guard":"numerical_drift_segment_not_physical_collision_time"})


def _diagnostics(request, force, velocities, scales):
    # This helper consumes only particles/scales.  The immutable authored input
    # is never rewritten and the new positions are not a fake static definition.
    particles = [{"mass_kg":p["mass_kg"], "position_m":q, "velocity_m_per_s":v}
                 for p,q,v in zip(request["system"]["particles"], force.positions, velocities)]
    return _initial_diagnostics({"system":{"particles":particles}, "scales":request["scales"]}, force, scales)


def _frame(force, velocities, diagnostics, index, dt_exact):
    return {"step_index":index, "time_s":_number(index*dt_exact,"physical time"),
        "positions_m":copy.deepcopy(force.positions), "velocities_m_per_s":copy.deepcopy(velocities),
        "forces_n":copy.deepcopy(force.forces_n),
        "potential_energy_j":diagnostics["potential_energy_j"],
        "kinetic_energy_j":diagnostics["kinetic_energy_j"],
        "total_energy_j":diagnostics["total_energy_j"],
        "linear_momentum_kg_m_per_s":diagnostics["linear_momentum_kg_m_per_s"].copy(),
        "angular_momentum_kg_m2_per_s":diagnostics["angular_momentum_kg_m2_per_s"].copy()}


def _scaled_state(frame, length, velocity_scale):
    return ([[ _number(Fraction(x)/length,"reduced position",_PATH) for x in row]
             for row in frame["positions_m"]],
            [[_number(Fraction(x)/velocity_scale,"reduced velocity",_PATH) for x in row]
             for row in frame["velocities_m_per_s"]])


def _drift_metrics(current, initial, scales, request, time_value):
    def maximum(values, references, scale):
        return max((_number(abs(Fraction(a)-Fraction(b))/Fraction(scale), "scaled conservation residual")
                    for a,b in zip(values,references)), default=0.0)
    com = []
    for actual, initial_r, velocity in zip(current["center_of_mass_m"], initial["center_of_mass_m"],
                                         initial["center_of_mass_velocity_m_per_s"]):
        expected = Fraction(initial_r)+Fraction(velocity)*Fraction(time_value)
        com.append(_number(abs(Fraction(actual)-expected)/Fraction(request["scales"]["length_m"]),
                           "scaled center of mass residual"))
    return {"max_energy_drift_scaled":maximum([current["total_energy_j"]],[initial["total_energy_j"]],request["scales"]["energy_j"]),
            "max_momentum_drift_scaled":maximum(current["linear_momentum_kg_m_per_s"],initial["linear_momentum_kg_m_per_s"],scales["momentum_kg_m_per_s"]),
            "max_angular_momentum_drift_scaled":maximum(current["angular_momentum_kg_m2_per_s"],initial["angular_momentum_kg_m2_per_s"],scales["angular_momentum_kg_m2_per_s"]),
            "max_com_ballistic_error_scaled":max(com,default=0.0)}


def _stop_reason(error):
    if error.code == "RESOURCE_LIMIT":
        return "resource_limit"
    if error.code == "CANCELLED":
        return "cancelled"
    if error.code == "ENGINE_FAILURE":
        return "engine_failure"
    if error.details.get("precision") == "binary64":
        return "range_error"
    return "domain_error"


def _observe(observer, factor, frame, control):
    if observer is not None:
        try:
            observer(factor, copy.deepcopy(frame))
        except Exception as error:
            raise CalculationError("Trusted step observer failed", code="ENGINE_FAILURE", path="/numerics",
                details={"exception_type":type(error).__name__}) from None
        control()


def _run_leg(request, prepared, time_leg, control, consume_force, observer, *, initial_force=None):
    factor = time_leg["refinement_factor"]
    dt_exact = Fraction(time_leg["dt_s"])
    h = Fraction(time_leg["reduced_dt"])
    length = Fraction(request["scales"]["length_m"])
    time_scale = Fraction(request["scales"]["time_s"])
    velocity_scale = length/time_scale
    # The admitted reduced masses are explicitly rounded binary64 solver inputs.
    masses = [Fraction(_number(value,"reduced mass",_PATH)) for value in prepared["reduced_masses"]]
    steps = time_leg["steps"]
    stride = int(request["numerics"]["sample_stride"])*factor
    kernel = _kernel(request)
    velocities = [[float(x) for x in p["velocity_m_per_s"]] for p in request["system"]["particles"]]
    attempted = completed = 0
    leg = None
    current_frame = None
    common = []
    try:
        control()
        if initial_force is None:
            attempted += 1
            consume_force()
            force = kernel.evaluate([p["position_m"] for p in request["system"]["particles"]], check_deadline=control)
        else:
            attempted += 1
            force = initial_force
        completed += 1
        initial = _diagnostics(request, force, velocities, prepared["derived_scales"])
        current_frame = _frame(force, velocities, initial, 0, dt_exact)
        leg = {"refinement_factor":factor,"dt_s":float(dt_exact),"requested_steps":steps,
            "completed_steps":0,"force_evaluations":attempted,"completed_force_evaluations":completed,
            "sampled_frames":[copy.deepcopy(current_frame)],"stop_reason":"completed",
            "max_energy_drift_scaled":0.0,"max_momentum_drift_scaled":0.0,
            "max_angular_momentum_drift_scaled":0.0,"max_com_ballistic_error_scaled":0.0,
            "diagnostics_evaluated_at":"every_accepted_full_step"}
        q, u = _scaled_state(current_frame,length,velocity_scale)
        if request["numerics"]["refinement"] != "none":
            common.append((q,u))
        _observe(observer,factor,current_frame,control)
        for index in range(1,steps+1):
            control()
            consume_force.attempted_time_step = True
            half = [[_number(Fraction(u[i][k])+h*Fraction(force.reduced_forces[i][k])/(2*masses[i]),
                             "half-step velocity",_PATH) for k in range(3)] for i in range(len(q))]
            trial_q = [[_number(Fraction(q[i][k])+h*Fraction(half[i][k]),"drift position",_PATH)
                        for k in range(3)] for i in range(len(q))]
            trial_positions = [[_number(Fraction(x)*length,"SI position",_PATH) for x in row] for row in trial_q]
            _drift_guard(force.positions,trial_positions,request["system"]["min_distance_m"],control)
            attempted += 1
            consume_force()
            trial_force = kernel.evaluate(trial_positions,check_deadline=control)
            completed += 1
            trial_u = [[_number(Fraction(half[i][k])+h*Fraction(trial_force.reduced_forces[i][k])/(2*masses[i]),
                                "full-step velocity",_PATH) for k in range(3)] for i in range(len(q))]
            trial_velocities = [[_number(Fraction(x)*velocity_scale,"SI velocity",_PATH) for x in row] for row in trial_u]
            diagnostics = _diagnostics(request,trial_force,trial_velocities,prepared["derived_scales"])
            frame = _frame(trial_force,trial_velocities,diagnostics,index,dt_exact)
            metrics = _drift_metrics(diagnostics,initial,prepared["derived_scales"],request,frame["time_s"])
            control()
            # This is the sole full-step acceptance boundary.  Diagnostic
            # tolerance crossing records evidence; it does not alter the step.
            q,u,force,velocities = trial_q,trial_u,trial_force,trial_velocities
            current_frame = frame
            leg["completed_steps"] = index
            for name,value in metrics.items():
                leg[name] = max(leg[name],value)
            if index % stride == 0 or index == steps:
                leg["sampled_frames"].append(copy.deepcopy(frame))
            if request["numerics"]["refinement"] != "none" and index % factor == 0:
                common.append(_scaled_state(frame,length,velocity_scale))
            _observe(observer,factor,frame,control)
        leg["force_evaluations"],leg["completed_force_evaluations"] = attempted,completed
        return leg,common
    except CalculationError as error:
        if leg is not None:
            leg["force_evaluations"],leg["completed_force_evaluations"] = attempted,completed
            leg["stop_reason"] = _stop_reason(error)
            if current_frame["step_index"] != leg["sampled_frames"][-1]["step_index"]:
                leg["sampled_frames"].append(copy.deepcopy(current_frame))
        error.partial_leg = leg
        error.details.setdefault("refinement_factor",factor)
        error.details.setdefault("attempted_force_evaluations",attempted)
        error.details.setdefault("completed_force_evaluations",completed)
        raise
    except Exception as error:
        failure = CalculationError("Trusted dynamics instrumentation failed",code="ENGINE_FAILURE",path="/numerics",
            details={"exception_type":type(error).__name__,"refinement_factor":factor})
        if leg is not None:
            leg["force_evaluations"],leg["completed_force_evaluations"] = attempted,completed
            leg["stop_reason"] = "engine_failure"
            if current_frame["step_index"] != leg["sampled_frames"][-1]["step_index"]:
                leg["sampled_frames"].append(copy.deepcopy(current_frame))
        failure.partial_leg = leg
        raise failure from None


def _resolution(request,states):
    result = {"mode":request["numerics"]["refinement"],"status":"not_checked",
              "coarse_pair_scaled_error":None,"fine_pair_scaled_error":None,
              "comparison_grid":"every_primary_integer_step",
              "interpretation":"finite_step_agreement_not_physical_validation"}
    if result["mode"] == "none":
        return result
    atol,rtol = Fraction(request["numerics"]["state_atol"]),Fraction(request["numerics"]["state_rtol"])
    def difference(left,right):
        maximum = Fraction(0)
        if len(left) != len(right):
            raise CalculationError("Refinement comparison grid is incomplete",code="ENGINE_FAILURE",path="/payload")
        for a,b in zip(left,right):
            for group_a,group_b in zip(a,b):
                for row_a,row_b in zip(group_a,group_b):
                    for x,y in zip(row_a,row_b):
                        x,y = Fraction(x),Fraction(y)
                        maximum = max(maximum,abs(x-y)/(atol+rtol*max(abs(x),abs(y))))
        return _number(maximum,"refinement scaled error","/payload/resolution_comparison")
    coarse,fine = difference(states[0],states[1]),difference(states[1],states[2])
    result.update(coarse_pair_scaled_error=coarse,fine_pair_scaled_error=fine,
                  status="pass" if coarse <= 1 and fine <= 1 and fine <= coarse else "not_converged")
    return result


def _payload(request,legs,resolution,partial):
    return {"contract_version":_CONTRACT,"operation":"integrate","module_id":"quanta.pair_dynamics",
        "module_version":"0.1.0","particle_ids":[p["id"] for p in request["system"]["particles"]],
        "masses_kg":[p["mass_kg"] for p in request["system"]["particles"]],
        "primary_refinement_factor":1,"time_kind":"evolving","initial_time_s":0,
        "physical_validation_status":"unvalidated","partial":partial,"legs":legs,
        "resolution_comparison":resolution}


def integrate_dynamics_request(value: bytes | str | dict, *, registry: ContractRegistry | None = None,
        check_cancel: Callable[[],bool] | None = None,
        step_observer: Callable[[int,dict],None] | None = None) -> dict:
    """Integrate one 0.3.1 request, preserving all status and publication boundaries.

    ``check_cancel`` is a trusted Python callback returning true when cancelled.
    ``step_observer`` receives detached full-step frames for diagnostics only;
    it cannot replace the force law or enlarge persisted output-frame budgets.
    """
    report = {"report_version":"0.1.0","scope":"standalone_dynamics_integration",
        "contract_version":_CONTRACT,"operation":"integrate",
        "module_ref":{"module_id":"quanta.pair_dynamics","module_version":"0.1.0",
                      "solver_id":"velocity_verlet_forward_ad","solver_version":"0.1.0"},
        "input_validation_status":"failed","execution_status":"FAILED",
        "numerical_status":"not_checked","resolution_status":"not_checked",
        "physical_validation_status":"unvalidated","partial":False,
        "input_sha256":None,"payload":None,"final_state":None,
        "dynamics_simulation_executed":False,"initial_force_evaluation_performed":False,
        "errors":[],"warnings":[],"provenance":None}
    started = time.monotonic()
    try:
        parsed = parse_json(value)
        if not isinstance(parsed,dict) or parsed.get("contract_version") != _CONTRACT:
            raise CalculationError("Time integration requires an explicit immutable0.3.1 request;0.3.0 remains validation-only",
                                   code="MODEL_UNSUPPORTED",path="/contract_version")
        validation,prepared = _prepare_dynamics_request(value,registry=registry)
    except StrictJSONError as error:
        report["errors"]=[_issue(error.code,str(error),error.path)]
        return report
    except (CalculationError,ValueError,OSError,TypeError) as error:
        report["errors"]=[_issue(getattr(error,"code","REGISTRY_SNAPSHOT_UNAVAILABLE"),str(error),getattr(error,"path",None))]
        return report
    report["initial_force_evaluation_performed"]=validation["initial_force_evaluation_performed"]
    report["errors"],report["warnings"]=validation["errors"],validation["warnings"]
    if not validation["valid"] or prepared is None:
        return report
    report.update(input_validation_status="pass",input_sha256=validation["input_sha256"])
    request,frozen=prepared["request"],prepared["registry"]
    limit_seconds=prepared["budgets"]["validation_wall_seconds"]
    deadline=min(prepared["deadline_monotonic"],started+limit_seconds)
    def control(*, enforce_deadline=True):
        if check_cancel is not None:
            try:
                cancelled = check_cancel()
                if not isinstance(cancelled,bool):
                    raise TypeError("Cancellation callback must return a boolean")
            except Exception as error:
                raise CalculationError("Trusted cancellation callback failed",code="ENGINE_FAILURE",path="/numerics",
                    details={"exception_type":type(error).__name__}) from None
            if cancelled:
                raise _Cancelled()
        if enforce_deadline and time.monotonic() > deadline:
            raise CalculationError("Standalone dynamics exceeded its wall deadline",code="RESOURCE_LIMIT",path="/numerics",
                details={"resource":"wall_seconds","limit":limit_seconds,"observed":time.monotonic()-started})
    calls=1 # The admitted initial force is reused for primary leg1.
    def consume_force():
        nonlocal calls
        calls+=1
        cap=prepared["budgets"]["limits"]["max_total_force_evaluations"]
        pair_cap=prepared["budgets"]["limits"]["max_pair_evaluations"]
        pairs=len(request["system"]["particles"])*(len(request["system"]["particles"])-1)//2
        if calls > cap or calls*pairs > pair_cap:
            raise CalculationError("Actual force work exceeds the frozen dynamics budget",code="RESOURCE_LIMIT",path="/numerics",
                details={"requested_force_calls":calls,"limit_force_calls":cap,"requested_pair_work":calls*pairs,"limit_pair_work":pair_cap})
    consume_force.attempted_time_step=False
    legs,states=[],[]
    resolution={"mode":request["numerics"]["refinement"],"status":"not_checked",
        "coarse_pair_scaled_error":None,"fine_pair_scaled_error":None,
        "comparison_grid":"every_primary_integer_step","interpretation":"finite_step_agreement_not_physical_validation"}
    provenance=None
    try:
        control()
        observed=environment_report()
        control()
        if not observed["valid"]:
            raise CalculationError("The selected numerical environment baseline does not match",code="MODEL_UNSUPPORTED",
                details={"environment_errors":observed["errors"]})
        from .dynamics_results import capture_provenance
        provenance=capture_provenance(request,registry=frozen,environment=observed,original_input=value,
                                      instrumentation_present=step_observer is not None)
        report["provenance"]=provenance
        control()
        known=len(json.dumps(report,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode())
        known+=prepared["budgets"]["trajectory_byte_bound"]+prepared["budgets"]["terminal_envelope_reserve_bytes"]
        if known > prepared["budgets"]["artifact_byte_limit"]:
            raise CalculationError("Actual provenance plus trajectory reservation exceeds run bytes",code="RESOURCE_LIMIT",path="/numerics",
                details={"requested":known,"limit":prepared["budgets"]["artifact_byte_limit"]})
        for i,time_leg in enumerate(prepared["time_legs"]):
            control()
            leg,state=_run_leg(request,prepared,time_leg,control,consume_force,step_observer,
                               initial_force=prepared["initial_force"] if i==0 else None)
            legs.append(leg)
            states.append(state)
        control()
        resolution=_resolution(request,states)
        numeric=all(leg["max_energy_drift_scaled"] <= request["numerics"]["energy_drift_atol"]
                    and leg["max_momentum_drift_scaled"] <= request["numerics"]["momentum_drift_atol"]
                    and leg["max_angular_momentum_drift_scaled"] <= request["numerics"]["angular_momentum_drift_atol"] for leg in legs)
        report["numerical_status"]="pass" if numeric else "not_converged"
        report["resolution_status"]=resolution["status"]
        success=numeric and resolution["status"] in {"pass","not_checked"}
        report["execution_status"]="SUCCEEDED" if success else "FAILED"
        if not numeric:
            report["errors"].append(_issue("NUM_NOT_CONVERGED","Declared all-step conservation tolerances were not met","/numerics"))
        if resolution["status"]=="not_converged":
            report["errors"].append(_issue("NUM_GRID_NOT_CONVERGED","Declared time-step agreement was not met","/numerics"))
        report["partial"]=not success
        report["payload"]=_payload(request,legs,resolution,not success)
    except KeyboardInterrupt:
        report.update(execution_status="CANCELLED",partial=False,payload=None,final_state=None)
        report["errors"]=[_issue("CANCELLED","Standalone dynamics interrupted")]
    except CalculationError as error:
        if error.code=="CANCELLED":
            report.update(execution_status="CANCELLED",partial=False,payload=None,final_state=None)
        else:
            partial=getattr(error,"partial_leg",None)
            if partial is not None:
                legs.append(partial)
            report.update(execution_status="FAILED",partial=bool(legs),
                          payload=_payload(request,legs,resolution,True) if legs else None,final_state=None)
        report["errors"].append(_issue(error.code,str(error),error.path,error.details))
    except Exception as error:
        report.update(execution_status="FAILED",partial=False,payload=None,final_state=None)
        report["errors"].append(_issue("ENGINE_FAILURE","Standalone dynamics failed unexpectedly",details={"exception_type":type(error).__name__}))
    report["dynamics_simulation_executed"]=consume_force.attempted_time_step
    from .dynamics_results import finalise_report
    try:
        control(enforce_deadline=report["execution_status"]=="SUCCEEDED")
        final=finalise_report(request,report,registry=frozen,provenance=provenance,
                              artifact_byte_limit=prepared["budgets"]["artifact_byte_limit"])
        control(enforce_deadline=report["execution_status"]=="SUCCEEDED")
        return final
    except (CalculationError,KeyboardInterrupt) as error:
        if isinstance(error,KeyboardInterrupt) or getattr(error,"code",None)=="CANCELLED":
            report.update(execution_status="CANCELLED",partial=False,payload=None,final_state=None,
                          numerical_status="not_checked",resolution_status="not_checked")
            report["errors"]=[_issue("CANCELLED","Standalone dynamics cancelled before publication")]
        elif error.code=="RESOURCE_LIMIT" and error.details.get("resource")=="wall_seconds":
            # The deadline prevents success publication, not honest failure
            # evidence.  Full-step trajectories already accepted stay visible.
            report.update(execution_status="FAILED",partial=report["payload"] is not None,final_state=None)
            if report["payload"] is not None:
                report["payload"]["partial"]=True
            report["errors"].append(_issue(error.code,str(error),error.path,error.details))
        else:
            report.update(execution_status="FAILED",partial=False,payload=None,final_state=None,
                          numerical_status="not_checked",resolution_status="not_checked")
            report["errors"].append(_issue(error.code,str(error),error.path,error.details))
        try:
            return finalise_report(request,report,registry=frozen,provenance=provenance,
                artifact_byte_limit=prepared["budgets"]["artifact_byte_limit"])
        except Exception as publication_error:
            # A failed run may return only its explicit refusal if the full
            # uncommitted evidence cannot fit or pass its integrity boundary.
            report.update(partial=False,payload=None,final_state=None,provenance=None,
                          numerical_status="not_checked",resolution_status="not_checked")
            report["errors"].append(_issue(getattr(publication_error,"code","ENGINE_FAILURE"),
                "Unpublished evidence omitted after publication refusal",details={"exception_type":type(publication_error).__name__}))
            return report
    except Exception as error:
        report.update(execution_status="FAILED",partial=False,payload=None,final_state=None,provenance=None,
                      numerical_status="not_checked",resolution_status="not_checked")
        report["errors"].append(_issue("ENGINE_FAILURE","Standalone dynamics publication failed unexpectedly",
                                     details={"exception_type":type(error).__name__}))
        return report
