"""Publication misuse tests using analytic free motion, independent of the solver."""
import copy
import hashlib
import json
import shutil
from fractions import Fraction

import pytest

from quanta.autodiff import CalculationError
from quanta.dynamics_results import (build_phase_state, capture_provenance, check_payload,
                                     finalise_report, transport_bytes)
from quanta.hashing import canonical_bytes
from quanta.registry import ContractRegistry


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def registry():
    return ContractRegistry(contract_version="0.3.1")


def request_for(registry, *, refinement="none", stride=1):
    request = json.loads(registry.raw_bytes["examples/free.request.json"])
    request["numerics"].update(steps=2,sample_stride=stride,refinement=refinement)
    return request


def frame_for(request, index, factor):
    """Exact binary free-motion fixture, not a production diagnostic helper."""
    particles = request["system"]["particles"]
    t = Fraction(request["numerics"]["dt_s"])*index/factor
    q = [[float(Fraction(x)+t*Fraction(v)) for x,v in zip(p["position_m"],p["velocity_m_per_s"])]
         for p in particles]
    v = [[float(x) for x in p["velocity_m_per_s"]] for p in particles]
    m = [Fraction(p["mass_kg"]) for p in particles]
    kinetic = float(sum((mass*sum((Fraction(x)**2 for x in velocity),Fraction())/2
                         for mass,velocity in zip(m,v)),Fraction()))
    momentum = [float(sum((mass*Fraction(velocity[j]) for mass,velocity in zip(m,v)),Fraction()))
                for j in range(3)]
    angular = [float(sum((mass*(Fraction(r[(j+1)%3])*Fraction(velocity[(j+2)%3])-
                                  Fraction(r[(j+2)%3])*Fraction(velocity[(j+1)%3]))
                          for mass,r,velocity in zip(m,q,v)),Fraction())) for j in range(3)]
    return {"step_index":index,"time_s":float(t),"positions_m":q,"velocities_m_per_s":v,
            "forces_n":[[0.0]*3 for _ in particles],"potential_energy_j":0.0,
            "kinetic_energy_j":kinetic,"total_energy_j":kinetic,
            "linear_momentum_kg_m_per_s":momentum,"angular_momentum_kg_m2_per_s":angular}


def leg_for(request, factor=1, *, completed=None, reason="completed"):
    n = request["numerics"]
    steps = factor*n["steps"]
    completed = steps if completed is None else completed
    indices = [factor*i for i in list(range(0,n["steps"],n["sample_stride"]))+[n["steps"]]
               if factor*i<=completed]
    if indices[-1] != completed:
        indices.append(completed)
    return {"refinement_factor":factor,"dt_s":float(Fraction(n["dt_s"])/factor),
            "requested_steps":steps,"completed_steps":completed,
            "force_evaluations":completed+1,"completed_force_evaluations":completed+1,
            "sampled_frames":[frame_for(request,i,factor) for i in indices],"stop_reason":reason,
            "max_energy_drift_scaled":0.0,"max_momentum_drift_scaled":0.0,
            "max_angular_momentum_drift_scaled":0.0,"max_com_ballistic_error_scaled":0.0,
            "diagnostics_evaluated_at":"every_accepted_full_step"}


def payload_for(request):
    refined = request["numerics"]["refinement"] == "halving_2"
    return {"contract_version":"0.3.1","operation":"integrate","module_id":"quanta.pair_dynamics",
            "module_version":"0.1.0","particle_ids":[p["id"] for p in request["system"]["particles"]],
            "masses_kg":[p["mass_kg"] for p in request["system"]["particles"]],
            "primary_refinement_factor":1,"time_kind":"evolving","initial_time_s":0,
            "physical_validation_status":"unvalidated","partial":False,
            "legs":[leg_for(request,r) for r in ([1,2,4] if refined else [1])],
            "resolution_comparison":{"mode":request["numerics"]["refinement"],
                "status":"pass" if refined else "not_checked",
                "coarse_pair_scaled_error":0.0 if refined else None,
                "fine_pair_scaled_error":0.0 if refined else None,
                "comparison_grid":"every_primary_integer_step",
                "interpretation":"finite_step_agreement_not_physical_validation"}}


def issue():
    return {"code":"ENGINE_FAILURE","category":"execution","message":"Synthetic terminal failure",
            "path":None,"step_id":None,"branch_index":None,"retryable":False,"details":{}}


def report_for(request,payload):
    return {"report_version":"0.1.0","scope":"standalone_dynamics_integration",
            "contract_version":"0.3.1","operation":"integrate",
            "module_ref":{"module_id":"quanta.pair_dynamics","module_version":"0.1.0",
                          "solver_id":"velocity_verlet_forward_ad","solver_version":"0.1.0"},
            "input_validation_status":"pass","execution_status":"SUCCEEDED","numerical_status":"pass",
            "resolution_status":payload["resolution_comparison"]["status"],
            "physical_validation_status":"unvalidated","partial":False,"payload":payload,
            "final_state":None,"errors":[],"warnings":[],"input_sha256":digest(canonical_bytes(request)),
            "provenance":None,"dynamics_simulation_executed":True,"initial_force_evaluation_performed":True}


def checked(request,payload,registry,**kwargs):
    check_payload(request,payload,registry=registry,execution_status=kwargs.get("execution","SUCCEEDED"),
                  numerical_status=kwargs.get("numerical","pass"),
                  resolution_status=kwargs.get("resolution",payload["resolution_comparison"]["status"]))


def test_successful_phase_and_actual_whole_report_bytes(registry):
    request = request_for(registry)
    report = report_for(request,payload_for(request))
    original = copy.deepcopy(report)
    result = finalise_report(request,report,registry=registry)
    assert report == original
    final = result["final_state"]
    assert final["physical_time"] == {"value":0.25,"unit":"s"}
    assert final["data"]["system"]["particles"][0]["position_m"] == report["payload"]["legs"][0]["sampled_frames"][-1]["positions_m"][0]
    content = {k:v for k,v in final.items() if k != "scientific_state_sha256"}
    assert final["scientific_state_sha256"] == digest(canonical_bytes(content))
    assert not any(k in final for k in ("run_id","state_id","solver_checkpoint"))
    provenance = result["provenance"]
    publication = provenance["publication"]
    assert publication["report_transport_bytes"] == len(transport_bytes(result))
    assert publication["payload_transport_bytes"] == len(transport_bytes(result["payload"]))
    assert publication["payload_canonical_sha256"] == digest(canonical_bytes(result["payload"]))
    projected = copy.deepcopy(result)
    projected["provenance"].pop("publication")
    assert publication["report_projection_sha256"] == digest(canonical_bytes(projected))
    for sha,text in provenance["captured_utf8_contents"].items():
        assert digest(text.encode()) == sha
    assert "dynamics_report.schema.json" in provenance["contract_files_sha256"]
    assert "src/quanta/dynamics_results.py" in provenance["source_files_sha256"]
    assert len(provenance["observed_locked_distributions"]) >= 20
    result["final_state"]["data"]["system"]["particles"][0]["position_m"][0] = 99
    assert report == original


def test_partial_terminal_frame_preserves_only_accepted_state(registry):
    request = request_for(registry,stride=2)
    payload = payload_for(request)
    payload.update(partial=True,legs=[leg_for(request,completed=1,reason="domain_error")])
    payload["legs"][0]["force_evaluations"] = 3  # failed trial after last accepted full step
    report = report_for(request,payload)
    report.update(execution_status="FAILED",numerical_status="not_checked",partial=True,errors=[issue()])
    result = finalise_report(request,report,registry=registry)
    assert [f["step_index"] for f in result["payload"]["legs"][0]["sampled_frames"]] == [0,1]
    assert result["final_state"] is None
    with pytest.raises(CalculationError):
        build_phase_state(request,payload,registry=registry)


@pytest.mark.parametrize("mutation",[
    lambda p:p["particle_ids"].reverse(),
    lambda p:p["masses_kg"].reverse(),
    lambda p:p["legs"][0].update(dt_s=0.25),
    lambda p:p["legs"][0].update(requested_steps=3),
    lambda p:p["legs"][0].update(completed_force_evaluations=2),
    lambda p:p["legs"][0].update(force_evaluations=4),
    lambda p:p["legs"][0]["sampled_frames"][-1].update(time_s=0.3),
    lambda p:p["legs"][0]["sampled_frames"][-1].update(step_index=1),
    lambda p:p["legs"][0]["sampled_frames"][-1]["positions_m"].pop(),
    lambda p:p["legs"][0]["sampled_frames"][0]["velocities_m_per_s"][0].__setitem__(0,0.5),
    lambda p:p["legs"][0]["sampled_frames"][-1].update(kinetic_energy_j=0.0),
    lambda p:p["legs"][0]["sampled_frames"][-1].update(total_energy_j=0.0),
    lambda p:p["legs"][0]["sampled_frames"][-1]["linear_momentum_kg_m_per_s"].__setitem__(0,0.0),
    lambda p:p["legs"][0]["sampled_frames"][-1]["angular_momentum_kg_m2_per_s"].__setitem__(0,0.0),
    lambda p:p["legs"][0]["sampled_frames"][-1]["forces_n"][0].__setitem__(0,float("nan")),
    lambda p:p.update(partial=True),
    lambda p:p.update(unknown_extension="unregistered"),
])
def test_registered_and_cross_field_misuse_rejected(registry,mutation):
    request = request_for(registry)
    payload = payload_for(request)
    mutation(payload)
    with pytest.raises(CalculationError):
        checked(request,payload,registry)


def test_refinement_factor_order_and_unstarted_suffix(registry):
    request = request_for(registry,refinement="halving_2")
    payload = payload_for(request)
    checked(request,payload,registry)
    for factors in ([1,4,2],[1,1,4],[2,4],[1,2]):
        bad = copy.deepcopy(payload)
        bad["legs"] = [leg_for(request,r) for r in factors]
        with pytest.raises(CalculationError):
            checked(request,bad,registry)
    payload["partial"] = True
    payload["legs"] = [leg_for(request,completed=1,reason="domain_error"),leg_for(request,2)]
    payload["resolution_comparison"].update(status="not_checked",coarse_pair_scaled_error=None,fine_pair_scaled_error=None)
    with pytest.raises(CalculationError):
        checked(request,payload,registry,execution="FAILED",numerical="not_checked")


def test_refinement_error_assessment_is_explicit_and_paired(registry):
    request = request_for(registry,refinement="halving_2")
    payload = payload_for(request)
    payload["resolution_comparison"].update(coarse_pair_scaled_error=0.1,fine_pair_scaled_error=0.2)
    with pytest.raises(CalculationError):
        checked(request,payload,registry)
    payload["partial"] = True
    payload["resolution_comparison"]["status"] = "not_converged"
    checked(request,payload,registry,execution="FAILED")
    payload["resolution_comparison"]["fine_pair_scaled_error"] = None
    with pytest.raises(CalculationError):
        checked(request,payload,registry,execution="FAILED")


@pytest.mark.parametrize("terminal_reason",["completed","engine_failure","resource_limit"])
def test_failure_at_last_accepted_step_preserves_unassessed_evidence(registry,terminal_reason):
    request = request_for(registry,refinement="halving_2")
    payload = payload_for(request)
    payload["partial"] = True
    payload["legs"][-1]["stop_reason"] = terminal_reason
    payload["resolution_comparison"].update(status="not_checked",coarse_pair_scaled_error=None,fine_pair_scaled_error=None)
    checked(request,payload,registry,execution="FAILED",numerical="not_checked")
    report = report_for(request,payload)
    report.update(execution_status="FAILED",numerical_status="not_checked",partial=True,errors=[issue()])
    assert finalise_report(request,report,registry=registry)["final_state"] is None


def test_failed_numerical_assessment_never_becomes_final_state(registry):
    request = request_for(registry)
    payload = payload_for(request)
    payload["partial"] = True
    payload["legs"][0]["max_energy_drift_scaled"] = 1.0
    report = report_for(request,payload)
    report.update(execution_status="FAILED",numerical_status="not_converged",partial=True,errors=[issue()])
    assert finalise_report(request,report,registry=registry)["final_state"] is None
    report["final_state"] = {"fake":"state"}
    with pytest.raises(CalculationError):
        finalise_report(request,report,registry=registry)


def test_cancellation_discards_standalone_active_payload(registry):
    request = request_for(registry)
    report = report_for(request,payload_for(request))
    report.update(execution_status="CANCELLED",numerical_status="not_checked",resolution_status="not_checked")
    with pytest.raises(CalculationError):
        finalise_report(request,report,registry=registry)
    report.update(payload=None,partial=False,errors=[issue()])
    result = finalise_report(request,report,registry=registry)
    assert result["payload"] is result["final_state"] is None
    assert result["provenance"]["publication"]["payload_transport_bytes"] == 0


def test_raw_input_and_scientific_identity_remain_distinct(registry):
    request = request_for(registry)
    original = json.dumps(request,indent=3)+"\n"
    provenance = capture_provenance(request,registry=registry,original_input=original)
    assert provenance["original_input_sha256"] == digest(original.encode())
    assert provenance["authored_request_canonical_sha256"] == digest(canonical_bytes(request))
    assert provenance["original_input_sha256"] != provenance["authored_request_canonical_sha256"]
    bad = copy.deepcopy(request)
    bad["numerics"]["steps"] = 1
    with pytest.raises(CalculationError):
        capture_provenance(request,registry=registry,original_input=bad)


@pytest.mark.parametrize("mutation",[
    lambda p:p.update(authored_request_canonical_sha256="0"*64),
    lambda p:p.update(initial_state_transport_sha256="0"*64),
    lambda p:p.update(registry_snapshot_sha256="0"*64),
    lambda p:p.update(environment_sha256="0"*64),
    lambda p:p.update(observed_locked_distributions=[]),
    lambda p:p["solver"].update(version="invented"),
    lambda p:p.update(contract_version="0.3.0"),
    lambda p:p.update(instrumentation_identity_captured=True),
    lambda p:p.update(original_input_encoding="invented"),
    lambda p:p["captured_utf8_contents"].update({"0"*64:"fake bytes"}),
    lambda p:p["source_files_sha256"].pop("src/quanta/dynamics_results.py"),
])
def test_provenance_mutations_rejected(registry,mutation):
    request = request_for(registry)
    provenance = capture_provenance(request,registry=registry)
    mutation(provenance)
    with pytest.raises(CalculationError):
        finalise_report(request,report_for(request,payload_for(request)),registry=registry,provenance=provenance)


@pytest.mark.parametrize("mutate",[
    lambda r:r.documents["dynamics_payload.schema.json"].update(additionalProperties=True),
    lambda r:r.documents["dynamics_payload.schema.json"]["properties"]["primary_refinement_factor"].update(const=True),
])
def test_mutable_active_rules_cannot_impersonate_frozen_snapshot(registry,mutate):
    request = request_for(registry)
    mutate(registry)
    assert registry.validate_integrity() == []  # ordinary loader check is insufficient for publication
    with pytest.raises(CalculationError,match="Active contract rules"):
        capture_provenance(request,registry=registry)


def test_changed_disk_snapshot_is_not_hidden_by_cached_registry(registry,tmp_path):
    copied = tmp_path/"v0.3.1"
    shutil.copytree(registry.contract_dir,copied)
    local = ContractRegistry(copied,contract_version="0.3.1")
    request = request_for(local)
    provenance = capture_provenance(request,registry=local)
    path = copied/"dynamics_payload.schema.json"
    path.write_bytes(path.read_bytes()+b"\n")
    with pytest.raises(CalculationError,match="changed on disk"):
        finalise_report(request,report_for(request,payload_for(request)),registry=local,provenance=provenance)


def test_artifact_cap_measures_full_actual_bytes_and_never_truncates(registry):
    request = request_for(registry)
    report = report_for(request,payload_for(request))
    full = finalise_report(request,report,registry=registry)
    measured = len(transport_bytes(full))
    with pytest.raises(CalculationError) as failure:
        finalise_report(request,report,registry=registry,artifact_byte_limit=measured-100)
    assert failure.value.code == "RESOURCE_LIMIT"
    assert failure.value.details["requested"] > failure.value.details["limit"]
    # Metadata/error bytes count too, including partial failures without any trajectory.
    report.update(execution_status="FAILED",numerical_status="not_checked",payload=None,
                  errors=[{**issue(),"details":{"text":"한"*10000}}])
    with pytest.raises(CalculationError) as failure:
        finalise_report(request,report,registry=registry,artifact_byte_limit=measured)
    assert failure.value.code == "RESOURCE_LIMIT"


def test_false_supplied_state_and_execution_flags_rejected(registry):
    request = request_for(registry)
    report = report_for(request,payload_for(request))
    report["final_state"] = {"state_id":"invented"}
    with pytest.raises(CalculationError):
        finalise_report(request,report,registry=registry)
    report["final_state"] = None
    report["initial_force_evaluation_performed"] = False
    with pytest.raises(CalculationError):
        finalise_report(request,report,registry=registry)


def test_signed_zero_is_transport_identity_not_canonical_state_identity(registry):
    request = request_for(registry)
    request["system"]["particles"][0]["position_m"][0] = -0.0
    provenance = capture_provenance(request,registry=registry)
    contents = provenance["captured_utf8_contents"]
    transport = contents[provenance["initial_state_transport_sha256"]]
    canonical = contents[provenance["initial_state_canonical_sha256"]]
    assert json.loads(transport)["system"]["particles"][0]["position_m"][0].hex() == "-0x0.0p+0"
    assert json.loads(canonical)["system"]["particles"][0]["position_m"][0] == 0
    assert provenance["initial_state_transport_sha256"] != provenance["initial_state_canonical_sha256"]
    payload = payload_for(request)
    # Generic arithmetic can erase -0; explicitly retain the authored initial carrier.
    payload["legs"][0]["sampled_frames"][0]["positions_m"][0][0] = -0.0
    checked(request,payload,registry)
    payload["legs"][0]["sampled_frames"][0]["positions_m"][0][0] = 0.0
    with pytest.raises(CalculationError,match="Initial SI positions"):
        checked(request,payload,registry)


def test_integral_float_request_tokens_are_not_rejected_at_publication(registry):
    request = request_for(registry)
    payload = payload_for(request)
    request["numerics"].update(steps=2.0,sample_stride=1.0)
    checked(request,payload,registry)
    assert build_phase_state(request,payload,registry=registry)["physical_time"]["value"] == 0.25


def test_coincident_retained_phase_cannot_become_a_state(registry):
    request = request_for(registry)
    payload = payload_for(request)
    frame = payload["legs"][0]["sampled_frames"][-1]
    frame["positions_m"][1] = frame["positions_m"][0].copy()
    with pytest.raises(CalculationError,match="pair-distance"):
        checked(request,payload,registry)
