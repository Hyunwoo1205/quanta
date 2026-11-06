#!/usr/bin/env python3
"""Measure standalone dynamics against independent ballistic/harmonic references.

No production force, integrator or diagnostic formula is used as the reference
trajectory. The accepted-step observer accumulates maxima without bypassing the
512-frame artifact cap or retaining a hidden full trajectory in this report.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import re

for _name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ.setdefault(_name, "1")

from quanta import __version__
from quanta.hashing import canonical_bytes
from quanta.registry import ContractRegistry

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_VERSION = "0.3.1"
R0 = (0.5, -0.25, 0.75)
V = (0.125, 0.0625, -0.03125)
EXACT_E = 1.916015625
EXACT_P = (0.5, 0.25, -0.125)
EXACT_L = (-0.15625, 0.4375, 1.75)


def request(name: str = "harmonic.request.json") -> dict:
    """Use the versioned, installed fixture without silently changing its marker."""
    registry = ContractRegistry(contract_version=CONTRACT_VERSION)
    errors = registry.validate_integrity()
    if errors:
        raise ValueError("The dynamics benchmark bundle is invalid: " + str(errors[:2]))
    value = json.loads((registry.contract_dir / "examples" / name).read_text())
    if value.get("contract_version") != CONTRACT_VERSION:
        raise ValueError("Benchmark fixture has the wrong contract marker")
    return value


def reference(t: float) -> tuple[list[list[float]], list[list[float]]]:
    """Closed-form two-body harmonic motion; no numerical stepping recurrence."""
    q = (2 * math.cos(t), math.sin(t), 0.0)
    w = (-2 * math.sin(t), math.cos(t), 0.0)
    center = [r + v * t for r, v in zip(R0, V)]
    positions = [[center[j] - 0.75 * q[j] for j in range(3)],
                 [center[j] + 0.25 * q[j] for j in range(3)]]
    velocities = [[V[j] - 0.75 * w[j] for j in range(3)],
                  [V[j] + 0.25 * w[j] for j in range(3)]]
    return positions, velocities


def _cross(a, b):
    return [a[(j + 1) % 3] * b[(j + 2) % 3] - a[(j + 2) % 3] * b[(j + 1) % 3]
            for j in range(3)]


def _max_difference(a, b, scale=1.0):
    if isinstance(a, (list, tuple)):
        if len(a) != len(b):
            raise ValueError("Reference comparison shape mismatch")
        return max((_max_difference(x, y, scale) for x, y in zip(a, b)), default=0.0)
    if isinstance(a, bool) or isinstance(b, bool):
        raise ValueError("Boolean is not a numerical reference component")
    left,right=float(a),float(b)
    if not math.isfinite(left) or not math.isfinite(right) or not math.isfinite(scale) or scale<=0:
        raise ValueError("Nonfinite or invalid numerical comparison")
    return abs(left-right)/scale


def _check_time(frame,value,factor):
    index=frame["step_index"]
    if isinstance(index,bool) or not isinstance(index,int) or not 0<=index<=factor*value["numerics"]["steps"]:
        raise ValueError("Accepted frame has an invalid integer step index")
    expected=float(Fraction(value["numerics"]["dt_s"])*index/factor)
    actual=frame["time_s"]
    if isinstance(actual,bool) or not math.isfinite(actual) or float(actual).hex()!=expected.hex():
        raise ValueError("Accepted frame time differs from independently indexed requested dt")


def _check_complete_saved_grid(value,payload):
    factors=[1] if value["numerics"]["refinement"]=="none" else [1,2,4]
    if [leg["refinement_factor"] for leg in payload["legs"]]!=factors:
        raise ValueError("Complete result omitted or changed a requested refinement leg")
    n,stride=value["numerics"]["steps"],value["numerics"]["sample_stride"]
    primary_indices=list(range(0,n,stride))+[n]
    final_time=float(Fraction(value["numerics"]["dt_s"])*n)
    for factor,leg in zip(factors,payload["legs"]):
        if leg["requested_steps"]!=factor*n or leg["completed_steps"]!=factor*n:
            raise ValueError("Complete leg has a different requested duration/step count")
        if float(leg["dt_s"]).hex()!=float(Fraction(value["numerics"]["dt_s"])/factor).hex():
            raise ValueError("Complete leg changed the requested step size")
        frames=leg["sampled_frames"]
        if [frame["step_index"] for frame in frames]!=[factor*i for i in primary_indices]:
            raise ValueError("Complete leg changed the declared sample schedule")
        for frame in frames:
            _check_time(frame,value,factor)
        if frames[-1]["time_s"]!=final_time:
            raise ValueError("Complete legs do not reach the requested common final time")


def _request_hash(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _successful(report):
    if report.get("execution_status") != "SUCCEEDED" or not isinstance(report.get("payload"), dict):
        raise ValueError("Named benchmark solver failed: " + json.dumps(
            {k: report.get(k) for k in ("execution_status", "numerical_status", "resolution_status", "errors")},
            ensure_ascii=False)[:1500])
    if (report.get("numerical_status")!="pass" or report.get("physical_validation_status")!="unvalidated"
            or report["payload"].get("partial") is not False):
        raise ValueError("Successful named solver result has inconsistent quality/partial axes")
    return report["payload"]


def _run(value, *, step_observer=None):
    from quanta.dynamics import integrate_dynamics_request
    before = canonical_bytes(value)
    report = integrate_dynamics_request(value, step_observer=step_observer)
    if canonical_bytes(value) != before:
        raise ValueError("The solver mutated its authored benchmark input")
    if report.get("execution_status")=="SUCCEEDED":
        payload=_successful(report)
        _check_complete_saved_grid(value,payload)
        expected="not_checked" if value["numerics"]["refinement"]=="none" else "pass"
        if (report.get("resolution_status")!=expected or payload["resolution_comparison"]["status"]!=expected
                or payload["resolution_comparison"]["mode"]!=value["numerics"]["refinement"]):
            raise ValueError("Successful named result misstates its requested refinement assessment")
    return report


def _summary(value, report):
    payload = report.get("payload")
    return {"request_sha256": _request_hash(value),
            "payload_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest() if payload else None,
            "execution_status": report.get("execution_status"),
            "numerical_status": report.get("numerical_status"),
            "resolution_status": report.get("resolution_status"),
            "physical_validation_status": report.get("physical_validation_status"),
            "saved_frame_counts": [len(leg["sampled_frames"]) for leg in payload["legs"]] if payload else []}


def _case(ident, name, passed, **data):
    return {"id": ident, "name": name, "status": "passed" if passed else "failed", **data}


def ballistic_case():
    value = request("free.request.json")
    expected_steps = value["numerics"]["steps"]
    initial = value["system"]["particles"]
    masses = [Fraction(p["mass_kg"]) for p in initial]
    r0 = [[Fraction(x) for x in p["position_m"]] for p in initial]
    v0 = [[Fraction(x) for x in p["velocity_m_per_s"]] for p in initial]
    exact_e = sum((m * sum(v * v for v in vel) / 2 for m, vel in zip(masses, v0)), Fraction())
    exact_p = [sum(m * vel[j] for m, vel in zip(masses, v0)) for j in range(3)]
    exact_l = [sum(m * _cross(r, v)[j] for m, r, v in zip(masses, r0, v0)) for j in range(3)]
    maxima = {key: 0.0 for key in ("position", "velocity", "force", "energy", "momentum", "angular_momentum", "center_of_mass")}
    count = 0
    def observe(factor, frame):
        nonlocal count
        if factor != 1 or frame["step_index"] != count:
            raise ValueError("Ballistic accepted-step observer order is invalid")
        _check_time(frame,value,factor)
        count += 1
        t = Fraction(frame["time_s"])
        r = [[float(x + v * t) for x, v in zip(pos, vel)] for pos, vel in zip(r0, v0)]
        maxima["position"] = max(maxima["position"], _max_difference(frame["positions_m"], r))
        maxima["velocity"] = max(maxima["velocity"], _max_difference(frame["velocities_m_per_s"], v0))
        maxima["force"] = max(maxima["force"], _max_difference(frame["forces_n"], [[0]*3]*2))
        maxima["energy"] = max(maxima["energy"], _max_difference(frame["total_energy_j"],exact_e))
        maxima["momentum"] = max(maxima["momentum"], _max_difference(frame["linear_momentum_kg_m_per_s"], exact_p))
        maxima["angular_momentum"] = max(maxima["angular_momentum"], _max_difference(frame["angular_momentum_kg_m2_per_s"], exact_l))
        actual_com = [math.fsum(float(m) * pos[j] for m, pos in zip(masses, frame["positions_m"])) / float(sum(masses)) for j in range(3)]
        ref_com = [float(sum(m * (pos[j] + vel[j] * t) for m, pos, vel in zip(masses, r0, v0)) / sum(masses)) for j in range(3)]
        maxima["center_of_mass"] = max(maxima["center_of_mass"], _max_difference(actual_com, ref_com))
    report = _run(value, step_observer=observe)
    payload = _successful(report)
    retained_error = 0.0
    for frame in payload["legs"][0]["sampled_frames"]:
        t = Fraction(frame["time_s"])
        expected = [[float(x+v*t) for x,v in zip(pos,vel)] for pos,vel in zip(r0,v0)]
        retained_error = max(retained_error,_max_difference(frame["positions_m"],expected),
                             _max_difference(frame["velocities_m_per_s"],v0))
    return _case("D01", "independent ballistic motion and invariants", count == expected_steps + 1 and max(maxima.values()) <= 1e-12 and retained_error<=1e-12,
                 reference="r(t)=r0+v0*t, v(t)=v0; independent exact rational initial E/P/L; scales all1",
                 accepted_frames_checked=count, retained_frame_max_state_error=retained_error,
                 max_scaled_errors=maxima, tolerance=1e-12, **_summary(value, report))


def harmonic_case():
    value = request()
    value["numerics"].update(dt_s=0.001, steps=1000, sample_stride=10, refinement="none")
    maxima = {key: 0.0 for key in ("position", "velocity", "force", "energy", "momentum", "angular_momentum", "center_of_mass")}
    count = 0
    def observe(factor, frame):
        nonlocal count
        if factor != 1 or frame["step_index"] != count:
            raise ValueError("Harmonic accepted-step observer order is invalid")
        _check_time(frame,value,factor)
        count += 1
        t = frame["time_s"]
        r, v = reference(t)
        forces = [[0.75 * (r[1][j] - r[0][j]) for j in range(3)],
                  [-0.75 * (r[1][j] - r[0][j]) for j in range(3)]]
        maxima["position"] = max(maxima["position"], _max_difference(frame["positions_m"], r))
        maxima["velocity"] = max(maxima["velocity"], _max_difference(frame["velocities_m_per_s"], v))
        maxima["force"] = max(maxima["force"], _max_difference(frame["forces_n"], forces))
        maxima["energy"] = max(maxima["energy"], _max_difference(frame["total_energy_j"],EXACT_E))
        maxima["momentum"] = max(maxima["momentum"], _max_difference(frame["linear_momentum_kg_m_per_s"], EXACT_P))
        maxima["angular_momentum"] = max(maxima["angular_momentum"], _max_difference(frame["angular_momentum_kg_m2_per_s"], EXACT_L))
        actual_com = [(frame["positions_m"][0][j] + 3 * frame["positions_m"][1][j])/4 for j in range(3)]
        maxima["center_of_mass"] = max(maxima["center_of_mass"], _max_difference(actual_com, [R0[j] + V[j] * t for j in range(3)]))
    report = _run(value, step_observer=observe)
    payload = _successful(report)
    tol = {key: (1e-6 if key in {"position", "velocity", "force", "energy"} else 1e-10) for key in maxima}
    retained_error = 0.0
    for frame in payload["legs"][0]["sampled_frames"]:
        r,v=reference(frame["time_s"])
        retained_error=max(retained_error,_max_difference(frame["positions_m"],r),
                           _max_difference(frame["velocities_m_per_s"],v))
    leg=payload["legs"][0]
    diagnostic_deltas={
        "energy":_max_difference(leg["max_energy_drift_scaled"],maxima["energy"]),
        "momentum":_max_difference(leg["max_momentum_drift_scaled"],maxima["momentum"]),
        "angular_momentum":_max_difference(leg["max_angular_momentum_drift_scaled"],maxima["angular_momentum"]),
        "center_of_mass":_max_difference(leg["max_com_ballistic_error_scaled"],maxima["center_of_mass"])}
    passed = (count == 1001 and all(maxima[key] <= tol[key] for key in maxima) and retained_error<=1e-6
              and max(diagnostic_deltas.values())<=1e-12)
    return _case("D02", "unequal-mass noncollinear harmonic closed form", passed,
                 reference="q=[2cos(t),sin(t),0], qdot=[-2sin(t),cos(t),0]; r1=R-.75q,r2=R+.25q,R=R0+Vt; no numerical reference stepping",
                 normalized_with={"L0":1,"V0":1,"E0":1,"P0":1,"J0":1},
                 accepted_frames_checked=count, max_scaled_errors=maxima, tolerances=tol,
                 retained_frame_max_state_error=retained_error,
                 runtime_vs_independent_allstep_diagnostic_deltas=diagnostic_deltas,
                 diagnostic_consistency_tolerance=1e-12,
                 runtime_diagnostic_maxima={key: payload["legs"][0][key] for key in payload["legs"][0] if key.startswith("max_")},
                 **_summary(value, report))


def convergence_case():
    value = request("harmonic-refinement.request.json")
    value["numerics"].update(dt_s=0.05, steps=20, sample_stride=1, refinement="halving_2")
    errors = {1: 0.0, 2: 0.0, 4: 0.0}
    common_counts = {1: 0, 2: 0, 4: 0}
    all_counts = {1: 0, 2: 0, 4: 0}
    def observe(factor, frame):
        if factor not in all_counts or frame["step_index"]!=all_counts[factor]:
            raise ValueError("Refined accepted-step observer order is invalid")
        _check_time(frame,value,factor)
        all_counts[factor]+=1
        if frame["step_index"] % factor:
            return
        common_counts[factor] += 1
        r, v = reference(frame["time_s"])
        errors[factor] = max(errors[factor], _max_difference(frame["positions_m"], r), _max_difference(frame["velocities_m_per_s"], v))
    report = _run(value, step_observer=observe)
    payload = _successful(report)
    retained_errors={}
    for leg in payload["legs"]:
        error=0.0
        for frame in leg["sampled_frames"]:
            r,v=reference(frame["time_s"])
            error=max(error,_max_difference(frame["positions_m"],r),_max_difference(frame["velocities_m_per_s"],v))
        retained_errors[leg["refinement_factor"]]=error
    observer_matches_payload=retained_errors==errors
    # This fixed well-conditioned fixture is deliberately above roundoff. Zero
    # error is indeterminate, never a division fallback or order acceptance.
    orders = [math.log2(errors[a]/errors[b]) if errors[a] > 1e-13 and errors[b] > 1e-13 else None
              for a, b in ((1,2),(2,4))]
    passed = (all_counts=={1:21,2:41,4:81} and all(c == 21 for c in common_counts.values()) and
              all(order is not None and 1.8 <= order <= 2.2 for order in orders) and errors[4] <= 1e-4 and
              observer_matches_payload and payload["primary_refinement_factor"] == 1 and report["resolution_status"] == "pass")
    return _case("D03", "same-duration independent second-order convergence", passed,
                 duration_s=1, dt_s=[0.05,0.025,0.0125], steps=[20,40,80],
                 common_integer_grid_counts=common_counts, max_exact_state_errors=errors,
                 all_integer_grid_counts=all_counts,
                 observer_and_retained_payload_errors_match=observer_matches_payload,
                 observed_orders=orders, order_band=[1.8,2.2], fine_error_limit=1e-4,
                 roundoff_floor=1e-13, runtime_resolution=payload["resolution_comparison"], **_summary(value, report))


def symmetry_case():
    base = request()
    base["numerics"].update(dt_s=0.001, steps=100, sample_stride=10, refinement="none")
    base_report = _run(base)
    base_payload = _successful(base_report)
    base_frames = base_payload["legs"][0]["sampled_frames"]
    base_ids = base_payload["particle_ids"]
    masses = {p["id"]:p["mass_kg"] for p in base["system"]["particles"]}
    total_mass = math.fsum(masses.values())
    def center(frame, ids):
        return [math.fsum(masses[ident]*frame["positions_m"][i][j]
                          for i,ident in enumerate(ids))/total_mass for j in range(3)]
    shift = [0.25,-0.5,0.125]
    def rotate(v):
        return [-v[1],v[0],v[2]]  # proper +90degree rotation about z
    values = []
    transformed = deepcopy(base)
    for p in transformed["system"]["particles"]:
        p["position_m"] = [a+b for a,b in zip(rotate(p["position_m"]),shift)]
        p["velocity_m_per_s"] = rotate(p["velocity_m_per_s"])
    values.append(("proper_rotation_translation", transformed))
    permuted = deepcopy(base)
    permuted["system"]["particles"].reverse()
    values.append(("particle_id_permutation", permuted))
    rescaled = deepcopy(base)
    rescaled["scales"] = {"length_m":2,"energy_j":3,"time_s":4}
    rescaled["system"]["potential"]["expression"]["args"][0]["value"] = 0.5
    values.append(("same_SI_model_different_L0_E0_T0", rescaled))
    measures = []
    for name, value in values:
        report = _run(value)
        payload = _successful(report)
        frames = payload["legs"][0]["sampled_frames"]
        ids = payload["particle_ids"]
        maxima = {key:0.0 for key in ("position","velocity","force","potential_energy",
                                    "kinetic_energy","total_energy","momentum","angular_momentum","center_of_mass")}
        if len(frames) != len(base_frames):
            raise ValueError("Symmetry test output grids differ")
        for actual, before in zip(frames, base_frames):
            if actual["step_index"] != before["step_index"] or actual["time_s"] != before["time_s"]:
                raise ValueError("Symmetry test output times differ")
            for ident in base_ids:
                a, b = ids.index(ident), base_ids.index(ident)
                for field, key in (("positions_m","position"),("velocities_m_per_s","velocity"),("forces_n","force")):
                    expected = before[field][b]
                    if name == "proper_rotation_translation":
                        expected = rotate(expected)
                        if field == "positions_m":
                            expected = [x+y for x,y in zip(expected,shift)]
                    maxima[key] = max(maxima[key], _max_difference(actual[field][a], expected))
            p_ref, l_ref = before["linear_momentum_kg_m_per_s"], before["angular_momentum_kg_m2_per_s"]
            if name == "proper_rotation_translation":
                p_ref = rotate(p_ref)
                l_ref = [x+y for x,y in zip(rotate(l_ref),_cross(shift,p_ref))]
            maxima["momentum"] = max(maxima["momentum"],_max_difference(actual["linear_momentum_kg_m_per_s"],p_ref))
            maxima["angular_momentum"] = max(maxima["angular_momentum"],_max_difference(actual["angular_momentum_kg_m2_per_s"],l_ref))
            for field,key in (("potential_energy_j","potential_energy"),("kinetic_energy_j","kinetic_energy"),
                              ("total_energy_j","total_energy")):
                maxima[key] = max(maxima[key],_max_difference(actual[field],before[field]))
            center_ref = center(before,base_ids)
            if name == "proper_rotation_translation":
                center_ref = [x+y for x,y in zip(rotate(center_ref),shift)]
            maxima["center_of_mass"] = max(maxima["center_of_mass"],_max_difference(center(actual,ids),center_ref))
        measures.append({"transform":name,"max_scaled_errors":maxima,"tolerance":1e-9,
                         "passed":max(maxima.values())<=1e-9,**_summary(value,report)})
    return _case("D04", "SI invariance with correct angular-momentum origin transform", all(m["passed"] for m in measures),
                 rotation="Rz(+pi/2), determinant+1", translation_m=shift,
                 angular_rule="L'=R*L+a cross (R*P)",
                 normalized_with="Baseline physical SI scales L0=E0=T0=1 for all transformed comparisons; raw U/K/E preserved",
                 rescaling="L0=2,E0=3,T0=4 and f(rho)=0.5rho^2 preserve U(r)=0.375r^2", measurements=measures,
                 base=_summary(base,base_report))


def reversibility_case():
    value = request()
    value["numerics"].update(dt_s=0.001,steps=1000,sample_stride=10,refinement="none")
    report = _run(value)
    last = _successful(report)["legs"][0]["sampled_frames"][-1]
    reverse = deepcopy(value)
    for i, p in enumerate(reverse["system"]["particles"]):
        p["position_m"] = last["positions_m"][i][:]
        p["velocity_m_per_s"] = [-v for v in last["velocities_m_per_s"][i]]
    reverse_report = _run(reverse)
    returned = _successful(reverse_report)["legs"][0]["sampled_frames"][-1]
    q_error = _max_difference(returned["positions_m"],[p["position_m"] for p in value["system"]["particles"]])
    v_error = _max_difference(returned["velocities_m_per_s"],[[-v for v in p["velocity_m_per_s"]] for p in value["system"]["particles"]])
    return _case("D05", "supplementary positive-step velocity reversal", max(q_error,v_error)<=1e-9,
                 max_position_error_scaled=q_error,max_velocity_error_scaled=v_error,tolerance=1e-9,
                 interpretation="Two explicit standalone initial-value requests, each time0; not checkpoint/continuation support and not a substitute for D02/D03.",
                 forward=_summary(value,report),reverse=_summary(reverse,reverse_report))


def sampling_case():
    dense = request()
    dense["numerics"].update(dt_s=0.001,steps=100,sample_stride=1,refinement="none")
    sparse = deepcopy(dense)
    sparse["numerics"]["sample_stride"] = 10
    dense_report, sparse_report = _run(dense), _run(sparse)
    dense_leg = _successful(dense_report)["legs"][0]
    sparse_leg = _successful(sparse_report)["legs"][0]
    dense_frames = {f["step_index"]:f for f in dense_leg["sampled_frames"]}
    same_frames = all(frame == dense_frames[frame["step_index"]] for frame in sparse_leg["sampled_frames"])
    diagnostics=["max_energy_drift_scaled","max_momentum_drift_scaled",
                 "max_angular_momentum_drift_scaled","max_com_ballistic_error_scaled"]
    same_diagnostics = all(dense_leg[key] == sparse_leg[key] for key in diagnostics)
    same_status = all(dense_report[key] == sparse_report[key] for key in ("execution_status","numerical_status","resolution_status"))
    counts_valid = len(dense_frames)==101 and len(sparse_leg["sampled_frames"])==11
    return _case("D06", "all-step diagnostic maxima independent of legal output sparsity", same_frames and same_diagnostics and same_status and counts_valid,
                 steps=100,interpretation="n100 keeps bothstride1/stride10 under declared512-frame cap; D02 independently observes all1001accepted steps without altering that cap.",
                 common_frames_equal=same_frames,diagnostic_maxima_equal=same_diagnostics,statuses_equal=same_status,
                 diagnostic_maxima={key:dense_leg[key] for key in diagnostics},
                 dense=_summary(dense,dense_report),sparse=_summary(sparse,sparse_report))


def drift_crossing_subcase():
    value = request("free.request.json")
    for p, r, v in zip(value["system"]["particles"],([ -1,0,0],[1,0,0]),([2,0,0],[-2,0,0])):
        p["position_m"],p["velocity_m_per_s"] = r,v
    value["numerics"].update(dt_s=1,steps=1,sample_stride=1,refinement="none")
    report = _run(value)
    payload = report.get("payload")
    valid = (report.get("execution_status")=="FAILED" and payload is not None and
             payload["partial"] is True and len(payload["legs"])==1 and
             payload["legs"][0]["completed_steps"]==0 and
             [f["step_index"] for f in payload["legs"][0]["sampled_frames"]]==[0] and
             report.get("final_state") is None and
             payload["legs"][0]["sampled_frames"][0]["positions_m"]==[[-1,0,0],[1,0,0]])
    return _case("D07_drift_segment_subcase", "interior drift crossing between safe endpoints", valid,
                 coverage="Drift segment crossing subcase only; other domain/range and fullD07 gates are separate tests.",
                 numerical_drift_path="d(s)=[-2+4s,0,0]; min distance0 at s=.5 although endpointdistances2",
                 no_reflection_or_clipping=True,errors=report.get("errors"),**_summary(value,report))


MEASUREMENTS = (ballistic_case,harmonic_case,convergence_case,symmetry_case,
                reversibility_case,sampling_case,drift_crossing_subcase)


def measure_cases():
    results = []
    for measure in MEASUREMENTS:
        try:
            results.append(measure())
        except Exception as exc:
            # Preserve a failed named gate instead of dropping a measurement.
            results.append({"id":measure.__name__,"status":"failed","exception_type":type(exc).__name__,"error":str(exc)[:1800]})
    return results


def source_record():
    import quanta.dynamics as dynamics
    package = Path(dynamics.__file__).resolve().parent
    hashes = {"quanta/"+p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.glob("*.py"))}
    hashes["scripts/verify_dynamics.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    registry = ContractRegistry(contract_version=CONTRACT_VERSION)
    return {"source_sha":os.environ.get("GITHUB_SHA") if re.fullmatch(r"[0-9a-f]{40}",os.environ.get("GITHUB_SHA","")) else None,
            "files_sha256":hashes,"source_set_sha256":hashlib.sha256(canonical_bytes(hashes)).hexdigest(),
            "source_hash_rule":"RFC8785 relative runtime-package/script path to raw-fileSHA256 map",
            "contract_version":CONTRACT_VERSION,"registry_files_sha256":registry.manifest,
            "registry_manifest_sha256":hashlib.sha256(canonical_bytes(registry.manifest)).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    # Reuse only the established lock/environment observer, never its physics.
    from verify_numerics import locked_environment
    environment = locked_environment()
    cases = measure_cases()
    passed = environment["valid"] and all(c["status"]=="passed" for c in cases)
    record = {"verification_kind":"standalone_dynamics_named_numerical_gates",
        "status":"passed" if passed else "failed","package_version":__version__,
        "created_at":datetime.now(timezone.utc).isoformat(),
        "scope":"Independent D01-D06 numerical fixtures plus one drift-guard subcase; no fullD07-D11/integration acceptance claim.",
        "reference_source":"docs/design/pair-dynamics-v0.1/validation-plan.json",
        "reference_constants":{"energy_j":EXACT_E,"momentum_kg_m_per_s":EXACT_P,"angular_momentum_kg_m2_per_s":EXACT_L},
        "tolerance_origin":"Fixed project gates from the pre-implementation design; no fitting or relaxation.",
        "cases":cases,"environment":environment,"source":source_record(),
        "full_design_acceptance_completed":False,
        "not_claimed":["generic_workflow_or_durable_asyncAPI","browser_trajectory_parity","OCIdeployment","solver_checkpoint_resume"],
        "physical_validation_status":"unvalidated"}
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(record,ensure_ascii=False,indent=2,allow_nan=False)+'\n')
    print(json.dumps({"status":record["status"],"output":str(args.output) if args.output else None,
                      "cases":{c["id"]:c["status"] for c in cases}},sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
