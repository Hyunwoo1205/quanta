"""Check inactive design consistency; this does NOT execute a dynamics solver."""
from __future__ import annotations

import copy
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
D = ROOT / "docs/design/pair-dynamics-v0.1"


def read(name):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads((D / name).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def semantic(request):
    def finite(value):
        if isinstance(value, (float, int)) and not isinstance(value, bool):
            if not math.isfinite(float(value)):
                raise ValueError("nonfinite binary64 value")
        elif isinstance(value, dict):
            for v in value.values():
                finite(v)
        elif isinstance(value, list):
            for v in value:
                finite(v)
    finite(request)
    ps = request["system"]["particles"]
    if len({p["id"] for p in ps}) != len(ps):
        raise ValueError("duplicate particle ID")
    n = request["numerics"]
    steps, stride = n["steps"], n["sample_stride"]
    if stride > steps:
        raise ValueError("stride exceeds duration")
    factors = [1] if n["refinement"] == "none" else [1, 2, 4]
    h = Fraction(float(n["dt_s"]))
    l, e, t = (Fraction(float(request["scales"][key])) for key in ("length_m", "energy_j", "time_s"))
    def represent(value, positive=False):
        result = float(value)
        if not math.isfinite(result) or (value != 0 and result == 0) or (positive and result <= 0):
            raise ValueError("derived value outside supported binary64 range")
        return result
    for scale in (e/l, l/t, e*t*t/(l*l), e*t/l, e*t):
        represent(scale, positive=True)
    for p in ps:
        represent(Fraction(float(p["mass_kg"]))*l*l/(e*t*t), positive=True)
        for x in p["position_m"]:
            represent(Fraction(float(x))/l)
        for x in p["velocity_m_per_s"]:
            represent(Fraction(float(x))*t/l)
    represent(Fraction(float(request["system"]["min_distance_m"]))/l, positive=True)
    for factor in factors:
        dt = float(h / factor)
        if dt <= 0 or not math.isfinite(dt) or Fraction(dt) != h / factor:
            raise ValueError("refined dt unrepresentable")
        half = represent(Fraction(dt)/2, positive=True)
        if Fraction(half) != Fraction(dt)/2:
            raise ValueError("SI half-step unrepresentable")
        reduced = represent(Fraction(dt)/t, positive=True)
        reduced_half = represent(Fraction(reduced)/2, positive=True)
        if Fraction(reduced_half) != Fraction(reduced)/2:
            raise ValueError("reduced half-step unrepresentable")
        previous = 0.0
        for j in range(1, factor * steps + 1):
            now = float(j * h / factor)
            if not math.isfinite(now) or now <= previous:
                raise ValueError("non-increasing or overflowing clock")
            previous = now
    evaluations = sum(f * steps + 1 for f in factors)
    pairs = len(ps) * (len(ps) - 1) // 2
    frames = 1 + (steps + stride - 1) // stride
    reserved_frames = len(factors) * (frames + 1)
    if evaluations > 10000 or pairs * evaluations > 1000000 or reserved_frames > 512:
        raise ValueError("planned resource ceiling")
    if max(factors) * steps > 10000:
        raise ValueError("refined leg steps ceiling")
    # Conservative trajectory-only bound; actual run provenance is separately counted.
    bound = 65536 + reserved_frames * (25 * (9 * len(ps) + 15) + 8 * len(ps) + 1024)
    if bound > 33554432:
        raise ValueError("trajectory byte ceiling")
    minimum = request["system"]["min_distance_m"]
    for i, p in enumerate(ps):
        for q in ps[i + 1:]:
            if math.dist(p["position_m"], q["position_m"]) <= minimum:
                raise ValueError("initial pair distance")
    nodes = 0
    params = request["system"]["potential"]["parameters"]
    def walk(node, depth=1):
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 128:
            raise ValueError("AST resource ceiling")
        if node["op"] == "param" and node["name"] not in params:
            raise ValueError("undefined parameter")
        for child in node.get("args", []):
            walk(child, depth + 1)
        if "arg" in node:
            walk(node["arg"], depth + 1)
    walk(request["system"]["potential"]["expression"])
    return {"evaluations": evaluations, "pair_evaluations": pairs * evaluations,
            "reserved_frames": reserved_frames, "trajectory_byte_bound": bound}


def main():
    checks = 0
    def check(value):
        nonlocal checks
        if not value:
            raise ValueError("design consistency check failed")
        checks += 1
    schema = read("request.schema.json")
    output = read("payload.schema.json")
    for item in (schema, output):
        Draft202012Validator.check_schema(item)
        check(True)
    validator = Draft202012Validator(schema)
    fixtures = {}
    for name in ("harmonic.request.json", "harmonic-refinement.request.json", "free.request.json"):
        request = read(name)
        validator.validate(request)
        fixtures[name] = semantic(request)
        check(True)
    request = read("harmonic.request.json")
    mutations = [
        lambda r: r["system"]["particles"][0].pop("mass_kg"),
        lambda r: r["system"]["particles"][0].update(mass_kg=0),
        lambda r: r["system"]["particles"][0].update(fixed=[False]*3),
        lambda r: r["system"].update(boundary="periodic"),
        lambda r: r["numerics"].update(integrator="euler"),
        lambda r: r.update(initial_time_s=1),
        lambda r: r.update(unknown_field=0),
        lambda r: r["system"]["particles"][0].pop("velocity_m_per_s"),
        lambda r: r["system"]["potential"].update(expression={"op":"var","name":"xi"}),
        lambda r: r["system"]["particles"][1].update(id="p1"),
        lambda r: r["numerics"].update(sample_stride=1001),
        lambda r: r["numerics"].update(steps=10000,refinement="halving_2"),
        lambda r: r["numerics"].update(sample_stride=1),
        lambda r: r["numerics"].update(dt_s=5e-324,refinement="halving_2"),
        lambda r: r["numerics"].update(dt_s=5e-324,refinement="none"),
        lambda r: r["scales"].update(time_s=1e308),
        lambda r: r["system"]["potential"].update(expression={"op":"param","name":"missing"}),
        lambda r: r["system"]["particles"][1].update(position_m=r["system"]["particles"][0]["position_m"]),
    ]
    for mutation in mutations:
        trial = copy.deepcopy(request)
        mutation(trial)
        try:
            validator.validate(trial)
            semantic(trial)
        except (ValueError, OverflowError, ValidationError):
            check(True)
        else:
            raise ValueError("unsupported design fixture unexpectedly accepted")
    # Independent exact initial K/P/L consistency, no Quanta force or time integrator.
    ps = request["system"]["particles"]
    f = Fraction
    masses = [f(p["mass_kg"]) for p in ps]
    positions = [[f(x) for x in p["position_m"]] for p in ps]
    velocities = [[f(x) for x in p["velocity_m_per_s"]] for p in ps]
    kinetic = sum(m * sum(v*v for v in vel)/2 for m, vel in zip(masses, velocities))
    potential = f(3, 8) * sum((positions[1][j]-positions[0][j])**2 for j in range(3))
    linear = [sum(m*vel[j] for m, vel in zip(masses, velocities)) for j in range(3)]
    angular = [sum(m*(r[(j+1)%3]*v[(j+2)%3]-r[(j+2)%3]*v[(j+1)%3])
                   for m,r,v in zip(masses,positions,velocities)) for j in range(3)]
    plan = read("validation-plan.json")
    exact = plan["analytic_harmonic"]
    check(kinetic+potential == f(exact["initial_energy_j"]))
    check(linear == list(map(f, exact["initial_momentum_kg_m_per_s"])))
    check(angular == list(map(f, exact["initial_angular_momentum_kg_m2_per_s"])))
    check(len({c["id"] for c in plan["cases"]}) == len(plan["cases"]) == 11)
    check(plan["status"] == "planned_not_executed")
    # Synthetic structure/size witnesses only, not engine output or trajectory evidence.
    frame = {"step_index":0,"time_s":0,
        "positions_m":[p["position_m"] for p in ps],
        "velocities_m_per_s":[p["velocity_m_per_s"] for p in ps],
        "forces_n":[[1.5,0,0],[-1.5,0,0]],
        "potential_energy_j":float(potential),"kinetic_energy_j":float(kinetic),
        "total_energy_j":float(kinetic+potential),
        "linear_momentum_kg_m_per_s":list(map(float,linear)),
        "angular_momentum_kg_m2_per_s":list(map(float,angular))}
    leg = {"refinement_factor":1,"dt_s":.001,"requested_steps":1000,
        "completed_steps":0,"force_evaluations":1,"completed_force_evaluations":1,
        "sampled_frames":[frame],"stop_reason":"domain_error",
        "max_energy_drift_scaled":0,"max_momentum_drift_scaled":0,
        "max_angular_momentum_drift_scaled":0,"max_com_ballistic_error_scaled":0,
        "diagnostics_evaluated_at":"every_accepted_full_step"}
    payload = {"draft_schema_version":"0.1.0","operation":"integrate",
        "module_id":"quanta.pair_dynamics","module_version":"0.1.0",
        "particle_ids":[p["id"] for p in ps],"masses_kg":[p["mass_kg"] for p in ps],
        "primary_refinement_factor":1,"time_kind":"evolving","initial_time_s":0,
        "physical_validation_status":"unvalidated","partial":True,"legs":[leg],
        "resolution_comparison":{"mode":"none","status":"not_checked",
        "coarse_pair_scaled_error":None,"fine_pair_scaled_error":None,
        "comparison_grid":"every_primary_integer_step",
        "interpretation":"finite_step_agreement_not_physical_validation"}}
    Draft202012Validator(output).validate(payload)
    check(True)
    trial = copy.deepcopy(payload)
    trial["legs"][0]["sampled_frames"][0]["velocities_m_per_s"]=[[0,0]]*2
    check(not Draft202012Validator(output).is_valid(trial))
    large = copy.deepcopy(frame)
    for key in ("positions_m","velocities_m_per_s","forces_n"):
        large[key]=[[-1.7976931348623157e308]*3 for _ in range(128)]
    large["kinetic_energy_j"]=1.7976931348623157e308
    structural_bytes=len(json.dumps(large,separators=(",",":"),allow_nan=False).encode())
    check(structural_bytes <= 25*(9*128+15)+8*128+1024)
    design=read("design.json")
    check(design["activation"]["active_registry_modified"] is False)
    check(design["activation"]["runtime_support"] is False)
    check(design["resources"]["max_total_force_evaluations"] == 10000)
    check(design["resources"]["max_pair_evaluations"] == 1000000)
    check(design["resources"]["max_total_output_frames"] == 512)
    from quanta.registry import ContractRegistry
    check(ContractRegistry().get_module("quanta.pair_dynamics", "0.1.0") is None)
    hashes = read("SHA256SUMS.json")
    for name, expected in hashes.items():
        check(hashlib.sha256((D/name).read_bytes()).hexdigest() == expected)
    print(json.dumps({"status":"passed","scope":"inactive_design_consistency_only",
        "checks":checks,"request_fixtures":fixtures,"synthetic_structure_fixture_only":True,
        "numerical_solver_executed":False,
        "physical_validation_status":"unvalidated"}, sort_keys=True))


if __name__ == "__main__":
    main()
