"""Validate a standalone 0.3 dynamics request without integrating physical time.

An accepted request is a validation result, not an executable workflow or a
numerically validated trajectory.  Only its initial pair force/domain and
initial diagnostic feasibility are evaluated here.
"""
from __future__ import annotations

import hashlib
import itertools
import math
import time
from fractions import Fraction
from typing import Any

from .autodiff import CalculationError, _fraction_float
from .hashing import canonical_bytes
from .parsing import StrictJSONError, parse_json, pointer
from .registry import ContractRegistry

CONTRACT_VERSION = "0.3.0"
_MODULE = "quanta.pair_dynamics"
_MODULE_VERSION = "0.1.0"
_MAX_BYTES = 1_048_576
_PROFILE_LIMITS = {
    "max_particles": 128, "max_base_steps": 10000,
    "max_total_force_evaluations": 10000, "max_pair_evaluations": 1000000,
    "max_total_output_frames": 512,
}
_COMMON_LIMITS = {"max_input_bytes": _MAX_BYTES, "max_artifact_bytes_per_run": 33554432,
                  "wall_seconds_per_step": 60, "wall_seconds_per_run": 120}


class _Invalid(ValueError):
    def __init__(self, code: str, message: str, path: str | None = None, **details):
        super().__init__(message)
        self.code, self.path, self.details = code, path, details


def _issue(code: str, message: str, path: str | None, details: dict | None = None) -> dict:
    category = ("resource" if code == "RESOURCE_LIMIT" else
                "support" if code in {"REGISTRY_SNAPSHOT_UNAVAILABLE", "MODEL_UNSUPPORTED"} else
                "numerical" if code == "EXPRESSION_DOMAIN" else "input")
    return {"code": code, "category": category, "message": message, "path": path,
            "step_id": None, "branch_index": None, "retryable": False, "details": details or {}}


def _limit(profile: dict, name: str, ceiling: int, path: str, *, allow_zero: bool = False) -> int:
    value = profile.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
        raise _Invalid("REGISTRY_SNAPSHOT_UNAVAILABLE", "Invalid frozen resource limit", path,
                       resource=name)
    # A supplied registry may lower a protection ceiling, never enlarge it.
    return min(value, ceiling)


def _ast_preflight(expression: Any, *, max_depth: int = 16, max_nodes: int = 128) -> None:
    stack, count = [(expression, 1, "/system/potential/expression")], 0
    while stack:
        node, depth, path = stack.pop()
        count += 1
        if depth > max_depth or count > max_nodes:
            raise _Invalid("RESOURCE_LIMIT", "Expression exceeds the effective AST resource limits", path,
                           max_depth=max_depth, max_nodes=max_nodes)
        if not isinstance(node, dict):
            continue  # The bounded schema reports its actual structural error.
        args = node.get("args", [])
        if isinstance(args, list):
            # Reject width before copying a hostile list into the traversal stack.
            if len(args) > 8:
                raise _Invalid("RESOURCE_LIMIT", "Expression arity exceeds8", path + "/args")
            stack.extend((child, depth + 1, path + "/args/" + str(i))
                         for i, child in enumerate(args))
        if "arg" in node:
            stack.append((node["arg"], depth + 1, path + "/arg"))


def _parameter_refs(expression: dict, parameters: dict) -> None:
    stack = [(expression, "/system/potential/expression")]
    while stack:
        node, path = stack.pop()
        if node["op"] == "param" and node["name"] not in parameters:
            raise _Invalid("INPUT_SEMANTIC", "Expression refers to an undefined parameter",
                           path + "/name")
        stack.extend((child, path + "/args/" + str(i))
                     for i, child in enumerate(node.get("args", [])))
        if "arg" in node:
            stack.append((node["arg"], path + "/arg"))


def _represent(value: Fraction, path: str, quantity: str, *, positive: bool = False) -> float:
    result = _fraction_float(value, path, quantity)
    if positive and result <= 0:
        raise _Invalid("INPUT_SEMANTIC", quantity + " must be positive", path)
    return result


def _scales(request: dict) -> tuple[dict[str, float], list[Fraction]]:
    raw = request["scales"]
    length, energy, duration = (Fraction(raw[key]) for key in ("length_m", "energy_j", "time_s"))
    exact = {"force_n": energy/length, "velocity_m_per_s": length/duration,
             "mass_kg": energy*duration*duration/(length*length),
             "momentum_kg_m_per_s": energy*duration/length,
             "angular_momentum_kg_m2_per_s": energy*duration}
    scales = {name: _represent(value, "/scales", name, positive=True) for name, value in exact.items()}
    reduced_masses = []
    for i, particle in enumerate(request["system"]["particles"]):
        path = "/system/particles/" + str(i)
        mass = Fraction(particle["mass_kg"]) / exact["mass_kg"]
        _represent(mass, path + "/mass_kg", "reduced mass", positive=True)
        reduced_masses.append(mass)
        for j, value in enumerate(particle["position_m"]):
            _represent(Fraction(value)/length, path + "/position_m/" + str(j), "reduced position")
        for j, value in enumerate(particle["velocity_m_per_s"]):
            _represent(Fraction(value)/exact["velocity_m_per_s"],
                       path + "/velocity_m_per_s/" + str(j), "reduced velocity")
    _represent(Fraction(request["system"]["min_distance_m"])/length,
               "/system/min_distance_m", "reduced minimum distance", positive=True)
    return scales, reduced_masses


def _budgets(request: dict, profile: dict, common: dict, source_bytes: int,
             canonical: bytes, registry: ContractRegistry) -> dict:
    limits = {key: _limit(profile, key, ceiling, "/resource_policy/profiles/pair_dynamics_cpu/" + key)
              for key, ceiling in _PROFILE_LIMITS.items()}
    common_limits = {key: _limit(common, key, ceiling, "/resource_policy/common_execution/" + key)
                     for key, ceiling in _COMMON_LIMITS.items()}
    if source_bytes > common_limits["max_input_bytes"]:
        raise _Invalid("RESOURCE_LIMIT", "Request exceeds effective input byte limit", None,
                       requested=source_bytes, limit=common_limits["max_input_bytes"])
    particles = request["system"]["particles"]
    n = request["numerics"]
    steps, stride = int(n["steps"]), int(n["sample_stride"])
    if stride > steps:
        raise _Invalid("INPUT_SEMANTIC", "Sample stride exceeds requested steps", "/numerics/sample_stride")
    factors = [1] if n["refinement"] == "none" else [1, 2, 4]
    count = len(particles)
    evaluations = sum(factor*steps+1 for factor in factors)
    pair_work = count*(count-1)//2 * evaluations
    frames = 1 + (steps+stride-1)//stride
    reserved_frames = len(factors)*(frames+1)
    quantities = [(count, "max_particles"), (max(factors)*steps, "max_base_steps"),
                  (evaluations, "max_total_force_evaluations"),
                  (pair_work, "max_pair_evaluations"), (reserved_frames, "max_total_output_frames")]
    for requested, key in quantities:
        if requested > limits[key]:
            raise _Invalid("RESOURCE_LIMIT", "Requested dynamics work exceeds the effective resource profile",
                           "/numerics", resource=key, requested=requested, limit=limits[key])
    # This is a trajectory reservation plus presently known bytes, NOT a complete
    # future run/provenance estimator. Its remaining budget is reported explicitly.
    trajectory = 65536 + reserved_frames*(25*(9*count+15)+8*count+1024)
    registry_bytes = sum(len(raw) for raw in registry.raw_bytes.values())
    manifest_bytes = len(canonical_bytes(registry.manifest))
    terminal_reserve = 8192 + 4096  # one initial-only execution step, future run gate rechecks
    known = trajectory + source_bytes + len(canonical) + registry_bytes + manifest_bytes + terminal_reserve
    cap = common_limits["max_artifact_bytes_per_run"]
    if known > cap:
        raise _Invalid("RESOURCE_LIMIT", "Known dynamics input/trajectory/provenance reservation exceeds run bytes",
                       "/numerics", requested=known, limit=cap)
    return {"refinement_factors": factors, "total_force_evaluations": evaluations,
            "total_pair_evaluations": pair_work, "reserved_output_frames": reserved_frames,
            "trajectory_byte_bound": trajectory, "source_input_bytes": source_bytes,
            "canonical_request_bytes": len(canonical), "frozen_registry_bytes": registry_bytes+manifest_bytes,
            "terminal_envelope_reserve_bytes": terminal_reserve,
            "known_minimum_reserved_run_bytes": known, "artifact_byte_limit": cap,
            "remaining_for_future_execution_provenance_bytes": cap-known,
            "complete_execution_provenance_estimate": False,
            "limits": limits, "wall_seconds_per_step": common_limits["wall_seconds_per_step"],
            "wall_seconds_per_run": common_limits["wall_seconds_per_run"],
            "validation_wall_seconds": min(common_limits["wall_seconds_per_step"], common_limits["wall_seconds_per_run"])}


def _time_grid(request: dict, factors: list[int]) -> list[dict]:
    h = Fraction(request["numerics"]["dt_s"])
    duration_scale = Fraction(request["scales"]["time_s"])
    steps = int(request["numerics"]["steps"])
    legs = []
    for factor in factors:
        dt_exact = h/factor
        dt = _represent(dt_exact, "/numerics/dt_s", "refined time step", positive=True)
        if Fraction(dt) != dt_exact:
            raise _Invalid("INPUT_SEMANTIC", "Refined step has no exact binary64 carrier", "/numerics/dt_s")
        half_exact = dt_exact/2
        half = _represent(half_exact, "/numerics/dt_s", "SI half-step", positive=True)
        if Fraction(half) != half_exact:
            raise _Invalid("INPUT_SEMANTIC", "SI half-step has no exact binary64 carrier", "/numerics/dt_s")
        reduced = _represent(dt_exact/duration_scale, "/numerics/dt_s", "reduced time step", positive=True)
        reduced_half = _represent(Fraction(reduced)/2, "/numerics/dt_s", "reduced half-step", positive=True)
        if Fraction(reduced_half) != Fraction(reduced)/2:
            raise _Invalid("INPUT_SEMANTIC", "Reduced half-step has no exact binary64 carrier", "/numerics/dt_s")
        previous = 0.0
        for index in range(1, factor*steps+1):
            now = _represent(index*dt_exact, "/numerics/dt_s", "physical time", positive=True)
            if now <= previous:
                raise _Invalid("INPUT_SEMANTIC", "Physical time grid does not strictly increase", "/numerics/dt_s")
            previous = now
        legs.append({"refinement_factor": factor, "dt_s": dt, "steps": factor*steps,
                     "final_time_s": previous, "reduced_dt": reduced})
    return legs


def _initial_diagnostics(request: dict, force_result: Any, scales: dict[str, float]) -> dict:
    particles = request["system"]["particles"]
    masses = [Fraction(p["mass_kg"]) for p in particles]
    positions = [[Fraction(x) for x in p["position_m"]] for p in particles]
    velocities = [[Fraction(x) for x in p["velocity_m_per_s"]] for p in particles]
    total_mass = sum(masses, Fraction())
    _represent(total_mass, "/system/particles", "total mass", positive=True)
    kinetic_exact = sum((m*sum((v*v for v in velocity), Fraction())/2
                         for m, velocity in zip(masses, velocities)), Fraction())
    kinetic = _represent(kinetic_exact, "/system/particles", "initial kinetic energy")
    total_energy = _represent(Fraction(kinetic)+Fraction(force_result.energy_j),
                              "/system/particles", "initial total energy")
    momentum_exact = [sum((m*v[axis] for m,v in zip(masses,velocities)), Fraction()) for axis in range(3)]
    angular_exact = [sum((m*(r[(axis+1)%3]*v[(axis+2)%3]-r[(axis+2)%3]*v[(axis+1)%3])
                         for m,r,v in zip(masses,positions,velocities)), Fraction()) for axis in range(3)]
    momentum = [_represent(x, "/system/particles", "initial momentum") for x in momentum_exact]
    angular = [_represent(x, "/system/particles", "initial angular momentum") for x in angular_exact]
    center = [_represent(sum((m*r[axis] for m,r in zip(masses,positions)), Fraction())/total_mass,
                         "/system/particles", "initial center of mass") for axis in range(3)]
    com_velocity = [_represent(x/total_mass, "/system/particles", "initial center of mass velocity")
                    for x in momentum_exact]
    # Mandatory normalized outputs must themselves be finite and nonzero-safe.
    energy_scale = Fraction(request["scales"]["energy_j"])
    for name,value in (("kinetic energy",kinetic),("potential energy",force_result.energy_j),("total energy",total_energy)):
        _represent(Fraction(value)/energy_scale,"/system/particles","reduced "+name)
    for quantity, values, scale in (("momentum",momentum,scales["momentum_kg_m_per_s"]),
                                    ("angular momentum",angular,scales["angular_momentum_kg_m2_per_s"])):
        for value in values:
            _represent(Fraction(value)/Fraction(scale), "/system/particles", "reduced "+quantity)
    return {"potential_energy_j": force_result.energy_j, "kinetic_energy_j": kinetic,
            "total_energy_j": total_energy, "linear_momentum_kg_m_per_s": momentum,
            "angular_momentum_kg_m2_per_s": angular, "center_of_mass_m": center,
            "center_of_mass_velocity_m_per_s": com_velocity,
            "scope": "initial_feasibility_only_not_trajectory"}


def validate_dynamics_request(value: bytes | str | dict, *, registry: ContractRegistry | None = None) -> dict:
    """Check a standalone request; acceptance never enables its time integrator."""
    report = {"scope": "standalone_dynamics_request_validation", "valid": False,
              "contract_version": CONTRACT_VERSION, "module_id": _MODULE,
              "module_version": _MODULE_VERSION, "operation": "integrate",
              "executable": False, "dynamics_simulation_executed": False,
              "initial_force_evaluation_performed": False,
              "physical_validation_status": "unvalidated", "input_sha256": None,
              "errors": [], "warnings": []}
    started = time.monotonic()
    try:
        request = parse_json(value, max_bytes=_MAX_BYTES)
        if not isinstance(request, dict):
            raise _Invalid("INPUT_SCHEMA", "Standalone dynamics request must be an object", "")
        if request.get("contract_version") != CONTRACT_VERSION:
            raise _Invalid("MODEL_UNSUPPORTED", "Standalone dynamics request requires contract0.3.0", "/contract_version")
        canonical = canonical_bytes(request)
        if isinstance(value, bytes):
            source_size = len(value)
        elif isinstance(value, str):
            source_size = len(value.encode("utf-8"))
        else:
            source_size = len(canonical)
        frozen = registry or ContractRegistry(contract_version=CONTRACT_VERSION)
        integrity = frozen.validate_integrity()
        if integrity:
            raise _Invalid("REGISTRY_SNAPSHOT_UNAVAILABLE", "Frozen dynamics bundle integrity check failed", None,
                           errors=integrity[:5])
        if frozen.data.get("contract_version") != CONTRACT_VERSION:
            raise _Invalid("REGISTRY_SNAPSHOT_UNAVAILABLE", "Wrong contract bundle supplied for dynamics validation", None)
        module = frozen.get_module(_MODULE, _MODULE_VERSION)
        if module is None:
            raise _Invalid("MODEL_UNSUPPORTED", "Exact dynamics registration is unavailable", "/system")
        caps = module["capabilities"]
        profile = frozen.resolve_schema(caps["resource_policy_ref"]+"#"+caps["resource_profile_pointer"])
        if _MODULE+"@"+_MODULE_VERSION not in profile.get("module_versions", []):
            raise _Invalid("REGISTRY_SNAPSHOT_UNAVAILABLE", "Dynamics resource profile binding is absent", None)
        common = frozen.resource_policy["common_execution"]
        ast_limits = {name: _limit(profile, name, ceiling,
            "/resource_policy/profiles/pair_dynamics_cpu/"+name,
            allow_zero=name == "max_parameters") for name, ceiling in
            (("max_ast_depth",16),("max_ast_nodes",128),("max_parameters",32))}
        potential = request.get("system", {}).get("potential", {}) if isinstance(request.get("system"), dict) else {}
        if isinstance(potential, dict) and "expression" in potential:
            _ast_preflight(potential["expression"], max_depth=ast_limits["max_ast_depth"], max_nodes=ast_limits["max_ast_nodes"])
            parameters = potential.get("parameters")
            if isinstance(parameters, dict) and len(parameters) > ast_limits["max_parameters"]:
                raise _Invalid("RESOURCE_LIMIT", "Parameter count exceeds the effective resource profile",
                               "/system/potential/parameters", requested=len(parameters), limit=ast_limits["max_parameters"])
        schema_ref = module.get("request_schema_ref")
        if not isinstance(schema_ref, str):
            raise _Invalid("REGISTRY_SNAPSHOT_UNAVAILABLE", "Dynamics request schema is not registered", None)
        errors = list(itertools.islice(frozen.validator(schema_ref).iter_errors(request), 20))
        if errors:
            report["errors"] = [_issue("INPUT_SCHEMA", error.message[:300], pointer(tuple(error.absolute_path))) for error in errors]
            return report
        identifiers = [p["id"] for p in request["system"]["particles"]]
        if len(identifiers) != len(set(identifiers)):
            raise _Invalid("INPUT_SEMANTIC", "Particle IDs must be unique", "/system/particles")
        _parameter_refs(request["system"]["potential"]["expression"], request["system"]["potential"]["parameters"])
        budgets = _budgets(request, profile, common, source_size, canonical, frozen)
        scales, _ = _scales(request)
        legs = _time_grid(request, budgets["refinement_factors"])
        deadline = started+budgets["validation_wall_seconds"]
        def check_deadline():
            if time.monotonic() > deadline:
                raise _Invalid("RESOURCE_LIMIT", "Initial dynamics validation exceeded its wall deadline", None)
        check_deadline()
        # Import after cheap structure/resource checks; this performs initial force
        # evaluation, not a dynamics request translated into a static definition.
        from .pair_kernel import PairForceKernel
        system = request["system"]
        kernel = PairForceKernel(count=len(system["particles"]),
            length_m=request["scales"]["length_m"], energy_j=request["scales"]["energy_j"],
            min_distance_m=system["min_distance_m"], expression=system["potential"]["expression"],
            parameters=system["potential"]["parameters"], particles_path="/system/particles",
            payload_path="/initial_state", scales_path="/scales", potential_path="/system/potential")
        result = kernel.evaluate([p["position_m"] for p in system["particles"]], check_deadline=check_deadline)
        report["initial_force_evaluation_performed"] = True
        initial = _initial_diagnostics(request, result, scales)
        check_deadline()
        report.update(valid=True, input_sha256=hashlib.sha256(canonical).hexdigest(),
                      budgets=budgets, derived_scales=scales, time_legs=legs, initial_state_checks=initial)
        report["warnings"].append(_issue("MODEL_UNSUPPORTED",
            "Request is valid, but the dynamics integrator and workflow execution are not implemented", None))
    except StrictJSONError as exc:
        report["errors"] = [_issue(exc.code, str(exc), exc.path)]
    except (CalculationError, _Invalid) as exc:
        report["errors"] = [_issue(exc.code, str(exc), exc.path, exc.details)]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        report["errors"] = [_issue("REGISTRY_SNAPSHOT_UNAVAILABLE",
            "Dynamics validation could not load or resolve the frozen bundle", None,
            {"reason": str(exc)[:200]})]
    return report
