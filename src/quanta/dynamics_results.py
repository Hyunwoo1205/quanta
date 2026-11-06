"""Checked standalone dynamics publication, scientific state and actual provenance.

No run/state UUIDs, saved code execution, implicit replay or checkpoint claims
are introduced here.  Structure alone is insufficient: phase arrays, counts,
times, scalar diagnostics and status combinations must agree before publication.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import itertools
import json
import math
from fractions import Fraction
from pathlib import Path

from . import __version__
from .autodiff import CalculationError, _fraction_float
from .environment import environment_report
from .hashing import canonical_bytes
from .parsing import StrictJSONError, parse_json
from .profiles import load_lock_files
from .registry import ContractRegistry

CONTRACT_VERSION = "0.3.1"
MAX_REPORT_BYTES = 33_554_432


def _fail(message, path="/payload", *, code="ENGINE_FAILURE", **details):
    raise CalculationError(message, code=code, path=path, details=details)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def transport_bytes(value) -> bytes:
    """The report transport preserves signed zero; scientific hashes use JCS."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _float(value, path="/payload"):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail("Payload number is not binary64", path)
    try:
        result = float(value)
    except (ValueError, OverflowError):
        _fail("Payload number has no binary64 carrier", path)
    if not math.isfinite(result) or (isinstance(value, int) and int(result) != value):
        _fail("Payload number has no exact finite binary64 carrier", path)
    return result


def _same_number(a, b):
    return _float(a).hex() == _float(b).hex()


def _same_tree(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return _same_number(a, b)
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_same_tree(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_tree(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _finite_tree(value, path="/payload"):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        _float(value, path)
    elif isinstance(value, dict):
        for key, child in value.items():
            _finite_tree(child, path + "/" + key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _finite_tree(child, path + "/" + str(index))


def _registered(registry: ContractRegistry, ref: str, value, path="/payload"):
    try:
        errors = list(itertools.islice(registry.validator(ref).iter_errors(value), 1))
    except (KeyError, TypeError, ValueError) as exc:
        _fail("Registered output schema is unavailable", path,
              code="REGISTRY_SNAPSHOT_UNAVAILABLE", reason=str(exc)[:160])
    if errors:
        _fail("Output violates its registered schema", path,
              reason=errors[0].message[:200])


def _integrity(registry):
    if registry.data.get("contract_version") != CONTRACT_VERSION or registry.validate_integrity():
        _fail("Standalone solver contract integrity is unavailable", None,
              code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    # Registry instances are Python objects: do not let mutated active rules be
    # represented by hashes of a different frozen byte snapshot.
    try:
        documents = {name:parse_json(raw) for name,raw in registry.raw_bytes.items()
                     if name.endswith(".json")}
        ids = {doc["$id"]:name for name,doc in documents.items() if "$schema" in doc and "$id" in doc}
        if (not _same_tree(documents,registry.documents) or not _same_tree(registry.data,documents["registry.json"]) or
                not _same_tree(registry.resource_policy,documents["resource_policy.json"]) or ids != registry.schema_ids):
            _fail("Active contract rules differ from their frozen bytes",None,code="REGISTRY_SNAPSHOT_UNAVAILABLE")
        for name,doc in documents.items():
            if "$schema" in doc:
                for alias in (name,doc.get("$id"),"https://quanta.invalid/contracts/v"+CONTRACT_VERSION+"/"+name):
                    if not _same_tree(registry.offline_registry.get(alias).contents,doc):
                        _fail("Active schema resolver differs from frozen rules",None,code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    except (KeyError, AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc,CalculationError):
            raise
        _fail("Active contract snapshot is malformed",None,code="REGISTRY_SNAPSHOT_UNAVAILABLE")


def _rounded(value: Fraction, quantity):
    return _fraction_float(value, "/payload", quantity)


def _frame_quantities(frame, masses):
    q = [[Fraction(_float(x)) for x in row] for row in frame["positions_m"]]
    v = [[Fraction(_float(x)) for x in row] for row in frame["velocities_m_per_s"]]
    m = list(map(Fraction, masses))
    kinetic = _rounded(sum((mass*sum((x*x for x in velocity), Fraction())/2
                            for mass, velocity in zip(m, v)), Fraction()), "kinetic energy")
    total = _rounded(Fraction(kinetic) + Fraction(frame["potential_energy_j"]), "total energy")
    p = [_rounded(sum((mass*velocity[j] for mass, velocity in zip(m, v)), Fraction()),
                  "linear momentum") for j in range(3)]
    angular = [_rounded(sum((mass*(r[(j+1)%3]*velocity[(j+2)%3] -
                                  r[(j+2)%3]*velocity[(j+1)%3])
                            for mass, r, velocity in zip(m, q, v)), Fraction()),
                        "angular momentum") for j in range(3)]
    return kinetic, total, p, angular


def _center(values, masses):
    total = sum(map(Fraction,masses),Fraction())
    return [_rounded(sum((Fraction(m)*Fraction(row[j]) for m,row in zip(masses,values)),Fraction())/total,
                     "center of mass") for j in range(3)]


def _lower_bound(maximum, observed):
    # Allow only a few ulps for alternative correctly rounded diagnostic order,
    # never an arbitrary absolute floor that hides small nonzero quantities.
    a, b = _float(maximum), _float(observed)
    return a >= b or b-a <= 8*max(math.ulp(a), math.ulp(b))


def check_payload(request: dict, payload: dict, *, registry: ContractRegistry,
                  execution_status: str, numerical_status: str,
                  resolution_status: str) -> None:
    """Validate structure and request-relative output semantics without extra forces."""
    _integrity(registry)
    _registered(registry, "dynamics_request.schema.json", request, "/request")
    _registered(registry, "dynamics_payload.schema.json", payload)
    _finite_tree(payload)
    if request.get("contract_version") != CONTRACT_VERSION:
        _fail("Payload request uses a different solver contract", "/contract_version")
    particles = request["system"]["particles"]
    ids = [p["id"] for p in particles]
    masses = [p["mass_kg"] for p in particles]
    if payload["particle_ids"] != ids or not _same_tree(payload["masses_kg"], masses):
        _fail("Particle identity or mass order changed")
    count = len(particles)
    n = request["numerics"]
    base_steps, stride = int(n["steps"]),int(n["sample_stride"])
    expected_factors = [1] if n["refinement"] == "none" else [1, 2, 4]
    legs = payload["legs"]
    factors = [leg["refinement_factor"] for leg in legs]
    if factors != expected_factors[:len(factors)]:
        _fail("Trajectory legs are not the unique requested prefix")
    if payload["partial"] != (execution_status != "SUCCEEDED"):
        _fail("Payload partial flag does not match execution outcome")
    if execution_status == "CANCELLED":
        _fail("Unpublished standalone cancellation cannot publish an active trajectory")
    frames_reserved = len(expected_factors)*(2 + math.ceil(n["steps"]/n["sample_stride"]))
    # F=1+ceil(n/s), plus one reserved terminal partial frame for each leg.
    if sum(len(leg["sampled_frames"]) for leg in legs) > frames_reserved:
        _fail("Trajectory exceeds its reserved frame count")
    length, energy, duration = (Fraction(request["scales"][key])
                                 for key in ("length_m", "energy_j", "time_s"))
    pscale = Fraction(_rounded(energy*duration/length, "momentum scale"))
    jscale = Fraction(_rounded(energy*duration, "angular momentum scale"))
    sample_indices = list(range(0,base_steps,stride)) + [base_steps]
    all_complete = len(legs) == len(expected_factors)
    total_calls = 0
    numeric_ok = True
    for leg_index,leg in enumerate(legs):
        factor = leg["refinement_factor"]
        steps = factor*n["steps"]
        completed = leg["completed_steps"]
        expected_dt = float(Fraction(n["dt_s"])/factor)
        if leg["requested_steps"] != steps or not _same_number(leg["dt_s"], expected_dt):
            _fail("Leg time step or requested length differs from request")
        if completed > steps:
            _fail("Completed steps exceed requested steps")
        complete = completed == steps
        all_complete = all_complete and complete and leg["stop_reason"] == "completed"
        if leg["stop_reason"] == "completed" and not complete:
            _fail("Completed leg stop reason disagrees with accepted length")
        if leg_index < len(legs)-1 and (not complete or leg["stop_reason"] != "completed"):
            _fail("A later refinement leg cannot follow an unfinished leg")
        attempted, successful = leg["force_evaluations"], leg["completed_force_evaluations"]
        low = completed+1
        high = min(completed+2, steps+1)
        if not low <= successful <= attempted <= high:
            _fail("Attempted/successful force counts disagree with accepted steps")
        if complete and (attempted != steps+1 or successful != steps+1):
            _fail("Complete VV leg must evaluate one initial and one force per step")
        total_calls += attempted
        expected_indices = [factor*j for j in sample_indices if factor*j <= completed]
        if expected_indices[-1] != completed:
            expected_indices.append(completed)
        frames = leg["sampled_frames"]
        if [frame["step_index"] for frame in frames] != expected_indices:
            _fail("Stored trajectory indices do not match requested sampling and terminal state")
        first = frames[0]
        if not _same_tree(first["positions_m"], [p["position_m"] for p in particles]):
            _fail("Initial SI positions changed")
        if not _same_tree(first["velocities_m_per_s"], [p["velocity_m_per_s"] for p in particles]):
            _fail("Initial synchronized velocities changed")
        initial_center = _center(first["positions_m"],masses)
        initial_center_velocity = _center(first["velocities_m_per_s"],masses)
        for frame in frames:
            if not _same_number(frame["time_s"], float(Fraction(expected_dt)*frame["step_index"])):
                _fail("Frame time is not the exact integer-index clock")
            for name in ("positions_m", "velocities_m_per_s", "forces_n"):
                if len(frame[name]) != count or any(len(row) != 3 for row in frame[name]):
                    _fail("Phase arrays do not have the requested particle shape")
            minimum2 = Fraction(request["system"]["min_distance_m"])**2
            for a,b in itertools.combinations(frame["positions_m"],2):
                if sum(((Fraction(x)-Fraction(y))**2 for x,y in zip(a,b)),Fraction()) <= minimum2:
                    _fail("Accepted phase frame violates the authored pair-distance domain")
            kinetic, total, momentum, angular = _frame_quantities(frame, masses)
            if not _same_number(frame["kinetic_energy_j"], kinetic) or not _same_number(frame["total_energy_j"], total):
                _fail("Frame K/U/E are not synchronized or arithmetically consistent")
            if not _same_tree(frame["linear_momentum_kg_m_per_s"], momentum):
                _fail("Frame momentum does not match its synchronized velocities")
            if not _same_tree(frame["angular_momentum_kg_m2_per_s"], angular):
                _fail("Frame angular momentum does not match its synchronized phase state")
            e_drift = _rounded(abs(Fraction(total)-Fraction(first["total_energy_j"]))/energy, "energy drift")
            p_drift = max(_rounded(abs(Fraction(x)-Fraction(y))/pscale, "momentum drift")
                          for x,y in zip(momentum, first["linear_momentum_kg_m_per_s"]))
            l_drift = max(_rounded(abs(Fraction(x)-Fraction(y))/jscale, "angular drift")
                          for x,y in zip(angular, first["angular_momentum_kg_m2_per_s"]))
            com_drift = max(_rounded(abs(Fraction(actual)-Fraction(initial)-Fraction(velocity)*Fraction(frame["time_s"]))/length,
                                     "center of mass drift")
                for actual,initial,velocity in zip(_center(frame["positions_m"],masses),initial_center,initial_center_velocity))
            for field, observed in (("max_energy_drift_scaled",e_drift),
                                    ("max_momentum_drift_scaled",p_drift),
                                    ("max_angular_momentum_drift_scaled",l_drift),
                                    ("max_com_ballistic_error_scaled",com_drift)):
                if not _lower_bound(leg[field], observed):
                    _fail("All-step diagnostic maximum understates a retained frame", "/payload/legs/"+field)
        numeric_ok = numeric_ok and all(leg[field] <= n[tolerance]
            for field,tolerance in (("max_energy_drift_scaled","energy_drift_atol"),
                                    ("max_momentum_drift_scaled","momentum_drift_atol"),
                                    ("max_angular_momentum_drift_scaled","angular_momentum_drift_atol")))
    planned_calls = n["steps"]+1 if len(expected_factors)==1 else 7*n["steps"]+3
    if total_calls > planned_calls:
        _fail("Trajectory force calls exceed its planned reservation")
    expected_numerical = ("pass" if numeric_ok else "not_converged") if all_complete else "not_checked"
    unassessed_failure = execution_status == "FAILED" and numerical_status == "not_checked"
    if numerical_status != expected_numerical and not unassessed_failure:
        _fail("Numerical status disagrees with complete trajectory diagnostics")
    resolution = payload["resolution_comparison"]
    if resolution["mode"] != n["refinement"] or resolution["status"] != resolution_status:
        _fail("Resolution mode/status differs from requested assessment")
    coarse, fine = resolution["coarse_pair_scaled_error"], resolution["fine_pair_scaled_error"]
    unassessed_resolution = execution_status == "FAILED" and resolution_status == "not_checked"
    if n["refinement"] == "none" or not all_complete or unassessed_resolution:
        if resolution_status != "not_checked" or coarse is not None or fine is not None:
            _fail("Unrequested or incomplete refinement cannot publish a resolution assessment")
    else:
        if coarse is None or fine is None:
            _fail("Completed refinement is missing both comparison errors")
        expected_resolution = "pass" if coarse <= 1 and fine <= 1 and fine <= coarse else "not_converged"
        if resolution_status != expected_resolution:
            _fail("Resolution status disagrees with its two requested comparison criteria")
    if execution_status == "SUCCEEDED" and (not all_complete or numerical_status != "pass" or
            resolution_status != ("not_checked" if n["refinement"] == "none" else "pass")):
        _fail("Success cannot publish an incomplete or nonconverged phase state")


def _phase_data(request, frame=None):
    system = copy.deepcopy(request["system"])
    if frame is not None:
        for p,q,v in zip(system["particles"],frame["positions_m"],frame["velocities_m_per_s"]):
            p["position_m"],p["velocity_m_per_s"] = copy.deepcopy(q),copy.deepcopy(v)
    return {"contract_version":CONTRACT_VERSION,"module_id":"quanta.pair_dynamics",
            "module_version":"0.1.0","representation":"particles_phase_space_3d",
            "representation_version":"0.1.0","time_kind":"evolving",
            "time_s":frame["time_s"] if frame is not None else request["initial_time_s"],
            "scales":copy.deepcopy(request["scales"]),"system":system}


def build_phase_state(request: dict, payload: dict, *, registry: ContractRegistry) -> dict:
    """Construct only the successful primary final scientific state, without IDs."""
    check_payload(request,payload,registry=registry,execution_status="SUCCEEDED",
                  numerical_status="pass",resolution_status=payload["resolution_comparison"]["status"])
    primary = payload["legs"][0]
    if payload["partial"] or primary["refinement_factor"] != 1 or primary["completed_steps"] != request["numerics"]["steps"]:
        _fail("Incomplete primary cannot become a final scientific state", "/final_state")
    data = _phase_data(request, primary["sampled_frames"][-1])
    metadata = {"contract_version":CONTRACT_VERSION,"position_unit":"m","velocity_unit":"m/s",
                "mass_unit":"kg","time_unit":"s","force_unit":"N","real_dtype":"float64",
                "finite_only":True,"velocity_time_convention":"synchronized_full_step",
                "physical_validation_status":"unvalidated"}
    _registered(registry,"dynamics_state.schema.json",data,"/final_state/data")
    _registered(registry,"dynamics_metadata.schema.json",metadata,"/final_state/metadata")
    content = {"data":data,"metadata":metadata,"physical_time":{"value":data["time_s"],"unit":"s"}}
    return {**content,"scientific_state_sha256":_sha(canonical_bytes(content))}


def capture_provenance(request: dict, *, registry: ContractRegistry,
                       environment: dict | None = None, original_input=None,
                       instrumentation_present: bool = False) -> dict:
    """Capture actual content-addressed inputs, trusted local code, locks and observation."""
    _integrity(registry)
    _registered(registry,"dynamics_request.schema.json",request,"/request")
    if type(instrumentation_present) is not bool:
        _fail("Instrumentation presence must be an explicit boolean", "/provenance")
    observed = parse_json(environment if environment is not None else environment_report())
    if observed.get("valid") is not True:
        _fail("Observed runtime does not match the locked numerical baseline", None, code="MODEL_UNSUPPORTED")
    contents = {}
    def capture(raw):
        digest = _sha(raw)
        contents[digest] = raw.decode("utf-8", errors="strict")
        return digest
    authored = parse_json(request)
    canonical_request = canonical_bytes(authored)
    if original_input is None or isinstance(original_input, dict):
        original = transport_bytes(authored if original_input is None else parse_json(original_input))
        source_encoding = "detached_dictionary_json"
    elif isinstance(original_input, bytes):
        original, source_encoding = original_input,"original_utf8_bytes"
    elif isinstance(original_input, str):
        original, source_encoding = original_input.encode("utf-8"),"original_utf8_text"
    else:
        _fail("Original input is not supported JSON", "/provenance")
    if not _same_tree(parse_json(original),authored):
        _fail("Original source bytes do not describe the effective authored request", "/provenance")
    source_files = {"src/quanta/"+path.name:capture(path.read_bytes())
                    for path in sorted(Path(__file__).resolve().parent.glob("*.py"))}
    bundle_files = {name:capture(raw) for name,raw in sorted(registry.raw_bytes.items())}
    manifest_raw = registry._manifest_path.read_bytes()
    if parse_json(manifest_raw) != registry.manifest:
        _fail("Frozen bundle manifest changed during capture", "/provenance", code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    locks = load_lock_files()
    lock_files = {name:capture(raw) for name,raw in sorted(locks.items())}
    lock = parse_json(locks["requirements.lock.json"])
    distributions = []
    for item in lock["packages"]:
        actual = importlib.metadata.version(item["name"])
        if actual != item["version"]:
            _fail("Installed distribution differs from its locked version", "/provenance",
                  code="MODEL_UNSUPPORTED", distribution=item["name"],expected=item["version"],observed=actual)
        distributions.append({"name":item["name"],"expected_version":item["version"],"observed_version":actual,
                              "locked_filename":item["filename"],"locked_wheel_sha256":item["sha256"]})
    if importlib.metadata.version("quanta-research-contracts") != __version__:
        _fail("Installed Quanta metadata differs from loaded package", "/provenance", code="MODEL_UNSUPPORTED")
    initial = _phase_data(request)
    result = {"provenance_version":"0.1.0","package_version":__version__,"contract_version":CONTRACT_VERSION,
              "solver":{"id":"velocity_verlet_forward_ad","version":"0.1.0"},
              "authored_request_canonical_sha256":capture(canonical_request),
              "original_input_sha256":capture(original),"original_input_encoding":source_encoding,
              "initial_state_canonical_sha256":capture(canonical_bytes(initial)),
              "initial_state_transport_sha256":capture(transport_bytes(initial)),
              "source_files_sha256":source_files,"contract_files_sha256":bundle_files,
              "contract_digest_manifest_sha256":capture(manifest_raw),
              "dependency_lock_files_sha256":lock_files,"observed_locked_distributions":distributions,
              "environment":observed,"instrumentation_present":instrumentation_present,
              "instrumentation_identity_captured":False,"captured_utf8_contents":contents}
    result["implementation_manifest_sha256"] = _sha(canonical_bytes({"package_version":__version__,"files":source_files}))
    result["registry_snapshot_sha256"] = bundle_files["registry.json"]
    result["environment_sha256"] = _sha(canonical_bytes(observed))
    return result


def _check_provenance(request, provenance, registry):
    try:
        if provenance["authored_request_canonical_sha256"] != _sha(canonical_bytes(request)):
            _fail("Provenance is bound to a different authored request", "/provenance")
        captured=provenance["captured_utf8_contents"]
        for sha,text in provenance["captured_utf8_contents"].items():
            if _sha(text.encode("utf-8")) != sha:
                _fail("Captured provenance bytes differ from their hash", "/provenance")
        current = {"src/quanta/"+p.name:_sha(p.read_bytes())
                   for p in sorted(Path(__file__).resolve().parent.glob("*.py"))}
        if current != provenance["source_files_sha256"]:
            _fail("Implementation source changed during dynamics execution", "/provenance")
        if {k:_sha(v) for k,v in registry.raw_bytes.items()} != provenance["contract_files_sha256"]:
            _fail("Frozen contract snapshot changed during execution", "/provenance")
        disk={name:_sha((registry.contract_dir/name).read_bytes())
              for name in registry.raw_bytes}
        if disk != provenance["contract_files_sha256"]:
            _fail("Frozen contract files changed on disk during execution", "/provenance")
        if _sha(registry._manifest_path.read_bytes()) != provenance["contract_digest_manifest_sha256"]:
            _fail("Frozen contract manifest changed during execution", "/provenance")
        if {k:_sha(v) for k,v in load_lock_files().items()} != provenance["dependency_lock_files_sha256"]:
            _fail("Dependency lock files changed during execution", "/provenance")
        expected = _sha(canonical_bytes({"package_version":provenance["package_version"],
                                         "files":provenance["source_files_sha256"]}))
        if expected != provenance["implementation_manifest_sha256"] or provenance["package_version"] != __version__:
            _fail("Implementation provenance manifest is inconsistent", "/provenance")
        if provenance["environment_sha256"] != _sha(canonical_bytes(provenance["environment"])):
            _fail("Environment observation differs from its recorded digest", "/provenance")
        if provenance["registry_snapshot_sha256"] != provenance["contract_files_sha256"]["registry.json"]:
            _fail("Registry snapshot reference differs from its captured file", "/provenance")
        # Every reference must resolve to captured bytes, not merely have hash-like syntax.
        refs = [provenance["original_input_sha256"],provenance["authored_request_canonical_sha256"],
                provenance["initial_state_canonical_sha256"],provenance["initial_state_transport_sha256"],
                provenance["contract_digest_manifest_sha256"],*provenance["source_files_sha256"].values(),
                *provenance["contract_files_sha256"].values(),*provenance["dependency_lock_files_sha256"].values()]
        if any(ref not in provenance["captured_utf8_contents"] for ref in refs):
            _fail("Provenance references unavailable captured bytes", "/provenance")
        if captured[provenance["authored_request_canonical_sha256"]].encode() != canonical_bytes(request):
            _fail("Captured authored request is not its canonical projection", "/provenance")
        if not _same_tree(parse_json(captured[provenance["original_input_sha256"]]),request):
            _fail("Captured original input does not match the request", "/provenance")
        initial=_phase_data(request)
        if captured[provenance["initial_state_canonical_sha256"]].encode() != canonical_bytes(initial):
            _fail("Captured initial scientific state is not the authored phase state", "/provenance")
        if captured[provenance["initial_state_transport_sha256"]].encode() != transport_bytes(initial):
            _fail("Captured initial phase transport changed numeric carriers", "/provenance")
        if provenance["provenance_version"] != "0.1.0" or provenance["contract_version"] != CONTRACT_VERSION or provenance["solver"] != {"id":"velocity_verlet_forward_ad","version":"0.1.0"}:
            _fail("Provenance identity differs from the selected implementation", "/provenance")
        if type(provenance["instrumentation_present"]) is not bool or provenance["instrumentation_identity_captured"] is not False:
            _fail("Instrumentation provenance makes an unsupported identity claim", "/provenance")
        if provenance["original_input_encoding"] not in {"detached_dictionary_json","original_utf8_bytes","original_utf8_text"}:
            _fail("Original input provenance has an unsupported encoding claim", "/provenance")
        if importlib.metadata.version("quanta-research-contracts") != __version__:
            _fail("Installed Quanta metadata differs from loaded implementation", "/provenance", code="MODEL_UNSUPPORTED")
        observed=environment_report()
        if not observed["valid"]:
            _fail("Runtime baseline changed during execution", "/provenance", code="MODEL_UNSUPPORTED")
        if canonical_bytes(observed) != canonical_bytes(provenance["environment"]):
            _fail("Observed runtime differs from its frozen observation", "/provenance", code="MODEL_UNSUPPORTED")
        expected_distributions = [{"name":item["name"],"expected_version":item["version"],
            "observed_version":importlib.metadata.version(item["name"]),"locked_filename":item["filename"],
            "locked_wheel_sha256":item["sha256"]} for item in parse_json(load_lock_files()["requirements.lock.json"])["packages"]]
        if expected_distributions != provenance["observed_locked_distributions"] or any(item["expected_version"] != item["observed_version"] for item in expected_distributions):
            _fail("Installed dependency inventory differs from its frozen lock observation", "/provenance", code="MODEL_UNSUPPORTED")
    except (KeyError, TypeError, AttributeError, UnicodeError, ValueError, OSError, importlib.metadata.PackageNotFoundError) as exc:
        if isinstance(exc, CalculationError):
            raise
        _fail("Incomplete or malformed provenance", "/provenance", reason=str(exc)[:160])


def finalise_report(request: dict, report: dict, *, registry: ContractRegistry,
                    provenance: dict | None = None, artifact_byte_limit: int | None = None) -> dict:
    """Return a detached, schema/semantic/byte-checked standalone report."""
    _integrity(registry)
    _registered(registry,"dynamics_request.schema.json",request,"/request")
    try:
        result = parse_json(report,max_bytes=MAX_REPORT_BYTES)
    except StrictJSONError as exc:
        _fail("Standalone result is not bounded strict JSON", "/",
              code="RESOURCE_LIMIT" if exc.code=="RESOURCE_LIMIT" else "ENGINE_FAILURE")
    if not isinstance(result,dict):
        _fail("Standalone result must be an object", "/")
    if result.get("contract_version") != CONTRACT_VERSION or result.get("physical_validation_status") != "unvalidated":
        _fail("Standalone report contract or physical status is invalid", "/")
    expected_input = _sha(canonical_bytes(request))
    if result.get("input_sha256") != expected_input:
        _fail("Report input hash differs from the effective authored request", "/input_sha256")
    if result.get("input_validation_status") != "pass":
        _fail("Publication requires a previously validated authored request", "/input_validation_status")
    payload = result.get("payload")
    execution = result.get("execution_status")
    if result.get("partial") != (payload is not None and execution != "SUCCEEDED"):
        _fail("Report partial flag does not match its execution and payload", "/partial")
    if payload is not None and execution != "SUCCEEDED":
        check_payload(request,payload,registry=registry,execution_status=execution,
                      numerical_status=result.get("numerical_status"),resolution_status=result.get("resolution_status"))
    if execution == "SUCCEEDED":
        if payload is None:
            _fail("Successful dynamics report has no trajectory")
        if result.get("numerical_status") != "pass" or result.get("resolution_status") != payload["resolution_comparison"]["status"]:
            _fail("Successful report status differs from its payload assessment", "/numerical_status")
        final_state = build_phase_state(request,payload,registry=registry)
        if result.get("final_state") is not None and not _same_tree(result["final_state"],final_state):
            _fail("Supplied final state differs from the successful primary phase state", "/final_state")
        result["final_state"] = final_state
    elif result.get("final_state") is not None:
        _fail("Failed or cancelled execution cannot publish a successful final state", "/final_state")
    if payload is None and (result.get("numerical_status") != "not_checked" or result.get("resolution_status") != "not_checked"):
        _fail("Absent trajectory cannot publish a numerical or resolution assessment", "/numerical_status")
    if payload is not None and (result.get("initial_force_evaluation_performed") is not True or
            (any(leg["completed_steps"] > 0 for leg in payload["legs"]) and result.get("dynamics_simulation_executed") is not True)):
        _fail("Execution flags disagree with the accepted trajectory", "/dynamics_simulation_executed")
    source_provenance = provenance if provenance is not None else result.get("provenance")
    if source_provenance is None:
        source_provenance = capture_provenance(request,registry=registry)
    result["provenance"] = copy.deepcopy(source_provenance)
    _check_provenance(request,result["provenance"],registry)
    _registered(registry,"dynamics_report.schema.json",result,"/")
    cap = registry.resource_policy["common_execution"]["max_artifact_bytes_per_run"]
    if isinstance(cap,bool) or not isinstance(cap,int) or cap<=0:
        _fail("Invalid report byte ceiling",None,code="REGISTRY_SNAPSHOT_UNAVAILABLE")
    cap = min(cap,MAX_REPORT_BYTES)
    if artifact_byte_limit is not None:
        if isinstance(artifact_byte_limit,bool) or not isinstance(artifact_byte_limit,int) or artifact_byte_limit<=0:
            _fail("Invalid requested report byte ceiling",None,code="RESOURCE_LIMIT")
        cap=min(cap,artifact_byte_limit)
    publication = {"serialization":"compact_utf8_json_preserving_signed_zero",
                   "artifact_byte_limit":cap,"report_transport_bytes":0,
                   "report_projection_sha256":None,"payload_canonical_sha256":None,
                   "payload_transport_sha256":None,"payload_transport_bytes":0}
    # Hash the complete report before adding the self-referential publication record.
    result["provenance"].pop("publication",None)
    publication["report_projection_sha256"] = _sha(canonical_bytes(result))
    if payload is not None:
        publication.update(payload_canonical_sha256=_sha(canonical_bytes(payload)),
                           payload_transport_sha256=_sha(transport_bytes(payload)),
                           payload_transport_bytes=len(transport_bytes(payload)))
    result["provenance"]["publication"] = publication
    for _ in range(12):
        actual=len(transport_bytes(result))
        if actual==publication["report_transport_bytes"]:
            break
        publication["report_transport_bytes"]=actual
    else:
        _fail("Report byte count could not reach a fixed point",None)
    if actual > cap:
        _fail("Complete report and provenance exceed the artifact byte ceiling",None,
              code="RESOURCE_LIMIT",requested=actual,limit=cap)
    _registered(registry,"dynamics_report.schema.json",result,"/")
    return result
