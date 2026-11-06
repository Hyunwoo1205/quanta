"""Standalone validation, initial analytic feasibility and rejection boundaries."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from quanta.dynamics_validation import validate_dynamics_request
from quanta.hashing import canonical_bytes
from quanta.registry import ContractRegistry

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "contracts/v0.3.0"


def request(name="harmonic"):
    return json.loads((BUNDLE / "examples" / (name + ".request.json")).read_text())


def codes(report):
    return {error["code"] for error in report["errors"]}


def rehashed_registry(tmp_path, update):
    dest = tmp_path / "bundle"
    shutil.copytree(BUNDLE, dest)
    profile = dest / "resource_policy.json"
    value = json.loads(profile.read_text())
    update(value)
    profile.write_text(json.dumps(value, indent=2) + "\n")
    path = dest / "SHA256SUMS.json"
    hashes = json.loads(path.read_text())
    hashes["resource_policy.json"] = hashlib.sha256(profile.read_bytes()).hexdigest()
    path.write_text(json.dumps(hashes, indent=2) + "\n")
    registry = ContractRegistry(dest, contract_version="0.3.0")
    assert registry.validate_integrity() == []
    return registry


@pytest.mark.parametrize("name", ["harmonic", "harmonic-refinement", "free"])
def test_examples_accept_validation_without_enabling_time_integration(name):
    authored = request(name)
    before = copy.deepcopy(authored)
    result = validate_dynamics_request(authored)
    assert result["valid"], result
    assert authored == before
    assert result["scope"] == "standalone_dynamics_request_validation"
    assert result["contract_version"] == "0.3.0"
    assert result["executable"] is False
    assert result["dynamics_simulation_executed"] is False
    assert result["initial_force_evaluation_performed"] is True
    assert result["physical_validation_status"] == "unvalidated"
    assert result["input_sha256"] == hashlib.sha256(canonical_bytes(authored)).hexdigest()
    assert result["initial_state_checks"]["scope"] == "initial_feasibility_only_not_trajectory"


def test_initial_unequal_mass_harmonic_constants_are_independent_exact_values():
    result = validate_dynamics_request(request())
    assert result["valid"]
    initial = result["initial_state_checks"]
    assert initial["potential_energy_j"] == 1.5
    assert initial["kinetic_energy_j"] == 0.416015625
    assert initial["total_energy_j"] == 1.916015625
    assert initial["linear_momentum_kg_m_per_s"] == [.5, .25, -.125]
    assert initial["angular_momentum_kg_m2_per_s"] == [-.15625, .4375, 1.75]
    assert initial["center_of_mass_m"] == [.5, -.25, .75]
    assert initial["center_of_mass_velocity_m_per_s"] == [.125, .0625, -.03125]


def test_consistent_unit_scale_change_retains_si_initial_energy_and_momenta():
    original = validate_dynamics_request(request())
    transformed = request()
    transformed["scales"].update(length_m=2, energy_j=3, time_s=4)
    transformed["system"]["potential"]["expression"]["args"][0]["value"] = .5
    changed = validate_dynamics_request(transformed)
    assert changed["valid"], changed
    for field in ("potential_energy_j", "kinetic_energy_j", "total_energy_j",
                  "linear_momentum_kg_m_per_s", "angular_momentum_kg_m2_per_s"):
        assert changed["initial_state_checks"][field] == pytest.approx(original["initial_state_checks"][field])
    assert changed["input_sha256"] != original["input_sha256"]


def test_refinement_uses_same_duration_and_reserves_terminal_frames():
    result = validate_dynamics_request(request("harmonic-refinement"))
    assert result["valid"]
    assert [leg["steps"] for leg in result["time_legs"]] == [20, 40, 80]
    assert [leg["dt_s"] for leg in result["time_legs"]] == [.05, .025, .0125]
    assert {leg["final_time_s"] for leg in result["time_legs"]} == {1.0}
    b = result["budgets"]
    assert b["total_force_evaluations"] == 143
    assert b["total_pair_evaluations"] == 143
    assert b["reserved_output_frames"] == 66
    assert b["complete_execution_provenance_estimate"] is False
    assert b["remaining_for_future_execution_provenance_bytes"] > 0


def test_whitespace_does_not_change_canonical_identity_but_source_bytes_are_accounted():
    text = json.dumps(request())
    compact = validate_dynamics_request(text)
    padded = validate_dynamics_request("  \n" + text + "\n")
    assert compact["valid"] and padded["valid"]
    assert compact["input_sha256"] == padded["input_sha256"]
    assert padded["budgets"]["source_input_bytes"] - compact["budgets"]["source_input_bytes"] == 4


@pytest.mark.parametrize("data", [b'{"contract_version":"0.3.0","contract_version":"0.3.0"}',
                                      b'{"contract_version":"0.3.0","x":NaN}',
                                      b'\xff', "[]", b" " * 1048577])
def test_strict_json_rejections_have_no_force_evaluation(data):
    result = validate_dynamics_request(data)
    assert not result["valid"]
    assert result["errors"]
    assert result["initial_force_evaluation_performed"] is False
    assert result["executable"] is False


@pytest.mark.parametrize("mutate", [
    lambda r: r["system"]["particles"][0].pop("mass_kg"),
    lambda r: r["system"]["particles"][0].pop("velocity_m_per_s"),
    lambda r: r["system"]["particles"][0].update(mass_kg=0),
    lambda r: r["system"]["particles"][0].update(mass_kg=-1),
    lambda r: r["system"]["particles"][0].update(fixed=[False]*3),
    lambda r: r["system"]["particles"][0].update(mass_kg=True),
    lambda r: r["system"].update(boundary="periodic"),
    lambda r: r["system"].update(module_version="9.9.9"),
    lambda r: r["system"].update(module_id="quanta.pair_static"),
    lambda r: r["numerics"].update(integrator="euler"),
    lambda r: r.update(initial_time_s=1),
    lambda r: r.update(contract_version="0.2.0"),
    lambda r: r.update(unknown_field=0),
    lambda r: r["system"]["potential"].update(expression={"op":"var","name":"xi"}),
    lambda r: r["system"]["particles"][1].update(id="p1"),
    lambda r: r["numerics"].update(sample_stride=1001),
    lambda r: r["system"]["potential"].update(expression={"op":"param","name":"missing"}),
])
def test_unsupported_or_ambiguous_inputs_rejected_before_force(mutate):
    trial = request()
    mutate(trial)
    result = validate_dynamics_request(trial)
    assert not result["valid"], result
    assert result["initial_force_evaluation_performed"] is False
    assert result["input_sha256"] is None


@pytest.mark.parametrize("mutate", [
    lambda r: r["numerics"].update(steps=10000),
    lambda r: r["numerics"].update(steps=1500,refinement="halving_2",sample_stride=1500),
    lambda r: r["numerics"].update(sample_stride=1),
])
def test_resources_refused_before_any_force_evaluator(mutate, monkeypatch):
    from quanta.pair_kernel import PairForceKernel
    def forbidden(*args, **kwargs):
        raise AssertionError("resource-refused request reached force evaluation")
    monkeypatch.setattr(PairForceKernel, "evaluate", forbidden)
    trial = request()
    mutate(trial)
    result = validate_dynamics_request(trial)
    assert not result["valid"]
    assert "RESOURCE_LIMIT" in codes(result)
    assert result["initial_force_evaluation_performed"] is False


@pytest.mark.parametrize("refinement", ["none", "halving_2"])
def test_subnormal_si_half_step_is_explicitly_rejected(refinement):
    trial = request()
    trial["numerics"].update(dt_s=5e-324, refinement=refinement)
    result = validate_dynamics_request(trial)
    assert not result["valid"]
    assert result["errors"][0]["path"] == "/numerics/dt_s"
    assert result["initial_force_evaluation_performed"] is False


@pytest.mark.parametrize("mutate", [
    lambda r: r["scales"].update(time_s=1e308),
    lambda r: r["scales"].update(length_m=1e308),
    lambda r: r["system"]["particles"][0].update(velocity_m_per_s=[1e308,1e308,1e308]),
    lambda r: [p.update(mass_kg=1e308) for p in r["system"]["particles"]],
])
def test_unrepresentable_derived_quantities_rejected(mutate):
    trial = request()
    mutate(trial)
    result = validate_dynamics_request(trial)
    assert not result["valid"]
    assert "EXPRESSION_DOMAIN" in codes(result)
    assert result["dynamics_simulation_executed"] is False


def test_initial_domain_failure_uses_dynamics_path_and_does_not_claim_force_completion():
    trial = request()
    trial["system"]["potential"]["expression"] = {"op":"log","arg":{"op":"const","value":-1}}
    result = validate_dynamics_request(trial)
    assert not result["valid"]
    assert "EXPRESSION_DOMAIN" in codes(result)
    assert result["errors"][0]["path"].startswith("/system/potential/")
    assert result["errors"][0]["details"]["pair_indices"] == [0, 1]
    assert result["initial_force_evaluation_performed"] is False


def test_large_finite_single_mass_is_not_rejected_by_an_invented_mass_cap():
    trial = request()
    trial["system"]["particles"][1]["mass_kg"] = 1e308
    result = validate_dynamics_request(trial)
    assert result["valid"], result
    assert result["executable"] is False


def test_coincident_initial_particles_rejected_without_payload():
    trial = request()
    trial["system"]["particles"][1]["position_m"] = trial["system"]["particles"][0]["position_m"][:]
    result = validate_dynamics_request(trial)
    assert not result["valid"]
    assert "INPUT_SEMANTIC" in codes(result)
    assert "initial_state_checks" not in result


def test_hostile_ast_is_bounded_before_recursive_oneof_validation(monkeypatch):
    registry = ContractRegistry(contract_version="0.3.0")
    original = registry.validator
    def guarded(ref):
        if ref == "dynamics_request.schema.json":
            raise AssertionError("oversized AST reached recursive request schema")
        return original(ref)
    monkeypatch.setattr(registry, "validator", guarded)
    trial = request()
    expression = {"op":"var","name":"rho"}
    for _ in range(18):
        expression = {"op":"neg","arg":expression}
    trial["system"]["potential"]["expression"] = expression
    result = validate_dynamics_request(trial, registry=registry)
    assert not result["valid"]
    assert "RESOURCE_LIMIT" in codes(result)


@pytest.mark.parametrize("field,value", [("max_ast_depth",2),("max_ast_nodes",3),("max_parameters",0),
                                         ("max_total_force_evaluations",1000),("max_total_output_frames",101),
                                         ("max_pair_evaluations",1000),("max_base_steps",999),("max_particles",1)])
def test_lower_frozen_resource_profile_is_honored(tmp_path, field, value):
    registry = rehashed_registry(tmp_path, lambda d: d["profiles"]["pair_dynamics_cpu"].update({field:value}))
    trial = request()
    if field == "max_parameters":
        trial["system"]["potential"]["parameters"] = {"unused":1}
    result = validate_dynamics_request(trial, registry=registry)
    assert not result["valid"], result
    assert "RESOURCE_LIMIT" in codes(result)
    assert result["initial_force_evaluation_performed"] is False


def test_zero_parameter_limit_still_accepts_parameter_free_model(tmp_path):
    registry = rehashed_registry(tmp_path, lambda d: d["profiles"]["pair_dynamics_cpu"].update(max_parameters=0))
    assert validate_dynamics_request(request(), registry=registry)["valid"]


def test_lower_run_wall_limit_caps_initial_validation_deadline(tmp_path, monkeypatch):
    registry = rehashed_registry(tmp_path, lambda d: d["common_execution"].update(wall_seconds_per_run=1))
    from quanta import dynamics_validation
    times = iter([0.0, 2.0])
    monkeypatch.setattr(dynamics_validation.time, "monotonic", lambda: next(times))
    result = validate_dynamics_request(request(), registry=registry)
    assert not result["valid"]
    assert "RESOURCE_LIMIT" in codes(result)
    assert result["initial_force_evaluation_performed"] is False


def test_bundle_digest_tamper_is_refused_before_schema_or_force(tmp_path):
    registry = rehashed_registry(tmp_path, lambda _: None)
    target = registry.contract_dir / "dynamics_request.schema.json"
    target.write_text(target.read_text()+" ")
    changed = ContractRegistry(registry.contract_dir, contract_version="0.3.0")
    result = validate_dynamics_request(request(), registry=changed)
    assert not result["valid"]
    assert "REGISTRY_SNAPSHOT_UNAVAILABLE" in codes(result)
    assert result["initial_force_evaluation_performed"] is False


def test_wrong_default_bundle_is_not_silently_upgraded():
    old = ContractRegistry()
    result = validate_dynamics_request(request(), registry=old)
    assert not result["valid"]
    assert "REGISTRY_SNAPSHOT_UNAVAILABLE" in codes(result)
    assert old.data["contract_version"] == "0.2.0"


def test_initial_validation_never_calls_static_module_adapter(monkeypatch):
    from quanta import pair, validation
    def forbidden(*args, **kwargs):
        raise AssertionError("dynamics request was presented as a static definition")
    monkeypatch.setattr(pair, "_PreparedPair", forbidden)
    monkeypatch.setattr(validation, "validate_definition", forbidden)
    assert validate_dynamics_request(request())["valid"]
