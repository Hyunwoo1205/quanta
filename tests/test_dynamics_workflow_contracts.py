"""The generic adapter imports, rather than rewrites, standalone science."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from referencing import Resource

from quanta.registry import ContractRegistry, experiment_registry

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "contracts/v0.4.0"
SCIENCE = ("dynamics_request.schema.json", "dynamics_payload.schema.json",
           "dynamics_state.schema.json", "dynamics_metadata.schema.json", "dynamics_report.schema.json")


@pytest.fixture
def registry():
    return ContractRegistry(contract_version="0.4.0")


def example(name="free_revision.json"):
    return json.loads((BUNDLE / "examples" / name).read_text())


def reseal(directory):
    values = {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(directory.rglob("*")) if p.is_file() and p.name != "SHA256SUMS.json"}
    (directory / "SHA256SUMS.json").write_text(json.dumps(values, indent=2) + "\n")


def test_generic_selection_remains_explicit(registry):
    assert ContractRegistry().contract_version == "0.2.0"
    assert experiment_registry(example()).contract_version == "0.4.0"
    assert experiment_registry({"schema_version":"0.2.0"}).contract_version == "0.2.0"
    assert experiment_registry(example(), registry) is registry


@pytest.mark.parametrize("version", [None, True, 4, [], {}, "0.4.1", "0.3.1", "unsupported"])
def test_unknown_versions_do_not_opt_into_generic_dynamics(version):
    value = example()
    value["schema_version"] = version
    selected = experiment_registry(value)
    assert selected.contract_version == "0.2.0"
    assert list(selected.validator("experiment.schema.json").iter_errors(value))


def test_missing_or_nonobject_version_remains_legacy():
    assert experiment_registry({}).contract_version == "0.2.0"
    assert experiment_registry([]).contract_version == "0.2.0"


@pytest.mark.parametrize("marker,supplied", [("0.4.0", "0.2.0"), ("0.2.0", "0.4.0")])
def test_supplied_generic_registry_mismatch_is_explicit(marker, supplied):
    with pytest.raises(ValueError, match="differs"):
        experiment_registry({"schema_version":marker}, ContractRegistry(contract_version=supplied))


def test_standalone_registry_cannot_be_used_as_generic():
    with pytest.raises(ValueError, match="generic registry"):
        experiment_registry(example(), ContractRegistry(contract_version="0.3.1"))


def test_bundle_integrity_and_exact_scientific_imports(registry):
    assert not registry.validate_integrity()
    source = ContractRegistry(contract_version="0.3.1")
    for name in SCIENCE:
        assert registry.raw_bytes[name] == source.raw_bytes[name]
        assert registry.documents[name]["$id"].endswith(":0.3.1")
    assert len(list(BUNDLE.rglob("*json"))) + 1 == 26
    assert len(registry.manifest) == 25


@pytest.mark.parametrize("name", ["free_revision.json", "harmonic_revision.json", "harmonic_refinement_revision.json"])
def test_registered_examples_validate_without_solver_execution(registry, name):
    value = example(name)
    registry.validator("experiment.schema.json").validate(value)
    registry.validator("dynamics_definition.schema.json").validate(value["definition"])
    module = registry.get_module("quanta.pair_dynamics", "0.1.0")
    registry.validator(module["input_schema_ref"]).validate(value["definition"]["system"])
    registry.validator(module["numerics_schema_ref"]).validate(value["definition"]["numerics"])


@pytest.mark.parametrize("mutation", [
    lambda d: d["protocol"]["steps"].append(deepcopy(d["protocol"]["steps"][0])),
    lambda d: d["protocol"]["steps"][0].update(source="integrate"),
    lambda d: d["protocol"]["steps"][0].update(operation="relax"),
    lambda d: d["protocol"]["steps"][0]["overrides"].append({"path":"/numerics/dt_s","value":1}),
    lambda d: d["protocol"]["sweep"]["axes"].append({"path":"/numerics/dt_s","values":[1]}),
    lambda d: d.update(unit_system="cgs"),
    lambda d: d.update(initial_time_s=1),
    lambda d: d["extensions"].update(unregistered=True),
    lambda d: d["system"].update(module_id="quanta.pair_static"),
    lambda d: d["system"]["particles"][0].update(fixed=[False, False, False]),
    lambda d: d["system"]["particles"][0].pop("mass_kg"),
    lambda d: d["scales"].pop("time_s"),
    lambda d: d["numerics"].update(thermostat="invented"),
    lambda d: d.update(observables=["unregistered"]),
    lambda d: d.update(observables=[]),
])
def test_first_integration_scope_fails_closed(registry, mutation):
    definition = example()["definition"]
    mutation(definition)
    assert list(registry.validator("dynamics_definition.schema.json").iter_errors(definition))


def test_explicit_import_urn_resolves_but_cross_bundle_url_does_not(registry):
    imported = registry.documents[SCIENCE[0]]
    assert registry.resolve_schema(imported["$id"]) == imported
    with pytest.raises(ValueError, match="allowlist"):
        registry.resolve_schema("https://quanta.invalid/contracts/v0.3.1/dynamics_request.schema.json")
    with pytest.raises(ValueError, match="allowlist"):
        registry.resolve_schema("https://unregistered.invalid/schema.json")


def test_evolving_port_and_generic_observable_bindings(registry):
    module = registry.get_module("quanta.pair_dynamics", "0.1.0")
    assert module["operations"] == ["integrate"]
    assert module["capabilities"]["execution_adapter_ref"] == "dynamics_adapter.json"
    assert [(p["port_id"], p["time_kind"], p["data_schema_ref"]) for p in module["ports"]] == [
        ("phase_in", "evolving", "dynamics_state.schema.json"),
        ("phase_out", "evolving", "dynamics_state.schema.json")]
    assert module["ports"][0]["allowed_sources"] == ["initial"]
    assert registry.get_module("quanta.pair_static", "0.1.0") is None
    for descriptor in registry.data["observables"]:
        assert descriptor["eligible_operations"] == ["integrate"]
        registry.validator("observable_manifest.schema.json").validate(descriptor)


@pytest.mark.parametrize("mutation", [
    lambda r: r.documents["dynamics_definition.schema.json"]["properties"]["protocol"]["properties"]["steps"].update(maxItems=True),
    lambda r: r.resource_policy["common_execution"].update(max_input_bytes=7),
    lambda r: r.data["modules"][0]["ports"][0].update(allowed_sources=["previous_success_same_branch"]),
])
def test_active_rules_cannot_impersonate_frozen_bytes(registry, mutation):
    mutation(registry)
    errors = registry.validate_integrity()
    assert any("snapshot" in e["message"] for e in errors)


def test_active_offline_alias_cannot_impersonate_frozen_document(registry):
    changed = deepcopy(registry.documents["experiment.schema.json"])
    changed["properties"]["schema_version"] = {"const":"invented"}
    registry.offline_registry = registry.offline_registry.with_resource(
        "experiment.schema.json", Resource.from_contents(changed))
    assert registry.validate_integrity()


def test_mutated_disk_files_are_rejected_after_registry_capture(tmp_path):
    directory = tmp_path / "bundle"
    shutil.copytree(BUNDLE, directory)
    registry = ContractRegistry(directory, contract_version="0.4.0")
    (directory / "dynamics_definition.schema.json").write_text("{}")
    assert registry.validate_integrity()


def test_resealed_changed_scientific_import_is_not_a_031_import(tmp_path):
    directory = tmp_path / "bundle"
    shutil.copytree(BUNDLE, directory)
    path = directory / "dynamics_request.schema.json"
    changed = json.loads(path.read_text())
    changed["title"] += " changed"
    path.write_text(json.dumps(changed))
    adapter = json.loads((directory / "dynamics_adapter.json").read_text())
    adapter["imported_scientific_schemas_sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (directory / "dynamics_adapter.json").write_text(json.dumps(adapter))
    reseal(directory)
    errors = ContractRegistry(directory, contract_version="0.4.0").validate_integrity()
    assert any("exact installed standalone" in e.get("details", {}).get("reason", "") for e in errors)


def test_explicit_resealed_tighter_policy_is_not_silently_raised(tmp_path):
    directory = tmp_path / "bundle"
    shutil.copytree(BUNDLE, directory)
    path = directory / "resource_policy.json"
    policy = json.loads(path.read_text())
    policy["common_execution"]["max_artifact_bytes_per_run"] = 4096
    policy["profiles"]["pair_dynamics_cpu"]["max_total_force_evaluations"] = 5
    path.write_text(json.dumps(policy))
    reseal(directory)
    registry = ContractRegistry(directory, contract_version="0.4.0")
    assert not registry.validate_integrity()
    assert registry.resource_policy["common_execution"]["max_artifact_bytes_per_run"] == 4096
    assert registry.resource_policy["profiles"]["pair_dynamics_cpu"]["max_total_force_evaluations"] == 5


@pytest.mark.parametrize("field,value", [
    ("fixed_request_members", {"contract_version":"0.3.1","operation":"integrate","initial_time_s":1}),
    ("fixed_request_members", {"contract_version":"0.3.1","operation":"integrate","initial_time_s":False}),
    ("definition_members_to_request", ["system","numerics"]),
    ("required_unit_system", "cgs"),
    ("allowed_protocol", {"steps":1,"source":"previous","overrides":False,"sweep_axes":0}),
])
def test_resealed_adapter_and_its_schema_cannot_redefine_compiled_mapping(tmp_path, field, value):
    directory = tmp_path / "bundle"
    shutil.copytree(BUNDLE, directory)
    adapter = json.loads((directory / "dynamics_adapter.json").read_text())
    adapter[field] = value
    (directory / "dynamics_adapter.json").write_text(json.dumps(adapter))
    schema = json.loads((directory / "dynamics_adapter.schema.json").read_text())
    schema["properties"][field] = {"const":value}
    (directory / "dynamics_adapter.schema.json").write_text(json.dumps(schema))
    reseal(directory)
    errors = ContractRegistry(directory, contract_version="0.4.0").validate_integrity()
    assert any("compiled supported mapping" in e.get("details", {}).get("reason", "") for e in errors)


@pytest.mark.parametrize("mutation", [
    lambda m: m["precision_contract"].update(real_dtype="float32"),
    lambda m: m["precision_contract"].update(finite_only=1),
    lambda m: m["unit_contract"].update(interchange_system="cgs"),
    lambda m: m["ports"][0].update(time_kind="static"),
    lambda m: m["ports"][0].update(allowed_sources=["previous_success_same_branch"]),
    lambda m: m.update(input_schema_ref="dynamics_state.schema.json"),
    lambda m: m["capabilities"]["expression"].update(variables=["xi"]),
    lambda m: m["capabilities"]["expression"].update(allowed_ops=["const"]),
    lambda m: m["capabilities"]["expression"].update(dimensionless=False),
    lambda m: m["capabilities"]["expression"].update(max_parameters=1),
    lambda m: m["capabilities"]["protocol"].update(source_policy="previous_allowed"),
    lambda m: m["capabilities"]["limits"].update(max_particles=64),
    lambda m: m["capabilities"]["expression_formats"][0].update(format_id="unsupported.ast"),
])
def test_resealed_module_cannot_misdeclare_implemented_precision_units_or_ports(tmp_path, mutation):
    directory = tmp_path / "bundle"
    shutil.copytree(BUNDLE, directory)
    path = directory / "registry.json"
    registry = json.loads(path.read_text())
    mutation(registry["modules"][0])
    path.write_text(json.dumps(registry))
    reseal(directory)
    assert ContractRegistry(directory, contract_version="0.4.0").validate_integrity()
