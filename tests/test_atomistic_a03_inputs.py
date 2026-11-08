"""A03 input mapping/rejection checks, not CP2K numerical/physical tests."""
from decimal import Decimal, localcontext
import hashlib
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("a03_inputs_for_test", ROOT / "scripts/atomistic_a03_inputs.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_nuclear_geometry_mapping_preserves_separation_and_translation():
    p = module.probe_metadata("h2")
    atoms = p["atoms"]
    x = [Decimal(a["engine_position_angstrom"][0]) for a in atoms]
    assert x[1] - x[0] == Decimal("0.8")
    assert (x[0] + x[1]) / 2 == Decimal("6")
    assert p["coordinate_translation_angstrom"] == [6, 6, 6]
    assert all([Decimal(v) for v in a["engine_position_angstrom"][1:]]
               == [Decimal(6), Decimal(6)] for a in atoms)


def test_internal_h2_reference_uses_locked_c02_geometry():
    p = module.probe_metadata("h2-reference")
    assert p["source_fixture"] == "C02-H2-reference"
    assert not p["public_runtime_contract"]
    coords = [[Decimal(v) for v in a["engine_position_angstrom"]] for a in p["atoms"]]
    assert coords == [[Decimal("5.62928"), 6, 6], [Decimal("6.37072"), 6, 6]]
    assert coords[1][0] - coords[0][0] == Decimal("0.74144")
    text = module.generate_input("h2-reference")
    assert "\n      H 5.62928 6 6\n      H 6.37072 6 6\n" in text


@pytest.mark.parametrize(("system", "expected_sha"), [
    ("he", "e2d6c35d143c9298abf873f25494a49211f32529c36b55c5f61a420eafdef8a9"),
    ("h2", "8b640cd7d1b8b3f296db780a91a160594af138a9222065a985e4d89aa835ec7f"),
    ("h2-reference", "7f3fd539da032f3660657960da8214ee67a07b9dd8f5fc79a105c4487ff3f5d9"),
])
def test_existing_resource_inputs_remain_byte_identical(system, expected_sha):
    text = module.generate_input(system, "cc-pVDZ", project="a04_resource_h2")
    assert hashlib.sha256(text.encode("ascii")).hexdigest() == expected_sha
    source = str(module.BOUNDARY_FIXTURE_PATH.relative_to(ROOT))
    assert source not in module.probe_metadata(system)["source_files_sha256"]


@pytest.mark.parametrize(("system", "fixture_id", "half_bond_m", "bond_angstrom"), [
    ("h2-short", "A04-H2-short", Decimal("3e-11"), Decimal("0.60")),
    ("h2-long", "A04-H2-long", Decimal("5e-11"), Decimal("1.00")),
])
@pytest.mark.parametrize("cell", [12, 16])
def test_internal_h2_boundary_uses_locked_geometry(system, fixture_id, half_bond_m, bond_angstrom, cell):
    meta = module.probe_metadata(system, cell_angstrom=cell)
    assert meta["source_fixture"] == fixture_id
    assert not meta["public_runtime_contract"]
    assert not meta["fixture_as_product_execution_selector"]
    model = meta["model"]
    assert (model["charge_e"], model["multiplicity"], model["electron_count"]) == (0, 1, 2)
    assert (model["method"], model["functional"]) == ("GAPW", "PBE")
    native_x = []
    center = Decimal(cell) / 2
    for atom, source_x in zip(meta["atoms"], (-half_bond_m, half_bond_m), strict=True):
        assert atom["element"] == "H"
        assert [Decimal(str(v)) for v in atom["source_position_m"]] == [source_x, 0, 0]
        x, y, z = (Decimal(v) for v in atom["engine_position_angstrom"])
        assert y == z == center
        native_x.append(x)
    assert (native_x[0] + native_x[1]) / 2 == center
    assert native_x[1] - native_x[0] == bond_angstrom
    source = module.BOUNDARY_FIXTURE_PATH
    assert meta["source_files_sha256"][str(source.relative_to(ROOT))] == hashlib.sha256(source.read_bytes()).hexdigest()
    deck = module.generate_input(system, cell_angstrom=cell)
    for atom in meta["atoms"]:
        assert "\n      H " + " ".join(atom["engine_position_angstrom"]) + "\n" in deck


@pytest.mark.parametrize("system", ["h2-reference", "h2-short", "h2-long"])
def test_a03_cli_keeps_additional_fixtures_internal(tmp_path, monkeypatch, system):
    output_dir = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "atomistic_a03_inputs", "--output-dir", str(output_dir), "--system", system,
    ])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2
    assert not output_dir.exists()


@pytest.mark.parametrize("system", ["he", "h2"])
def test_mass_conversion_recovers_bare_nuclear_mass_not_neutral_atomic_mass(system):
    p = module.probe_metadata(system)
    with localcontext() as ctx:
        ctx.prec = 40
        for a in p["atoms"]:
            error = abs(Decimal(a["engine_mass_amu"]) * Decimal(p["engine_mass_unit_kg"])
                        - Decimal(a["bare_nuclear_mass_kg"]))
            assert error < Decimal("1e-64")
    assert p["engine_unit_codata_edition"] == 2006


def test_density_semantics_and_pinned_paths_cannot_use_soft_default():
    text = module.generate_input("h2", "cc-pVTZ", data_dir="/quanta-data")
    assert "DENSITY_INCLUDE TOTAL_DENSITY" in text
    assert "XRD_INTERFACE F" in text and "STRIDE 1 1 1" in text
    assert "BASIS_SET_FILE_NAME /quanta-data/cc-pVTZ.cp2k" in text
    assert "POTENTIAL_FILE_NAME /quanta-data/ALL_POTENTIALS" in text
    assert "SOFT_DENSITY" not in text and "TOTAL_HARD_APPROX" not in text
    assert "IGNORE_CONVERGENCE_FAILURE" not in text


@pytest.mark.parametrize("changes", [
    {"system": "li"}, {"basis": "aug-cc-pVDZ"}, {"project": "a\n&GLOBAL"},
    {"data_dir": "/data/../etc"}, {"data_dir": "/data # injected"},
    {"cutoff_ry": 50}, {"cell_angstrom": True}, {"density": "false"},
])
def test_unsupported_physics_numerics_or_input_injection_rejected(changes):
    with pytest.raises(ValueError):
        module.generate_input(**changes)


def test_cancel_probe_stays_static_and_exploratory():
    p = module.probe_metadata("h2", "cc-pVQZ", cell_angstrom=20,
                              cutoff_ry=800, rel_cutoff_ry=80)
    text = module.generate_input("h2", "cc-pVQZ", cell_angstrom=20,
                                 cutoff_ry=800, rel_cutoff_ry=80)
    assert p["operation"] == "ENERGY_FORCE"
    assert "&MD" not in text
    assert p["physical_validation_status"] == "unvalidated"
    assert not p["public_runtime_contract"]
