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


def test_stretched_h2_resource_input_remains_byte_identical():
    text = module.generate_input("h2", "cc-pVDZ", project="a04_resource_h2")
    assert hashlib.sha256(text.encode("ascii")).hexdigest() == (
        "8b640cd7d1b8b3f296db780a91a160594af138a9222065a985e4d89aa835ec7f"
    )


def test_a03_cli_keeps_reference_fixture_internal(tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "atomistic_a03_inputs", "--output-dir", str(output_dir), "--system", "h2-reference",
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
