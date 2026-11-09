"""Fail-closed parsing of orbital and explicitly requested GAPW atom-grid evidence."""
from pathlib import Path

import pytest


@pytest.mark.parametrize(("basis", "element", "atom_count", "per_atom", "cap"), [
    ("cc-pVQZ", "He", 1, 30, 6),
    ("cc-pVQZ", "He", 1, 30, 8),
    ("cc-pVQZ", "H", 2, 30, 8),
    ("cc-pV5Z", "He", 1, 55, 8),
    ("cc-pV5Z", "He", 1, 55, 10),
])
def test_basis_checks_printed_atom_grid_cap(monkeypatch, basis, element, atom_count, per_atom, cap):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from atomistic_a04_basis_output import parse_basis_conditioning

    grid = f" QS| GAPW|      atom-s-grid:  max l : {cap}"
    total = per_atom * atom_count
    output = f"""
{grid}
 ATOMIC KIND INFORMATION
  1. Atomic kind: {element} Number of atoms: {atom_count}
 Orbital Basis Set {basis}
 Number of orbital shell sets: 5
 Number of orbital shells: 15
 Number of primitive Cartesian functions: 80
 Number of Cartesian basis functions: 70
 Number of spherical basis functions: {per_atom}
 Number of orbital functions: {total}
 Number of independent orbital functions: {total}
 OVERLAP MATRIX CONDITION NUMBER
 1-Norm and 2-Norm Condition Numbers using Diagonalization
 CN : |A|*|A^-1|:       2.000E+003
 CN : max/min ev: 2.000E+000 / 1.000E-003 = 2.000E+003 Log(2-CN): 3.3010
"""
    kwargs = {"basis": basis, "element": element, "atom_count": atom_count, "expected_atom_grid_max_l": cap}
    result = parse_basis_conditioning(output, **kwargs)
    assert result["conditioning_passed"]
    assert result["orbital_functions"] == total
    assert result["expected_atom_grid_max_l"] == result["reported_atom_grid_max_l"] == cap
    assert result["effective_density_lmax"] == cap  # Historical readers use this alias.

    result = parse_basis_conditioning(output.replace(grid, grid.replace(str(cap), "12")), **kwargs)
    assert not result["conditioning_passed"]
    assert result["conditioning_failures"] == ["unexpected_atom_grid_max_l"]

    for invalid in (output.replace(grid, ""), output + grid + "\n"):
        with pytest.raises(ValueError, match="GAPW atom-grid max l"):
            parse_basis_conditioning(invalid, **kwargs)
    with pytest.raises(ValueError, match="spherical count"):
        parse_basis_conditioning(output.replace(f"spherical basis functions: {per_atom}",
                                                "spherical basis functions: 999"), **kwargs)
