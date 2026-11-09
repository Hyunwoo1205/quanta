"""Fail-closed parsing of the 5Z orbital and GAPW density evidence."""
from pathlib import Path

import pytest


def test_final_basis_checks_expected_spherical_count_and_effective_density_lmax(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from atomistic_a04_basis_output import parse_basis_conditioning

    output = """
 QS| GAPW|      atom-s-grid:  max l :                                          8
 ATOMIC KIND INFORMATION
  1. Atomic kind: He Number of atoms: 1
 Orbital Basis Set cc-pV5Z
 Number of orbital shell sets: 5
 Number of orbital shells: 15
 Number of primitive Cartesian functions: 80
 Number of Cartesian basis functions: 70
 Number of spherical basis functions: 55
 Number of orbital functions: 55
 Number of independent orbital functions: 55
 OVERLAP MATRIX CONDITION NUMBER
 1-Norm and 2-Norm Condition Numbers using Diagonalization
 CN : |A|*|A^-1|:       2.000E+003
 CN : max/min ev: 2.000E+000 / 1.000E-003 = 2.000E+003 Log(2-CN): 3.3010
"""
    kwargs = {"basis": "cc-pV5Z", "element": "He", "atom_count": 1, "expected_density_lmax": 8}
    result = parse_basis_conditioning(output, **kwargs)
    assert result["conditioning_passed"]
    assert result["orbital_functions"] == 55
    assert result["effective_density_lmax"] == 8

    result = parse_basis_conditioning(output.replace("max l :                                          8",
                                                     "max l :                                          6"), **kwargs)
    assert not result["conditioning_passed"]
    assert result["conditioning_failures"] == ["unexpected_effective_density_lmax"]

    with pytest.raises(ValueError, match="GAPW effective density lmax"):
        parse_basis_conditioning(output.replace("atom-s-grid", "other-grid"), **kwargs)
    with pytest.raises(ValueError, match="spherical count"):
        parse_basis_conditioning(output.replace("spherical basis functions: 55", "spherical basis functions: 30"),
                                 **kwargs)
