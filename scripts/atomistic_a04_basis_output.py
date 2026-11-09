"""CP2K 2026.2 orbital-basis and overlap evidence for A04."""

import math
import re

# Counts for the locked H/He definitions.
SPHERICAL_PER_ATOM = {"cc-pVDZ": 5, "cc-pVTZ": 14, "cc-pVQZ": 30, "cc-pV5Z": 55}

# A four-significant-digit ES11.3E3 value must be one printable step
# inside each strict engineering boundary (min(S) > 1e-5, kappa_2 < 1e8).
MIN_PRINTED_EIGENVALUE = 1.001e-5
MAX_PRINTED_CONDITION_NUMBER = 9.999e7

_KIND_INFO = "ATOMIC KIND INFORMATION"
_OVERLAP_INFO = "OVERLAP MATRIX CONDITION NUMBER"
_DIAGONALIZATION = "1-Norm and 2-Norm Condition Numbers using Diagonalization"
_KIND = re.compile(r"\s*(\d+)\.\s+Atomic kind:\s+(\S+)\s+Number of atoms:\s+(\d+)\s*")
_ORBITAL_BASIS = re.compile(
    r"^[ \t]*Orbital Basis Set[ \t]+(\S+)[ \t]*\r?\n(?:[ \t]*\r?\n)*"
    r"^[ \t]*Number of orbital shell sets:[ \t]+[0-9]+[ \t]*\r?\n"
    r"^[ \t]*Number of orbital shells:[ \t]+[0-9]+[ \t]*\r?\n"
    r"^[ \t]*Number of primitive Cartesian functions:[ \t]+[0-9]+[ \t]*\r?\n"
    r"^[ \t]*Number of Cartesian basis functions:[ \t]+[0-9]+[ \t]*\r?\n"
    r"^[ \t]*Number of spherical basis functions:[ \t]+([0-9]+)[ \t]*$",
    re.MULTILINE,
)
_ES = r"([+-]?\d\.\d{3}E[+-]\d{3})"
_RATIO = re.compile(
    rf"CN : max/min ev: +{_ES} */ +{_ES} *= *{_ES} +Log\(2-CN\): +([+-]?\d+\.\d{{4}})"
)
_RANK_WARNING = re.compile(
    r"numerical rank of the overlap matrix is lower|Ill-conditioned S matrix|"
    r"Condition number estimate of overlap matrix is not reliable|"
    r"basis set is overcomplete|Cholesky decompose failed|"
    r"WARNING: the lebedev grid is built for angular momentum",
    re.IGNORECASE,
)


def _one(matches, label):
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {label}, found {len(matches)}")
    return matches[0]


def parse_basis_conditioning(text, *, basis, element, atom_count, expected_density_lmax=None):
    """Return checked CP2K output and the separate overlap guard decision.

    The intended inputs have one atomic kind, one locked orbital basis,
    OT SCF, and one ENERGY_FORCE calculation. Structural/evidence errors
    raise ValueError. Valid measurements can fail conditioning with a reason.
    """
    if (
        basis not in SPHERICAL_PER_ATOM
        or type(atom_count) is not int
        or (element, atom_count) not in {("H", 2), ("He", 1)}
    ):
        raise ValueError("Basis and fixture must match the locked H2/He matrix")

    lines = text.splitlines()
    stripped = [line.strip() for line in lines]
    kind_header = _one([i for i, line in enumerate(stripped) if line == _KIND_INFO], _KIND_INFO)
    overlap_header = _one(
        [i for i, line in enumerate(stripped) if line == _OVERLAP_INFO], _OVERLAP_INFO
    )
    if kind_header >= overlap_header:
        raise ValueError("Atomic-kind information must precede the overlap diagnostic")
    kind_lines = lines[kind_header + 1 : overlap_header]
    kind = _one([match for line in kind_lines if (match := _KIND.fullmatch(line))], "atomic kind")
    kind_index, kind_name, kind_atom_count = kind.groups()
    if (kind_index, kind_name.casefold(), kind_atom_count) != ("1", element.casefold(), str(atom_count)):
        raise ValueError("Atomic kind or atom count differs from the expected fixture")

    found_basis, found_spherical = _one(
        _ORBITAL_BASIS.findall("\n".join(kind_lines)), "orbital-basis report"
    )
    expected_spherical = SPHERICAL_PER_ATOM[basis]
    if found_basis.casefold() != basis.casefold() or int(found_spherical) != expected_spherical:
        raise ValueError("Orbital basis name or spherical count differs from the locked basis")

    # These CP2K counters are bookkeeping in OT. The overlap diagnostic
    # below establishes the eigenvalue evidence for the supplied guard.
    expected_ao = expected_spherical * atom_count
    totals = []
    for label in ("Number of orbital functions", "Number of independent orbital functions"):
        matches = re.findall(rf"^[ \t]*{label}:[ \t]+([0-9]+)[ \t]*\r?$", text, re.MULTILINE)
        totals.append(int(_one(matches, label)))
    if totals != [expected_ao, expected_ao]:
        raise ValueError("SCF orbital totals differ from the expected full AO count")

    diag_header = _one(
        [i for i, line in enumerate(stripped) if line == _DIAGONALIZATION], _DIAGONALIZATION
    )
    if diag_header <= overlap_header or diag_header + 2 >= len(lines):
        raise ValueError("Overlap diagonalization block is missing or truncated")
    if not stripped[diag_header + 1].startswith("CN : |A|*|A^-1|:"):
        raise ValueError("Overlap diagonalization block lacks its 1-norm row")

    ratio_line = stripped[diag_header + 2]
    warnings = [line.strip() for line in lines if _RANK_WARNING.search(line)]
    evidence = {
        "basis": basis,
        "basis_reported": found_basis,
        "element": element,
        "atom_count": atom_count,
        "spherical_functions_per_atom": expected_spherical,
        "orbital_functions": totals[0],
        "independent_orbital_functions_reported": totals[1],
        "overlap_ratio_line": ratio_line,
        "overlap_warnings": warnings,
    }
    failures = []
    if expected_density_lmax is not None:
        if type(expected_density_lmax) is not int or expected_density_lmax not in (6, 8):
            raise ValueError("Expected the locked QZ or 5Z effective density lmax")
        actual_density_lmax = int(_one(re.findall(
            r"(?m)^[ \t]*QS\|[ \t]+GAPW\|[ \t]+atom-s-grid:[ \t]+max l[ \t]*:[ \t]*(\d+)[ \t]*$",
            text,
        ), "GAPW effective density lmax"))
        evidence.update(expected_density_lmax=expected_density_lmax, effective_density_lmax=actual_density_lmax)
        if actual_density_lmax != expected_density_lmax:
            failures.append("unexpected_effective_density_lmax")
    if re.fullmatch(rf"CN : max/min EV: +{_ES} */ +{_ES} +Log\(CN\): infinity", ratio_line):
        return {
            **evidence,
            "conditioning_passed": False,
            "conditioning_failures": [*failures, "nonpositive_overlap_minimum"],
        }
    match = _RATIO.fullmatch(ratio_line)
    if match is None:
        raise ValueError("Missing or malformed CP2K diagonalization max/min row")
    maximum, minimum, condition, log_condition = map(float, match.groups())
    if not all(map(math.isfinite, (maximum, minimum, condition, log_condition))):
        raise ValueError("Nonfinite overlap diagnostic")
    if not 0 < minimum <= maximum or condition < 1:
        raise ValueError("Inconsistent positive overlap eigenvalue row")
    if not math.isclose(condition, maximum / minimum, rel_tol=0.0016):
        raise ValueError("Overlap ratio inconsistent with printed extremal eigenvalues")
    if abs(log_condition - math.log10(condition)) > 0.0003:
        raise ValueError("Overlap log condition inconsistent with printed ratio")

    if minimum < MIN_PRINTED_EIGENVALUE:
        failures.append("overlap_minimum_outside_printed_guard")
    if condition > MAX_PRINTED_CONDITION_NUMBER:
        failures.append("overlap_condition_outside_printed_guard")
    if warnings:
        failures.append("engine_rank_or_grid_warning")
    return {
        **evidence,
        "overlap_max_eigenvalue_printed": maximum,
        "overlap_min_eigenvalue_printed": minimum,
        "overlap_condition_2_printed": condition,
        "conditioning_passed": not failures,
        "conditioning_failures": failures,
    }
