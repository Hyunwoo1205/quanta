"""Independent analytic overlap preflight for fixed Quanta A04 H/He fixtures."""

from functools import lru_cache
from hashlib import sha256
from math import comb, factorial, gamma
import argparse
import json
from pathlib import Path
import platform

import numpy as np

from atomistic_a04_basis_output import MIN_PRINTED_EIGENVALUE, MAX_PRINTED_CONDITION_NUMBER
from check_atomistic_a02 import parse_cp2k_basis


BSE = "9fe07596f87753343e0a5748d1722135b21b8623"
ROOT = Path(__file__).resolve().parents[1]
A01 = ROOT / "docs/design/atomistic-a01-v0.1"
A02 = ROOT / "docs/design/atomistic-a02-v0.1"
A04 = ROOT / "docs/design/atomistic-a04-v0.1"
BASIS_PATHS = {
    "cc-pVQZ": A02 / "assets/cc-pVQZ.cp2k",
    "cc-pV5Z": A04 / "basis-candidates/cc-pV5Z-H-He.cp2k",
    "cc-pV6Z": A04 / "basis-candidates/cc-pV6Z-H-He.cp2k",
}
ANCHOR = ROOT / "docs/verification/atomistic-a04/even-grid-final-42646711532.json"
CASES = ("C01-He", "A04-H2-short", "C02-H2-reference", "C03-H2-stretched", "A04-H2-long")


def load_json(path):
    return json.loads(path.read_bytes())


def read_shells(path, basis):
    """Group one-exponent-list spherical contractions by angular momentum."""
    parsed = parse_cp2k_basis(path)
    if set(parsed) != {"H", "He"}:
        raise ValueError("Expected exactly the H and He basis definitions")
    shells = {}
    for symbol, (name, rows) in parsed.items():
        if name != basis:
            raise ValueError("Unexpected basis name")
        blocks = {}
        for (l, exponents, coefficients), count in rows.items():
            prior_exponents, vectors = blocks.setdefault(l, (exponents, []))
            if prior_exponents != exponents:
                raise ValueError("Expected a common exponent list per angular shell")
            vectors.extend([coefficients] * count)
        shells[symbol] = {
            l: (np.array(exponents, dtype=float), np.array(vectors, dtype=float).T)
            for l, (exponents, vectors) in sorted(blocks.items())
        }
    return shells


def one_dimensional_moment(power, exponent):
    if power % 2:
        return 0.0
    return gamma((power + 1) / 2) / exponent ** ((power + 1) / 2)


@lru_cache(maxsize=None)
def solid_harmonic(l, m):
    """Real or imaginary part of (x+iy)^m times a regular solid harmonic."""
    kmax = abs(m)
    polynomial = {}
    for k in range((l - kmax) // 2 + 1):
        zdegree = l - 2 * k - kmax
        # Derivative of P_l(z/r), with the factor r^l made polynomial.
        legendre = ((-1) ** k * factorial(2 * l - 2 * k)
                    / (2 ** l * factorial(k) * factorial(l - k) * factorial(zdegree)))
        for x2 in range(k + 1):
            for y2 in range(k - x2 + 1):
                z2 = k - x2 - y2
                multinomial = factorial(k) / (factorial(x2) * factorial(y2) * factorial(z2))
                for yp in range(kmax + 1):
                    phase = (1j ** yp)
                    trig = phase.imag if m < 0 else phase.real
                    key = (2 * x2 + kmax - yp, 2 * y2 + yp, 2 * z2 + zdegree)
                    polynomial[key] = polynomial.get(key, 0.0) + legendre * multinomial * comb(kmax, yp) * trig
    return tuple((i, j, k, v) for (i, j, k), v in sorted(polynomial.items()) if v)


def primitive_block(l, m, left, right_l, right, distance):
    """Contract Cartesian moments of exact spherical polynomials."""
    a = left[:, None]
    b = right[None, :]
    exponent = a + b
    pa = b * distance / exponent
    pb = -a * distance / exponent
    a_poly = solid_harmonic(l, m)
    b_poly = solid_harmonic(right_l, m)

    @lru_cache(maxsize=None)
    def z_moment(i, j):
        total = np.zeros_like(exponent)
        for u in range(i + 1):
            for v in range(j + 1):
                if not (u + v) % 2:
                    total += (comb(i, u) * comb(j, v) * pa ** (i - u) * pb ** (j - v)
                              * one_dimensional_moment(u + v, exponent))
        return total

    @lru_cache(maxsize=None)
    def xy_moments(i, j):
        return one_dimensional_moment(i, exponent) * one_dimensional_moment(j, exponent)

    def norm(poly, power, alpha):
        constant = sum(
            co * cv * one_dimensional_moment(i + u, 1.0) * one_dimensional_moment(j + v, 1.0)
            * one_dimensional_moment(k + w, 1.0)
            for i, j, k, co in poly for u, v, w, cv in poly
        )
        return (2 * alpha) ** (power / 2 + 0.75) / np.sqrt(constant)

    integral = np.zeros_like(exponent)
    for i, j, k, co in a_poly:
        for u, v, w, cv in b_poly:
            if not ((i + u) % 2 or (j + v) % 2):
                integral += co * cv * xy_moments(i + u, j + v) * z_moment(k, w)
    return (integral * norm(a_poly, l, a) * norm(b_poly, right_l, b)
            * np.exp(-a * b * distance ** 2 / exponent))


def overlap(shells, distance):
    """Normalize each contracted AO to unit self-overlap, with no rank truncation."""
    sizes = []
    indices = {}
    for l, (_, c) in shells.items():
        for m in range(-l, l + 1):
            start = sum(sizes)
            sizes.append(c.shape[1])
            indices[l, m] = slice(start, start + c.shape[1])
    n = sum(sizes)
    onsite = np.zeros((n, n))
    for (l, m), index in indices.items():
        exps, c = shells[l]
        onsite[index, index] = c.T @ primitive_block(l, m, exps, l, exps, 0) @ c
    norms = np.sqrt(np.diag(onsite))
    onsite /= norms[:, None] * norms[None, :]
    if distance is None:
        return onsite
    intersite = np.zeros_like(onsite)
    for (l, m), index in indices.items():
        for (r, s), jndex in indices.items():
            if m != s:
                continue
            a, ac = shells[l]
            b, bc = shells[r]
            intersite[index, jndex] = ac.T @ primitive_block(l, m, a, r, b, distance) @ bc
    intersite /= norms[:, None] * norms[None, :]
    return np.block([[onsite, intersite], [intersite.T, onsite]])


def evaluate():
    bases = {basis: read_shells(path, basis) for basis, path in BASIS_PATHS.items()}
    fixtures_paths = (A01 / "fixtures.json", A04 / "boundary-fixtures.json")
    units_path = A02 / "density-and-units.json"
    fixtures = {
        row["fixture_id"]: row
        for path in fixtures_paths for row in load_json(path)["valid"]
    }
    bohr_m = load_json(units_path)["engine_unit_profile"]["a_bohr_m"]
    rows = []
    for name in CASES:
        atoms = fixtures[name]["atoms"]
        symbol = atoms[0]["element"]
        distance_m = (float(np.linalg.norm(np.array(atoms[0]["position"]) - atoms[1]["position"]))
                      if len(atoms) == 2 else None)
        for name_basis, source in bases.items():
            matrix = overlap(source[symbol], None if distance_m is None else distance_m / bohr_m)
            assert np.max(np.abs(np.diag(matrix) - 1)) <= 1e-13
            assert np.max(np.abs(matrix - matrix.T)) <= 1e-13
            eigenvalues = np.linalg.eigvalsh(matrix)
            eigen_min, eigen_max = map(float, eigenvalues[[0, -1]])
            assert eigen_min > 0
            condition = eigen_max / eigen_min
            rows.append({
                "fixture_id": name,
                "distance_angstrom": None if distance_m is None else distance_m / 1e-10,
                "basis": name_basis,
                "dimension": len(eigenvalues),
                "min_eigenvalue": eigen_min,
                "max_eigenvalue": eigen_max,
                "condition_2": condition,
                "numerical_rank_by_floor": {
                    str(cut): int(np.count_nonzero(eigenvalues >= cut))
                    for cut in (MIN_PRINTED_EIGENVALUE, 1e-6, 1e-7, 1e-8)
                },
                "against_existing_overlap_limit_only": (
                    eigen_min >= MIN_PRINTED_EIGENVALUE and condition <= MAX_PRINTED_CONDITION_NUMBER
                ),
            })
    # Match rounded engine diagnostics on the two previously executed fixtures.
    pilots = load_json(ANCHOR)["pilots"]
    expected = {}
    for system, fixture in (("he", "C01-He"), ("h2-short", "A04-H2-short")):
        for label, basis in (("qz8", "cc-pVQZ"), ("5z8", "cc-pV5Z")):
            evidence = pilots[system]["cases"][label]["basis_conditioning"]
            expected[fixture, basis] = [evidence[key] for key in (
                "overlap_min_eigenvalue_printed", "overlap_max_eigenvalue_printed",
                "overlap_condition_2_printed",
            )]
    for row in rows:
        key = row["fixture_id"], row["basis"]
        if key in expected:
            actual = [row[k] for k in ("min_eigenvalue", "max_eigenvalue", "condition_2")]
            np.testing.assert_allclose(actual, expected[key], rtol=5e-4, atol=0)
    return {
        "scope": "Analytic, normalized, untruncated real-spherical AO overlap only",
        "limitations": "No CP2K calculation, DFT solution, numerical accuracy, RAM envelope, or physics acceptance tested.",
        "basis_set_exchange_commit": BSE,
        "versions": {"python": platform.python_version(), "numpy": np.__version__},
        "engine_bohr_m": bohr_m,
        "comparison_with_existing_limits": {
            "lambda_min_at_least": MIN_PRINTED_EIGENVALUE,
            "condition_2_at_most": MAX_PRINTED_CONDITION_NUMBER,
        },
        "cp2k_rounded_anchor_matches": len(expected),
        "input_sha256": {
            path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in (*BASIS_PATHS.values(), *fixtures_paths, units_path, ANCHOR)
        },
        "rows": rows,
    }


if __name__ == "__main__":
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--output", type=Path, required=True)
    opts = args.parse_args()
    s = primitive_block(0, 0, np.array([1.2]), 0, np.array([1.2]), 0.7)[0, 0]
    np.testing.assert_allclose(s, np.exp(-0.6 * 0.7 ** 2), atol=2e-15, rtol=0)
    result = evaluate()
    opts.output.write_bytes((json.dumps(result, indent=2) + "\n").encode())
    for row in result["rows"]:
        print(row["fixture_id"], row["basis"], row["dimension"],
              "%.9g" % row["min_eigenvalue"], "%.9g" % row["condition_2"],
              row["against_existing_overlap_limit_only"])
