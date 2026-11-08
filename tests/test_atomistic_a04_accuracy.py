"""Independent synthetic fields exercise the fixed A04 comparison geometry."""

import json
import math
from pathlib import Path

import numpy as np
import pytest


ROOT = Path(__file__).resolve().parents[1]
BOHR_PER_ANGSTROM = 1e-10 / json.loads(
    (ROOT / "docs/design/atomistic-a02-v0.1/density-and-units.json").read_bytes()
)["engine_unit_profile"]["a_bohr_m"]


@pytest.fixture
def comparison(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    from compare_atomistic_a04_accuracy import compare_density
    from verify_atomistic_a03 import parse_cube
    return compare_density, parse_cube


def _field(value):
    mantissa, exponent = f"{value: .5E}".split("E")
    return f"{mantissa}E{int(exponent):+04d}"


def _cube(path, parse, values, cell, *, atom_offset=0):
    axis = values.shape[0]
    step = cell * BOHR_PER_ANGSTROM / axis
    center = cell * BOHR_PER_ANGSTROM / 2
    with path.open("w", encoding="ascii", newline="\n") as output:
        output.write("-Quickstep-\n TOTAL ELECTRON DENSITY\n 2 0 0 0\n")
        for i in range(3):
            direction = np.eye(3)[i] * step
            output.write(f" {axis} " + " ".join(f"{v:.6f}" for v in direction) + "\n")
        for delta in (-0.25, 0.25):
            output.write(f" 1 1 {center + delta + atom_offset:.6f} {center:.6f} {center:.6f}\n")
        for row in values.reshape(-1, axis):
            for start in range(0, axis, 6):
                output.write("".join(_field(v) for v in row[start:start + 6]) + "\n")
    return {"status": "measured", "density": parse(path)}


def test_native_crop_counts_shell_without_cancellation(tmp_path, comparison):
    compare, parse = comparison
    ref = np.zeros((12,) * 3)
    ref[0, 0, 0] = -3
    ref[-1, -1, -1] = 2
    ref[3, 2, 3] = -5
    ref[3, 3, 9] = 6
    ref[3, 3, 3] = -2
    cand = ref[3:9, 3:9, 3:9].copy()
    cand[0, 0, 0] += 1
    reference_cube = tmp_path / "reference.cube"
    candidate_cube = tmp_path / "candidate.cube"
    reference = _cube(reference_cube, parse, ref, 4)
    candidate = _cube(candidate_cube, parse, cand, 2)
    result = compare(reference, candidate, reference_cube, candidate_cube, 4, 2)
    dv = (4 * BOHR_PER_ANGSTROM / 12) ** 3
    assert result["method"] == "native_aligned_crop"
    assert result["reference_overlap_start_index"] == [3] * 3
    assert result["reference_outer_shell_samples"] == 12**3 - 6**3
    assert result["reference_outer_shell_absolute_integral_electrons"] == pytest.approx(16 * dv)
    assert result["reference_outer_shell_signed_integral_electrons"] == pytest.approx(0)
    primary = result["primary"]
    assert primary["overlap_absolute_density_difference_integral_electrons"] == pytest.approx(dv)
    assert primary["overlap_signed_density_difference_integral_electrons"] == pytest.approx(dv)
    assert primary["overlap_maximum_absolute_density_difference_electron_per_bohr3"] == pytest.approx(1)
    assert primary["overlap_rms_density_difference_electron_per_bohr3"] == pytest.approx(1 / math.sqrt(6**3))
    assert primary["zero_extended_absolute_density_difference_integral_electrons"] == pytest.approx(17 * dv)
    assert result["sensitivity"] is None


@pytest.mark.parametrize("power", [3, 4])
def test_noncoincident_grids_recover_polynomial_and_expose_sensitivity(tmp_path, comparison, power):
    compare, parse = comparison

    def polynomial(axis):
        x, y, z = np.meshgrid(axis, axis, axis, indexing="ij")
        return x**power + y + z - 10 + x * y * z

    ref = np.zeros((16,) * 3)
    ref[4:12, 4:12, 4:12] = polynomial(np.arange(8) * 3)
    cand = polynomial(np.arange(6) * 4)
    reference_cube = tmp_path / "reference.cube"
    candidate_cube = tmp_path / "candidate.cube"
    reference = _cube(reference_cube, parse, ref, 4)
    candidate = _cube(candidate_cube, parse, cand, 2)
    result = compare(reference, candidate, reference_cube, candidate_cube, 4, 2)
    assert result["method"] == "separable_lagrange_4pt_and_6pt"
    assert result["reference_overlap_grid_counts"] == [8] * 3
    assert result["interpolation_right_extrapolated_planes_per_axis"] == 1
    assert result["sensitivity"]["overlap_absolute_density_difference_integral_electrons"] < 1e-7
    if power == 3:
        assert result["primary"]["overlap_absolute_density_difference_integral_electrons"] < 1e-7
        assert result["interpolants_overlap_l1_electrons"] < 1e-7
    else:
        assert result["primary"]["overlap_absolute_density_difference_integral_electrons"] > 1
        assert result["interpolants_overlap_l1_electrons"] > 1


def test_rejects_changed_cube_digest(tmp_path, comparison):
    compare, parse = comparison
    reference_cube = tmp_path / "reference.cube"
    candidate_cube = tmp_path / "candidate.cube"
    reference = _cube(reference_cube, parse, np.zeros((12,) * 3), 4)
    candidate = _cube(candidate_cube, parse, np.zeros((6,) * 3), 2)
    _cube(candidate_cube, parse, np.ones((6,) * 3), 2)
    with pytest.raises(ValueError, match="digest differs"):
        compare(reference, candidate, reference_cube, candidate_cube, 4, 2)


@pytest.mark.parametrize("candidate_count", [8, 6])
def test_equal_cell_compares_whole_domain(tmp_path, comparison, candidate_count):
    compare, parse = comparison

    def field(count):
        x, y, z = np.meshgrid(np.arange(count) * (24 // count), np.arange(count) * (24 // count),
                              np.arange(count) * (24 // count), indexing="ij")
        return 2 * x - y + z - 5

    reference_cube = tmp_path / "reference.cube"
    candidate_cube = tmp_path / "candidate.cube"
    reference = _cube(reference_cube, parse, field(8), 4)
    candidate = _cube(candidate_cube, parse, field(candidate_count) + 1, 4)
    result = compare(reference, candidate, reference_cube, candidate_cube, 4, 4)
    cell_volume = (4 * BOHR_PER_ANGSTROM) ** 3
    assert result["reference_overlap_start_index"] == [0] * 3
    assert result["reference_overlap_grid_counts"] == [8] * 3
    assert result["reference_outer_shell_samples"] == 0
    assert result["reference_outer_shell_absolute_integral_electrons"] == 0
    assert result["reference_outer_shell_signed_integral_electrons"] == 0
    primary = result["primary"]
    assert primary["overlap_absolute_density_difference_integral_electrons"] == pytest.approx(cell_volume)
    assert primary["zero_extended_absolute_density_difference_integral_electrons"] == pytest.approx(cell_volume)
    if candidate_count == 8:
        assert result["method"] == "native_aligned_crop"
        assert result["sensitivity"] is None
    else:
        assert result["method"] == "separable_lagrange_4pt_and_6pt"
        assert result["sensitivity"]["overlap_absolute_density_difference_integral_electrons"] == pytest.approx(cell_volume)


def test_rejects_coarser_reference_for_equal_cells(tmp_path, comparison):
    compare, parse = comparison
    reference_cube = tmp_path / "reference.cube"
    candidate_cube = tmp_path / "candidate.cube"
    reference = _cube(reference_cube, parse, np.zeros((6,) * 3), 4)
    candidate = _cube(candidate_cube, parse, np.zeros((8,) * 3), 4)
    with pytest.raises(ValueError, match="reference grid at least as fine"):
        compare(reference, candidate, reference_cube, candidate_cube, 4, 4)


def test_rejects_nonmatching_atoms(tmp_path, comparison):
    compare, parse = comparison
    reference_cube = tmp_path / "reference.cube"
    candidate_cube = tmp_path / "candidate.cube"
    reference = _cube(reference_cube, parse, np.zeros((12,) * 3), 4)
    candidate = _cube(candidate_cube, parse, np.zeros((6,) * 3), 2, atom_offset=0.001)
    with pytest.raises(ValueError, match="Ordered CUBE atoms do not align"):
        compare(reference, candidate, reference_cube, candidate_cube, 4, 2)


@pytest.mark.parametrize(("track", "runs", "factors"), [
    ("cell", [(12, 800, 80), (16, 800, 80)], ["cell_angstrom", "cell_angstrom"]),
    ("cutoff", [(12, 400, 40), (12, 400, 80), (12, 600, 80), (12, 800, 80)],
     ["rel_cutoff_ry", "cutoff_ry", "cutoff_ry"]),
    ("relative", [(12, 800, 40), (12, 800, 60), (12, 800, 80)], ["rel_cutoff_ry", "rel_cutoff_ry"]),
])
def test_refinement_only_executes_preregistered_cases(monkeypatch, tmp_path, track, runs, factors):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import run_atomistic_a04_resource_ci as runner

    prior = json.loads(runner.ENDPOINT_RECEIPT.read_bytes())
    observed = []
    compared = []

    def attempt(case, *args, ranks, swap, expected_input, cube):
        observed.append((case.cell, case.cutoff, case.rel_cutoff))
        assert ranks == 1 and swap == 0 and cube.parent == tmp_path
        return {"status": "measured"}

    def pair(reference_case, case, *_):
        compared.append((reference_case, case))
        return {"within_all_endpoint_thresholds": False}

    monkeypatch.setattr(runner, "refinement_attempt", attempt)
    monkeypatch.setattr(runner, "compare_accuracy_pair", pair)
    report = {"cases": [], "verification_scope": {}}
    assert runner.run_one_factor(track, prior["candidate"], tmp_path, tmp_path, report) == "measured"
    assert observed == runs
    assert [row["factor"] for row in report["comparisons"]] == factors
    assert len(compared) == len(factors) - int(track == "cell")
    if track == "cell":
        assert report["comparisons"][-1]["reused_workflow_run_id"] == 42443582121


@pytest.mark.parametrize(("system", "fixture"), [
    ("he", "C01-He"), ("h2-reference", "C02-H2-reference"),
    ("h2-short", "A04-H2-short"), ("h2-long", "A04-H2-long"),
])
def test_fixed_fixture_runs_each_declared_setting(monkeypatch, tmp_path, system, fixture):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import run_atomistic_a04_resource_ci as runner

    boundary = system in runner.BOUNDARY_SYSTEMS
    prior_path = runner.BOUNDARY_PREDECESSOR if boundary else runner.FIXTURE_PREDECESSOR
    prior = json.loads(prior_path.read_bytes())
    observed = []

    def attempt(case, *_, ranks, swap, cube):
        observed.append((case.cell, case.cutoff, case.rel_cutoff))
        assert case.system == system and ranks == 1 and swap == 0 and cube.parent == tmp_path
        return {"status": "measured", "input_metadata": {"source_fixture": fixture}}

    def pair(reference_case, case, *_):
        assert reference_case.system == case.system == system
        assert (reference_case.cell, reference_case.cutoff, reference_case.rel_cutoff) == (16, 800, 80)
        return {"within_all_endpoint_thresholds": False}

    monkeypatch.setattr(runner, "refinement_attempt", attempt)
    monkeypatch.setattr(runner, "compare_accuracy_pair", pair)
    report = {"cases": [], "verification_scope": {}}
    assert runner.run_fixed_fixture(system, prior["candidate"], tmp_path, tmp_path, report) == "measured"
    assert observed == [(12, 400, 40), (12, 600, 80), (12, 800, 80), (16, 800, 80)]
    assert [x["candidate_role"] for x in report["comparisons"]] == [
        "lightweight", "intermediate", "matched_cutoff_cell_check",
    ]
    scope = "h2_boundary_accuracy_screen" if boundary else "fixed_fixture_accuracy_screen"
    assert report["verification_scope"] == {scope: "measured"}


def test_helium_comparison_requires_one_force_row(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import run_atomistic_a04_resource_ci as runner

    check_map = {c["id"]: c for c in json.loads(runner.VALIDATION_PLAN.read_bytes())["checks"]}
    one_atom = {
        "engine_energy_hartree": -2.0,
        "engine_forces_hartree_per_bohr": [[0.0, 0.0, 0.0]],
        "engine_hard_soft_electron_count": 2.0,
        "density": {"atom_count": 1, "electron_integral": 2.0},
    }
    assert runner.accuracy_scalars(one_atom, one_atom, check_map)["force_passed"]
    with pytest.raises(ValueError, match="matching the fixture"):
        runner.accuracy_scalars(
            one_atom, {**one_atom, "engine_forces_hartree_per_bohr": [[0.0] * 3] * 2}, check_map,
        )
