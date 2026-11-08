"""G0 input provenance and atomic-grid deck isolation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "a04_grid_inputs_for_test", ROOT / "scripts/atomistic_a03_inputs.py"
)
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)
PLAN_PATH = ROOT / "docs/design/atomistic-a04-v0.1/remaining-numerical-validation.json"
FIXTURES = json.loads(PLAN_PATH.read_text(encoding="utf-8"))["fixtures"]


class TestA04GridInputs(unittest.TestCase):
    def test_default_atomic_grid_preserves_qualified_input_bytes(self):
        for fixture in FIXTURES:
            with self.subTest(system=fixture["system"]):
                cell, cutoff, relative = fixture["baseline_cell_cutoff_relative"]
                settings = {
                    "system": fixture["system"],
                    "project": "a04_resource_h2",
                    "cell_angstrom": cell,
                    "cutoff_ry": cutoff,
                    "rel_cutoff_ry": relative,
                }
                default = inputs.generate_input(**settings)
                self.assertEqual(
                    hashlib.sha256(default.encode("ascii")).hexdigest(), fixture["baseline_deck_sha256"]
                )
                self.assertEqual(
                    inputs.generate_input(**settings, radial_grid=100, lebedev_grid=110), default
                )

    def test_atomic_grid_refinement_changes_one_directive(self):
        baseline = inputs.generate_input("he")
        baseline_numerics = inputs.probe_metadata("he")["numerics"]
        for axis, level, directive, default_level in (
            ("radial_grid", 150, "RADIAL_GRID", 100),
            ("radial_grid", 200, "RADIAL_GRID", 100),
            ("lebedev_grid", 146, "LEBEDEV_GRID", 110),
            ("lebedev_grid", 194, "LEBEDEV_GRID", 110),
        ):
            with self.subTest(axis=axis, level=level):
                old_line = f"      {directive} {default_level}\n"
                new_line = f"      {directive} {level}\n"
                change = {axis: level}
                self.assertEqual(baseline.count(old_line), 1)
                self.assertEqual(inputs.generate_input("he", **change), baseline.replace(old_line, new_line, 1))
                self.assertEqual(
                    inputs.probe_metadata("he", **change)["numerics"], {**baseline_numerics, **change}
                )

    def test_atomic_grid_rejects_unregistered_levels_or_types(self):
        for axis, level in (
            ("radial_grid", 151),
            ("radial_grid", 150.0),
            ("radial_grid", True),
            ("lebedev_grid", 145),
            ("lebedev_grid", 146.0),
            ("lebedev_grid", "146"),
        ):
            with self.subTest(axis=axis, level=level), self.assertRaises(ValueError):
                inputs.generate_input("he", **{axis: level})
