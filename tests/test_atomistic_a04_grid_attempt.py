"""A04 keeps the submitted grid deck tied to the expected hash."""
from hashlib import sha256
import importlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
    runner = importlib.import_module("run_atomistic_a04_resource_ci")


class TestA04GridAttempt(unittest.TestCase):
    def test_refined_deck_must_match_before_container_creation(self):
        case = runner.Case(
            "he-grid-probe", 12, 800, True, 360, rel_cutoff=80, system="he",
            radial_grid=200, lebedev_grid=194,
        )
        expected = runner.generate_input(
            "he", "cc-pVDZ", project=runner.PROJECT, cutoff_ry=800, rel_cutoff_ry=80,
            radial_grid=200, lebedev_grid=194,
        ).encode("ascii")
        digest = sha256(expected).hexdigest()

        for recorded_hash, reaches_creation in ((digest, True), ("0" * 64, False)):
            with self.subTest(reaches_creation=reaches_creation), TemporaryDirectory() as folder:
                scratch = Path(folder)
                observed = []

                def inspect_deck(name, image_id, budget, work, inputs, candidate, **layout):
                    observed.append((inputs / "input.inp").read_bytes())
                    raise OSError("Stop the test before using Docker")

                result = {}
                with (
                    patch.object(runner, "container_args", side_effect=inspect_deck),
                    patch.object(runner, "run_docker") as docker,
                    patch.object(runner, "clean_container"),
                ):
                    runner.run_attempt(
                        case, 1, 6 * runner.GIB, 8 * runner.GIB, {"image_id": "mock"},
                        scratch, scratch, result, expected_input=recorded_hash,
                    )
                docker.assert_not_called()
                self.assertEqual(observed, [expected] if reaches_creation else [])
                self.assertEqual(result["submitted_input_sha256"], digest)
                self.assertEqual(result["input_metadata"]["basis"], "cc-pVDZ")
                self.assertEqual(result["input_metadata"]["numerics"]["radial_grid"], 200)
                self.assertEqual(result["input_metadata"]["numerics"]["lebedev_grid"], 194)
