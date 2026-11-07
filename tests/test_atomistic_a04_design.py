"""Check the A04 draft and its evidence links without running CP2K."""
from copy import deepcopy
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from hashlib import sha256
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
DRAFT = "docs/design/atomistic-a04-v0.1/profile.json"


def read_json(relative_path):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def authored_pair():
    return {
        "system": {
            "atoms": [
                {"id": "first", "element": "H", "isotope_mass_number": 1,
                 "position_m": [0, 0, 0]},
                {"id": "second", "element": "H", "isotope_mass_number": 1,
                 "position_m": [7e-11, 0, 0]},
            ],
            "boundary": "isolated_nonperiodic_3d",
            "charge_e": 0,
            "multiplicity": 1,
        },
        "model": "all_electron_pbe_gapw",
        "numerics": {"basis_set": "cc-pVDZ"},
        "operation": "single_point_energy_forces",
        "observables": ["total_energy_j", "forces_n"],
    }


class AtomisticA04DesignTests(unittest.TestCase):
    def setUp(self):
        self.profile = read_json(DRAFT)
        self.schema = read_json(self.profile["input_schema"])
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema)

    def test_authored_positions_are_not_fixture_selectors(self):
        first = authored_pair()
        second = deepcopy(first)
        second["system"]["atoms"] = [
            {"id": "a", "element": "H", "isotope_mass_number": 1,
             "position_m": [2e-11, 3e-11, -1e-11]},
            {"id": "b", "element": "H", "isotope_mass_number": 1,
             "position_m": [2e-11, 1.2e-10, -1e-11]},
        ]
        second["observables"].append("electron_number_density_per_m3")
        helium = deepcopy(first)
        helium["system"]["atoms"] = [
            {"id": "atom", "element": "He", "isotope_mass_number": 4,
             "position_m": [2e-11, -1e-11, 0]},
        ]
        for instance in (first, second, helium):
            with self.subTest(atoms=instance["system"]["atoms"]):
                self.validator.validate(instance)

    def test_schema_rejects_unsupported_requests(self):
        wrong_isotope = authored_pair()
        wrong_isotope["system"]["atoms"][0]["isotope_mass_number"] = 2
        mixed_pair = authored_pair()
        mixed_pair["system"]["atoms"][0].update(element="He", isotope_mass_number=4)
        wrong_charge = authored_pair()
        wrong_charge["system"]["charge_e"] = 1
        wrong_boundary = authored_pair()
        wrong_boundary["system"]["boundary"] = "periodic"
        wrong_basis = authored_pair()
        wrong_basis["numerics"]["basis_set"] = "unlocked"
        fixture = dict(authored_pair(), fixture_id="C03")
        raw_input = dict(authored_pair(), cp2k_input="&GLOBAL")
        motion = dict(authored_pair(), operation="integrate")
        unsupported_output = dict(authored_pair(), observables=["wavefunction"])
        for instance in (wrong_isotope, mixed_pair, wrong_charge, wrong_boundary,
                         wrong_basis, fixture, raw_input, motion, unsupported_output):
            with self.subTest(instance=instance):
                self.assertFalse(self.validator.is_valid(instance))

    def test_candidate_identity_is_bound_and_public_support_is_inactive(self):
        self.assertFalse(self.profile["executable"])
        self.assertIsNone(self.profile["runtime_contract_version"])
        self.assertEqual(self.profile["physical_validation_status"], "unvalidated")
        candidate = self.profile["candidate_platform"]
        self.assertEqual(candidate["platform"], "linux/arm64")
        self.assertEqual(candidate["public_runtime_platforms"], [])
        proof = read_json(candidate["provenance"])
        self.assertEqual(candidate["quanta_build_commit"], proof["quanta_build_commit"])
        self.assertEqual(candidate["cp2k_commit"], proof["source"]["upstream_commit"])
        for key, evidence_key in (
            ("binary_sha256", "binary_sha256"),
            ("manifest_digest", "locked_platform_manifest_digest"),
            ("config_digest", "locked_config_digest"),
        ):
            with self.subTest(key=key):
                self.assertEqual(candidate[key], proof["candidate"][evidence_key])
        for case in proof["a03_cases"]:
            self.assertTrue(case["native_execution_gate_passed"])
            self.assertTrue(case["oci_execution_gate_passed"])

    def test_unit_binary64_and_mass_rounding_match_evidence(self):
        units = self.profile["units"]
        evidence = read_json(units["conversion_evidence"])
        conversion = evidence["engine_conversion_candidate"]
        self.assertEqual(units["engine_constants_edition"], conversion["constants_edition"])
        self.assertEqual(units["engine_to_si_binary64_hex"], conversion["binary64_hex"])
        for key, value in units["engine_to_si_binary64_hex"].items():
            self.assertEqual(float.fromhex(value), conversion["derived_values"][key])
        references = evidence["independent_reference_nuclear_masses"]
        self.assertEqual(units["nuclear_masses_edition"], references["constants_edition"])
        for isotope, key in (("H-1", "H1_bare_proton_mass_kg"),
                             ("He-4", "He4_bare_alpha_particle_mass_kg")):
            mass = units["bare_nuclei"][isotope]
            self.assertEqual(mass["mass_kg"], references[key])
            with localcontext() as ctx:
                ctx.prec = 40
                ctx.rounding = ROUND_HALF_EVEN
                engine_mass = Decimal(mass["mass_kg"]) / Decimal("1.660538782e-27")
            self.assertEqual(str(engine_mass), mass["engine_mass_u"])
            self.assertEqual(float(engine_mass).hex(), mass["engine_mass_u_binary64_hex"])

    def test_basis_choices_resolve_to_locked_bytes(self):
        basis = self.profile["basis_and_potential"]
        choices = self.schema["properties"]["numerics"]["properties"]["basis_set"]["enum"]
        self.assertEqual(choices, basis["candidate_basis_sets"])
        manifest = read_json(basis["lock"])
        files = {Path(item["path"]).name: item for item in manifest["files"]}
        for filename in [basis["potential_file"], *(f"{name}.cp2k" for name in choices)]:
            with self.subTest(filename=filename):
                entry = files[filename]
                raw = (ROOT / entry["path"]).read_bytes()
                self.assertEqual(len(raw), entry["size_bytes"])
                self.assertEqual(sha256(raw).hexdigest(), entry["sha256"])

    def test_cube_precision_does_not_imply_resolution_acceptance(self):
        cube = self.profile["cube"]
        evidence = read_json(self.profile["units"]["conversion_evidence"])["cube_candidate"]
        for key in ("field_format", "field_significant_digits"):
            self.assertEqual(cube[key], evidence[key])
        self.assertEqual(cube["field_significant_digits"], 5)
        self.assertEqual(cube["geometry_format"], "F12.6")
        self.assertTrue(cube["preserve_raw_file_bytes"])
        self.assertFalse(cube["allow_clipping_smoothing_or_renormalization"])
        self.assertEqual(cube["field_shape_convergence_status"], "not_tested")
        validation = self.profile["validation"]
        plan = read_json(validation["plan"])
        self.assertTrue(all(check["status"] == "not_executed" for check in plan["checks"]))
        self.assertEqual(validation["resolution_acceptance_status"], "not_tested")
