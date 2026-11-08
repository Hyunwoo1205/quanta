"""Generate bounded, internal A03 CP2K installation probes.

These are exploratory ENERGY_FORCE inputs, not a registered Quanta experiment
contract, public fixture menu, A04 frozen profile, or scientific acceptance run.
The generator does not install or execute CP2K and never modifies A01/A02 files.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

ROOT = Path(__file__).resolve().parents[1]
A01 = ROOT / "docs/design/atomistic-a01-v0.1"
A02 = ROOT / "docs/design/atomistic-a02-v0.1"
BASES = ("cc-pVDZ", "cc-pVTZ", "cc-pVQZ")
BOUNDARY_FIXTURE_PATH = ROOT / "docs/design/atomistic-a04-v0.1/boundary-fixtures.json"
BOUNDARY_SYSTEM_FIXTURES = {"h2-short": "A04-H2-short", "h2-long": "A04-H2-long"}
SYSTEM_FIXTURES = {
    "he": "C01-He",
    "h2": "C03-H2-stretched",
    "h2-reference": "C02-H2-reference",
    **BOUNDARY_SYSTEM_FIXTURES,
}
A03_CLI_SYSTEMS = ("he", "h2")


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def probe_metadata(
    system: str = "he", basis: str = "cc-pVDZ", project: str = "a03_probe",
    data_dir: str = "/quanta-data", *, cell_angstrom: int = 12,
    cutoff_ry: int = 400, rel_cutoff_ry: int = 40, eps_scf: float = 1e-8,
    max_scf: int = 80, density: bool = True, radial_grid: int = 100, lebedev_grid: int = 110,
    overlap_condition: bool = False,
) -> dict:
    """Describe an internal probe and its explicit SI-to-native mapping.

    Allowed cell/grid/SCF choices are the predeclared A01 candidate levels, not
    measured convergence. Additional atomic-grid/split candidates below are
    recorded explicitly and remain subject to A04/P2 refinement.
    """
    if system not in SYSTEM_FIXTURES or basis not in BASES:
        raise ValueError("unsupported internal probe system or basis")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", project):
        raise ValueError("project must be a bounded single safe identifier")
    if not isinstance(data_dir, str) or not re.fullmatch(r"/[A-Za-z0-9_/-]+", data_dir):
        raise ValueError("data_dir must be a safe absolute container path")
    if ".." in PurePosixPath(data_dir).parts or str(PurePosixPath(data_dir)) != data_dir:
        raise ValueError("data_dir must be normalized without parent traversal")
    qz = basis == "cc-pVQZ"
    for value, allowed, name in (
        (cell_angstrom, (12, 16, 20), "cell_angstrom"),
        (cutoff_ry, (400, 600, 800, 1000, 1200) if qz else (400, 600, 800), "cutoff_ry"),
        (rel_cutoff_ry, (40, 60, 80, 120) if qz else (40, 60, 80), "rel_cutoff_ry"),
        (eps_scf, (1e-8, 1e-9, 1e-10), "eps_scf"),
    ):
        if isinstance(value, bool) or value not in allowed:
            raise ValueError(f"unsupported A01 candidate {name}")
    if type(radial_grid) is not int or radial_grid not in ((100, 150, 200, 250) if qz else (100, 150, 200)):
        raise ValueError("unsupported A04 candidate radial_grid")
    if type(lebedev_grid) is not int or lebedev_grid not in ((110, 146, 194, 302) if qz else (110, 146, 194)):
        raise ValueError("unsupported A04 candidate lebedev_grid")
    if type(max_scf) is not int or not 1 <= max_scf <= 500:
        raise ValueError("max_scf must be an integer in 1..500")
    if type(density) is not bool or type(overlap_condition) is not bool:
        raise ValueError("density and overlap_condition must be boolean")
    if overlap_condition and not density:
        raise ValueError("A04 overlap diagnostic requires the full-density print section")

    fixture_path = BOUNDARY_FIXTURE_PATH if system in BOUNDARY_SYSTEM_FIXTURES else A01 / "fixtures.json"
    fixture = next(f for f in _read(fixture_path)["valid"]
                   if f["fixture_id"] == SYSTEM_FIXTURES[system])
    source_paths = (
        A01 / "fixtures.json", A01 / "profile.json", A01 / "reference-data.json",
        A02 / "density-and-units.json", A02 / "engine-lock.json",
    )
    if fixture_path == BOUNDARY_FIXTURE_PATH:
        source_paths += (fixture_path,)
    refs = _read(A01 / "reference-data.json")["constants"]
    units = _read(A02 / "density-and-units.json")["engine_unit_profile"]
    atoms = []
    with localcontext() as ctx:
        ctx.prec = 40
        center = Decimal(cell_angstrom) / 2
        engine_amu = Decimal(str(units["atomic_mass_kg"]))
        for atom in fixture["atoms"]:
            key = "proton_mass_kg" if atom["element"] == "H" else "alpha_particle_mass_kg"
            mass = Decimal(str(refs[key]["value"]))
            # The coordinate translation is represented explicitly; it is not
            # an assertion that finite-cell energies are translation invariant.
            xyz = [Decimal(str(v)) / Decimal("1e-10") + center for v in atom["position"]]
            atoms.append({"id": atom["id"], "element": atom["element"],
                          "source_position_m": atom["position"],
                          "engine_position_angstrom": [str(x) for x in xyz],
                          "bare_nuclear_mass_kg": str(mass),
                          "engine_mass_amu": str(mass / engine_amu),
                          "mass_reference": "NIST-CODATA-2022:" + key})
    return {
        "document_kind": "internal_atomistic_a03_probe",
        "status": "exploratory_settings_not_A04_frozen_not_scientific_acceptance",
        "public_runtime_contract": False,
        "fixture_as_product_execution_selector": False,
        "physical_validation_status": "unvalidated",
        "system": system, "source_fixture": fixture["fixture_id"],
        "project": project, "operation": "ENERGY_FORCE", "basis": basis,
        "data_dir": data_dir,
        "model": {"method": "GAPW", "functional": "PBE", "potential": "ALL",
                  "charge_e": 0, "multiplicity": 1, "electron_count": 2,
                  "uks": False, "dispersion": False, "periodic": "NONE"},
        "numerics": {"cell_angstrom": cell_angstrom, "cutoff_ry": cutoff_ry,
                     "rel_cutoff_ry": rel_cutoff_ry, "ngrids": 4,
                     "eps_scf": eps_scf, "max_scf": max_scf,
                     "poisson_solver": "MT", "scf_guess": "ATOMIC",
                     "scf_method": "OT/DIIS/FULL_ALL", "eps_default": 1e-12,
                     "eps_pgf_orb": 1e-10, "epsfit": 1e-4, "epsiso": 1e-12,
                     "epssvd": 1e-8, "epsrho0": 1e-8,
                     "lmaxn0": 2, "lmaxn1": 6, "quadrature": "GC_LOG",
                     "radial_grid": radial_grid, "lebedev_grid": lebedev_grid},
        "numerical_caveat": "Candidates only. MT requires cell > twice density support; cell/tail, grid, basis and atomic-grid convergence are not established by this probe.",
        **({"overlap_condition": True} if overlap_condition else {}),
        "density": {"enabled": density, "quantity": "electron_number_density_hard_plus_soft",
                    "density_include": "TOTAL_DENSITY", "stride": [1, 1, 1],
                    "xrd_interface": False, "append": False,
                    "clipping_or_renormalization": False},
        "energy_output": {"unit": "hartree", "scope": "electronic plus nuclear repulsion; no ZPE/rest/thermal terms"},
        "forces_output": {"file": "forces.xyz", "format": "CP2K ATOMIC FORCES table, not XYZ despite filename suffix",
                          "unit": "hartree/bohr", "ndigits": 15},
        "coordinate_translation_angstrom": [cell_angstrom / 2] * 3,
        "atoms": atoms,
        "engine_mass_unit_kg": str(units["atomic_mass_kg"]),
        "engine_unit_codata_edition": units["codata_edition"],
        "data_sha256": {f"{basis}.cp2k": _sha(A02 / "assets" / f"{basis}.cp2k"),
                        "ALL_POTENTIALS": _sha(A02 / "assets/ALL_POTENTIALS")},
        "source_files_sha256": {str(p.relative_to(ROOT)): _sha(p) for p in source_paths},
        "unselected_version_locked_defaults": "Remaining engine defaults are tied to the actually measured binary; this is not a complete frozen numerical profile.",
    }


def generate_input(*args, **kwargs) -> str:
    """Return CP2K text for the bounded internal probe described above."""
    p = probe_metadata(*args, **kwargs)
    n = p["numerics"]
    density_text = ""
    if p["density"]["enabled"]:
        density_text = """    &PRINT
      &E_DENSITY_CUBE ON
        DENSITY_INCLUDE TOTAL_DENSITY
        STRIDE 1 1 1
        XRD_INTERFACE F
        APPEND F
      &END E_DENSITY_CUBE
    &END PRINT
"""
    if p.get("overlap_condition", False):
        diagnostic = """      &OVERLAP_CONDITION ON
        1-NORM FALSE
        DIAGONALIZATION TRUE
        ARNOLDI FALSE
      &END OVERLAP_CONDITION
"""
        density_text = density_text.replace("    &PRINT\n", "    &PRINT\n" + diagnostic, 1)
    coords = "\n".join("      " + a["element"] + " " + " ".join(a["engine_position_angstrom"])
                       for a in p["atoms"])
    a = p["atoms"][0]  # all atoms of each bounded probe have one element/isotope
    kind = f"""    &KIND {a['element']}
      ELEMENT {a['element']}
      BASIS_SET {p['basis']}
      POTENTIAL ALL
      MASS {a['engine_mass_amu']}
      RADIAL_GRID {n['radial_grid']}
      LEBEDEV_GRID {n['lebedev_grid']}
    &END KIND"""
    return f"""# Internal A03 exploratory probe; not an A04 profile/scientific pass.
&GLOBAL
  PROJECT {p['project']}
  RUN_TYPE ENERGY_FORCE
  PRINT_LEVEL MEDIUM
&END GLOBAL
&FORCE_EVAL
  METHOD QUICKSTEP
  &DFT
    BASIS_SET_FILE_NAME {p['data_dir']}/{p['basis']}.cp2k
    POTENTIAL_FILE_NAME {p['data_dir']}/ALL_POTENTIALS
    CHARGE 0
    MULTIPLICITY 1
    UKS F
    &QS
      METHOD GAPW
      EPS_DEFAULT 1.0E-12
      EPS_PGF_ORB 1.0E-10
      EPSFIT 1.0E-4
      EPSISO 1.0E-12
      EPSSVD 1.0E-8
      EPSRHO0 1.0E-8
      LMAXN0 2
      LMAXN1 6
      QUADRATURE GC_LOG
    &END QS
    &MGRID
      NGRIDS 4
      CUTOFF [Ry] {n['cutoff_ry']}
      REL_CUTOFF [Ry] {n['rel_cutoff_ry']}
    &END MGRID
    &POISSON
      PERIODIC NONE
      POISSON_SOLVER MT
    &END POISSON
    &SCF
      SCF_GUESS ATOMIC
      EPS_SCF {n['eps_scf']:.12E}
      MAX_SCF {n['max_scf']}
      &OT ON
        MINIMIZER DIIS
        PRECONDITIONER FULL_ALL
      &END OT
      &PRINT
        &RESTART OFF
        &END RESTART
      &END PRINT
    &END SCF
    &XC
      &XC_FUNCTIONAL PBE
      &END XC_FUNCTIONAL
    &END XC
{density_text}  &END DFT
  &SUBSYS
    &CELL
      ABC [angstrom] {n['cell_angstrom']} {n['cell_angstrom']} {n['cell_angstrom']}
      PERIODIC NONE
    &END CELL
    &COORD
      UNIT angstrom
{coords}
    &END COORD
{kind}
  &END SUBSYS
  &PRINT
    &PROGRAM_RUN_INFO ON
      ENERGY_UNIT hartree
    &END PROGRAM_RUN_INFO
    &FORCES ON
      FILENAME =forces.xyz
      FORCE_UNIT hartree/bohr
      NDIGITS 15
    &END FORCES
  &END PRINT
&END FORCE_EVAL
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--data-dir", default="/quanta-data")
    parser.add_argument("--basis", choices=BASES, default="cc-pVDZ")
    parser.add_argument("--system", choices=A03_CLI_SYSTEMS, default="he")
    args = parser.parse_args()
    p = probe_metadata(args.system, args.basis, data_dir=args.data_dir)
    text = generate_input(args.system, args.basis, data_dir=args.data_dir)
    p["input_utf8_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "probe.inp").write_text(text, encoding="utf-8")
    (args.output_dir / "probe.json").write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output_dir": str(args.output_dir), "input_utf8_sha256": p["input_utf8_sha256"]}))


if __name__ == "__main__":
    main()
