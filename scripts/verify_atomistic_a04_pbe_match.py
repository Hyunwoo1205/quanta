#!/usr/bin/env python3
"""Spot-check the pinned CP2K scalar PBE kernel against LibXC 7.0.0.

Uses the exact unpolarized CP2K routine in a standalone binary, outside the
engine's grid and SCF paths. Requires a local CP2K git checkout and a shared
LibXC 7.0.0 build from the Quanta-locked archive. Run with --help for inputs.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import re
import subprocess
import tempfile
from pathlib import Path

CP2K_COMMIT = "67b5da876dd6a76b8b021d5a04d1c81ba79a4c50"
LIBXC_ARCHIVE_SHA256 = "e9ae69f8966d8de6b7585abd9fab588794ada1fab8f689337959a35abbf9527d"
CP2K_SOURCES = {
    "src/xc/xc_pbe.F": "53e89074030aad219ffe5847f6c0d31ea39030d6d6e8a2de20945cc43eb9aefb",
    "src/base/kinds.F": "509bf418e94a8a0194bc1f95cdb960f3b355d937d069aaeccde532b9f0ff6eaf",
    "src/common/mathconstants.F": "e1385f0fa30cddf4a6c2942d51d47528cfce3b5ae3e0923d615badbdc7f95c01",
    "src/xc/xc_input_constants.F": "e78a4a8a55e3475c62d976d86fd4d2d0ec99eda9598e7054d7e04082f0a57c78",
    "src/input_cp2k_xc.F": "332cda33e1d90c5e3002fcc1e965633d009f28caadbc98c188474cd26e314e3b",
}
DENSITIES = (1e-8, 1e-5, 1e-3, 0.01, 0.1, 1.0, 4.0, 8.0)
REDUCED_GRADIENTS = (0.0, 0.01, 0.1, 0.5, 1.0, 3.0, 10.0, 100.0)
ARITHMETIC_TOLERANCE = 2e-12
FIELDS = ("energy_density", "density_derivative", "gradient_norm_derivative")
Point = tuple[float, float, float]
Triple = tuple[float, float, float]
DoublePtr = ctypes.POINTER(ctypes.c_double)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        args, cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def native_library(
    args: argparse.Namespace, build: Path
) -> tuple[ctypes.CDLL, dict[str, str]]:
    sources = {}
    for path, digest in CP2K_SOURCES.items():
        raw = subprocess.check_output(
            ["git", "show", f"{CP2K_COMMIT}:{path}"], cwd=args.cp2k_checkout
        )
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f"CP2K source hash mismatch for {path}")
        sources[path] = raw.decode("utf-8")

    kernel = re.search(
        r"^   SUBROUTINE pbe_lda_calc\(.*?^   END SUBROUTINE pbe_lda_calc\n",
        sources["src/xc/xc_pbe.F"],
        flags=re.MULTILINE | re.DOTALL,
    )
    if kernel is None:
        raise ValueError("pinned CP2K scalar kernel boundary missing")

    # These are the exact pinned declarations. CPABORT is only the kernel's
    # unsupported-parametrization path. The wrapper passes ORIG exclusively.
    source = (
        """#define CPABORT(message) error stop message
module a04_native_pbe
  use iso_c_binding, only: c_double
  implicit none
  integer, parameter :: dp = selected_real_kind(14, 200)
  integer, parameter :: xc_pbe_orig = 11, xc_pbe_rev = 12, xc_pbe_sol = 13
  real(kind=dp), parameter :: pi = 3.14159265358979323846264338_dp
contains
"""
        + kernel[0]
        + """
  subroutine a04_pbe(rho, g, sx, sc, result) bind(c)
    real(c_double), value :: rho, g, sx, sc
    real(c_double), intent(out) :: result(3)
    real(dp) :: e(1), vrho(1), vg(1), unused(1, 7)

    e = 0
    vrho = 0
    vg = 0
    unused = 0
    call pbe_lda_calc([rho], [g], e, vrho, vg, unused(:,1), unused(:,2), &
         unused(:,3), unused(:,4), unused(:,5), unused(:,6), unused(:,7), &
         1, 1, 1.0e-10_dp, xc_pbe_orig, sc, sx)
    result = [e(1), vrho(1), vg(1)]
  end subroutine a04_pbe
end module a04_native_pbe
"""
    )
    source_path = build / "native.F90"
    source_path.write_text(source, encoding="utf-8")
    command(
        [
            args.fc,
            "-O2",
            "-ffp-contract=off",
            "-fPIC",
            "-cpp",
            "-ffree-line-length-none",
            "-c",
            "native.F90",
            "-o",
            "native.o",
        ],
        build,
    )
    command(
        [
            args.cc,
            "-shared",
            "native.o",
            "-l:libgfortran.so.5",
            "-lm",
            "-o",
            "native.so",
        ],
        build,
    )
    native = ctypes.CDLL(str(build / "native.so"))
    native.a04_pbe.argtypes = [ctypes.c_double] * 4 + [DoublePtr]
    native.a04_pbe.restype = None
    return native, {
        "verbatim_routine_sha256": hashlib.sha256(kernel[0].encode("utf-8")).hexdigest(),
        "harness_source_sha256": sha256(source_path),
        "standalone_binary_sha256": sha256(build / "native.so"),
        "fortran_compiler": command([args.fc, "--version"], build).splitlines()[0],
        "c_link_driver": command([args.cc, "--version"], build).splitlines()[0],
    }


def libxc_library(path: Path) -> ctypes.CDLL:
    libxc = ctypes.CDLL(str(path))
    libxc.xc_version.argtypes = [ctypes.POINTER(ctypes.c_int)] * 3
    libxc.xc_version.restype = None
    version = [ctypes.c_int() for _ in range(3)]
    libxc.xc_version(*(ctypes.byref(part) for part in version))
    if tuple(part.value for part in version) != (7, 0, 0):
        raise ValueError("expected LibXC 7.0.0")
    libxc.xc_func_alloc.argtypes = []
    libxc.xc_func_alloc.restype = ctypes.c_void_p
    libxc.xc_func_init.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    libxc.xc_func_init.restype = ctypes.c_int
    libxc.xc_func_end.argtypes = [ctypes.c_void_p]
    libxc.xc_func_end.restype = None
    libxc.xc_func_free.argtypes = [ctypes.c_void_p]
    libxc.xc_func_free.restype = None
    libxc.xc_func_set_ext_params.argtypes = [ctypes.c_void_p, DoublePtr]
    libxc.xc_func_set_ext_params.restype = None
    libxc.xc_gga_exc_vxc.argtypes = [ctypes.c_void_p, ctypes.c_size_t] + [DoublePtr] * 5
    libxc.xc_gga_exc_vxc.restype = None
    return libxc


def native_samples(
    lib: ctypes.CDLL, points: list[Point], exchange: float, correlation: float
) -> list[Triple]:
    results = []
    for density, _, gradient in points:
        result = (ctypes.c_double * 3)()
        lib.a04_pbe(density, gradient, exchange, correlation, result)
        results.append((result[0], result[1], result[2]))
    return results


def libxc_samples(
    lib: ctypes.CDLL, points: list[Point], functional: int, parameters: Triple | None = None
) -> list[Triple]:
    func = lib.xc_func_alloc()
    if not func:
        raise RuntimeError("LibXC functional allocation failed")
    try:
        if lib.xc_func_init(func, functional, 1) != 0:  # XC_UNPOLARIZED
            raise RuntimeError(f"LibXC functional {functional} initialization failed")
        try:
            if parameters is not None:
                lib.xc_func_set_ext_params(func, (ctypes.c_double * 3)(*parameters))
            doubles = ctypes.c_double * len(points)
            rho = doubles(*(p[0] for p in points))
            sigma = doubles(*(p[2] ** 2 for p in points))
            eps, vrho, vsigma = doubles(), doubles(), doubles()
            lib.xc_gga_exc_vxc(func, len(points), rho, sigma, eps, vrho, vsigma)
            return [
                (density * eps[i], vrho[i], 2.0 * gradient * vsigma[i])
                for i, (density, _, gradient) in enumerate(points)
            ]
        finally:
            lib.xc_func_end(func)
    finally:
        lib.xc_func_free(func)


def comparison(
    points: list[Point], left: list[Triple], right: list[Triple]
) -> dict[str, object]:
    fields = {}
    for index, field in enumerate(FIELDS):
        samples = []
        for (density, s, gradient), cp2k, libxc in zip(points, left, right, strict=True):
            a, b = cp2k[index], libxc[index]
            if not (math.isfinite(a) and math.isfinite(b)):
                raise ValueError(f"nonfinite {field} at rho={density}, s={s}")
            absolute = abs(a - b)
            samples.append(
                {
                    "rho": density,
                    "s": s,
                    "gradient_norm": gradient,
                    "cp2k": a,
                    "libxc": b,
                    "absolute": absolute,
                    "normalized": absolute / max(1.0, abs(a), abs(b)),
                }
            )
        worst = max(samples, key=lambda row: row["normalized"])
        fields[field] = {
            "worst_normalized": worst,
            "worst_absolute": max(samples, key=lambda row: row["absolute"]),
            "points_exceeding_tolerance": sum(
                row["normalized"] > ARITHMETIC_TOLERANCE for row in samples
            ),
        }
    return {
        "arithmetic_equivalence_on_frozen_points": all(
            row["points_exceeding_tolerance"] == 0 for row in fields.values()
        ),
        "fields": fields,
    }


def add_components(left: list[Triple], right: list[Triple]) -> list[Triple]:
    return [
        (a[0] + b[0], a[1] + b[1], a[2] + b[2])
        for a, b in zip(left, right, strict=True)
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cp2k-checkout", type=Path, required=True)
    parser.add_argument("--libxc-archive", type=Path, required=True)
    parser.add_argument("--libxc-library", type=Path, required=True)
    parser.add_argument("--rounded-libxc-library", type=Path)
    parser.add_argument("--rounded-libxc-source", type=Path)
    parser.add_argument("--fc", default="gfortran")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sha256(args.libxc_archive) != LIBXC_ARCHIVE_SHA256:
        raise ValueError("LibXC source archive hash mismatch")
    if bool(args.rounded_libxc_library) != bool(args.rounded_libxc_source):
        parser.error("provide both rounded LibXC library and source tree or neither")

    points = [
        (rho, s, 2 * (3 * math.pi**2) ** (1 / 3) * rho ** (4 / 3) * s)
        for rho in DENSITIES
        for s in REDUCED_GRADIENTS
    ]
    with tempfile.TemporaryDirectory(prefix="quanta-pbe-") as temp:
        native, native_metadata = native_library(args, Path(temp))
        native_x = native_samples(native, points, 1.0, 0.0)
        native_c = native_samples(native, points, 0.0, 1.0)
        native_total = native_samples(native, points, 1.0, 1.0)
    libxc = libxc_library(args.libxc_library.resolve())
    libxc_x = libxc_samples(libxc, points, 101)  # XC_GGA_X_PBE
    libxc_c = libxc_samples(libxc, points, 130)  # XC_GGA_C_PBE
    default = {
        "exchange": comparison(points, native_x, libxc_x),
        "correlation": comparison(points, native_c, libxc_c),
        "sum": comparison(points, native_total, add_components(libxc_x, libxc_c)),
    }

    libxc_x_mod = libxc_samples(libxc, points, 320)  # XC_GGA_X_PBE_MOD
    libxc_c_beta = libxc_samples(
        libxc, points, 130, (0.066725, (1 - math.log(2)) / math.pi**2, 1.0)
    )
    diagnostic = {
        "exchange": comparison(points, native_x, libxc_x_mod),
        "correlation": comparison(points, native_c, libxc_c_beta),
        "sum": comparison(points, native_total, add_components(libxc_x_mod, libxc_c_beta)),
    }
    result = {
        "schema_version": 1,
        "scope": (
            "Unpolarized binary64 pointwise energy density and first derivatives. "
            "The standalone native source test does not exercise CP2K integration, "
            "the shipped binary, or total-system numerical acceptance."
        ),
        "physical_validation_status": "unvalidated",
        "cp2k": {
            "commit": CP2K_COMMIT,
            "source_file_sha256": CP2K_SOURCES,
            "parametrization": "ORIG",
            "density_cutoff_e_per_bohr3": 1e-10,
            **native_metadata,
        },
        "libxc": {
            "version": "7.0.0",
            "locked_source_archive_sha256": LIBXC_ARCHIVE_SHA256,
            "tested_shared_library_sha256": sha256(args.libxc_library),
            "default_ids": [101, 130],
        },
        "points": {
            "count": len(points),
            "densities_e_per_bohr3": DENSITIES,
            "reduced_gradients_s": REDUCED_GRADIENTS,
            "gradient_norm_e_per_bohr4": "2*(3*pi^2)^(1/3)*rho^(4/3)*s",
            "gradient_derivative": "CP2K d(rho*eps)/d|grad rho| versus LibXC 2*|grad rho|*vsigma",
            "compared_units": dict(zip(FIELDS, ("Eh/bohr^3", "Eh", "Eh*bohr"), strict=True)),
        },
        "criterion": {
            "absolute_error_divided_by_max_of_one_and_two_magnitudes": ARITHMETIC_TOLERANCE,
            "role": "pointwise arithmetic equivalence diagnostic, distinct from the M04 total-system limits",
        },
        "default_libxc": default,
        "separate_parameter_diagnostic": {
            "exchange_id": 320,
            "correlation_id": 130,
            "correlation_beta": 0.066725,
            "scope": "diagnostic only, preserves the default comparison and leaves LibXC's internal PW92 constants unchanged",
            "results": diagnostic,
        },
    }
    if args.rounded_libxc_library is not None:
        patched_sources = {
            "src/gga_c_pbe.c": "03e93f0af082466946cb5b6bf3a6e79339227f41d381c59676bcf1f67df19e2f",
            "src/maple2c/gga_exc/gga_c_pbe.c": "12783055bf4c61ae37d04acbdab2b458c378c566a38f17d7a88858d833101fb7",
        }
        for path, digest in patched_sources.items():
            if sha256(args.rounded_libxc_source / path) != digest:
                raise ValueError(f"rounded LibXC source hash mismatch for {path}")
        rounded_digest = sha256(args.rounded_libxc_library)
        if rounded_digest == result["libxc"]["tested_shared_library_sha256"]:
            raise ValueError("expected a separate library for the rounded diagnostic")
        rounded = libxc_library(args.rounded_libxc_library.resolve())
        rounded_x = libxc_samples(rounded, points, 320)  # XC_GGA_X_PBE_MOD
        rounded_c = libxc_samples(rounded, points, 130)  # patched XC_GGA_C_PBE
        result["separate_rounded_build_diagnostic"] = {
            "scope": "Spin-unpolarized energy density and first derivatives only",
            "tested_shared_library_sha256": rounded_digest,
            "patch_script_sha256": sha256(
                Path(__file__).with_name("patch_atomistic_a04_libxc_rounded.py")
            ),
            "patched_source_sha256": patched_sources,
            "required_build_option": "-DDISABLE_FXC=ON",
            "ids": [320, 130],
            "beta": 0.066725,
            "pw92_unpolarized_a": 0.031091,
            "results": {
                "exchange": comparison(points, native_x, rounded_x),
                "correlation": comparison(points, native_c, rounded_c),
                "sum": comparison(points, native_total, add_components(rounded_x, rounded_c)),
            },
        }
    args.output.write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
