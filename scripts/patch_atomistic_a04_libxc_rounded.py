#!/usr/bin/env python3
"""Patch a fresh LibXC 7.0.0 tree for a restricted PBE sensitivity run.

This is a separate diagnostic build. Configure with -DDISABLE_FXC=ON and
use GGA_X_PBE_MOD plus the patched GGA_C_PBE for restricted SCF only.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def read_pinned(path: Path, digest: str) -> str:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"LibXC source hash mismatch for {path}")
    return data.decode("utf-8")


def replace_pinned(source: str, old: str, new: str, count: int) -> str:
    if source.count(old) != count:
        raise ValueError(f"unexpected number of occurrences of {old!r}")
    return source.replace(old, new)


def patch(source_root: Path) -> None:
    # For unpolarized PW92 in the generated PBE EXC/VXC functions, the three
    # coefficients dependent on A are 1/(2*A), 2*A, and 2*A*alpha1/12.
    # Convert them from A=.0310907 to CP2K native A=.031091, with alpha1=.21370.
    # The polarized and unused higher derivative kernels are outside this scope.
    defaults = source_root / "src/gga_c_pbe.c"
    generated = source_root / "src/maple2c/gga_exc/gga_c_pbe.c"
    c_source = read_pinned(
        defaults, "d449da1e327e5c5c17dc50174c25793aeea1876c4d1250d53ae12ded3e6395da"
    )
    generated_source = read_pinned(
        generated, "0b0045c5027af1e250128a4243285715714d31ebbf6ff83dab52ca03cc17ad70"
    )
    c_source = replace_pinned(
        c_source,
        "static const double pbe_values[PBE_N_PAR] =\n  {0.06672455060314922,",
        "static const double pbe_values[PBE_N_PAR] =\n  {0.066725,",
        1,
    )
    marker = "#ifndef XC_DONT_COMPILE_FXC"
    split = generated_source.index(marker)
    first_order = generated_source[:split]
    first_order = replace_pinned(
        first_order, "0.16081979498692535067e2", "(1.0 / (2.0 * 0.031091))", 2
    )
    first_order = replace_pinned(
        first_order, "0.621814e-1", "(2.0 * 0.031091)", 2
    )
    first_order = replace_pinned(
        first_order, "0.11073470983333333333e-2", "(2.0 * 0.031091 * 0.21370 / 12.0)", 1
    )
    defaults.write_text(c_source, encoding="utf-8")
    generated.write_text(first_order + generated_source[split:], encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("libxc_source", type=Path)
    args = parser.parse_args()
    patch(args.libxc_source)


if __name__ == "__main__":
    main()
