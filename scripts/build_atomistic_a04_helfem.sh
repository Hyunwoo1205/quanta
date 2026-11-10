#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
    echo "Usage: $0 new-build-directory" >&2
    exit 2
fi
if [[ "$(uname -m)" != x86_64 ]] || ! cc --version | head -n1 | grep -F 'Debian 14.2.0-19' >/dev/null \
    || ! c++ --version | head -n1 | grep -F 'Debian 14.2.0-19' >/dev/null; then
    echo "A04 local pilot build requires x86-64 Debian GCC/G++ 14.2.0-19" >&2
    exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
locks="$root/deploy/helfem-a04"
patch="$locks/verification-observables-no-clamp.patch"
mapfile -t pins < <(python3 - "$locks/pilot-v2.json" <<'PY'
import json
import sys

plan = json.load(open(sys.argv[1], encoding="utf-8"))
for key in (
    "helfem_commit", "wignernj_commit", "openorbitaloptimizer_commit",
    "libxc_archive_sha256", "verification_patch_sha256",
):
    print(plan[key])
PY
)
printf '%s  %s\n' "${pins[4]}" "$patch" | sha256sum -c -
mkdir -- "$1"
base="$(cd -- "$1" && pwd)"
deps="$base/deps"
mkdir -p "$deps/sysroot" "$deps/libxc-src"

while read -r digest path; do
    package="$deps/${path##*/}"
    curl --fail --location --silent --show-error --max-time 120 \
        "https://deb.debian.org/debian/$path" --output "$package"
    printf '%s  %s\n' "$digest" "$package" | sha256sum -c -
    dpkg-deb -x "$package" "$deps/sysroot"
done < "$locks/debian-trixie-amd64.sha256"
archive="$deps/libxc-7.0.0.tar.bz2"
curl --fail --location --silent --show-error --max-time 120 \
    https://www.cp2k.org/static/downloads/libxc-7.0.0.tar.bz2 --output "$archive"
printf '%s  %s\n' "${pins[3]}" "$archive" | sha256sum -c -
tar -xjf "$archive" -C "$deps/libxc-src" --strip-components=1

checkout() {
    git clone --quiet "https://github.com/susilehtola/$1.git" "$2"
    git -C "$2" checkout --detach --quiet "$3"
    test "$(git -C "$2" rev-parse HEAD)" = "$3"
}
checkout HelFEM "$base/source" "${pins[0]}"
checkout wignernj "$deps/wignernj" "${pins[1]}"
checkout OpenOrbitalOptimizer "$deps/ooo" "${pins[2]}"
git -C "$base/source" apply "$patch"

libdir="$deps/sysroot/usr/lib/x86_64-linux-gnu"
export LD_LIBRARY_PATH="$libdir"
export PATH="$deps/sysroot/usr/bin:$PATH"
cmake -G Ninja -S "$deps/libxc-src" -B "$deps/libxc-obj" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-O1 \
    "-DCMAKE_INSTALL_PREFIX=$deps/libxc-prefix" -DBUILD_SHARED_LIBS=ON \
    -DENABLE_FORTRAN=OFF -DENABLE_PYTHON=OFF -DMAXORDER=2 -DBUILD_TESTING=OFF
cmake --build "$deps/libxc-obj" --parallel 3
cmake --install "$deps/libxc-obj"

cmake -G Ninja -S "$base/source" -B "$base/obj" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE='-O2 -DNDEBUG -ffp-contract=off' \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DHELFEM_USE_OPENMP=OFF -DHELFEM_EIGEN_BLAS=OFF \
    -DHELFEM_FLOAT128=OFF -DHELFEM_OPENTRUSTREGION=OFF -DHELFEM_BUILD_TESTS=OFF \
    -DHELFEM_FETCH_LIBXC=OFF "-DCMAKE_PREFIX_PATH=$deps/libxc-prefix;$deps/sysroot/usr" \
    "-DFETCHCONTENT_SOURCE_DIR_WIGNERNJ=$deps/wignernj" "-DFETCHCONTENT_SOURCE_DIR_OPENORBITALOPTIMIZER=$deps/ooo" \
    "-DHDF5_ROOT=$libdir/hdf5/serial" "-DHDF5_CXX_INCLUDE_DIR=$deps/sysroot/usr/include/hdf5/serial" \
    -DWIGNERNJ_BUILD_EXAMPLES=OFF -DWIGNERNJ_BUILD_FORTRAN=OFF -DWIGNERNJ_BUILD_LTO=OFF \
    -DWIGNERNJ_BUILD_TESTS=OFF
cmake --build "$base/obj" --parallel 2 --target atomic diatomic
sha256sum "$base/obj/src/"{atomic,diatomic} "$deps/libxc-prefix/lib/libxc.so.15"
