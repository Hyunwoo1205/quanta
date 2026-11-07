#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

inputs=/opt/quanta-build
prefix=/opt/quanta-cp2k
evidence="$prefix/evidence"
source_sha=67b5da876dd6a76b8b021d5a04d1c81ba79a4c50
source_tree=2e4405ec65578a3d8205bc23adf69249798d98d3
architecture="${QUANTA_CP2K_ARCH:-arm64}"
openblas_isa_options=()
case "$architecture" in
    arm64)
        machine=aarch64
        isa=armv8-a
        elf_machine=AArch64
        openblas_target=ARMV8
        ;;
    amd64)
        machine=x86_64
        isa=x86-64-v2
        elf_machine='Advanced Micro Devices X86-64'
        openblas_target=CORE2
        openblas_isa_options=(-DNO_AVX=ON -DNO_AVX2=ON -DNO_AVX512=ON)
        ;;
    *) echo "Unsupported CP2K build architecture: $architecture" >&2; exit 2 ;;
esac
baseline="-march=$isa -mtune=generic -fno-lto"
mkdir -p "$evidence"

[[ "$(uname -m)" == "$machine" && "$(dpkg --print-architecture)" == "$architecture" ]]
if [[ "$architecture" == amd64 ]]; then
    /lib64/ld-linux-x86-64.so.2 --help >"$evidence/x86-64-loader-hwcaps.txt"
    grep -Eq '^[[:space:]]+x86-64-v2 \(supported, searched\)' "$evidence/x86-64-loader-hwcaps.txt"
fi
case "${1:?choose fetch or compile}" in
    fetch)
        cd "$inputs"
        mkdir -p archives
        while read -r hash filename; do
            [[ "$hash" =~ ^[0-9a-f]{64}$ && "$filename" =~ ^[A-Za-z0-9.-]+$ ]]
            curl --fail --location --silent --show-error --retry 3 --max-time 180 \
                "https://www.cp2k.org/static/downloads/$filename" --output "archives/$filename"
        done <source-archives.sha256
        (cd archives && sha256sum --check ../source-archives.sha256)
        git init -q cp2k
        git -C cp2k fetch --depth 1 https://github.com/cp2k/cp2k.git "$source_sha"
        git -C cp2k -c advice.detachedHead=false checkout --detach FETCH_HEAD
        git -C cp2k config --local core.abbrev 40
        ;;
    compile) ;;
    *) exit 2 ;;
esac

cd "$inputs"
[[ "$(git -C cp2k rev-parse HEAD)" == "$source_sha" ]]
[[ "$(git -C cp2k rev-parse 'HEAD^{tree}')" == "$source_tree" ]]
[[ "$(git -C cp2k log -1 --format=%h)" == "$source_sha" ]]
[[ -z "$(git -C cp2k status --porcelain)" ]]
(cd archives && sha256sum --check ../source-archives.sha256)
cp source-archives.sha256 "$evidence/"
printf '%s\n%s\n' "$source_sha" "$source_tree" >"$evidence/cp2k-git.txt"
(
    cd cp2k
    git ls-files -z | xargs -0 -r sha256sum
) >"$evidence/cp2k-source-files.sha256"
if [[ "$1" == fetch ]]; then
    exit 0
fi

jobs="${2:?set a compiler parallelism limit from 1 to 4}"
[[ "$jobs" =~ ^[1-4]$ ]]
deps="$prefix/deps"
mkdir -p "$deps"
export CC=gcc-15 CXX=g++-15 FC=gfortran-15 MPICH_CC=gcc-15 MPICH_CXX=g++-15 MPICH_FC=gfortran-15
export CFLAGS="$baseline" CXXFLAGS="$baseline" FCFLAGS="$baseline" FFLAGS="$baseline"
export PKG_CONFIG_PATH="$deps/lib/pkgconfig" LD_LIBRARY_PATH="$deps/lib"
{
    uname -m
    gcc-15 --version
    g++-15 --version
    gfortran-15 --version
    ld --version
    cmake --version
    ninja --version
    mpichversion
    printf 'ISA=%s\nOpenBLAS target=%s\njobs=%s\n' "$baseline" "$openblas_target" "$jobs"
} >"$evidence/toolchain.txt"
# Ubuntu's MPICH wrappers export distro packaging flags to consumers.
# Keep the signed MPI runtime and use build-local wrappers for a consistent ISA and LTO policy.
mpi_wrappers="$inputs/mpi-wrappers"
mkdir "$mpi_wrappers"
for name in mpicc mpicxx mpifort; do
    original="/usr/bin/$name.mpich"
    adjusted="$mpi_wrappers/$name"
    "$original" -show >"$evidence/$name-original.txt"
    sed -e 's/ -flto=auto//g' -e 's/ -ffat-lto-objects//g' \
        -e 's/ -mbranch-protection=standard//g' "$original" >"$adjusted"
    chmod 755 "$adjusted"
    "$adjusted" -show >"$evidence/$name.txt"
    "$adjusted" -compile-info >>"$evidence/$name.txt"
    "$adjusted" -link-info >>"$evidence/$name.txt"
    if grep -Eq '(^|[[:space:]])(-flto(=[^[:space:]]*)?|-ffat-lto-objects|-mbranch-protection=[^[:space:]]*)([[:space:]]|$)' "$evidence/$name.txt"; then
        cat "$evidence/$name.txt" >&2
        printf 'Unexpected MPI wrapper options in %s\n' "$name" >&2
        exit 1
    fi
    sha256sum "$original" "$adjusted" >>"$evidence/mpi-wrapper-files.sha256"
done
export PATH="$mpi_wrappers:$PATH"

unpack() {
    local package="$1" archive="$2" components="${3:-1}"
    mkdir "$package"
    tar -xf "archives/$archive" --directory "$package" --strip-components="$components"
}

check_compile_flags() {
    python3 - "$1" "$isa" <<'PY'
import json
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
isa = sys.argv[2]
baseline = f"-march={isa}"
allowed = {baseline, "-mtune=generic", "-mcpu=generic"}
x86_extensions = {"-msse", "-msse2", "-msse3", "-mssse3", "-msse4.1", "-msse4.2", "-mpopcnt"}
commands = json.loads(path.read_text())
if not commands:
    raise SystemExit(f"No compile commands in {path}")
for command in commands:
    arguments = command.get("arguments") or shlex.split(command["command"])
    flags = {arg for arg in arguments if arg.startswith(("-march=", "-mtune=", "-mcpu="))}
    if baseline not in flags or flags - allowed:
        raise SystemExit(f"Unexpected compiler target flags in {command['file']}: {sorted(flags)}")
    if isa == "x86-64-v2":
        extensions = {
            arg for arg in arguments if arg.startswith(("-mavx", "-mfma", "-mf16c", "-mbmi", "-msse", "-mssse"))
        }
        if extensions - x86_extensions:
            raise SystemExit(f"Unexpected x86 extensions in {command['file']}: {sorted(extensions)}")
    lto_flags = [
        arg for arg in arguments
        if arg in {"-flto", "-ffat-lto-objects"} or arg.startswith("-flto=")
    ]
    if "-fno-lto" not in arguments or lto_flags:
        raise SystemExit(f"Unexpected link-time optimization flags in {command['file']}: {lto_flags}")
print(path.name, len(commands), isa, "baseline verified")
PY
}

cmake_build() {
    local name="$1" source="$2" destination="$3"
    shift 3
    local build="$inputs/build-$name"
    printf 'Configuring %s\n' "$name"
    cmake -S "$source" -B "$build" -G Ninja \
        "-DCMAKE_INSTALL_PREFIX=$destination" -DCMAKE_INSTALL_LIBDIR:PATH=lib \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
        "-DMPI_C_COMPILER=$mpi_wrappers/mpicc" "-DMPI_CXX_COMPILER=$mpi_wrappers/mpicxx" \
        "-DMPI_Fortran_COMPILER=$mpi_wrappers/mpifort" \
        "-DCMAKE_C_FLAGS=$baseline" "-DCMAKE_CXX_FLAGS=$baseline" \
        "-DCMAKE_Fortran_FLAGS=$baseline" "-DCMAKE_ASM_FLAGS=$baseline" \
        -DCMAKE_EXE_LINKER_FLAGS=-fno-lto -DCMAKE_SHARED_LINKER_FLAGS=-fno-lto \
        -DCMAKE_C_FLAGS_RELEASE=-O2 -DCMAKE_CXX_FLAGS_RELEASE=-O2 \
        -DCMAKE_Fortran_FLAGS_RELEASE=-O2 -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        "-DCMAKE_PREFIX_PATH=$deps" "-DCMAKE_INSTALL_RPATH=$deps/lib;$prefix/lib" \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DBUILD_TESTING=OFF "$@" \
        >"$evidence/$name-configure.log" 2>&1 || { cat "$evidence/$name-configure.log"; return 1; }
    cp "$build/CMakeCache.txt" "$evidence/$name-CMakeCache.txt"
    cp "$build/compile_commands.json" "$evidence/$name-compile_commands.json"
    check_compile_flags "$build/compile_commands.json"
    if [[ "$name" == cp2k ]]; then
        grep -Fx 'CMAKE_INSTALL_LIBDIR:PATH=lib' "$build/CMakeCache.txt"
        grep -Fx 'BUILD_SHARED_LIBS:BOOL=ON' "$build/CMakeCache.txt"
        cmake --build "$build" --parallel "$jobs" --target grid_miniapp \
            >"$evidence/cp2k-grid-link.log" 2>&1 \
            || { tail -n 80 "$evidence/cp2k-grid-link.log"; return 1; }
    fi
    printf 'Building %s (jobs=%s)\n' "$name" "$jobs"
    cmake --build "$build" --parallel "$jobs" >"$evidence/$name-build.log" 2>&1 \
        || { tail -n 130 "$evidence/$name-build.log"; return 1; }
    cmake --install "$build" >"$evidence/$name-install.log" 2>&1 \
        || { cat "$evidence/$name-install.log"; return 1; }
}

unpack openblas OpenBLAS-0.3.33.tar.gz
cmake_build openblas "$inputs/openblas" "$deps" \
    "-DTARGET=$openblas_target" "${openblas_isa_options[@]}" -DDYNAMIC_ARCH=OFF -DUSE_OPENMP=ON \
    -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF
openblas="$deps/lib/libopenblas.so"
test -e "$openblas"

unpack fftw fftw-3.3.11.tar.gz
printf 'Building fftw (jobs=%s)\n' "$jobs"
(
    cd fftw
    CFLAGS="$baseline -O2 -std=c17" MPICC=mpicc ./configure \
        --prefix="$deps" --libdir="$deps/lib" --enable-openmp --enable-mpi --enable-shared --disable-static
    make -j "$jobs"
    make install
) >"$evidence/fftw-build.log" 2>&1 || { tail -n 100 "$evidence/fftw-build.log"; exit 1; }
cp fftw/config.log "$evidence/fftw-config.log"

unpack scalapack scalapack-2.2.3.tar.gz
cmake_build scalapack "$inputs/scalapack" "$deps" \
    -DBUILD_SHARED_LIBS=ON -DSCALAPACK_BUILD_TESTS=OFF \
    "-DCMAKE_C_FLAGS=$baseline -fpermissive -std=c17" \
    "-DCMAKE_Fortran_FLAGS=$baseline -fallow-argument-mismatch" \
    "-DBLAS_LIBRARIES=$openblas" "-DLAPACK_LIBRARIES=$openblas"

unpack dbcsr dbcsr-2.10.0.tar.gz
cmake_build dbcsr "$inputs/dbcsr" "$deps" \
    -DBUILD_SHARED_LIBS=ON -DUSE_OPENMP=ON -DUSE_MPI=ON -DUSE_MPI_F08=ON \
    -DWITH_EXAMPLES=OFF -DUSE_LIBXS=OFF -DUSE_LIBXSMM=OFF \
    "-DBLAS_LIBRARIES=$openblas" "-DLAPACK_LIBRARIES=$openblas"

unpack libxc libxc-7.0.0.tar.bz2
cmake_build libxc "$inputs/libxc" "$deps" \
    -DBUILD_SHARED_LIBS=ON -DENABLE_FORTRAN=ON -DDISABLE_KXC=OFF \
    -DCMAKE_C_FLAGS_RELEASE=-O1 \
    "-DCMAKE_C_FLAGS=$baseline -fno-var-tracking"

unpack libint libint-v2.13.1-cp2k-lmax-5.tar.xz 2
cmake_build libint "$inputs/libint" "$deps" \
    -DBUILD_SHARED_LIBS=ON -DLIBINT2_ENABLE_FORTRAN=ON \
    -DCMAKE_DISABLE_FIND_PACKAGE_Boost=ON -DCMAKE_CXX_FLAGS_RELEASE=-O1

cmake_build cp2k "$inputs/cp2k" "$prefix" \
    -DCMAKE_BUILD_TYPE=Generic -DBUILD_SHARED_LIBS:BOOL=ON \
    "-DCP2K_DATA_DIR=$prefix/share/cp2k/data" \
    -DCP2K_USE_ACCEL=NONE -DCP2K_USE_EVERYTHING=OFF -DCP2K_USE_MPI=ON \
    -DCP2K_BLAS_VENDOR=OpenBLAS -DCP2K_SCALAPACK_VENDOR=GENERIC \
    -DCP2K_USE_DBCSR_CONFIG=ON -DCP2K_USE_FFTW3=ON -DCP2K_USE_LIBXC=ON -DCP2K_USE_LIBINT2=ON \
    -DCP2K_USE_LIBXS=OFF -DCP2K_USE_LIBXSMM=OFF

ln -s cp2k.psmp "$prefix/bin/cp2k"
grep -rFl "#define __COMPILE_REVISION \"$source_sha\"" "$inputs/build-cp2k" --include='*.h' \
    | sort >"$evidence/cp2k-build-info-locations.txt"
test -s "$evidence/cp2k-build-info-locations.txt"
while IFS= read -r path; do
    cat "$path"
done <"$evidence/cp2k-build-info-locations.txt" >"$evidence/cp2k-build-info.h"
[[ -z "$(git -C cp2k status --porcelain)" ]]

cp "$inputs/build-cp2k/install_manifest.txt" "$evidence/cp2k-install-manifest.txt"
libcp2k="$prefix/lib/libcp2k.so.2026.2"
grep -Fx "$libcp2k" "$evidence/cp2k-install-manifest.txt"
test -f "$libcp2k"
# GNU Generic includes -g. Drop debug sections in the transferred image and
# keep before/after file hashes for the exact executable and shared library.
engine_files=("$prefix/bin/cp2k.psmp" "$libcp2k")
sha256sum "${engine_files[@]}" >"$evidence/cp2k-before-debug-strip.sha256"
strip --strip-debug "${engine_files[@]}"
sha256sum "${engine_files[@]}" >"$evidence/cp2k-after-debug-strip.sha256"

find "$prefix/lib" "$deps/lib" -type f -name '*.a' -delete
rm -rf "$prefix/include" "$deps/include" "$deps/share" "$deps/bin" \
    "$prefix/lib/cmake" "$deps/lib/cmake" "$prefix/lib/pkgconfig" "$deps/lib/pkgconfig"
(
    cd "$prefix"
    find bin lib deps/lib share/cp2k/data -type f -print0 | sort -z | xargs -0 -r sha256sum
) >"$evidence/installed-files.sha256"
readelf -h "$prefix/bin/cp2k.psmp" >"$evidence/cp2k-elf-header.txt"
grep -F "$elf_machine" "$evidence/cp2k-elf-header.txt"
