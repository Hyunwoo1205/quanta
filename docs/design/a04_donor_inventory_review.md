# A04 의존성 후보의 네이티브 실행 근거

Quanta 소스 `b7bfa8f90a7d5d05e74f7d8fefefe3be72cfc379`의 두 네이티브 A03 아티팩트에서 `report.json`과 `inventory.txt`를 읽었다. 각 inventory의 SHA-256이 보고서와 일치한다. A02의 원본 매니페스트·config SHA와 크기, 매니페스트의 config descriptor도 대조했다. 두 실행은 같은 A02 이미지에서 He-D, H2-D, H2-T, 초기화 중 취소와 취소 후 H2를 통과했다.

| 항목 | amd64 | ARM64 |
| --- | --- | --- |
| 네이티브 ZIP 아티팩트 ID | `13559349965` | `13560242687` |
| ZIP SHA-256 | `0bb9813aca50222232fe20a7c13313900b2b96141ebde42dcb673d3983ccf7dc` | `2b86ef511a458356de8a724d2d7f9ea28745732727f56214d00f48371b81ac6a` |
| inventory SHA-256 | `ed0df608b29b15901140ab187feb61f4a9d410ba711fc45c341e0240c770b4d7` | `dcc0e5aaf790812964b886020ba3e78c7755f98d552f73f4881880eae45bbf9c` |
| A02 플랫폼 매니페스트 SHA-256 | `28e35f63a5253b95cc0f50e786370669185ad9f58eacacf33170cb1257216f36` | `ab4826caab2833c856df3455781fe57771ec04da7988588e0b0b6f0e687ecade` |
| A02 config SHA-256 | `f3d9dc68a19277908fa0656c79c7c3f80179b1e909116ae19266d4cd8d5adb0d` | `882a6f30ac4d9e705b5b3a474f9085c19d7f820b1531a4526b320e3f1e164c95` |
| 실행 파일 SHA-256 | `5adf67d256e25776162f1d543ff67979a0c147594f944897e3bba977c23b2bdc` | `aa8cb64079e94aac831588d359c7e7c008a693701de6e3bcdd58491f850ceb7c` |
| 컨테이너 동적 로더 경로 | `/lib64/ld-linux-x86-64.so.2` | `/lib/ld-linux-aarch64.so.1` |
| ldd에 경로가 표시된 라이브러리 / 그중 Spack 트리 | 136 / 125 | 144 / 133 |

두 이미지에서 `command -v cp2k`는 `/opt/cp2k/install/bin/cp2k`, `readlink -f`는 `/opt/cp2k/install/bin/cp2k.psmp`를 반환했다. SHA-256은 링크를 따라간 실행 파일의 값이다. 실제 의존성 목록에는 별도 `/opt/cp2k/install/lib/libcp2k.so.2026.2`가 있고 이 파일의 SHA는 이번 inventory에 없다. 새 빌드 영수증은 실행 파일과 CP2K 자체 공유 라이브러리·런처의 바이트를 각각 고정해야 한다.

두 엔진은 CP2K `2026.2`, 리비전 `unknown`, 컴파일러 `GCC 15.2.0`을 보고했다. amd64는 `-march=sandybridge -mtune=sandybridge`, ARM64는 `-march=armv8-a`에 `lse`, `dotprod`, `rcpc2`, `pauth` 등을 더한 플래그를 보고했다. ARM64에만 GauXC, DeepMD, LibTorch 계열 기능 플래그가 추가로 나타났다. 같은 버전과 ARM64 OCI variant `v8`만으로 두 플랫폼의 기능 또는 모든 ARM 호스트의 CPU 호환성을 판단할 수 없다.

## 의존성으로 검토할 수 있는 범위

- 두 config의 Ubuntu 라벨은 `26.04`이고, 컨테이너 dpkg 기록은 `base-files=14ubuntu6.2`, `libc6=libc6-dev=2.43-2ubuntu2.4`, `gcc-15=g++-15=gfortran-15=15.2.0-16ubuntu1`, `binutils=2.46-3ubuntu2`다. `libgcc-s1`, `libgfortran5`, `libgomp1`, `libstdc++6`의 패키지 버전은 `16-20260322-1ubuntu1`이다. 보고서 호스트의 glibc 2.39는 컨테이너 ABI 근거와 구분한다. 패키지 목록에 CMake·Ninja·Git·Make·pkgconf 항목이 없으며 다른 경로의 도구 존재 여부는 미확인이다.
- 두 아키텍처의 `/opt/cp2k/spack/spack/opt/spack/view/lib`에 OpenBLAS `libopenblas.so.0`, DBCSR `libdbcsr.so.2.10`, ScaLAPACK `libscalapack.so.2.2`, MPI `libmpi.so.12`와 `libmpifort.so.12`, FFTW `libfftw3.so.3`와 `libfftw3_omp.so.3`, LibXC `libxc.so.15`와 `libxcf03.so.15`가 해석됐다. 컴파일 옵션에 MPICH `5.0.1`과 FFTW `3.3.11` 경로가 있고, `libfftw3_mpi.so.3`는 두 환경에서 해당 FFTW 패키지 경로로 해석됐다. 라이브러리 이름과 컴파일 옵션은 버전·ABI 조사에 쓸 수 있으며 실제 빌드 입력 파일 해시는 아직 없다.
- 두 바이너리 모두 `libint` 플래그를 보고하지만 ldd에 Libint 이름으로 해석된 공유 객체는 없다. Libint2의 설치 헤더와 필요한 정적 아카이브 또는 링크 대상, Fortran 인터페이스를 별도로 확인해야 한다. DBCSR의 SONAME `2.10`도 CMake가 요구하는 `DBCSRConfig.cmake` 버전과 MPI 설정을 대체하지 않는다.
- A02 config history의 비어 있지 않은 레이어를 매니페스트와 순서대로 대조하면 두 이미지 모두 인덱스 3에서 Spack 트리를 복사하고 인덱스 4에서 CP2K 설치 디렉터리를 별도로 복사한다. 이 분리와 실제 ldd 해석은 의존성 제공 이미지로 점검할 근거다. 최종 파일 시스템의 개발 파일과 후속 레이어의 변경은 목록을 읽어 확인해야 한다. [A02 고정 이미지 메타데이터](https://github.com/Hyunwoo1205/quanta/tree/12bd610a53fd4fae10162b93e7fe88ad6f65c626/docs/design/atomistic-a02-v0.1/images)
- history의 GCC/GFortran 15 패키지 설치, Spack·CP2K 분리 복사, `ldconfig`, `run_tests --keepalive || echo ...`는 고정 GCC 15 공식 레시피의 runtime 단계와 일치한다. 이것은 설치 구조를 설명한다. 원본 빌드의 소스 연결과 regression 결과는 별도 증거가 필요하다. [공식 GCC 15 Dockerfile](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tools/docker/Dockerfile.test_spack_psmp-gcc15#L65-L99)

| Spack 복사 레이어 | 압축 크기 | 매니페스트 blob SHA-256 | config의 비압축 DiffID |
| --- | ---: | --- | --- |
| amd64 | 387,573,246 B | `e8db62afb2232adb9b4c931785cecce0a759092469f272982bb61422916bb008` | `d7f466422c7f8a7a1f4addae108329ba87ed2cfaf707806829955651b3703718` |
| ARM64 | 580,393,363 B | `9f56d1d9a610033d1899eda274f7f6b33ab4d369e59aa0900eb797690aacae33` | `2cafe43488894390ad5c4fd72719832382c31a5757d300e4e809eb4e79410053` |

## 첫 구성 전에 확인할 항목

기존 네이티브 CI에서 amd64 잠금 이미지의 최종 파일 시스템을 대상으로 작은 경로 검사부터 한다. MPICH의 `mpicc`, `mpifort`, `mpiexec`, 헤더·Fortran 모듈과 라이브러리의 일치, DBCSR CMake config·모듈·MPI 옵션, FFTW/OpenBLAS/ScaLAPACK/LibXC/Libint2의 개발 파일·링크 이름·정확한 package prefix를 확인한다. 파일별 SHA·symlink 대상과 ELF 아키텍처·필요 런타임을 기록한다. Spack의 `view`와 패키지 트리 밖에 의존하는 경로는 분리해 적고, 라이브러리 파일만 모아서 원래 레이아웃을 잃지 않게 한다. [CP2K 2026.2 CMake 요구 사항](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/CMakeLists.txt)

개발 파일이 갖춰진 경우에만 별도 잠근 Ubuntu 26.04 빌더에서 GCC·GFortran·glibc·MPI 호환성을 확인하고 작은 C/Fortran 링크 검사와 CP2K CMake configure로 진행한다. CMake가 선택한 경로는 고정한 의존성 트리로 제한하고, 과거 CP2K `install` 디렉터리를 빌드와 실행에 포함하지 않는다. 출력에는 CMake cache와 실제 해석된 라이브러리 경로를 보관한다. 필수 입력이 빠졌으면 누락 목록을 확정한 뒤 고정 의존성 빌드 경로를 평가한다. [CP2K 공식 Dockerfile의 설치 단계](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tools/docker/Dockerfile.test_spack_psmp-4x2#L65-L91)

이번 근거로 amd64 잠금 이미지의 Spack 트리는 첫 의존성 검사 후보다. ARM64의 같은 엔진 SHA는 최신 OCI 실행의 He-D에서 `SIGILL`로 종료됐다. 실패 모듈과 명령은 미확인이며, ARM64 Spack 재사용에는 실제 OCI HWCAP과 해당 정적·동적 파일의 최소 ISA 및 링크 경로를 따로 확인해야 한다. 개발 파일의 완결성과 ABI, 정확한 Ubuntu base digest, 패키지별 바이트, 런타임 라이브러리와 과거 CP2K 전체 소스의 연결은 미확인이다. 새 빌드와 A04 검증 결과는 아직 없다. 물리 검증 상태는 `unvalidated`다. [OCI 실행](https://github.com/Hyunwoo1205/quanta/actions/runs/42339547954) · [새 ARM 후보 기준](a04_traceable_build_next.md#oci-arm-실행-신호와-새-후보-기준)
