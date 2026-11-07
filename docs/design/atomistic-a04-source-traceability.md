# A04 후보 소스 추적성 검증

이 문서는 CP2K 후보의 빌드 입력과 실제 바이너리의 연결을 검토합니다. ARMv8-A 후보의 실측 결과와 후속 검증 범위를 아래에 기록합니다. A04 프로필과 자유 JSON 계약의 동결은 소스·실행·수치 검증의 근거를 검토한 뒤 판단합니다.

두 A02 고정 이미지의 최신 네이티브 inventory에서 Spack 의존성 경로와 별도 `libcp2k.so.2026.2` 로딩을 확인했다. 아래의 의존성 제공 이미지 검토는 이 경로와 원본 레이어 기록에 근거한다. 헤더·Fortran 모듈·CMake 설정과 링크에 필요한 파일의 존재 및 ABI는 첫 검사에서 확인할 항목이다. [네이티브 의존성 근거](a04_donor_inventory_review.md)

## OCI ARM 실행 신호와 새 후보 기준

OCI 실행 42339547954는 고정 ARM 이미지 식별을 통과했으며, He-D CP2K 자식이 시작 후 6.433초에 `SIGILL`로 종료됐다. 원본 `wait4` 결과는 `-4`, 셸과 컨테이너 결과는 252다. 수렴·에너지·힘·CUBE는 얻지 못했다. 컨테이너 관측 메모리 정점은 1,717,563,392 B, 운영 가드의 호스트 가용 메모리 최솟값은 10,058,166,272 B다. OCI와 통과한 네이티브 ARM 실행의 엔진 SHA는 `aa8cb64079e94aac831588d359c7e7c008a693701de6e3bcdd58491f850ceb7c`로 같다. [OCI 실행](https://github.com/Hyunwoo1205/quanta/actions/runs/42339547954)

그 바이너리의 네이티브 inventory가 기록한 GCC 15.2 ARM 타깃은 다음과 같다.

```text
-march=armv8-a+flagm2+lse+dotprod+rdma+crc+aes+sha3+fp16fml+jscvt+fcma+rcpc2+frintts+sb+pauth
```

Oracle의 A1은 Ampere Altra Q80-30 계열이다. Ampere는 Altra의 명령어 호환성을 Armv8.2+로, 컴파일 타깃을 `neoverse-n1`로 설명한다. GCC 15.2의 N1 모델은 Armv8.2-A에 FP16·RCpc·DotProd·profiling을 추가한다. 기존 옵션의 `rcpc2`·`fp16fml`은 GCC Armv8.4-A 기본군이고 `flagm2`·`frintts`·`sb`는 Armv8.5-A 기본군이다. 일부 옵션은 어셈블러에서 허용하는 확장만 제어한다. 실제 OCI HWCAP 대조는 아래와 같으며, 고장 명령·PC·모듈은 미확인이다. [Oracle A1 사양](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm) · [Ampere GCC 가이드](https://amperecomputing.com/tutorials/gcc-guide-ampere-processors) · [GCC 15.2 N1 모델](https://github.com/gcc-mirror/gcc/blob/releases/gcc-15.2.0/gcc/config/aarch64/aarch64-cores.def#L119) · [GCC 15.2 확장 표](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/AArch64-Options.html)

[OCI 읽기 전용 진단 42340357555](../verification/atomistic-a03/oci/42340357555.json)는 실제 호스트의 `AT_HWCAP`과 `AT_HWCAP2`를 읽었다. 원본 옵션의 `flagm2`·`frintts`·`rcpc2`·`fp16fml`·`sb`·`pauth` 및 일부 다른 확장은 각각의 HWCAP에서 확인되지 않았다. 같은 실행의 He 로그는 SHA·27,762 B로 검증했고 SIGILL·Quickstep 초기화와 백트레이스의 `qs_scf` 표지를 확인했다. 다른 이미지를 받거나 계산을 실행하지 않았고 운영 컨테이너를 보존했다. 컴파일 타깃과 호스트 기능 차이는 ISA 호환성 문제를 강하게 뒷받침한다. 이 진단은 fault PC/opcode 또는 실제 고장 ELF 모듈을 특정하지 않는다. [Linux ARM64 HWCAP](https://docs.kernel.org/arch/arm64/elf_hwcaps.html)

후속 [OCI 동기 SIGILL 추적](../verification/atomistic-a03/oci/42360862172.json)은 PC와 fault 주소가 일치하고 `libcp2k.so.2026.2` ELF의 오프셋 `0x2754d80`에서 읽은 네 바이트가 실제 ELF 파일과 일치함을 확인했다. `78c7de6e`는 LLVM19에서 `FCMLA v24.2d, v27.2d, v30.2d, #0`이며 Armv8.3 FCMA가 필요하다. 실제 호스트 HWCAP에 FCMA가 없다. CP2K 소스 GNU Release의 native 타깃 추가를 피하기 위해 후보는 공식 Generic 설정과 LP64 ARMv8-A를 사용한다. [LLVM19 정의](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.7/llvm/lib/Target/AArch64/AArch64InstrInfo.td#L1565-L1571)

새 ARM64 후보의 보수적 기준은 LP64 `-march=armv8-a -mtune=generic`이다. CP2K, 자체 공유 라이브러리와 모든 정적·동적 의존성에 동일한 최소 ISA를 적용하거나 그 기준과 호환되는 배포 바이너리를 근거와 함께 고정한다. 실제 C/C++/Fortran/어셈블리 및 링크 명령, OpenBLAS 커널 선택과 의존성 CPU 옵션을 확인한다. 첫 OpenBLAS 빌드는 고정 버전에서 범용 `TARGET=ARMV8`과 단일 타깃을 검토한다. 호환성 근거가 확보될 때까지 기존 ARM Spack 트리의 재사용은 보류한다. 새 후보의 실제 OCI A1 검증은 동일 He-D부터 시작하고, 성공 후 전체 격리 A03 사례로 진행한다. [GCC 15.2 AArch64 기준](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/AArch64-Options.html) · [OpenBLAS 빌드 설정](https://www.openmathlib.org/OpenBLAS/docs/build_system/)

## 소스와 빌드 입력

1. CP2K v2026.2의 전체 Git 커밋 `67b5da876dd6a76b8b021d5a04d1c81ba79a4c50`과 트리 `2e4405ec65578a3d8205bc23adf69249798d98d3`을 사용한다. 새 checkout에서 `git rev-parse HEAD HEAD^{tree}`와 clean 상태를 확인하고 소스 입력의 전체 파일 SHA-256 목록과 크기를 남긴다. 추적 파일은 수정 없이 별도 build 디렉터리에서 컴파일한다. 공식 릴리스 tarball의 `REVISION=git:c92cc08`은 그 별도 아카이브의 기록이다. [고정 소스](https://github.com/cp2k/cp2k/tree/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50)
2. 빌더에서 소스의 `.git`을 읽을 수 있게 하고 `git config --local core.abbrev 40`을 적용한다. 컴파일 전 동일 사용자·경로에서 `git log -1 --format=%h`가 고정 전체 SHA를 출력하는지 확인한다. 공식 CMake가 생성한 `__COMPILE_REVISION`과 설치된 바이너리의 `--version`이 이 SHA를 보고해야 한다. 생성된 헤더 원문을 보관한다. [공식 build-info 생성기](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/cmake/GenerateCp2kBuildInfo.cmake)
3. 두 이미지의 Ubuntu 26.04 라벨, glibc 2.43 패키지, GCC/GFortran 15 패키지와 config history가 공식 GCC 15 레시피의 runtime 단계에 부합한다. 새 build·runtime base는 Ubuntu 26.04 계열에서 플랫폼별 manifest/config SHA를 별도 선정해 잠근다. 빌더 이미지와 레시피, GCC/G++/GFortran·링커·CMake 3.24 이상·Ninja·Python의 버전과 실제 패키지 바이트 SHA를 기록한다. apt 입력은 고정 스냅샷과 패키지 SHA로 잠그고 컴파일 전에 검증한다. 확인된 설치 구조만으로 과거 바이너리의 소스나 회귀 결과를 확정할 수 없다. [공식 GCC 15 Dockerfile](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tools/docker/Dockerfile.test_spack_psmp-gcc15)
4. 첫 amd64 의존성 후보는 A02가 고정한 공식 이미지의 Spack 패키지 트리다. ARM64에는 위의 별도 ISA 조건을 적용한다. 매니페스트에서 CP2K 설치와 별도인 트리의 최종 경로·symlink와 CMake package config·헤더·Fortran 모듈을 확인한다. 예를 들어 Libint2의 `Libint2::int2`와 `libint_f.mod`, DBCSR package config의 버전과 MPI 설정을 확인해야 한다. 검증한 의존성 파일의 SHA와 ABI를 잠근 뒤 새 이미지에 필요한 의존성만 복사한다. CP2K 실행 파일, 자체 공유 라이브러리와 설치 데이터는 새 checkout의 설치 결과를 사용한다. 개발 파일이나 호환 컴파일러가 없으면 누락 목록을 남기고 구성을 중단한다. 후속 의존성 빌드의 입력은 고정 Spack 및 packages 커밋, `spack.lock`, 모든 source 또는 buildcache 바이트 SHA와 compiler externals를 포함한다. [공식 의존성 복사 단계](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tools/docker/Dockerfile.test_spack_psmp-gcc15#L74-L91) · [Spack 개발 빌드](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/docs/getting-started/build-with-spack.md)
5. 첫 구성은 CPU `psmp`, MPICH, OpenBLAS BLAS/LAPACK, 동일 MPI용 ScaLAPACK·DBCSR, FFTW3, LibXC와 Libint2를 명시한다. 시작 플래그는 `CP2K_USE_ACCEL=NONE`, `CP2K_USE_EVERYTHING=OFF`, `CP2K_USE_MPI=ON`, `CP2K_BLAS_VENDOR=OpenBLAS`, `CP2K_SCALAPACK_VENDOR=GENERIC`, `CP2K_USE_DBCSR_CONFIG=ON`, `CP2K_USE_FFTW3=ON`, `CP2K_USE_LIBXC=ON`, `CP2K_USE_LIBINT2=ON`이다. 이 경로의 DBCSR 요구 버전은 2.9 이상이다. 해석된 전이 의존성과 실제 컴파일 옵션을 확인한 뒤 플랫폼별 잠금에 정확한 버전·해시를 넣는다. [CP2K CMake 옵션](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/CMakeLists.txt)

## 2026-11-07 실제 ARM 후보와 확인 범위

- 기존 OCI 이미지의 `SIGILL`은 CP2K 공유 라이브러리의 `FCMLA`에서 확인했습니다. 새 후보는 Ubuntu 26.04 ARM64 고정 베이스·스냅샷, CP2K v2026.2 Git 전체 SHA, 6개 해시 고정 소스 의존성, GNU `Generic` 및 `-march=armv8-a -mtune=generic -fno-lto`를 사용했습니다. MPICH·운영체제 런타임은 서명된 배포 패키지이며 빌드 전용 래퍼에서 배포 패키징 LTO/ISA 플래그를 제거했습니다. [조사와 빌드 근거](../verification/atomistic-a03/armv8a-retry-20261107.json)
- 재빌드 ARM 후보는 `67b5da876dd6a76b8b021d5a04d1c81ba79a4c50`을 보고합니다. ARM He-D 단독, ARM A03 전체와 OCI 격리 실측에서 같은 바이너리 SHA를 확인했습니다. x86 A03는 기존 이미지 대조군입니다. OCI의 동일 아카이브로 계산·취소·후속 계산 다섯 사례, 이미지 증명, 웹 및 운영 보존 게이트를 통과했습니다. [OCI 영수증](../verification/atomistic-a03/oci/42372870103.json)
- 이 후보의 실제 라이브러리·도구·출처 증거 및 고정 GAPW 회귀 결과는 아래에 있습니다. 새 ARM의 리비전 확인은 기존 공식 이미지의 소스 대응을 입증하지 않습니다. 별도 x86 추적 가능 후보와 A04 수치·물리 허용오차 검토는 후속 범위이며, 물리 검증 상태는 `unvalidated`입니다.

## 고정 GAPW 회귀 실측 결과

ARMv8-A 후보의 소스·빌드·라이브러리 SHA와 A03 이미지/바이너리 증거를 대조했습니다. 동일 이미지의 네이티브 ARM CI에서 고정 `QS/regtest-gapw-2`가 종료 코드 0과 `Status: OK`로 **5/5 통과**했습니다. H₂ 재시작 쌍은 원래 순서를 유지했습니다. CP2K의 `E_total` 비교는 기준 에너지로 나눈 상대 오차를 사용합니다. 영수증에 원시 에너지·상대 오차·원래 허용오차를 구분해 기록했습니다. [출처 대조](../verification/atomistic-a04/armv8a-source-dependency-review.json) · [실행 영수증](../verification/atomistic-a04/gapw-42376916235.json) · [원본 오차 판정](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tests/matcher_classes.py#L60-L73)

고정 소스에서 CODATA2006 엔진 단위, GAPW 전체 전자수밀도 및 CUBE E13.5E3 출력 형식을 확인했습니다. CODATA2022의 bare H-1·He-4 핵질량은 별도 출처와 대조했습니다. 다음은 이 값의 적용과 반올림 규칙, 밀도 수렴·독립 오차 기준, 초기 자유 JSON 계약을 검토하는 일입니다. 물리 검증은 `unvalidated`입니다. [단위·밀도 근거](../verification/atomistic-a04/candidate-units-and-cube-source-crosscheck.json)

## 실행 순서

1. 기존 CI와 같은 `ubuntu-24.04`·`ubuntu-24.04-arm` 네이티브 환경에서 호스트 아키텍처와 여유 RAM·디스크를 기록한다. 첫 amd64 구성으로 컴파일러, 패키지 경로와 ABI를 확인한다. 실제 compile 전 CPU 병렬수, 메모리·디스크·벽시계 상한을 job에 기록하고, 초과 또는 의존성 불일치 시 종료한다. 운영 OCI는 실측을 통과한 후보를 위한 별도 격리 검증 경로다. [기존 네이티브 CI](https://github.com/Hyunwoo1205/quanta/blob/b621e836af61d7b63933ab7802722fa1ee79f531/.github/workflows/atomistic-a03.yml)
2. 양쪽 네이티브 job에서 같은 잠금 규칙으로 입력을 준비하고 네트워크를 끈 빌드 단계에서 컴파일한다. 실제 CMake cache·compile commands·build-info·빌드 로그와 시간/최대 RSS/디스크 사용량을 보관한다. 새 바이너리·CP2K 공유 라이브러리·런처와 실행 시 해석된 라이브러리 파일의 SHA를 기록한다. 최종 native image manifest/config와 `docker create` 후 실제 실행한 바이너리 SHA를 같은 빌드 영수증에 연결한다.
3. 같은 바이너리의 고정 Quickstep GAPW 회귀 묶음 `QS/regtest-gapw-2`를 1 rank·1 thread로 실행한다. 고정된 MPI 런처와 CP2K 자료 디렉터리를 명시한다. 원본 테스트 다섯 건, 기존 허용오차, `Status: OK`와 종료 코드 0을 모두 확인한다. [고정 회귀 실행기](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tests/do_regtest.py) · [기준과 허용오차](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tests/QS/regtest-gapw-2/TEST_FILES.toml)
4. 새 후보의 별도 잠금으로 A03 실행기의 격리·아티팩트·자원 검사와 He-D/H2-D/H2-T, H2 초기화 중 취소, 취소 후 새 H2 계산을 양쪽에서 재실측한다. PBE/GAPW/POTENTIAL ALL과 고정 기저·자료, 힘, 전체 전자수밀도 CUBE 원본을 확인한다. A02 잠금과 과거 실행 근거는 이력으로 보존하고, 출력 차이는 기존 조건과 실제 의존성 차이로 설명한다. [A03 후보 입력 및 실측 설계](https://github.com/Hyunwoo1205/quanta/blob/12bd610a53fd4fae10162b93e7fe88ad6f65c626/scripts/atomistic_a03_inputs.py)

## 합격과 미확인 범위

- **소스 추적성**은 플랫폼마다 전체 소스 → 레시피·도구·의존성 → 성공한 native job → 바이너리 SHA → 이미지 manifest/config → 실제 실행 SHA가 이어지고, build-info와 엔진 리비전이 고정 Git SHA와 일치할 때 검토한다. 작은 영수증과 잠금은 GitHub, 큰 로그·원시 CUBE는 실행 아티팩트와 프로젝트 Drive에 보관한다.
- **실행 검증**은 고정 upstream 회귀와 새 후보 A03 결과가 모두 통과해야 한다. A04 동결 전 연결된 소스로 CODATA2006 엔진→SI, CODATA2022 기준, bare 핵질량과 전체 전자수밀도 의미를 다시 대조한다. 밀도 적분, 음수 및 고정폭 E13.5E3 정밀도는 원본대로 기록한다. 독립 수치·물리 검증은 이후 검증 항목에 남는다.
- 기존 공식 A02 이미지의 실행 근거는 CP2K 2026.2와 `revision unknown`을 보고하며, 그 바이너리와 전체 소스의 대응은 확인되지 않았습니다. 새 ARM 후보의 빌드·실행 근거는 위 실측 절에 있습니다. 공식 CMake는 빌드 시각을 포함합니다. 이미지 단위 재현성을 판단하려면 별도의 통제된 비교가 필요합니다. 물리 검증 상태는 `unvalidated`입니다.
