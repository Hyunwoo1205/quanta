# A04 후보 소스 추적성 검증

다음 작업은 기존 네이티브 CI에서 새 CP2K 후보의 빌드 입력을 잠그고, 실제 바이너리까지 이어지는 증거를 만드는 것이다. 먼저 amd64에서 의존성 준비와 CMake 구성을 확인하고, 같은 레시피를 amd64와 ARM64에서 각각 실행한다. A04 프로필과 자유 JSON 계약 동결은 빌드·실행 증거 검토 뒤에 판단한다.

## 소스와 빌드 입력

1. CP2K v2026.2의 전체 Git 커밋 `67b5da876dd6a76b8b021d5a04d1c81ba79a4c50`과 트리 `2e4405ec65578a3d8205bc23adf69249798d98d3`을 사용한다. 새 checkout에서 `git rev-parse HEAD HEAD^{tree}`와 clean 상태를 확인하고 소스 입력의 전체 파일 SHA-256 목록과 크기를 남긴다. 추적 파일은 수정 없이 별도 build 디렉터리에서 컴파일한다. 공식 릴리스 tarball의 `REVISION=git:c92cc08`은 그 별도 아카이브의 기록이다. [고정 소스](https://github.com/cp2k/cp2k/tree/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50)
2. 빌더에서 소스의 `.git`을 읽을 수 있게 하고 `git config --local core.abbrev 40`을 적용한다. 컴파일 전 동일 사용자·경로에서 `git log -1 --format=%h`가 고정 전체 SHA를 출력하는지 확인한다. 공식 CMake가 생성한 `__COMPILE_REVISION`과 설치된 바이너리의 `--version`이 이 SHA를 보고해야 한다. 생성된 헤더 원문을 보관한다. [공식 build-info 생성기](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/cmake/GenerateCp2kBuildInfo.cmake)
3. 공식 레시피와 같은 Ubuntu 26.04 계열을 출발점으로 삼되, 플랫폼별 build·runtime base manifest/config SHA를 선정해 잠근다. 빌더 이미지와 레시피, 설치 도구, GCC/G++/GFortran·링커·CMake 3.24 이상·Ninja·Python의 버전과 실제 패키지 바이트 SHA를 기록한다. apt 입력은 고정 스냅샷과 필요한 패키지 SHA로 잠그고, 컴파일 전에 모든 입력을 검증한다. [공식 Dockerfile](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tools/docker/Dockerfile.test_spack_psmp-4x2)
4. 첫 의존성 후보는 A02가 이미 고정한 플랫폼별 공식 이미지의 Spack 패키지 트리다. 이 트리의 라이브러리, 헤더, Fortran 모듈과 CMake package config를 확인하고 실제 사용하는 트리의 파일 해시와 ABI를 잠근다. 새 이미지에는 필요한 의존성만 복사하고 CP2K 실행 파일, 자체 공유 라이브러리와 설치 데이터는 새 checkout의 설치 결과만 사용한다. 필요한 개발 파일이나 호환 컴파일러가 없으면 구성 시도에서 중단하고 누락 목록을 남긴다. 후속 의존성 빌드의 입력은 고정 Spack 및 packages 커밋, 확정된 `spack.lock`, 모든 source 또는 buildcache 바이트 SHA, compiler externals를 포함한다. [공식 의존성 복사 단계](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tools/docker/Dockerfile.test_spack_psmp-4x2#L74-L91) · [Spack 개발 빌드](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/docs/getting-started/build-with-spack.md)
5. 첫 구성은 CPU `psmp`, MPICH, OpenBLAS BLAS/LAPACK, 동일 MPI용 ScaLAPACK·DBCSR, FFTW3, LibXC와 Libint2를 명시한다. 시작 플래그는 `CP2K_USE_ACCEL=NONE`, `CP2K_USE_EVERYTHING=OFF`, `CP2K_USE_MPI=ON`, `CP2K_BLAS_VENDOR=OpenBLAS`, `CP2K_SCALAPACK_VENDOR=GENERIC`, `CP2K_USE_DBCSR_CONFIG=ON`, `CP2K_USE_FFTW3=ON`, `CP2K_USE_LIBXC=ON`, `CP2K_USE_LIBINT2=ON`이다. 이 경로의 DBCSR 요구 버전은 2.9 이상이다. 해석된 전이 의존성과 실제 컴파일 옵션을 확인한 뒤 플랫폼별 잠금에 정확한 버전·해시를 넣는다. [CP2K CMake 옵션](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/CMakeLists.txt)

## 실행 순서

1. 기존 CI와 같은 `ubuntu-24.04`·`ubuntu-24.04-arm` 네이티브 환경에서 호스트 아키텍처와 여유 RAM·디스크를 기록한다. 첫 amd64 구성으로 컴파일러, 패키지 경로와 ABI를 확인한다. 실제 compile 전 CPU 병렬수, 메모리·디스크·벽시계 상한을 job에 기록하고, 초과 또는 의존성 불일치 시 종료한다. 운영 OCI는 실측을 통과한 후보를 위한 별도 격리 검증 경로다. [기존 네이티브 CI](https://github.com/Hyunwoo1205/quanta/blob/b621e836af61d7b63933ab7802722fa1ee79f531/.github/workflows/atomistic-a03.yml)
2. 양쪽 네이티브 job에서 같은 잠금 규칙으로 입력을 준비하고 네트워크를 끈 빌드 단계에서 컴파일한다. 실제 CMake cache·compile commands·build-info·빌드 로그와 시간/최대 RSS/디스크 사용량을 보관한다. 새 바이너리·CP2K 공유 라이브러리·런처와 실행 시 해석된 라이브러리 파일의 SHA를 기록한다. 최종 native image manifest/config와 `docker create` 후 실제 실행한 바이너리 SHA를 같은 빌드 영수증에 연결한다.
3. 같은 바이너리의 고정 Quickstep GAPW 회귀 묶음 `QS/regtest-gapw-2`를 1 rank·1 thread로 실행한다. 고정된 MPI 런처와 CP2K 자료 디렉터리를 명시한다. 원본 테스트 다섯 건, 기존 허용오차, `Status: OK`와 종료 코드 0을 모두 확인한다. [고정 회귀 실행기](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tests/do_regtest.py) · [기준과 허용오차](https://github.com/cp2k/cp2k/blob/67b5da876dd6a76b8b021d5a04d1c81ba79a4c50/tests/QS/regtest-gapw-2/TEST_FILES.toml)
4. 새 후보의 별도 잠금으로 A03 실행기의 격리·아티팩트·자원 검사와 He-D/H2-D/H2-T, H2 초기화 중 취소, 취소 후 새 H2 계산을 양쪽에서 재실측한다. PBE/GAPW/POTENTIAL ALL과 고정 기저·자료, 힘, 전체 전자수밀도 CUBE 원본을 확인한다. A02 잠금과 과거 실행 근거는 이력으로 보존하고, 출력 차이는 기존 조건과 실제 의존성 차이로 설명한다. [A03 후보 입력 및 실측 설계](https://github.com/Hyunwoo1205/quanta/blob/12bd610a53fd4fae10162b93e7fe88ad6f65c626/scripts/atomistic_a03_inputs.py)

## 합격과 미확인 범위

- **소스 추적성**은 플랫폼마다 전체 소스 → 레시피·도구·의존성 → 성공한 native job → 바이너리 SHA → 이미지 manifest/config → 실제 실행 SHA가 이어지고, build-info와 엔진 리비전이 고정 Git SHA와 일치할 때 검토한다. 작은 영수증과 잠금은 GitHub, 큰 로그·원시 CUBE는 실행 아티팩트와 프로젝트 Drive에 보관한다.
- **실행 검증**은 고정 upstream 회귀와 새 후보 A03 결과가 모두 통과해야 한다. A04 동결 전 연결된 소스로 CODATA2006 엔진→SI, CODATA2022 기준, bare 핵질량과 전체 전자수밀도 의미를 다시 대조한다. 밀도 적분, 음수 및 고정폭 E13.5E3 정밀도는 원본대로 기록한다. 독립 수치·물리 검증은 이후 검증 항목에 남는다.
- 현재 공식 A02 이미지의 실행 근거에는 CP2K 2026.2와 `revision unknown`이 기록돼 있다. 그 바이너리와 전체 소스의 연결, 새 베이스 다이제스트와 의존성 closure, 빌드 용량·시간, 새 후보 실행은 미확인이다. 공식 CMake가 build timestamp를 넣으므로 비트 단위 재현성은 별도 두 번의 통제된 빌드와 비교가 필요하다. 현재 물리 검증 상태는 `unvalidated`다.
