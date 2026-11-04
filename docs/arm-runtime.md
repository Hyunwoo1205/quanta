# OCI A1용 ARM 실행 프로필

갱신 2026-11-05 · 현재 패키지 0.9.0 · 입력 계약 0.2.0

화면·API·계산·SQLite를 OCI 한 대에서 운영하기 위해 Linux aarch64 프로필을 추가합니다. 기존 Linux x86_64 프로필과 과거 검증 기록은 보존합니다. 외부 인증·ASGI 실행은 [운영 인증·HTTP](production-access.md)에 설명합니다. 백업 도구·실제 OCI 배포는 다음 단계입니다. 루프백 개발 서버를 인터넷에 그대로 노출하지 않습니다.

## 프로필과 설치

| 항목 | x86_64 | aarch64 |
|---|---|---|
| CPython | 3.12.14 | 3.12.14 |
| NumPy·SciPy | 2.3.5·1.17.0 | 동일 버전 |
| 직접·전이 잠금 | `requirements.lock.txt/json` | `requirements.aarch64.lock.txt/json` |
| Dockerfile | `Dockerfile`, linux/amd64 | `Dockerfile.aarch64`, linux/arm64 |
| 실제 CI 실행기 | ubuntu-24.04 | ubuntu-24.04-arm |

Linux에서 Python 3.12.14를 준비한 뒤 기존 `bash scripts/bootstrap.sh`를 사용합니다. 실제 OS·CPU를 확인해 해당 잠금만 선택합니다. 미지원 플랫폼이나 해당 아키텍처 잠금이 없으면 실패하며 x86 파일로 대체하지 않습니다. 가상 환경을 활성화한 뒤 다음 명령으로 실제 관측을 확인합니다.

```bash
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
python scripts/check_environment.py
quanta environment
quanta evaluate examples/pair_energy_forces.json --format text
```

오프라인 설치는 해당 CPU의 wheel 디렉터리를 지정합니다. ARM wheel을 x86 환경에서 실행하는 절차가 아닙니다.

```bash
QUANTA_OFFLINE=1 QUANTA_WHEELHOUSE=.cache/wheels-aarch64 bash scripts/bootstrap.sh
```

실제 ARM 호스트의 컨테이너 설치 확인은 다음과 같습니다. 이미지 기본 명령은 계약 검사이며 외부 공개용 서버 시작 명령은 아닙니다.

```bash
docker build --platform linux/arm64 -f Dockerfile.aarch64 -t quanta-arm .
docker run --rm --workdir /tmp quanta-arm python -m quanta environment
docker run --rm --workdir /tmp quanta-arm python -m quanta evaluate /app/examples/pair_energy_forces.json
```

## 의존성 준비와 실제 검증

0.9.0은 운영 인증 의존성을 포함해 전체 27개를 잠급니다. 이전 0.8.0의 20개 배포 버전·파일·해시는 그대로 유지했습니다. CPython 3.12와 호환되는 `abi3` ARM wheel도 검증하며 다른 CPU·미래 Python ABI로 대체하지 않습니다.

`scripts/prepare_arm_lock.py`는 기존 x86 잠금의 출처·무결성을 확인한 후 **현재 native 잠금과 동일한 전체 버전**의 CPython 3.12 ARM wheel을 교차 다운로드합니다. 공식 PyPI 배포 SHA-256·wheel metadata·아키텍처·패키지 집합을 검사하고, 두 ARM 잠금을 완성해 게시합니다. 필요한 wheel이 없으면 버전을 자동 올리거나 소스 빌드로 대체하지 않습니다. x86 잠금은 수정하지 않습니다.

```bash
python scripts/prepare_arm_lock.py
```

ARM 잠금의 `preparation.native_arm_validation=not_performed`는 **잠금 생성 방법**의 기록입니다. 이후 실제 ARM 시험이 통과해도 생성 당시 기록은 덮어쓰지 않고 CI 결과와 측정 artifact로 실행 근거를 남깁니다. 교차 다운로드·선택기 mock 시험·에뮬레이션은 ARM 수치 합격의 근거가 아닙니다.

CI는 두 실제 아키텍처에서 OS·CPU·Python을 먼저 관측하고, 전체 Python·Node 시험, A·SI·B·WF·S·W·P 일곱 측정과 설치 컨테이너의 계산·HTTP·웹 흐름을 실행합니다. 환경·선택 잠금 해시·측정 JSON은 CPU별 artifact로 분리합니다. 이 기록은 OCI A1의 성능·디스크·접속·장애 복구 검증과 구분합니다. A1에서는 배포 전에 같은 흐름을 다시 확인합니다.

이전 0.8.0 구현 commit `2265913`의 [CI 41848627402](https://github.com/Hyunwoo1205/quanta/actions/runs/41848627402)는 x86_64에서 Python **456개(223.91초)**, aarch64에서 **456개(297.56초)**와 각각 Node **25개**, 여섯 측정·설치 컨테이너 검증을 통과했습니다. artifact 보존 기한과 별개로 [x86 원본 측정](verification/v0.8.0/x86_64/)과 [ARM 원본 측정](verification/v0.8.0/aarch64/)을 저장소에 보존합니다. ZIP digest·원본 파일 SHA·실행 환경·로컬 설치 wheel 검증은 [검증 기록](arm_runtime_verification.json)에 있습니다. 이후 문서·측정 원본 보존 변경은 검증한 구현·README·잠금을 바꾸지 않습니다.

## 저장 기록과 재실행

패키지에는 양쪽 아키텍처의 잠금 다섯 파일을 포함합니다. 실행 번들의 기존 논리 이름 `requirements.in`, `requirements.lock.txt`, `requirements.lock.json`은 유지하면서 실제 호스트에서 선택한 파일 bytes를 캡처합니다. 따라서 ARM 잠금의 target·배포 해시는 x86와 다른 의존성 manifest로 고정됩니다. 서로 다른 설치 위치에서 잠금 일부를 혼합하지 않습니다.

실행 시 캡처한 lock target과 실제 OS·CPU·CPython을 대조하고, 결과 검증에서도 관측 환경과 lock target의 모순을 거부합니다. 이전 x86 결과는 계속 읽을 수 있으나 엄밀한 replay는 원래 구현·잠금에 맞는 신뢰 환경이 필요합니다. ARM으로 이동한 뒤 과거 결과를 같은 실행 지문으로 재현했다고 표시하지 않습니다.

계산 모형·허용오차·자식 메모리 1,024 MiB·벽시계 120초·수치 스레드 1개 정책은 유지합니다. 물리 검증 상태는 `unvalidated`입니다. 배포 전에는 새 실행 수락 중지·작업 비우기·기존 이미지와 DB 보관을 포함한 [OCI 배포 계획](deployment-plan.md)을 따릅니다.

현재 0.9.0의 두 CPU 실행·일곱 측정·설치 패키지 결과는 [운영 인증 검증 기록](production_access_verification.json)에 이전 0.8.0 기록과 구분해 남깁니다.
