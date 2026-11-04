# Quanta

검증 가능한 물리·화학 모형을 연결하고, 연구자가 실험을 직접 구성하는 연구 시뮬레이션 플랫폼을 개발합니다. 특정 활용 분야로 목표를 한정하지 않으며 모형의 적용 범위·근사·수치 오차·검증 근거를 함께 관리합니다.

현재 개발 버전 `0.8.0`은 **브라우저 연구 작업 공간, 실험 정의 검증기, 에너지·힘 계산·정적 탐색·유한 1차원 양자 상태, 다단계 실행과 비동기 API**에 아키텍처별 실행 프로필을 추가합니다. 브라우저에서 입력을 구성·검증·저장하고 계산 진행·실행 기록·수치 결과·산출물을 확인합니다. SQLite에 불변 입력과 결과를 보존하며 입력 검증·수치 및 해상도 수렴·실제 현상에 대한 물리적 검증을 구분합니다.

## 시작하기

Linux x86_64 또는 aarch64와 CPython 3.12.14를 대상으로 합니다. bootstrap은 실제 호스트에 맞는 잠금을 선택하고 미지원 환경을 거부합니다. 직접·전이 의존성은 아키텍처별 버전·해시 잠금으로 관리합니다. [ARM 지원과 검증](docs/arm-runtime.md)에 준비·실제 실행·OCI 검증을 구분해 설명합니다.

```bash
git clone https://github.com/Hyunwoo1205/quanta.git
cd quanta
bash scripts/bootstrap.sh
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
quanta environment
quanta check-contracts
quanta validate contracts/v0.2.0/examples/pair_revision.json
quanta validate contracts/v0.2.0/examples/quantum_revision.json --format text
quanta evaluate examples/pair_energy_forces.json --format text
quanta relax examples/pair_relax.json --format text
quanta eigenstates examples/quantum_eigenstates.json --format text
quanta plan examples/pair_workflow.json --format text
quanta run examples/pair_workflow.json --output-dir .cache/run-example --format text
quanta replay .cache/run-example --output-dir .cache/run-replay --format text
python -m pytest
python scripts/verify_numerics.py --output .cache/numerical-verification.json
python scripts/verify_relaxation.py --output .cache/relaxation-verification.json
python scripts/verify_quantum.py --output .cache/quantum-verification.json
python scripts/verify_workflow.py --output .cache/workflow-verification.json
python scripts/verify_service.py --output .cache/service-verification.json
python scripts/verify_web.py --output .cache/web-verification.json
```

`python -m quanta`로도 같은 명령을 실행할 수 있습니다. 성공의 종료 코드는 `0`, 입력·환경·계약·계산 오류와 미수렴은 `2`입니다. 표준 입력은 파일명 대신 `-`를 사용합니다. 보고서에는 오류 코드·JSON Pointer와 지원 범위를 포함합니다.

## 구현 범위

- UTF-8 JSON의 중복 키, 비유한 수, 잘못된 문자와 지원하지 않는 버전을 거부합니다.
- JSON Schema Draft 2020-12와 등록 모듈의 엄격한 스키마를 함께 적용합니다. 스키마는 동봉된 등록부에서만 해석합니다.
- 단위·척도·표현식·초기 정의역·실험 단계·변경값·반복 축·자원 상한을 검사합니다.
- 유효한 작성 정의를 RFC 8785로 정규화해 `input_sha256`을 계산합니다. 다른 해시의 대상은 별도 계약으로 구분합니다.
- `quanta.pair_static@0.1.0`의 `energy_forces`를 실제 구현했습니다. 같은 수식 트리의 전방 자동미분, 모든 쌍의 합산, SI 복원과 결과 계약 검사를 수행합니다.
- 같은 계산 커널로 `relax`를 구현했습니다. 자유 좌표만 L-BFGS-B로 탐색하고 실제 기울기로 수렴을 판정하며, 실패 시 마지막 수락 배치를 부분 결과로 보존합니다. 전역 최솟값이나 최소점임을 보증하지 않습니다.
- `quanta.quantum_stationary@0.1.0`의 `eigenstates`로 유한 1차원 구간·실수 퍼텐셜·양 끝 파동함수 0의 조건에서 낮은 상태를 구합니다. SI 에너지·파동함수·선택 관측량을 반환하고 수치 잔차와 격자 수렴을 별도 판정합니다.
- `plan`·`run`·`replay`로 분기·다단계 절차, 현재 변경값, 허용된 상태 전달, 오류와 부분 결과를 처리합니다. 실제 식별자와 분리된 과학 해시를 보존하고 새 번들을 저장·검증·재실행합니다.
- `quanta serve --store .cache/local-service`로 인증된 루프백 HTTP API를 실행합니다. 불변 revision·24시간 멱등성·진행 상태·취소·재시작 복구·산출물 다운로드를 SQLite와 단일 계산 자식 프로세스에 연결합니다. 토큰 설정과 실제 제출 예시는 [실행 서비스](docs/execution-service.md)에 있습니다.
- 같은 서버의 `http://127.0.0.1:8765/`에서 [브라우저 작업 공간](docs/web-workspace.md)을 엽니다. 예제·JSON 편집, 불변 입력 저장, 단계·분기 선택, 결과 표·그래프·원본 다운로드를 제공합니다. Node·프런트엔드 빌드·외부 CDN 없이 설치 패키지에서 직접 제공합니다. 공개 배포는 별도 단계입니다.
- 수치 기준 A01~A04·SI 동등성과 B01~B06, 다단계 실행의 독립 기준을 측정하고 [에너지·힘](docs/numerical_verification.json), [정적 탐색](docs/relaxation_verification.json), [양자 상태](docs/quantum_verification.json), [다단계 실행](docs/workflow_verification.json)의 실제값·기준·오차·코드·환경을 기록합니다. 물리 검증 상태는 `unvalidated`입니다.

저장소의 여섯 측정 JSON은 0.7.0 x86 구현의 보존 기록입니다. 0.8.0의 최신 x86·ARM 실행 근거는 [아키텍처별 CI](https://github.com/Hyunwoo1205/quanta/actions)와 각 실행의 `numerical-verification-<architecture>-<commit>` artifact에서 확인합니다. 실제 ARM 합격과 OCI A1 배포 검증은 별도로 기록합니다.

`evaluate`, `relax`, `eigenstates`는 각각 해당 연산 한 단계, 초기 조건, 변경값·반복 축 없는 입력만 받습니다. 여러 단계가 들어 있는 기존 계약 예제를 부분 실행하지 않습니다. 사용 API와 결과 의미는 [단일 배치 평가](docs/pair-evaluation.md), [정적 상태 탐색](docs/relaxation.md), [양자 정적 상태](docs/quantum-stationary.md)를 참고합니다.

다단계·반복 축은 별도 `run` 명령을 사용합니다. 선택한 등록 모듈의 호환된 입출력만 전달하며 임의 물리 결합·상태 변환을 추정하지 않습니다. 계획·결과·저장·재실행 방법과 서버 이전의 적용 범위는 [다단계 실험 실행](docs/workflows.md)에 있습니다. 같은 번들 목적지가 존재하면 덮어쓰지 않으므로 예제를 반복할 때는 새 경로를 지정합니다.

`contracts/v0.2.0`의 등록부와 검증 계획은 가져온 계획 시점의 자료입니다. 실제 제공 범위와 측정 결과는 현재 코드·이 문서·측정 기록을 기준으로 구분합니다. 모듈 전체 또는 미실행 시험을 일괄 완료로 표시하지 않습니다.

모든 미래 모형을 처음 두 모듈의 차원·경계·수식·정밀도에 제한하지 않습니다. 새 기능은 등록 규격과 실제 검증을 갖춘 뒤 제공하며, 시간 변화·모형 결합 등은 확장 후보로 관리합니다.

## 저장 구조

| 위치 | 내용 |
|---|---|
| `src/quanta/` | 입력 검증·계산·실행 계획·번들·SQLite 서비스·HTTP·작업자·CLI |
| `contracts/v0.2.0/` | 버전 관리되는 스키마·정책·예제·계획 |
| `tests/` | 입력·등록부·정규화, 계산 모듈·수렴·수치 기준 및 실패 경로 시험 |
| `scripts/` | 환경 구축·확인·의존성 관리 |
| `docs/` | 구현 상태, 환경 기록, 재현 방법 |
| `.github/workflows/` | 자동 검증 |

코드·명세·시험의 기준 저장소는 이 GitHub 저장소입니다. 계획서·설명 문서·참고 자료와 큰 결과 파일은 지정한 개인용 Drive 폴더에서 관리합니다.

- [전체 계획](https://docs.google.com/document/d/1HlDfah1c5Idk2HIS2heLiicOgAvN2HbTL_3yP4OZD4k)
- [기본 설계](https://docs.google.com/document/d/14L4CkkRRF-yW0TXBXeKFoe4EL76jLzUL4VjqzfOIPA0)
- [세부 명세](https://docs.google.com/document/d/1t0SUe1Z3tYB5rlpnujeguBRqIQzxuAynOcCxLk27tIQ)
- [확장 기능 후보](https://docs.google.com/document/d/12NWa74reRApixxAQQJOtrWre-7ZiuPYz8mgmVvarfaE)
- [프로젝트 폴더](https://drive.google.com/drive/folders/14i_M4KPTJhN9K3HzqcsGsGVxCN8-quA_)

현재 상태와 다음 작업은 [WORKPLAN.md](WORKPLAN.md), 검증 범위는 [docs/validation.md](docs/validation.md)를 참고합니다.
