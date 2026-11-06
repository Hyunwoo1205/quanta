# Quanta

Quanta는 연구자가 물질계·환경·상호작용·실험 절차를 설계하면 물리 법칙에 근거한 계산으로 실제 입자의 운동과 물리계의 시간에 따른 상호작용·구조 변화·반응을 예측하고, 그 결과를 3D로 관찰·분석하는 연구용 시뮬레이션 플랫폼을 목표로 합니다. 전자·쿼크 등 미시 구성요소부터 원자·분자와 거시적 물질계까지 지원 모형을 검증하며 확장합니다. 소재 개발은 여러 응용 중 하나입니다.

사용자는 JSON으로 실험계·초기 상태·환경/경계·물리 모형·수치 조건·절차·관측량을 자유롭게 설계하고 실행합니다. 이후 시각 편집기도 같은 실험 정의를 읽고 씁니다. 3D는 이 자유 실험 환경의 편집·관찰 수단이며 내부 검증 사례를 고정 실험 메뉴로 사용하지 않습니다.

같은 3D 공간에서 화면을 확대·축소하면 입자·원자·분자·집합 구조·거시적 물질로 관찰 범위와 세부 표현이 자연스럽게 바뀌도록 설계합니다. 표현 수준이 바뀌어도 공간적 위치·물리적 시각과 계산 결과의 대응을 유지합니다. 화면의 표시 수준 전환과 물리 모형의 연결을 구분하며, 계산 모형을 연결할 때는 상태 전달·보존량·적용 범위를 명시하고 검증합니다.

2026-11-06에 확정한 3D 목표는 계산한 운동과 동적 상태의 구현입니다. 첨부 이미지는 시각적 참고이며 설명용 전자 궤도나 임의 애니메이션을 연구 결과로 취급하지 않습니다. 양자적 구성요소는 해당 이론의 동적 상태·관측량으로 표현하며 계산하지 않은 고전적 경로를 실제 궤적으로 주장하지 않습니다. 정적인 전자밀도 표시만으로 전체 목표를 충족했다고 판정하지 않습니다. 현재 0.16.0은 범용 입자 궤적 기반이며 원자·전자구조·화학 반응·물리적 규모 연결은 미구현입니다. 모형의 적용 범위·근사·수치 오차·검증 근거를 함께 관리합니다.

## 통합 개발계획 v1.0

2026-11-06 전체 재계획은 [통합 프로젝트 계획](https://docs.google.com/document/d/1HlDfah1c5Idk2HIS2heLiicOgAvN2HbTL_3yP4OZD4k)의 최신 탭과 [첫 원자계 상세설계](https://docs.google.com/document/d/14L4CkkRRF-yW0TXBXeKFoe4EL76jLzUL4VjqzfOIPA0)를 기준으로 합니다. [기계 판독 개발 계획](docs/design/research-roadmap-v1.json)은 단계·의존관계·합격 기준·첫13개 작업을 기록한 비실행 계획이며 런타임 계약이나 지원 기능이 아닙니다.

첫 경로는 원자핵+전자 기반의 제한된 원자계 계약·엔진 실측(P1)→정적 에너지·힘·전자 상태/첫3D(P2)→계산된 원자 운동/동적3D(P3)입니다. CP2K를 첫 엔진의 우선 검토 후보로 두고 설치·수치/물리·자원/취소 근거 뒤 채택합니다. 정적 계산은 중간 단계이며 비정지 초기조건의 실제 핵 변위·속도 변화까지 확인해야 첫 운동 목표를 달성합니다. 현재 새 엔진·원자계 계약은 미구현이며 운영0.16.0은 유지합니다.

환경·자유 절차(P4), 화학 변화(P5), 별도 전자 시간 전파(P6), 큰 계/통계(P7), 첫 순차 미시→거시 연결(P8)을 확장합니다. P6는P2 이후 독립 분기이며 P7/P8은P5/P6 완료를 선행 필수로 두지 않습니다. 확대·축소3D와 원본 대응은P2부터 병행하며 쿼크/QCD는 초기 선행 의존성에서 제외합니다. A01의 첫 범위·기준·입력 묶음은 [비실행 원자계 설계](docs/design/atomistic-a01-v0.1/README.md)에 선정했습니다. 중성2전자 He/H2 내부 검증계·PBE 전전자 계산 의도·정상7/거부9 입력·12개 사전 과학 기준을 기록했고 [설계 정합성 검사](docs/atomistic_a01_design_verification.json)를 통과했습니다. [A02 잠금 후보](docs/design/atomistic-a02-v0.1/README.md)에서 CP2K2026.2 소스·플랫폼별 이미지 식별자·cc-pVXZ 자료와 전체 전자밀도 출력 의미를 고정하고 [실제 원본/잠금 검사](docs/atomistic_a02_lock_verification.json)를 통과했습니다. 소스/자료 잠금과 실제 설치·바이너리/소스 대응·과학 검증은 구분하며 [A03 실제 native 측정](docs/atomistic_a03_native_verification.json)에서 ARM/x86의 격리 계산·전체밀도 출력·자원·초기화 중 취소/정리·후속 계산을 통과했습니다. 실제 OCI 실측은 전체CI 뒤 수행합니다. 실제 바이너리 revision은unknown이며 [소스 연결과 CUBE 정밀도 정정](docs/design/atomistic-a03-v0.1/binary-source-binding-review.json)을 기록했습니다. A04의 실제 프로필 동결과 공개 원자계 실행은 아직no-go입니다.

현재 패키지 `0.16.0`은 **브라우저 연구 작업 공간, 실험 정의 검증기, 에너지·힘 계산·정적 탐색·유한 1차원 양자 상태, 다단계 실행과 비동기 API**에 아키텍처별 실행 프로필·운영 인증·영속 저장 배포 구성과 SQLite 백업 복구를 제공합니다. 이메일을 인증한 계정의 아이디·비밀번호 로그인과 선택형 이메일 이중 인증을 추가하며 실제 배포·메일 발송 확인은 별도 검증 근거로 구분합니다. 브라우저에서 입력을 구성·검증·저장하고 계산 진행·실행 기록·수치 결과·산출물을 확인합니다. SQLite에 불변 입력과 결과를 보존하며 입력 검증·수치 및 해상도 수렴·실제 현상에 대한 물리적 검증을 구분합니다.

Cloudflare Access가 기본 운영 인증입니다. Cloudflare에 등록하지 않은 도메인은 [직접 HTTPS와 소유자 접속키](docs/direct-https.md)를 명시적으로 선택할 수 있습니다. 이 선택은 운영용 ASGI 경계·루프백·인증된 API를 유지하며 자동으로 활성화되지 않습니다. 공개 TLS·실제 로그인·OCI 앱 배포 확인은 코드 지원과 별도로 기록합니다.

직접 HTTPS의 새 브라우저 인증은 [서버 계정과 Gmail 인증](docs/account-login.md)을 사용합니다. 이메일 인증 후 공개 가입, 아이디·비밀번호 로그인, 선택형 이메일 추가 인증과 재설정을 제공합니다. 최초 관리자만 기존 `local` 실험 기록을 이어받고 공개 가입자는 별도 자료·자원 한도를 사용합니다. 기존 소유자 키는 운영·비공개 초기 설정용으로 유지합니다. Gmail 자격 설정·실제 이메일 수신 확인 전에는 가입이 완료된 것으로 표시하지 않습니다.

## 동역학 웹·3D 궤적

개발0.16.0은 [버전별 동역학 웹 입력과3D 저장 궤적 재생](docs/dynamics-web.md)을 추가합니다. 회전·이동·확대·입자 선택·시간 재생과 선택 시각의 SI 수치/관측량을 연결하고, 원본 산출물 bytes·SHA·payload를 대조합니다. 실제 브라우저·native CI·운영 반영의 완료 범위는 WORKPLAN과 [검증 기록](docs/dynamics_web_verification.json)을 따릅니다.

## 동역학 실험 실행

0.15.0은 [동역학 실험의 실행·저장·재실행](docs/dynamics-workflows.md)을 추가합니다. 명시적 실험 계약0.4.0에서 초기 조건의 단일 integrate를 기존 계획·SQLite·비동기 작업자·HTTP·산출물·번들 재실행에 연결합니다. 물리 시각과 질량·위치·속도를 가진 위상 상태를 보존합니다. 기존 실험 기본 계약0.2.0과 검증 전용0.3.0·[독립 solver0.3.1](docs/dynamics-integration.md)의 원본을 유지합니다. 실제 OCI 운영은 고정 소스5723290의0.16.0이며 계정·기존 기록·Gmail 설정의 전환 보존과 실제 계산·공개 HTTPS/웹 자산을 [검증 기록](docs/oci_dynamics_web_upgrade_verification.json)에서 확인합니다. 현재 범용 입자 쌍 모형과 실제 분자 구조·결합 모형을 구분합니다. 자세한 현재/과거 범위는 WORKPLAN을 따릅니다.

```bash
quanta check-contracts --contract-version 0.4.0
quanta plan contracts/v0.4.0/examples/free_revision.json --format text
quanta run contracts/v0.4.0/examples/free_revision.json --output-dir .cache/dynamics-run --format text
quanta replay .cache/dynamics-run --output-dir .cache/dynamics-replay --format text
```

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
python scripts/verify_production.py --output .cache/production-verification.json
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
- 같은 서버의 `http://127.0.0.1:8765/`에서 [브라우저 작업 공간](docs/web-workspace.md)을 엽니다. 예제·JSON 편집, 불변 입력 저장, 단계·분기 선택, 결과 표·그래프·원본 다운로드를 제공합니다. Node·프런트엔드 빌드·외부 CDN 없이 설치 패키지에서 직접 제공합니다. 외부 로그인용 서버 실행은 [운영 인증·HTTP](docs/production-access.md)를 따릅니다. 실제 OCI 배포는 별도 검증 단계입니다. [운영 배포·백업 복구](docs/operations.md)에 마운트 검사·비 root 컨테이너·자동 재시작·일일 백업과 새 경로 복구 절차를 설명합니다.
- 수치 기준 A01~A04·SI 동등성과 B01~B06, 다단계 실행의 독립 기준을 측정하고 [에너지·힘](docs/numerical_verification.json), [정적 탐색](docs/relaxation_verification.json), [양자 상태](docs/quantum_verification.json), [다단계 실행](docs/workflow_verification.json)의 실제값·기준·오차·코드·환경을 기록합니다. 물리 검증 상태는 `unvalidated`입니다.

저장소의 여섯 측정 JSON은 0.7.0 x86 구현의 보존 기록입니다. 0.9.0의 보존된 x86·ARM 실행 근거는 [아키텍처별 CI](https://github.com/Hyunwoo1205/quanta/actions)와 각 실행의 `numerical-verification-<architecture>-<commit>` artifact에서 확인합니다. 실제 ARM 합격과 OCI A1 배포 검증은 별도로 기록합니다.

`evaluate`, `relax`, `eigenstates`는 각각 해당 연산 한 단계, 초기 조건, 변경값·반복 축 없는 입력만 받습니다. 여러 단계가 들어 있는 기존 계약 예제를 부분 실행하지 않습니다. 사용 API와 결과 의미는 [단일 배치 평가](docs/pair-evaluation.md), [정적 상태 탐색](docs/relaxation.md), [양자 정적 상태](docs/quantum-stationary.md)를 참고합니다.

다단계·반복 축은 별도 `run` 명령을 사용합니다. 선택한 등록 모듈의 호환된 입출력만 전달하며 임의 물리 결합·상태 변환을 추정하지 않습니다. 계획·결과·저장·재실행 방법과 서버 이전의 적용 범위는 [다단계 실험 실행](docs/workflows.md)에 있습니다. 같은 번들 목적지가 존재하면 덮어쓰지 않으므로 예제를 반복할 때는 새 경로를 지정합니다.

`contracts/v0.2.0`의 등록부와 검증 계획은 가져온 계획 시점의 자료입니다. 실제 제공 범위와 측정 결과는 현재 코드·이 문서·측정 기록을 기준으로 구분합니다. 모듈 전체 또는 미실행 시험을 일괄 완료로 표시하지 않습니다.

모든 미래 모형을 처음 두 모듈의 차원·경계·수식·정밀도에 제한하지 않습니다. 새 기능은 등록 규격과 실제 검증을 갖춘 뒤 제공하며, 현재 독립 입자 동역학의 지원 범위 밖 시간 의존 모형·모형 결합 등은 확장 후보로 관리합니다.

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
