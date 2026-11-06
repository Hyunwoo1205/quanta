# 동역학 계약·검증과 공용 힘 커널

2026-11-06 · 개발 앱0.13.0 · 기본 실험 계약0.2.0 · 독립 동역학 요청 계약0.3.0

이 문서는0.13.0의 구현 기반 기록입니다. 현재0.14.0의 실제 시간적분과 실행용0.3.1 계약은 [독립 동역학 실행](dynamics-integration.md)을 참고합니다.

이번 단계는 [설계 기준0.1](design/pair-dynamics-v0.1/README.md)의 첫 구현 기반입니다. 새 번들의 해시·등록·오프라인 해석, 독립 입력 검증과 초기 힘·진단 가능성 검사, 기존 정적 계산에서 추출한 공용 힘 커널을 구현합니다. velocity-Verlet 시간적분·완성 궤적·동역학 D01~D11 합격·웹/API 실행 연결은 후속 작업입니다.

## 두 계약과 명시적인 진입점

| 경계 | 현재 의미 |
|---|---|
| `ContractRegistry()` / 기존 `validate`, `evaluate`, `relax`, `run` / 웹·API | 기존0.2.0 실험 계약·계산 경로 |
| `ContractRegistry(contract_version="0.3.0")` | 별도 해시 잠금된 독립 동역학 요청 검증 기반 |
| `quanta check-contracts --contract-version 0.3.0` | 새 번들 스키마·참조·등록·자원 바인딩 무결성 검사 |
| `quanta validate-dynamics request.json` | 0.3.0 독립 요청의 구조·의미·자원·초기 정의역 및 진단 가능성 검사 |

`contracts/v0.2.0` 원본을 수정하지 않습니다. 새 번들은 `contracts/v0.3.0`에 따로 저장하고 패키지에 포함합니다. 디렉터리 이름·선택 버전·로드한 등록부 버전의 혼동을 거부하며, 선언된 로컬 allowlist와 버전별 URI만 해석하고 원격 스키마를 가져오지 않습니다. 기본 버전은 설치된 새 번들 존재만으로 바뀌지 않습니다.

0.3.0 모듈은 `quanta.pair_dynamics@0.1.0`이며 `request_scope=standalone_solver_request`, `execution_supported=false`, `generic_experiment_supported=false`입니다. 입력 스키마는 `dynamics_request.schema.json`, payload는 `dynamics_payload.schema.json`, 상태 데이터·메타데이터도 별도 스키마로 등록합니다. 입출력 port·관측량 선언은 이후 실행기의 연결 규약이며 이번 구현이 그 실행을 지원한다는 뜻은 아닙니다. 구조 스키마 외의 payload 교차 검사와 실제 시간적분 상태 게시도 후속 실행기에서 완성해야 합니다.

## 독립 요청 검증

설계 초안의 `draft_schema_version` 대신 `contract_version="0.3.0"`을 사용합니다. 나머지 명시적 질량·위치·속도·L0/E0/T0·초기 시각0·동일 쌍 퍼텐셜·dt/steps/sample_stride/refinement/목표값 규칙을 유지합니다. 동봉된 세 예시는 같은 변환을 적용한 입력이며 실제 궤적 결과가 아닙니다.

```bash
quanta validate-dynamics contracts/v0.3.0/examples/harmonic.request.json
quanta validate-dynamics contracts/v0.3.0/examples/harmonic-refinement.request.json --format text
quanta validate-dynamics contracts/v0.3.0/examples/free.request.json
```

엄격한1MiB JSON 읽기, 계약·등록부 무결성, 스키마, 고유 입자ID와 필수 질량/속도, AST 깊이·노드·계수 참조, 유한 척도·무차원 양·nonzero underflow, 각 leg의 SI/무차원 half-step과 정수 시각 격자, 표본/연산/바이트 예약을 확인합니다. 비싼 초기 힘 계산 전에 자원 한도를 확인합니다. 더 낮게 선언한 유효 보호 한도는 그대로 지키고 더 높은 값으로 하드 상한을 확대하지 않습니다.

검증의 마지막에는 공용 커널로 초기 배치의 모든 쌍 힘·에너지와 AST 정의역을 실제 평가합니다. 독립적인 초기 K/E/P/L·질량중심 계산이 유한하게 표현되는지도 확인합니다. 이는 `initial_force_evaluation_performed=true`로 시간적분과 구분합니다. 질량·속도를 제거하거나 module_id를 정적으로 바꿔 기존 정의 검증기를 우회하지 않습니다.

정상 입력도 `executable=false`, `dynamics_simulation_executed=false`입니다. `valid=true`는 현재 확인한 입력 경계만 통과했다는 뜻이며 미래 궤적의 안정성·완료·물리적 정확도를 보장하지 않습니다. 출력은 원본 입력의 RFC8785 해시, 파생 척도, 시각 leg와 예약 예산·초기 가능성 확인을 포함하고 정상 run/state/trajectory를 꾸며 만들지 않습니다. JSON·text 출력 모두 이 한계를 표시합니다.

바이트 예산은 현재 아는 원본/정규 요청·동봉 등록부·궤적 예약·종료 기록의 최소 합계이며 아직 없는 실행 전체 provenance의 완전한 추정이 아닙니다. 남은 예산과 `complete_execution_provenance_estimate=false`를 함께 반환하고 실제 실행기는 추가 provenance와 실제 산출물 bytes를 다시 확인해야 합니다.

## 공용 힘 커널과 기존 계산 보존

`src/quanta/pair_kernel.py`의 `PairForceKernel`은 명시적인 입자 수·L0/E0·최소거리·퍼텐셜/계수와 좌표를 받아 모든 쌍의 에너지·힘을 계산합니다. 질량·속도·고정 마스크·시간·모듈 신원은 이 커널의 책임으로 넘기지 않습니다. 입력을 스냅샷으로 보존하고 기존 자동미분·전 쌍 합산 순서·안전한 Fraction 곱/합·정의역·마감 검사 정책을 사용합니다.

기존 `_PreparedPair` 어댑터는 기존0.2 정의와 정확한 정적 module_id를 계속 검사합니다. 고정 좌표의 signed-zero 보존, 자유 기울기와 정적/relax payload 의미도 어댑터에서 유지합니다. 수식을 새로 맞추거나 힘을 보정하지 않습니다.

새 파일과 패키지 버전은 구현 지문을 바꿉니다. 과거 bundle의 엄격한 replay 해시를 다시 쓰지 않으며 이전 구현과 다르면 명시적으로 거부합니다. 같은 불변 입력을 현재 버전으로 계산하는 것은 별도의 새 run입니다. 구 버전 결과와 당시 검증 근거는 보존합니다.

## 검증 근거와 다음 단계

이번 단계의 실제 로컬·원격 시험과 설치 패키지 확인은 [구현 검증 기록](dynamics_foundation_verification.json), 현재 진행 위치는 [WORKPLAN](../WORKPLAN.md)을 따릅니다. 새 정적 커널과 초기 진단 검사 통과를 동역학 시간적분 시험 합격으로 표시하지 않습니다. 물리 검증 상태는 `unvalidated`입니다.

다음 작업은 velocity-Verlet의 단일 요청 시간적분과 drift 선분 최소거리·전 스텝 진단·정확한 sampling·부분 결과/해상도/실패 상태 검사입니다. 이어 D01~D11의 독립 수치/자원/실행 연결 검증을 완료하고 웹·시각화에 연결합니다. OCI 배포·재부팅·추가 백업은 이번 기반 구현에 포함하지 않습니다.
