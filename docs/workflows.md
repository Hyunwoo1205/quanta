# 다단계 실험 실행과 재현 기록

개발 버전 `0.5.0` · 입력/결과 계약 `0.2.0` · 로컬 보고서·번들 `0.1.0`

## 실행 방법

```bash
quanta plan examples/pair_workflow.json --format text
quanta run examples/pair_workflow.json --output-dir .cache/run-example --format text
quanta replay .cache/run-example --output-dir .cache/run-replay --format text
quanta run examples/quantum_workflow.json --format text
```

`plan`은 계산 없이 분기·단계·지원 계약·실제 구현을 고정합니다. `run`은 동기식으로 계산하고 `replay`는 저장된 입력·출처·bytes·고정 바인딩을 검증한 후 새 식별자로 계산합니다. `--format json`이 기본이며 `plan`·`run`의 파일명 `-`는 표준 입력입니다. 성공 종료 코드는 0, 입력·실행·저장 오류와 미수렴은 2입니다. 기존 `evaluate`·`relax`·`eigenstates`의 단일 단계 경계는 유지합니다.

쌍 예제는 k 값 2·4의 두 조건에서 초기 평가 → 정적 탐색 → 탐색 결과 평가의 6단계를 실행합니다. 양자 예제는 같은 구간에서 서로 다른 질량의 초기 설정을 각각 계산합니다. 기존 모듈의 차원·경계·수식·정밀도·수치 판정은 그대로입니다.

```python
from pathlib import Path
from quanta.planning import plan_experiment
from quanta.workflow import run_experiment
from quanta.run_store import validate_run_report, write_bundle, read_bundle, replay_bundle

data = Path("examples/pair_workflow.json").read_bytes()
plan = plan_experiment(data)
report = run_experiment(data)
if report["result"] is not None:
    print(report["result"]["execution_status"])
    print(validate_run_report(report))
    write_bundle(report, ".cache/python-run")
    restored = read_bundle(".cache/python-run")
    replayed = replay_bundle(".cache/python-run")
```

## 단계와 조건 해결

반복 축은 작성한 순서로 Cartesian product를 만들며, 각 분기에서 단계를 순서대로 실행합니다. 동일한 값을 두 번 작성해도 분기와 저장 식별자는 별개입니다. 동일한 과학 내용은 같은 과학 해시를 가질 수 있습니다.

`source=initial`은 해당 분기의 반복 조건이 적용된 원래 정의에서 시작합니다. 앞 단계 ID를 출처로 쓰면 같은 분기의 그 성공 출력과 유효 정의를 승계한 뒤 현재 변경값을 적용합니다. 앞 단계의 매개변수 변경은 이 경로에서 승계되며, 초기 출처로 돌아가면 초기화됩니다. 반복 축 값을 승계한 결과 위에 다시 덮어쓰지 않습니다.

초기 상태, 선택한 원래 출력, 변경값을 적용한 준비 입력, 새 출력은 별도 식별자를 갖습니다. 출처 바인딩의 `source_state_ref`는 원래 자료이고 `effective_input_state_ref`는 별도 준비 입력입니다. 성공 결과의 `state_ref`가 새 출력 상태입니다. 준비가 끝나지 않은 단계에는 단계 해시·준비 바인딩을 만들지 않습니다.

현재 하나의 실험 정의는 선택한 등록 모듈의 연산을 실행합니다. 쌍 모듈의 성공 배치만 호환 쌍 연산에 전달합니다. 양자 해 배열을 설정으로 바꾸거나 서로 다른 모형을 자동 결합하지 않습니다.

전체 관측량 요청은 각 단계의 지원 목록과 교집합을 취합니다. 예를 들어 최적화 이력만 요청한 실험의 단일 에너지 평가 단계는 선택 관측량이 비어 있지만 필수 에너지·힘·진단·후속 상태는 여전히 계산합니다. 기존 정의 스키마의 비어 있지 않은 관측량 조건을 만족시키는 내부 `energy` carrier는 필수 출력의 검증용이며 실제 선택 바인딩·해시에는 빈 교집합을 기록합니다.

## 결과와 실패

보고서는 `valid`로 입력·계획 유효성을, 중첩된 `result.execution_status`로 실제 실행 결과를 나타냅니다. 수락 전 오류는 `result=null`이며 실행 식별자를 꾸며 만들지 않습니다. 유효한 계획도 자원 또는 실행 환경 문제로 실행이 거부될 수 있습니다.

`result`는 동봉된 `result.schema.json`을 따릅니다. 단계별 `SUCCEEDED`, `FAILED`, `SKIPPED`, 수치·해상도 상태·진단·payload·산출물과 실제 초기·준비·출력 상태를 포함합니다. 전체 수치·해상도 상태는 적용 가능한 단계 중 `not_converged` → `not_checked` → `pass` 순서로 집계하며, 모두 적용 대상이 아니면 `not_applicable`입니다. 물리 검증은 `unvalidated`, 근거 참조는 비어 있습니다.

실패한 단계에 의존하는 단계만 건너뛰며 독립적인 초기 단계와 다른 분기는 계속 계산합니다. 실패·미수렴·부분 payload는 증거로 보존하되 출력 상태로 승격하지 않습니다. 전체 시간·저장 한도는 남은 계산을 중단합니다. 먼저 성공한 단계의 자료를 전체 실패에 맞춰 변경하지 않습니다.

운영 상한은 등록 정책과 고정한 낮은 정책을 따릅니다. 계산기의 `deadline_check` 연결로 단계·전체 시간 검사를 내부 쌍·격자·결과 공개 검사에 전달하며 검사 사이의 작업을 강제 선점하지 않습니다. 기록의 실제 저장 크기를 누적 검사하고 말단 오류용 `8192*expanded_steps+4096` bytes를 확보합니다. 예산에 맞춰 과학 데이터를 줄이지 않습니다.

## 서로 다른 해시

| 해시 | 묶는 내용 |
|---|---|
| `input_sha256` | 작성한 전체 정의; protocol·관측량 포함, envelope의 생성 ID·제목·일시는 제외 |
| run `resolved_input_sha256` | 분기 기본값·상징적인 단계 출처·등록 및 실제 구현 바인딩의 고정 계획 |
| step `resolved_input_sha256` | 해당 시점의 실제 과학 입력·연산·관측량·출처 과학 내용·관련 바인딩 |
| `state_content_hashes` | 단위·척도·표현·데이터·과학 metadata; 저장 ID·생산 이력과 분리 |
| `execution_fingerprint` | 고정 계획·실제 코드·잠금 의존성·상수·정책·실제 실행 환경 |
| artifact `sha256` | 해당 자료의 실제 저장 UTF-8 bytes |

과학 projection은 계약대로 RFC 8785로 정규화합니다. 원본 projection bytes와 각 digest의 대상 bytes를 내용 주소로 보존합니다. 같은 과학 내용과 다른 저장·생산 이력은 구분합니다. 실행 전에 잠금 20개 배포와 프로젝트 패키지의 실제 설치 버전을 모두 관측·대조하며, 실제 수치 라이브러리와 스레드 구성도 실행 환경에 묶습니다.

## 저장 번들과 재실행

새 디렉터리에 `bundle.json`, 실제 metadata bytes의 `bundle.sha256`, SHA 이름의 UTF-8 `assets/`를 저장합니다. 동일 내용은 한 번 저장하며 기존 목적지는 덮어쓰지 않습니다. 모든 bytes를 준비한 뒤 metadata를 마지막에 공개합니다. 중단되어 metadata가 없는 디렉터리는 유효한 번들로 읽지 않습니다.

일반 JSON 전송은 고정 좌표의 `-0.0` 부호 비트를 보존하고, 과학 해시의 JCS 규칙은 별도로 유지합니다. 초기·준비·출력 상태와 실제 단계 입력, 중복된 상태 기록의 일관성은 0의 부호까지 비교합니다. JCS로 캡처한 과학 projection과 payload artifact는 정규화 규칙대로 비교합니다. 읽을 때 raw checksum·내용 주소·형식·배열·단위 metadata·출처·상태·해시·산출물의 정합을 검사합니다. 심볼릭 링크나 경로 밖 자료를 불러오지 않습니다. 이 검사는 인증 서명이나 결과의 물리적 정확도를 증명하는 기능은 아닙니다.

재실행은 저장된 Python 텍스트를 실행하지 않습니다. 현재 신뢰한 설치 코드·잠금·상수·정책·계약이 고정 바인딩과 일치할 때만 같은 입력으로 새 실행을 만듭니다. 사용할 수 없거나 달라졌으면 명시적으로 거부합니다. 원본 실행을 변경하지 않고 새 `run_id`와 상태·산출물 ID, `provenance.replay_of`를 기록합니다. 실제 환경은 다시 관측하므로 환경이 달라지면 실행 지문도 달라집니다.

로컬 CLI는 작성된 revision envelope를 그대로 보존합니다. 후속 0.6.0의 [실행 서비스](execution-service.md)는 별도 HTTP 경로에서 서버 발급 revision·소유권·인증·큐·취소·24시간 멱등성을 제공합니다. 로컬 CLI에 서버 소유권을 임의로 부여하지 않으며, 두 경로 모두 재실행은 불변 입력부터 같은 절차를 수행합니다. 부분 체크포인트 재개는 제공하지 않습니다.

## 검증 근거

[구현 계획](workflow-plan.md), [실제 실행 검증](workflow_verification.json), [개발 검증 기록](verification.md)을 참고합니다. 실제 측정은 다음 명령으로 다시 만들 수 있습니다.

```bash
python scripts/verify_workflow.py --output .cache/workflow-verification.json
```

조건별 수동 기준, 출처 승계·초기화, 선택 관측량, 실패·부분 결과, 독립적인 해시 재구성, 저장·재실행·변조 거부를 확인합니다. C01·C02·C04의 이번 범위만 검사하며 C03과 미래 기능의 계획 상태를 일괄 통과로 바꾸지 않습니다.
