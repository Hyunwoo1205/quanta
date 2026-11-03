# 단일 배치의 에너지·힘 계산

패키지 `0.3.0` · 모듈 `quanta.pair_static@0.1.0` · 이 문서의 연산 `energy_forces`

## 사용 방법

```bash
quanta evaluate examples/pair_energy_forces.json
quanta evaluate examples/pair_energy_forces.json --format text
```

동봉 예제의 결과는 약 `4e-21 J`, 두 대상의 x방향 힘은 약 `+4e-11 N`, `-4e-11 N`입니다. 첫 대상은 고정되어 있지만 힘을 0으로 지우지 않습니다. 좌표는 입력과 동일합니다.

Python에서는 실험 입력 전체를 검증하고 실제 지원 범위까지 확인하는 함수를 사용할 수 있습니다.

```python
from pathlib import Path
from quanta.evaluation import evaluate_experiment

report = evaluate_experiment(Path("examples/pair_energy_forces.json").read_bytes())
if report["evaluation_status"] == "SUCCEEDED":
    print(report["payload"]["energy_j"])
    print(report["payload"]["forces_n"])
else:
    print(report["errors"])
```

하위 함수 `quanta.pair.evaluate_pair(definition)`은 단일 배치를 계산하는 라이브러리 API입니다. 정의를 검증하지만 절차를 실행하거나 변경값·반복 축을 적용하지 않습니다. 실험 파일의 실행 경계 확인에는 상위 `evaluate_experiment`를 사용합니다. `quanta.validation.validate_definition`으로 식별자를 새로 만들지 않고 정의만 검증할 수도 있습니다.

## 계산과 수치 정책

입자 2~128개의 비주기 3차원 배치와 등록된 동일 쌍 퍼텐셜을 지원합니다. 모든 `i<j` 쌍을 한 번씩 계산하고 각 쌍의 반대 방향 힘을 두 대상에 누적합니다. 거리 절단·보정식·힘의 임의 제거는 도입하지 않습니다.

같은 수식 트리에서 값과 거리 변수에 대한 1차 도함수를 함께 구합니다. 각 노드의 값과 도함수는 binary64입니다. 곱·몫·상쇄의 국소 중간 연산에는 정확 산술을 사용해 가짜 overflow나 underflow를 피한 뒤 노드 결과를 binary64로 확정합니다. 합산에는 안정적인 누적을 사용합니다. 입력 검증의 값 전용 계산에도 같은 기본 연산 정책을 적용합니다.

각 노드, 거리와 SI 복원·최종 합산의 비유한 결과 및 표현할 수 없는 비영 값의 underflow는 오류입니다. 정확한 0, 0 지수, 수식에 의존하지 않는 값의 0 도함수는 보존합니다. `log`·`sqrt`는 첫 모듈의 등록 규격대로 양수 인수를 요구합니다. 해석식·유한차분은 시험 기준으로만 쓰며 운영 미분을 대체하지 않습니다.

길이·에너지 척도 `L0/E0`를 사용하고 에너지는 `E0`, 힘은 `E0/L0`로 SI 단위에 복원합니다. 거리는 SI 좌표 차이에서 구한 뒤 척도로 나누어, 좌표를 먼저 나누면서 가까운 두 위치가 합쳐지는 오류를 피합니다.

## 결과와 상태

`payload`는 기존 모듈 결과 스키마를 따르고 입자 수·형상·유한값·쌍 인덱스도 검사합니다. 필수 에너지·힘·좌표·진단은 항상 반환하며 요청한 경우에만 쌍별 에너지를 추가합니다.

- `iterations=0`, `evaluations=1`, `stop_reason=evaluated`.
- `free_gradient_inf`는 자유 좌표의 무차원 기울기 최대 절댓값이며 모두 고정됐으면 0입니다.
- `minimum_confirmed=false`이고 최적화 이력은 생성하지 않습니다.
- 비반복 단일 평가이므로 `numerical_status`와 `resolution_status`는 `not_applicable`입니다. 이는 정확도 시험에 대한 판정과 다른 정보입니다.
- 실제 현상과 비교한 근거가 없으므로 `physical_validation_status=unvalidated`입니다.

상위 보고서의 `report_version=0.2.0`은 향후 전체 실행 결과 envelope와 별개의 단일 연산 형식입니다. `input_validation_status`와 `evaluation_status`를 구분합니다. `calculation_executed=true`는 유효한 계산 결과가 생성됐음을 뜻하며, 단일 에너지·힘 평가에서는 성공 결과에만 설정됩니다. `partial=false`입니다. 정적 탐색의 실패·부분 결과 의미는 [별도 문서](relaxation.md)를 따릅니다. 작성 정의의 해시, 코드 파일 해시와 실제 환경을 연결합니다. run·state 식별자나 실행 지문을 꾸며 생성하지 않습니다.

## 지원 범위와 근거

상위 명령은 정확히 한 개의 초기 `energy_forces` 단계만 실행하며 변경값·반복 축·다단계 입력은 명시적으로 거부합니다. 같은 커널을 사용하는 `relax`는 별도 명령으로 제공합니다. 다른 모듈의 solver, 시간 변화와 실행 서버·웹 화면은 후속 작업입니다.

A01~A03 및 SI 동등성의 실제 입력·기준값·오차·허용오차·판정·코드·환경은 [수치 검증 기록](numerical_verification.json)에 있습니다. 기록을 다시 만들려면 다음 명령을 실행합니다.

```bash
python scripts/verify_numerics.py --output .cache/numerical-verification.json
```

허용오차는 명시한 매끄럽고 적절히 스케일된 기준 문제의 무차원 값에 적용합니다. 임의 실험의 오차 또는 물리적 정확도를 보증하는 값으로 전용하지 않습니다. 연속 구간 전체의 수식 매끄러움을 증명하는 도구도 아닙니다.
