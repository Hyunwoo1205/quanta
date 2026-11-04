# 고정 좌표 조건의 정적 상태 탐색

패키지 `0.4.0` · 모듈 `quanta.pair_static@0.1.0` · 연산 `relax`

## 사용 방법

```bash
quanta relax examples/pair_relax.json --format text
quanta relax examples/pair_relax.json
```

예제는 한 대상을 고정하고 다른 대상의 x 좌표만 변화시킵니다. 기준 거리에서 에너지와 자유 기울기가 0에 도달합니다. 임의 입력의 성공을 보장하는 예제는 아닙니다.

```python
from pathlib import Path
from quanta.evaluation import relax_experiment

report = relax_experiment(Path("examples/pair_relax.json").read_bytes())
if report["evaluation_status"] == "SUCCEEDED":
    print(report["payload"]["final_positions_m"])
elif report["partial"]:
    print(report["errors"], report["payload"]["stop_reason"])
```

상위 API는 정확히 한 개의 초기 `relax` 단계만 실행합니다. 변경값·반복 축·다단계 입력을 명시적으로 거부합니다. 하위 `quanta.relaxation.relax_pair(definition)`는 정의만 받으며 절차를 실행하지 않습니다. 실패하면 `RelaxationError`의 `partial_payload`에 유효한 마지막 수락 배치 또는 `None`을 담습니다.

## 계산과 종료 기준

에너지·힘 계산과 동일한 수식 트리·자동미분·SI 복원 커널을 사용합니다. 자유 좌표의 초기 위치에 대한 무차원 변위만 SciPy L-BFGS-B에 전달합니다. 고정 좌표는 최적화 변수에서 제외하고 입력 비트를 보존하며 반력은 그대로 계산합니다. 모두 고정된 `relax` 입력은 거부합니다.

실제 수락 배치의 `free_gradient_inf <= gradient_tolerance`일 때 수치 수렴으로 판정합니다. `free_gradient_inf`는 자유 좌표의 무차원 에너지 기울기 최대 절댓값입니다. 초기 배치가 기준을 충족하면 반복 0회·평가 1회로 종료할 수 있습니다. 에너지 변화 기준 `energy_ftol`이나 solver의 성공 표지만으로 수렴을 선언하지 않습니다.

`minimum_confirmed=false`는 항상 유지합니다. 기울기가 작아도 최소점·전역 최솟값·안정성이 입증된 것은 아닙니다. 관측한 기울기 수렴과 실제 현상에 대한 물리 검증도 구분하며, `physical_validation_status=unvalidated`, `resolution_status=not_applicable`입니다.

| 상황 | 오류 코드 | 종료 사유 |
|---|---|---|
| 실제 자유 기울기 기준 충족 | 없음 | `gradient_tolerance` |
| 에너지 변화 기준만 충족 | `NUM_NOT_CONVERGED` | `energy_tolerance_without_gradient` |
| 다른 solver 종료, 기울기 미달 | `NUM_NOT_CONVERGED` | `line_search_failed` |
| 수락 반복 수 한도 | `RESOURCE_LIMIT` | `iteration_limit` |
| 커널 평가 수 한도 | `RESOURCE_LIMIT` | `evaluation_limit` |
| 벽시계 시간 한도 | `RESOURCE_LIMIT` | `wall_time_limit` |
| 시도 배치의 정의역·수치 범위 오류 | 해당 계산 오류 | `expression_domain_error` 또는 `numerical_range_error` |

한도는 등록 정책과 입력의 `max_iterations`, `max_evaluations`를 따릅니다. 벽시계 상한은 등록 정책의 단계·전체 실행 상한과 60초 중 최솟값입니다. 시간은 단조 시계로 계산 전후·쌍 계산·수락 및 최종 결과 검사에서 확인합니다. 검사 사이의 작업을 강제 선점하는 실시간 제한기는 아닙니다.

초기 평가와 실패한 수치 시도도 평가 횟수에 포함합니다. 이미 캐시한 같은 배치의 재사용은 추가 평가로 세지 않습니다. 반복 횟수는 수락된 갱신 수입니다. 선택한 `optimization_history`는 초기 0행과 수락된 각 반복만 포함하며, 실패한 선탐색 시도는 넣지 않습니다. 정의역 오류가 난 시도를 임의 보정하거나 건너뛰지 않습니다.

## 실패와 부분 결과

보고서 `report_version=0.2.0`에서 실행 성공은 `evaluation_status=SUCCEEDED`, `partial=false`입니다. 한도·오류로 중단되면 `FAILED`이며, 유효하게 수락된 배치가 있을 때만 `partial=true`, `calculation_executed=true`와 해당 payload를 반환합니다. 그 이전의 실패는 payload가 없습니다. CLI 종료 코드는 성공 0, 실패 2입니다.

`numerical_status`는 실행 성공 여부와 독립입니다. 실제 기울기 기준이 충족되면 `pass`, 유효한 수락 배치에서 미달이면 `not_converged`, 계산 결과가 없으면 `not_checked`입니다. 예를 들어 수렴 배치의 최종 결과 검사 중 시간이 초과하면 실행은 실패하지만 보존된 배치의 기울기 판정은 `pass`일 수 있습니다. 부분 결과를 전체 실행 성공으로 해석하지 않습니다.

결과 스키마·유한값·형상·쌍 인덱스·고정 좌표·이력의 정합을 확인한 배치만 공개합니다. 작성 입력·코드 해시·환경을 연결하며 전체 실행 시스템의 run·state 식별자나 실행 지문은 만들지 않습니다.

## 검증 근거

[A04 측정 기록](relaxation_verification.json)은 독립 참조로 거리 오차와 자유 기울기를 확인합니다. 원래 기준은 기준 거리 오차/L0 및 자유 기울기가 각각 `1e-6` 이하인 것입니다. 최종 에너지·힘·쌍 표·고정 좌표·이력·진단도 대조합니다. 재측정:

```bash
python scripts/verify_relaxation.py --output .cache/relaxation-verification.json
```

이 기준은 지정한 매끄러운 기준 문제의 수치 구현 시험이며 임의 실험의 오차나 물리적 정확도를 보증하지 않습니다. solver 옵션의 의미는 [SciPy 1.17 L-BFGS-B 문서](https://docs.scipy.org/doc/scipy-1.17.0/reference/optimize.minimize-lbfgsb.html)를 참고합니다.
