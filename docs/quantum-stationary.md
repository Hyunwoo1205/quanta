# 1차원 양자 정적 상태 계산

패키지 `0.4.0` · 모듈 `quanta.quantum_stationary@0.1.0` · 연산 `eigenstates`

## 사용 방법

```bash
quanta eigenstates examples/quantum_eigenstates.json --format text
quanta eigenstates examples/quantum_eigenstates.json
```

동봉 예제는 퍼텐셜 0, 유한 구간 `[0,1e-9] m`, 질량 `1e-30 kg`에서 낮은 4개 상태를 구합니다. 내부 격자 255·511·1023개를 순서대로 사용합니다. JSON 결과에는 좌표, 에너지, 파동함수, 요청한 확률밀도·기댓값, 격자별 결과와 진단이 포함됩니다.

```python
from pathlib import Path
from quanta.evaluation import eigenstates_experiment

report = eigenstates_experiment(Path("examples/quantum_eigenstates.json").read_bytes())
if report["evaluation_status"] == "SUCCEEDED":
    print(report["payload"]["energies_j"])
elif report["partial"]:
    print(report["errors"], report["payload"]["grid_results"])
```

상위 API는 정확히 한 개의 `eigenstates` 단계, `source=initial`, 변경값·반복 축 없는 입력만 실행합니다. 미지원 절차의 일부를 실행하지 않습니다. 하위 `quanta.quantum.eigenstates(definition)`은 정의를 검증한 뒤 계산하며 절차를 실행하지 않습니다. 실패하면 `QuantumError`의 `partial_payload`에 마지막으로 검증한 격자 결과 또는 `None`을 담습니다. 전체 실행 시스템의 run·state 식별자는 만들지 않습니다.

## 계산하는 문제

입력은 유한 구간 `[a,b]`, 양의 질량, 실수의 유한한 퍼텐셜, 양 끝 파동함수 0의 경계 조건입니다. 위치에 따른 퍼텐셜은 등록된 수식 트리로 지정합니다. 변수는 절대 위치가 아닌 `xi=(x-a)/L0`이며 에너지는 `E0*v(xi)`입니다. 구간을 이동하며 동일한 물리적 퍼텐셜을 유지하려면 이 원점 정의도 함께 고려해야 합니다.

무차원 방정식은 `[-alpha*d²/dxi²+v(xi)]*phi=epsilon*phi`이고 `alpha=hbar²/(2*m*E0*L0²)`입니다. `h=6.62607015e-34 J s`와 `hbar=h/(2*pi)`를 사용합니다. 내부 균등 격자에 2차 중심차분을 적용해 실수 대칭 삼중대각 행렬을 만들고, 고정된 SciPy 1.17의 `eigh_tridiagonal`, 인덱스 선택 및 `stebz` 드라이버로 낮은 상태부터 구합니다. 연속 퍼텐셜의 매끄러움은 사용자가 선택한 모형의 조건이며, 프로그램의 격자점 검사만으로 구간 전체의 매끄러움을 증명하지 않습니다.

| 결과 필드 | 의미와 단위 |
|---|---|
| `x_m` | 양 끝을 포함한 물리적 절대 좌표, m |
| `energies_j` | 낮은 순서의 에너지, J |
| `states.real`, `states.imag` | 상태별 파동함수, `m^-1/2`; 실수 문제의 허수 성분은 0 |
| `density_per_m` | 요청한 상태별 확률밀도, `m^-1` |
| `x_mean_m`, `x2_mean_m2` | 요청한 절대 위치·위치 제곱 기댓값, m·m² |
| `kinetic_mean_j`, `potential_mean_j` | 같은 차분 연산자와 격자의 운동·퍼텐셜 에너지 기댓값, J |
| `grid_results` | 완료한 격자별 내부 점 수·SI 에너지와 입력 허용오차 |

좌표·에너지·파동함수·격자별 결과·진단은 필수입니다. 확률밀도와 각 기댓값은 요청한 경우에만 추가합니다. 배열의 상태 수와 좌표 수, 경계 0, 유한값·좌표 엄격 증가, 결과 스키마를 확인합니다. 각 상태는 물리적 격자 간격으로 정규화하며, 절댓값이 최대인 첫 성분을 양수로 정해 부호를 일관되게 표시합니다. 이 부호 선택은 확률밀도를 바꾸지 않습니다.

## 수치 판정과 격자 수렴

보고서 `report_version=0.2.0`에서 다음 상태를 분리합니다.

| 상태 | 판정 |
|---|---|
| `evaluation_status` | 요청한 계산·검사가 모두 끝나면 `SUCCEEDED`, 오류·미수렴·한도 초과는 `FAILED` |
| `numerical_status` | 공개한 격자의 정규화·직교성·고유방정식 잔차 검사 결과 |
| `resolution_status` | 요청한 격자 세분화의 에너지 수렴 결과; 세분화 0회 또는 비교 미완료는 `not_checked` |
| `physical_validation_status` | 실제 현상 대조 근거가 없으므로 `unvalidated` |

정규화·직교성 최대 오차는 `1e-10`, 정규화 고유방정식 잔차는 `1e-12` 이하를 요구합니다. 수치 유효 격자만 다음 계산과 부분 결과의 근거로 사용합니다. 고유쌍 계산이 정확하다는 판정과 연속 문제의 격자 오차가 작다는 판정은 다릅니다.

세분화는 `n -> 2*n+1`로 구간·질량·퍼텐셜·척도를 유지합니다. 요청된 마지막 두 인접 격자에서 모든 상태의 무차원 에너지가 `abs(Efine-Ecoarse) <= grid_energy_atol+grid_energy_rtol*abs(Efine)`를 충족하면 해상도 `pass`입니다. `grid_results.energies_j`는 SI 에너지이고 같은 행의 `atol/rtol`은 입력의 **무차원** 허용오차입니다. 비교할 때는 에너지를 `E0`로 나눕니다.

격자 수렴은 입력한 유한 구간에 대한 판정입니다. 무한 구간을 근사하려는 경우의 경계 오차는 별도로 검토해야 합니다. B06은 지정 기준 문제에서 경계·격자 오차를 분리해 확인하는 시험이며, 모든 입력의 경계 오차를 자동 보증하는 기능은 아닙니다.

## 오류와 부분 결과

격자 수렴 기준을 충족하지 못하면 `NUM_NOT_CONVERGED`, `numerical_status=pass`, `resolution_status=not_converged`이며 마지막 유효 격자를 부분 결과로 반환합니다. 세분화 도중 solver·수식·범위·시간 오류가 나면 완료·검증된 격자만 보존합니다. 결과가 없으면 payload도 없습니다. `calculation_executed=true`는 유효한 계산 결과가 생성됐음을 뜻하며 전체 실행 성공 여부는 `evaluation_status`로 확인합니다.

이미 확인한 수치·해상도 판정은 실행 성공과 독립적으로 보존합니다. 예를 들어 최종 결과 검사 중 시간 초과는 `FAILED`이지만 보존된 격자의 수치 검사가 `pass`일 수 있습니다. CLI 종료 코드는 성공 0, 실패 2입니다.

계약의 내부 점 수·상태 수·최종 격자·최대 세분화 횟수를 지킵니다. 벽시계는 등록 정책의 단계·전체 상한과 60초 중 최솟값이며 계산 전후와 결과 검사에서 단조 시계로 확인합니다. 개별 LAPACK 호출을 중간에 강제 선점하는 실시간 제한기는 아닙니다. 상한 초과나 표현 불가능한 값에 대해 격자·상태 수·정밀도를 조용히 줄이지 않습니다.

## 검증과 적용 범위

[구현 계획](quantum-module-plan.md)의 B01~B06을 [실제 측정 기록](quantum_verification.json)에서 확인합니다. 이산·연속 기준해, 정규화·직교성·잔차, 2차 격자 수렴과 지정 이차 퍼텐셜의 경계 오차 분리를 측정합니다. 재실행:

```bash
python scripts/verify_quantum.py --output .cache/quantum-verification.json
```

이 결과는 선언한 유한 1차원 문제와 지정 수치 기준에 적용합니다. 시간 변화, 다중 대상의 양자 상호작용, 현재 쌍 모형과의 결합, 다른 차원·경계는 이후 등록·구현·검증할 영역입니다. 최초 계약의 계획 상태와 현재 구현·실측 기록은 구분합니다.
