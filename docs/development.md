# 개발 환경과 재현 설치

확인일: 2026-11-04 (UTC+09:00). 기준은 CPython 3.12.14, Linux x86_64, CPU와 수치 라이브러리별 스레드 1개입니다. 다른 플랫폼에는 현재 휠 잠금을 재사용하지 않습니다.

`bash scripts/bootstrap.sh`는 프로젝트 전용 `.venv`에 해시가 일치하는 배포 휠과 편집 가능한 패키지를 설치하고 실제 환경을 검사합니다. 공유 Python 환경은 수정하지 않습니다. 실행 전에 다음 값을 설정하면 같은 스레드 기준을 유지할 수 있습니다.

```bash
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
source .venv/bin/activate
python scripts/check_environment.py
python -m pip check
python -m quanta check-contracts
python -m pytest
```

`requirements.in`은 직접 선택한 버전, `requirements.lock.txt`는 전이 의존성까지 포함한 설치 잠금, `requirements.lock.json`은 배포 파일 이름·공식 출처·SHA-256을 기록합니다. 잠금은 해당 Linux x86_64 휠 하나씩을 허용합니다. `scripts/check_environment.py`는 설치 버전과 잠금 파일 해시, 실제 로드된 BLAS 스레드 수를 확인합니다.

잠금 변경은 기준 Python으로 `python scripts/lock_dependencies.py`를 명시적으로 실행합니다. 이 명령은 공개 PyPI에서 호환 휠을 내려받고 각 파일을 공식 배포 메타데이터의 해시와 대조합니다. 잠금 변경 후에는 새 가상 환경에서 재설치와 시험을 다시 실행합니다. `.cache/wheels`가 준비되어 있으면 `QUANTA_OFFLINE=1 QUANTA_VENV=.venv-recheck bash scripts/bootstrap.sh`로 네트워크 없이 잠금 설치를 재검사할 수 있습니다. 캐시와 가상 환경은 저장소에 넣지 않습니다.

GitHub Actions는 동일 설치·환경 확인·계약 검사·시험·예제 검증과 컨테이너 빌드를 실행하도록 구성했습니다. 공식 Actions는 커밋 SHA, 공식 Python 컨테이너는 Linux amd64 이미지 digest로 고정했습니다. 로컬에는 Docker 실행기가 없어 로컬 이미지 빌드는 실행하지 않았습니다. 원격 CI의 실행 결과는 별도로 확인해야 합니다.

설치 환경과 구현 범위의 실제 확인 결과는 `runtime_manifest.json`에 기록합니다. 이 검사는 물리적 정확도나 계산 엔진의 검증을 뜻하지 않습니다.

`python scripts/verify_numerics.py --output docs/numerical_verification.json`은 지정한 단일 배치의 A01~A03과 SI 척도 동등성만 측정합니다. 독립 해석식, 실제 에너지의 중심차분, 기하 변환과 합력·토크를 사용하며 실제 오차·허용오차·입력·환경·코드 해시를 저장합니다. 실패하면 JSON에 실패를 남기고 비정상 종료합니다. 원래 계약의 계획 상태를 변경하지 않습니다. GitHub Actions에서는 측정 JSON을 실행별 artifact로 보존합니다.
