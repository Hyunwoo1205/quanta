# Quanta

검증 가능한 물리·화학 모형을 연결하고, 연구자가 실험을 직접 구성하는 연구 시뮬레이션 플랫폼을 개발합니다. 특정 활용 분야로 목표를 한정하지 않으며 모형의 적용 범위·근사·수치 오차·검증 근거를 함께 관리합니다.

현재 릴리스는 **개발 기반과 실험 정의 검증기**입니다. 계산 엔진, 실행 서버, 웹 화면은 아직 구현하지 않았습니다. 입력이 유효하다는 판정은 계산이 수행되었거나 물리적 정확도가 검증되었다는 뜻이 아닙니다.

## 시작하기

Linux x86_64와 CPython 3.12.14를 기준으로 합니다. 직접·전이 의존성은 해시가 포함된 잠금 파일로 관리합니다.

```bash
git clone https://github.com/Hyunwoo1205/quanta.git
cd quanta
bash scripts/bootstrap.sh
source .venv/bin/activate
quanta environment
quanta check-contracts
quanta validate contracts/v0.2.0/examples/pair_revision.json
quanta validate contracts/v0.2.0/examples/quantum_revision.json --format text
python -m pytest
```

`python -m quanta`로도 같은 명령을 실행할 수 있습니다. 검증 성공의 종료 코드는 `0`, 입력·환경·계약 오류는 `2`입니다. 표준 입력은 `quanta validate -`를 사용합니다. 검증 보고서에는 오류 코드·JSON Pointer·단계·분기 정보를 포함합니다.

## 구현 범위

- UTF-8 JSON의 중복 키, 비유한 수, 잘못된 문자와 지원하지 않는 버전을 거부합니다.
- JSON Schema Draft 2020-12와 등록 모듈의 엄격한 스키마를 함께 적용합니다. 스키마는 동봉된 등록부에서만 해석합니다.
- 단위·척도·표현식·초기 정의역·실험 단계·변경값·반복 축·자원 상한을 검사합니다.
- 유효한 작성 정의를 RFC 8785로 정규화해 `input_sha256`을 계산합니다. 다른 해시의 대상은 별도 계약으로 구분합니다.
- 첫 모듈의 등록은 구현 계획을 나타냅니다. `physical_validation_status`는 `unvalidated`이며 수치 합격 시험은 아직 실행하지 않습니다.

모든 미래 모형을 처음 두 모듈의 차원·경계·수식·정밀도에 제한하지 않습니다. 새 기능은 등록 규격과 실제 검증을 갖춘 뒤 제공하며, 시간 변화·모형 결합 등은 확장 후보로 관리합니다.

## 저장 구조

| 위치 | 내용 |
|---|---|
| `src/quanta/` | 입력 검증, 등록부, 정규화·해시, CLI |
| `contracts/v0.2.0/` | 버전 관리되는 스키마·정책·예제·계획 |
| `tests/` | 정상·오류 입력, 등록부, 정규화 기준 시험 |
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
