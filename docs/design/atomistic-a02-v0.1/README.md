# A02 계산 엔진·자료·출력 잠금 후보

이 자료는 **사용자 JSON 실험을 실행할 계산 기반**을 준비합니다. JSON의 계·조건·모형·절차·관측량이 원본이며 3D는 편집·관찰 인터페이스입니다. 내부 He/H2·fixture ID를 제품의 고정 실험 메뉴로 사용하지 않습니다. 실제 연산과 시각 편집은 각각 P2/P4에서 같은 실험 계약을 사용하도록 `authoring-requirements.json`에 기준을 명시했습니다.

- `engine-lock.json`: CP2K2026.2 소스와 플랫폼별 이미지 후보·미확인 실행 게이트.
- `source-evidence.json`: 공식 소스 압축파일의 실제 bytes/SHA와 고정 커밋의 관련 파일 식별자.
- `basis-source-selection.json`: MolSSI BSE 고정 커밋의 H/He 기저 계수와 원본 파일 출처.
- `assets/`, `basis-json/`, `references/`: unaugmented cc-pVDZ/VTZ/VQZ version1의 정확한 CP2K/JSON 출력과 원 논문 출처. 계수·지수·수축을 바꾸지 않았습니다.
- `images/`: 레지스트리 manifest/config만 보존합니다. 이미지 레이어 다운로드·설치·실행을 뜻하지 않습니다.
- `density-and-units.json`: 전전자 hard+soft 출력·CUBE 반올림·엔진의 CODATA2006 단위와 A01 CODATA2022 참조값 구분.
- `licenses/`: CP2K GPL 및 BSE BSD 고지 보존.

```bash
python scripts/check_atomistic_a02.py
```

원본 다운로드 자료를 보유한 경우 `--source-archive PATH --source-root PATH --bse-source-dir PATH`로 원본 해시/선택 계수도 대조합니다. 검사기는 설치·CP2K·과학 계산을 실행하지 않습니다. 소스/자료/이미지 식별자 잠금과 실제 바이너리·설치 재현·물리 검증을 구분합니다. 이미지 메타데이터에 CP2K revision 증명이 없어 A03에서 실제 버전/리비전을 확인하고 필요 시 실제 소스를 명시적으로 재고정해야 합니다.

A01의 PBE 전전자 의도·cc-pVXZ 계열·사전 오차 기준·기존 과학 계약은 바꾸지 않았습니다. A03의 격리 설치·기능·자원·취소·밀도 검사와 A04의 실제 프로필/단위/JSON 계약 동결은 후속 작업입니다. 운영0.16.0·인증·DB·기존 의존성·OCI 배포를 변경하지 않습니다.
