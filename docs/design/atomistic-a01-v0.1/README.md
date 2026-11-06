# A01 원자계 범위·기준·입력 묶음

이 디렉터리는 원자핵+전자 기반 첫 계산 경로의 **비실행 설계 자료**입니다. 설명과 선정 이유는 기존 [첫 원자계 상세설계](https://docs.google.com/document/d/14L4CkkRRF-yW0TXBXeKFoe4EL76jLzUL4VjqzfOIPA0)의 A01 절을 따릅니다. 앱0.16.0·기존 과학 계약·운영 기능을 바꾸지 않습니다.

- `profile.json`: 중성·닫힌껍질 He/H2 내부 검증 범위와 PBE 전전자 계산 의도, 미지원 조건·후속 동결 게이트.
- `reference-data.json`: NIST 독립 물리 기준·CODATA2022 상수·공식 계산/전자장 의미의 출처.
- `fixtures.json`: 정적 원자/분자·비평형·회전/이동·순서·단위와 후속 P3 운동 seed, 명시적 거부 입력.
- `validation-plan.json`: 연동·수치·전자장·대칭·물리 모형별 사전 기준. 과학 검사는 아직 미실행입니다.
- `manifest.json`: 지정한 파일의 정확한 UTF-8 bytes·크기·SHA-256. RFC8785 과학 상태 해시와 다른 대상입니다.

```bash
python scripts/check_atomistic_a01.py --output docs/atomistic_a01_design_verification.json
```

이 검사는 입력 의미·단위/좌표 변환·핵 질량/초기 운동량·참조/파일 해시를 대조합니다. 전자구조 엔진·힘 계산·원자 운동·3D·물리 정확도의 합격시험이 아닙니다. 내부 거부 코드는 공개 API에 등록되지 않았습니다. 실제 관측량과 결과를 만들거나 `physical_validation_status=unvalidated`를 승격하지 않습니다.

첫 검증계는 사용자가 선택할 고정 실험 메뉴나 플랫폼 전체 지원 범위가 아닙니다. A02에서 엔진/자료 버전·배포 및 기저 파일 해시·전전자 밀도 export를 확인하고 A03 실측/A04 계약 동결을 거친 뒤 실행을 지원합니다. 실패하면 원인과 변경 이유를 명시하며 모형·근사·오차 기준을 조용히 바꾸지 않습니다.
