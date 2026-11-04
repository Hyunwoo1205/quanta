# 실행 API와 비동기 작업

패키지 `0.6.0`은 기존 모형·계약 `0.2.0`을 그대로 사용하는 단일 호스트 개발용 실행 서비스를 제공합니다. HTTP 요청에서 계산을 직접 기다리지 않고 실행 ID를 받은 뒤 진행 상태와 결과를 조회합니다. 새 계산 모형을 추가하거나 물리 검증 범위를 확대한 단계는 아닙니다.

## 실행과 결과 확인

README의 잠금 환경을 먼저 설치합니다. Linux x86_64·CPython 3.12.14가 현재 기준입니다. 다음 명령은 같은 셸에서 실행합니다. API 토큰은 화면에 출력하지 않고 환경 변수로 전달합니다.

```bash
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
export QUANTA_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
quanta serve --store .cache/local-service --port 8765 &
QUANTA_SERVER_PID=$!
python scripts/service_example.py examples/pair_workflow.json
kill -INT "$QUANTA_SERVER_PID"
wait "$QUANTA_SERVER_PID"
```

서버 시작 메시지가 나온 뒤 예제를 실행합니다. 전경에서 `quanta serve`를 실행하고 다른 터미널에서 **같은 토큰**을 지정해 예제를 실행해도 됩니다. 예제는 새 실험·불변 revision을 만들고 실행을 제출해, 실행 ID와 최종 상태·각 단계의 수치 payload를 출력합니다. 예제를 재실행하면 별도 실험을 만듭니다. 토큰을 바꾸더라도 같은 저장 경로의 고정 소유자 `local`에 연결됩니다.

`Ctrl+C` 또는 SIGTERM으로 정상 종료하면 실행 중 작업에 취소를 요청하고 작업자를 정리합니다. 새 서버는 이전 SQLite 기록을 유지합니다. 강제 종료로 끊긴 작업은 독점 작업자 잠금 획득 후 `FAILED` 또는 `CANCELLED`로 확정하고 대기 중 작업은 계속 실행합니다. 살아 있는 이전 계산 자식도 잠금을 보유하므로 두 작업자가 동시에 계산하지 않습니다.

HTTP 어댑터는 `127.0.0.1`에만 바인딩합니다. 토큰은 32자 이상의 가시 ASCII 문자열이며 요청의 `Authorization: Bearer …`로 인증합니다. 공개 HTTPS·외부 계정·공유·역할 권한·분산 호스팅은 후속 배포 단계입니다.

## 요청 경로

모든 경로에 인증이 필요하며 JSON 요청은 UTF-8·유한 수·중복 키 없음·최대 1 MiB 조건을 따릅니다. 정의의 과학적 한도는 동봉 자원 정책을 그대로 검사합니다. 알 수 없는 요청 필드는 거부합니다.

| 메서드와 경로 | 입력 또는 반환 |
|---|---|
| `POST /v1/experiments` | `{title}` → 서버 발급 실험 ID |
| `GET /v1/experiments?limit=50&cursor=…` | 소유자 범위의 생성 순 목록과 다음 cursor |
| `GET /v1/experiments/{id}` | 실험 metadata와 revision ID 목록 |
| `POST /v1/experiments/{id}/revisions` | `{schema_version,title,definition}` → 불변 revision envelope |
| `GET /v1/revisions/{id}` | 저장한 revision 원본 |
| `POST /v1/validate` | `{schema_version,definition}` → 검증 보고서, 저장·계산 없음 |
| `GET /v1/capabilities` | 실제 구현 연산, 등록부·포트·표현·관측량과 자원 정책 |
| `POST /v1/runs` | `{revision_id}`와 `Idempotency-Key` → 202 실행 ID·고정 입력 해시 |
| `GET /v1/runs/{id}` | 상태·진행·진단·상태 변경 기록·산출물 metadata |
| `POST /v1/runs/{id}/cancel` | 빈 본문 또는 `{}` → 취소 상태 |
| `POST /v1/runs/{id}/replay` | 빈 본문 또는 `{}`와 새 멱등성 키 → 202 새 실행 |
| `GET /v1/runs/{id}/result` | 검증한 공통 계산 결과 envelope, 없으면 409 |
| `GET /v1/runs/{id}/artifacts` | 인증된 산출물 manifest |
| `GET /v1/artifacts/{artifact_id}` | manifest의 SHA-256·크기에 맞는 원본 bytes |

서버가 소유자를 결정하며 요청의 소유자 필드를 신뢰하지 않습니다. 누락·외부 소유자 식별자는 모두 404입니다. revision 수정 경로는 없고 정의를 바꾸려면 새 revision을 만듭니다. 저장 파일의 경로나 비인증 다운로드 URL을 반환하지 않습니다.

## 실행과 취소의 의미

| 현재 상태 | 허용하는 다음 상태 |
|---|---|
| `QUEUED` | `RUNNING`, `CANCELLED`, `FAILED` |
| `RUNNING` | `SUCCEEDED`, `FAILED`, `CANCEL_REQUESTED` |
| `CANCEL_REQUESTED` | `CANCELLED` |
| 종료 상태 | 변경 없음 |

SQLite의 원자적 트랜잭션에서 먼저 확정된 완료·실패 또는 취소가 우선합니다. 취소 요청이 먼저 확정되면 이후 성공을 공개하지 않습니다. 이미 성공한 단계의 검증된 상태·산출물은 취소된 실행에서도 근거로 보존할 수 있으며 전체 성공을 뜻하지 않습니다. 계산기가 취소를 확인할 때 현재 출력은 후속 입력 상태로 승격하지 않습니다.

`progress`는 `completed_steps,total_steps,active_step,active_branch`입니다. 처리한 성공·실패·건너뛴 단계를 세며, 실행하지 않은 취소 단계는 완료 수에 넣지 않습니다. solver 반복 수나 선형대수 호출의 남은 시간을 퍼센트로 바꾸지 않습니다. 전체 작업 상태와 `numerical_status`, `resolution_status`, `physical_validation_status`는 별도 판정입니다.

대기 중 취소, 입력 수락 후 사전 거부, 강제 종료에는 검증된 계산 결과가 없을 수 있습니다. 이 경우 서비스 상태·진단과 불변 입력만 보존하고 가상의 payload를 만들지 않습니다. `/result`는 409를 반환합니다.

## 멱등성·재실행·자원

멱등성 키는 소유자·endpoint별 24시간입니다. 같은 키와 같은 JSON 본문은 같은 실행 ID를 반환하고, 다른 본문은 409 `IDEMPOTENCY_CONFLICT`입니다. JSON 공백·객체 키 순서 차이는 JCS로 정규화합니다. 기존 키의 재요청은 대기열이 가득 차도 새 작업을 만들지 않습니다. 키 유효 기간 후에는 새 실행을 제출할 수 있습니다.

수락 시 원본 revision과 계획·구현·등록부·정책 바인딩을 고정합니다. 작업자는 실행 전에 현재 신뢰하는 코드와 일치하는지 검사하며 다른 구현으로 조용히 바꾸지 않습니다. 재실행은 종료한 원본 실행의 불변 입력에서 새 실행을 시작합니다. 계산 근거가 있으면 그것도 검증하고, 중단으로 결과가 없더라도 수락한 입력·계획이 현재 바인딩과 일치하면 재실행할 수 있습니다. 저장한 소스 문자열은 실행하지 않습니다. 단계 중간 체크포인트 재개는 제공하지 않습니다.

소유자당 대기 작업 10개, 최대 대기 600초, 계산 작업자 1개, 수치 라이브러리별 스레드 1개입니다. 계산 자식 프로세스는 Linux `RLIMIT_AS` 1024 MiB와 CPU 시간 상한, 감독자의 전체 프로세스 벽시계 120초 상한을 적용합니다. 주소 공간 한도는 RSS 측정과 다릅니다. 기존 엔진의 단계 60초·실행 120초 및 산출물 32 MiB 한도도 유지합니다. 자식의 준비·검증·저장 시간도 외부 프로세스 한도에 포함됩니다.

취소는 기존 계산 검사 지점에서 협력적으로 처리합니다. 검사 지점에 돌아오지 않으면 5초 후 계산 프로세스를 강제 종료합니다. 강제 종료에서 아직 확정하지 않은 단계·산출물을 보존했다고 주장하지 않습니다. SQLite 보고서와 산출물 bytes는 하나의 트랜잭션으로 공개합니다. 저장소는 같은 호스트의 로컬 디스크를 사용하고 신뢰하지 않는 사용자가 직접 수정할 수 없게 관리해야 합니다.

## 검증 범위

저장·동시 중복 요청·취소/완료 경쟁·재시작·외부 식별자·HTTP framing·실제 자식 계산·산출물 해시·재실행을 시험합니다. `scripts/verify_service.py`는 실제 HTTP와 별도 계산 프로세스의 측정 기록을 남깁니다. 기존 A01~A04·SI 동등성·B01~B06·WF01~WF06은 별도로 다시 측정합니다. C03의 구현한 단일 호스트 범위를 확인하며 미래 분산 시스템이나 물리적 정확도까지 인증하지 않습니다.
