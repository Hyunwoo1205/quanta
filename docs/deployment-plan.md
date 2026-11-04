# 비공개 클라우드 파일럿 배포 계획

작성일: 2026-11-04 · 기준 소스: `959dc2cfceb1e271ee99e7fe6b6e598d4f4d3d43` · 상태: 계획

## 목표와 범위

첫 배포는 **본인 한 명만 로그인해 사용하는 비공개 연구 작업 공간**으로 만듭니다. 브라우저에서 실험 작성 → 검증 → 저장 → 실행 → 결과·원본 다운로드를 완료하고, 서버 재시작과 백업 복구 후에도 기록을 보존하는 것이 목표입니다.

현재 패키지는 `0.7.0`, 입력 계약은 `0.2.0`입니다. 이 문서는 운영용 인증·HTTP 어댑터, 배포 패키지와 실제 사용 검증의 계획이며 구현 완료 기록이 아닙니다. 서버 구매·도메인 변경·클라우드 배포는 아직 수행하지 않았습니다. 기존 계산 모형·정밀도·수치 기준을 유지하며 물리 검증 상태는 계속 `unvalidated`입니다.

## 권장 구성과 비용

| 항목 | 첫 배포의 선택 | 이유·조건 |
|---|---|---|
| 호스트 | AWS Lightsail 서울, Linux x86_64, 2 vCPU·4 GB RAM·80 GB SSD | 현재 Linux 계산 자식 프로세스와 로컬 SQLite를 유지하기 쉬운 단일 VM |
| 진입점 | 소유한 도메인의 HTTPS 주소 하나 | 화면·API·산출물 다운로드를 같은 출처로 제공 |
| 로그인 | Cloudflare Access, 본인 이메일만 허용, 이메일 일회용 코드 | 초기에는 별도 비밀번호 저장·회원가입 없이 접속 |
| 원본 연결 | Cloudflare named Tunnel → 호스트 내부 HTTP | 계산 서버의 HTTP 포트를 인터넷에 직접 열지 않음 |
| 앱 | 운영용 ASGI 어댑터 + Uvicorn 프로세스 1개 | 기존 실행 서비스와 단일 계산 감독자 재사용 |
| 계산 | 동시에 자식 프로세스 1개, 수치 스레드 1개 | 현재 자원·대기열 정책 유지 |
| 영속 저장 | 같은 VM의 로컬 SSD에 별도 데이터 디렉터리 | 앱 이미지 교체와 DB 수명을 분리 |
| 백업 | SQLite 일관된 스냅샷 → 암호화한 호스트 밖 저장소 | 기본안은 비공개 S3 저장소, 복구 시험 포함 |

2026-11-04 공식 공개 요금 기준 Linux IPv4 2 vCPU·4 GB·80 GB Lightsail 번들은 **월 US$24**입니다. Cloudflare Access는 50명 이하 무료 요금제를 사용할 수 있습니다. 도메인·백업 저장·추가 전송·세금은 별도이며, 구매 시 해당 계정의 지역별 실제 견적을 다시 확인합니다. 기존 DigitalOcean 계정을 활용한다면 Singapore의 Basic Regular 2 vCPU·4 GiB·80 GiB 월 US$24가 대안입니다. 두 호스트를 함께 운영하지 않습니다.

이 크기는 단일 사용자 파일럿의 **초기 가정**입니다. Lightsail은 버스트 CPU이므로 지속 계산에서는 크레딧과 기준 성능의 영향을 받습니다. 실제 호스트에서 계산 시간·최대 메모리·동시 HTTP 응답을 측정한 뒤 크기를 확정하며, 긴 계산을 계속 돌릴 필요가 생기면 전용 CPU 상품을 다시 비교합니다. 단일 VM 장애 시 서비스 중단을 허용하는 초기 구성입니다.

프런트엔드만 따로 배포하거나 분산 큐·네트워크 SQLite를 도입하지 않습니다. SQLite WAL은 같은 호스트에서 사용해야 하고, 현재 계산기는 네이티브 Python 의존성·자식 프로세스·Linux 자원 제한을 사용합니다. Cloudflare Workers에 현재 엔진을 그대로 올리는 방식은 이번 배포안에 맞지 않습니다.

## 구현 순서와 통과 조건

| 순서 | 작업과 산출물 | 다음 단계로 가는 조건 |
|---|---|---|
| 1. 운영 인증·HTTP | ASGI 어댑터, Access JWT 검증, 명시적 설정 검사, 로그인 세션에 연결한 화면 | 인증·소유권·Host·Origin·원본 JSON 보존의 로컬 통합 시험 통과 |
| 2. 실행·저장·복구 | 운영 컨테이너 실행 명령, 단일 작업자 수명 관리, 영속 볼륨, 상태 점검, 백업·복구 명령과 운영 설명서 | 설치 이미지의 실제 계산·종료·재시작 및 별도 위치 복구 시험 통과 |
| 3. 비공개 실제 배포 | 선택 호스트, 도메인·Access 정책·Tunnel, 데이터 이전, 고정 이미지 digest 기록 | 허용 계정만 접속, 직접 HTTP 접근 차단, 실제 호스트 자원·수치 측정 통과 |
| 4. 실제 브라우저 검증 | 데스크톱·모바일 전체 작업 흐름과 로그인 만료·장애 기록 | 아래 사용·복구 기준을 실제 환경에서 만족하고 미확인 항목을 명시 |

1~2단계는 유료 서버를 만들기 전에 진행할 수 있습니다. 다음 구현 단위는 운영 인증·배포 준비를 중심으로 한 `0.8.0`을 후보로 삼되, 버전은 구현 완료 시 확정합니다. 이 계획 작성으로 패키지 버전이나 의존성 잠금은 바꾸지 않습니다.

## 1. 운영 인증과 HTTP 경계

현재 `quanta serve`는 루프백 전용 `http.server`와 메모리 bearer 토큰을 사용하는 개발 어댑터입니다. Host·Origin도 localhost에 한정되고 브라우저 요청은 `credentials: 'omit'`입니다. 도메인만 연결해서 공개할 수 없으므로 운영 어댑터를 추가합니다.

- 기존 계산·저장 서비스는 재사용하고 공개 요청 처리를 얇은 ASGI 어댑터에 연결합니다. Uvicorn은 `workers=1`, 자동 reload 없이 실행합니다. 개발용 루프백·bearer 모드는 유지합니다.
- 공개 HTTPS origin과 호스트명을 설정에 고정합니다. 신뢰하는 Tunnel 경로 외의 전달 헤더를 신뢰하지 않으며 Host·Origin 검사를 와일드카드로 완화하지 않습니다. 변경 요청은 같은 출처·허용 Content-Type 경계를 검사합니다.
- 원본 요청 bytes를 기존 엄격한 파서에 전달합니다. 1 MiB 입력 제한·중복 키·비유한 수 거부, 정수·실수 토큰과 `-0` 부호 보존을 유지합니다. 프레임워크의 자동 JSON·숫자 변환으로 과학 입력을 바꾸지 않습니다.
- Access 애플리케이션과 본인 이메일 허용 정책을 **공개 라우트보다 먼저** 구성합니다. `cloudflared`의 Access 검증도 켜고 앱에서도 `Cf-Access-Jwt-Assertion`의 서명·고정 알고리즘·issuer·audience·유효 기간을 검증합니다. 알려진 팀의 JWKS 주소만 사용하고 키 캐시·교체·갱신 빈도 상한을 처리합니다. 임의 이메일 헤더나 토큰의 원격 키 URL을 신뢰하지 않습니다.
- 검증한 허용 외부 계정을 기존 내부 소유자 `local`에 명시적으로 연결하여 현재 실험 기록을 승계합니다. 신원 누락이나 다른 계정에 기본 소유자를 부여하지 않습니다. 다중 사용자 가입·공유는 별도 확장입니다.
- 운영 화면은 API·산출물 요청 모두 `credentials: 'same-origin'`으로 로그인 세션을 사용합니다. 토큰을 수동 입력하거나 브라우저 영구 저장소에 보관하지 않습니다. 실험·실행·다운로드 전체에 같은 인증·소유권 검사를 적용합니다.
- 로그인 만료·로그인 HTML 응답·인증 리다이렉트를 정상 계산 결과로 처리하지 않습니다. polling을 멈추고 재로그인을 안내하며, 미저장 입력은 현재 화면에서 보존하거나 이동 전에 내보낼 수 있게 합니다. 재로그인 후 서버 기록을 다시 조회하고 계산을 자동 중복 제출하지 않습니다. 로그아웃은 이미 수락한 서버 계산을 취소하지 않습니다.

Uvicorn·JWT 검증 등 새 의존성이 필요하면 구현 단계에서 유지되는 공식 버전을 확인하고 모든 전이 의존성의 wheel 버전·해시를 잠급니다. CPython 3.12.14·Linux x86_64와 기존 과학 계산 의존성 기준은 별도 변경 없이 유지합니다.

## 2. 컨테이너·데이터·운영 상태

현재 Dockerfile의 기본 명령은 계약 검사이므로 운영 서버 시작 명령과 배포 설정을 별도로 작성합니다. 비 root 앱, 고정 이미지 digest, 비밀 설정 분리, 재시작 정책과 정상 종료를 포함합니다. 실행 토큰·Tunnel 자격 증명·백업 키를 git·이미지·URL·로그에 넣지 않습니다.

HTTP 프로세스 하나가 계산 감독자 하나를 시작하고 기존 프로세스 간 독점 잠금을 유지합니다. HTTP worker나 복제본을 늘려 계산 감독자가 중복되는 배포를 금지합니다. 데이터는 같은 호스트의 로컬 영속 디렉터리에 두고 권한·여유 공간을 확인합니다.

기존 계산 자식의 주소 공간 1,024 MiB·벽시계 120초·단일 수치 스레드와 대기열 정책을 유지합니다. 컨테이너 전체 제한은 HTTP·감독자·자식과 호스트 여유를 포함해 실제 측정 후 설정합니다. 계산 결과를 빨리 얻기 위해 수치 판정이나 자원 상한을 조용히 변경하지 않습니다.

운영 상태 점검은 HTTP 응답만 확인하지 않습니다. 감독자 thread 생존·치명적 오류, DB 접근 가능 여부와 디스크 여유를 readiness에 반영하고, 상세 진단은 외부에 공개하지 않습니다. 작업자 오류·반복 재시작·백업 실패·디스크 부족을 운영 기록에서 확인할 수 있게 합니다. 입력 전문·인증 헤더를 기록하지 않고 request/run ID·오류 코드·시각으로 추적합니다.

## 3. 백업·업그레이드·롤백

- 실행 중 DB는 Python SQLite backup API 등 일관된 스냅샷 절차로 보관합니다. 활성 DB 파일 하나만 복사해 WAL 변경을 빠뜨리지 않습니다. 저장된 실험·불변 revision·고정 계획·실행 이력·산출물이 함께 복구되어야 합니다.
- 매일 백업 7개·주간 백업 4개와 업그레이드 직전 백업을 초기 보존안으로 둡니다. 호스트 밖에 암호화해 저장하고 앱의 운영 데이터는 자동 삭제하지 않습니다. 업로드 완료·크기·해시·복구 가능 여부를 확인합니다.
- 목표 RPO는 24시간, 목표 RTO는 1시간입니다. 이는 **복구 시험 전의 목표**이며 보장된 실측치가 아닙니다. 별도 디렉터리 또는 대체 VM에 복원해 SQLite integrity와 기록·산출물 해시, 실제 조회·다운로드를 확인하고 소요 시간을 남깁니다.
- 첫 실사용 전에 한 번 복구하고, 이후 스키마 변경·배포 절차 변경 때 다시 확인합니다. 원본 데이터를 복구 시험으로 덮어쓰지 않습니다.

수락한 실행 계획은 패키지 버전과 전체 Python 구현에 묶입니다. 인증 어댑터를 추가하는 변경도 고정 구현 해시를 바꿀 수 있으므로 업데이트 시 새 실행 수락을 중지하고 대기·실행 작업을 비운 뒤 백업·이미지 교체를 수행합니다. 처리할 수 없는 고정 계획을 새 코드로 조용히 다시 계획하지 않습니다.

이전 이미지 digest·잠금·DB 버전을 함께 보관합니다. 이전 실행의 엄밀한 replay는 일치하는 신뢰 이미지가 필요합니다. 여러 버전 replay를 현재 앱이 자동 분기하는 기능은 아직 없습니다. 필요할 때 이전 이미지와 백업 사본의 격리 실행 절차를 마련하고, 준비되지 않았으면 재실행 불가 이유를 명확히 표시합니다.

롤백은 단일 인스턴스를 멈춘 뒤 이전 이미지로 교체합니다. DB 스키마가 역호환되지 않으면 검증한 이전 백업을 사용하며, 복원 시점 이후의 기록 손실 범위를 먼저 확인합니다. 동일 SQLite에 구·신 버전을 동시에 연결하는 rolling 배포는 하지 않습니다.

## 4. 실제 검증과 완료 기준

기준 소스의 [CI 41829356124](https://github.com/Hyunwoo1205/quanta/actions/runs/41829356124)는 Python 399개·Node 25개 시험, 여섯 수치·서비스·웹 측정, 설치 wheel·컨테이너 실행을 통과했습니다. 기존 실제 브라우저 기록은 정적 데스크톱 확인이며 **인증된 브라우저 계산·모바일 검증의 근거가 아닙니다**. 운영 어댑터 구현 후 새 소스에 대한 회귀와 아래 검증을 따로 남깁니다.

| 영역 | 실제 확인할 동작 |
|---|---|
| 접근 | 허용 이메일 로그인, 미인증·다른 계정·만료/위조 JWT·잘못된 audience 거부, Host·교차 출처 요청 차단, HTTP 포트 직접 접근 차단 |
| 작성·실행 | 예제 선택, 원본 숫자와 `-0` 보존, 오류 표시, 저장 후 실행, 동일 멱등성 키 재시도로 중복 실행 없음 |
| 결과 | 쌍 계산·정적 탐색·양자·다단계 실행의 실제 표·그래프, 상태 구분, 원본 bytes·크기·SHA가 맞는 다운로드 |
| 상태 변화 | 진행·취소·새 replay, 연결 끊김·세션 만료·재로그인 후 기록 재조회, 미저장 입력 보호 |
| 화면 | 데스크톱 Chrome 및 실제 사용하는 모바일 Safari 또는 Chrome의 입력·표·그래프·다운로드·가로 넘침 |
| 장애·복구 | 정상 종료·재시작, 계산 자식 종료·감독자 실패 감지, 디스크 부족 시 기록 보호, 별도 위치 백업 복원 |
| 자원·재현 | 실호스트 wall time·메모리·CPU credit·HTTP 응답, 현재 A·SI·B·WF·S·W 기준과 환경/이미지/측정 해시 |

브라우저 자동화·모바일 viewport 검사는 보조 근거로 활용하되 실제 기기 검증과 구분합니다. 최소한 실제 배포 URL에서 로그인 → 검증 → 저장 → 계산 → 결과·다운로드와 재시작·복구가 확인되어야 파일럿 완료로 기록합니다. 확인하지 못한 기기·장애는 통과로 표시하지 않습니다.

## 실제 배포 전에 필요한 입력

호스트 계정과 결제 예산, 소유한 도메인·Cloudflare 계정, 허용할 로그인 이메일, 백업 저장소·복구 키 보관 위치가 필요합니다. 이 값들이 없어도 운영 어댑터·컨테이너·백업 도구의 로컬 구현과 검증은 먼저 진행할 수 있습니다. 배포 시점에는 사용할 주소·최종 견적·데이터 이전 대상을 구체화합니다.

## 근거 자료

가격·서비스 조건은 2026-11-04 확인 기준이며 실제 배포 시 다시 확인합니다.

- [AWS Lightsail 요금](https://aws.amazon.com/lightsail/pricing/), [지원 지역](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-regions-and-availability-zones-in-amazon-lightsail.html), [CPU 기준 성능·버스트](https://docs.aws.amazon.com/lightsail/latest/userguide/baseline-cpu-performance.html)
- [DigitalOcean Droplet 요금](https://www.digitalocean.com/pricing/droplets)
- [Cloudflare Zero Trust 요금](https://www.cloudflare.com/plans/), [이메일 일회용 코드](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/)
- [Access로 자체 호스팅 앱 보호](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/), [Access JWT 검증](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), [Tunnel 원본 설정](https://developers.cloudflare.com/tunnel/reference/origin-parameters/)
- [Python HTTP 서버의 운영 제한](https://docs.python.org/3.12/library/http.server.html), [Uvicorn 배포](https://uvicorn.dev/deployment/), [PyJWT 검증](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [SQLite 백업 API](https://www.sqlite.org/backup.html), [Python SQLite backup](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup), [SQLite WAL 제약](https://www.sqlite.org/wal.html), [Workers 자원 제한](https://developers.cloudflare.com/workers/platform/limits/)
