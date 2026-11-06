# OCI 직접 HTTPS 선택 구성

앱 0.12.0의 직접 HTTPS 브라우저 로그인은 [서버 계정과 Gmail 인증](account-login.md)을 따릅니다. `owner-token` 환경 이름과 기존 서버 키는 유지하며, 브라우저의 기본 흐름은 이메일 인증 가입과 아이디·비밀번호·서버 세션입니다. 아래 bearer API·서버 환경 구성은 운영·초기 설정 경계로 유지합니다. 실제 계정 업그레이드·기존 과학 기록 보존·메일 설정의 확인 상태는 [계정 배포 기록](oci_accounts_upgrade_verification.json)과 WORKPLAN을 기준으로 합니다. 앱 배포나 Gmail TLS 연결만으로 실제 SMTP 인증·메일 수신·가입·추가 인증을 확인한 것으로 표시하지 않습니다.

2026-11-06 · 앱 0.12.0 계정 안내와 이전 bearer 운영 기록 구분

Cloudflare Access·Tunnel 어댑터 지원은 유지합니다. 이 문서는 외부 DNS의 A/AAAA 레코드로 OCI에 직접 연결하고, Caddy가 HTTPS를 종료하며 Quanta가 계정 세션 또는 운영용 소유자 bearer를 검사하는 구성을 설명합니다. 이 파일과 예시는 서버 설치·방화벽 개방·인증 방식 전환을 실행하지 않습니다.

## 연결과 인증

브라우저는 Caddy의 HTTPS 443에 연결하고 Caddy는 같은 호스트의 `127.0.0.1:8765`에 전달합니다. 앱은 기존 단일 worker·loopback listener·systemd 재시작 정책을 사용합니다. 8765를 외부에 공개하거나 두 번째 Quanta worker를 실행하지 않습니다. 기존 Caddy나 다른 웹 서비스가 있으면 설정을 대조해 병합하며 기존 설정을 예시로 덮어쓰지 않습니다.

최초 설치에서는 [owner-token 환경 예시](../deploy/oci/app.owner-token.env.example)를 `/etc/quanta/app.env`의 출발점으로 사용합니다. 실제 공개 origin은 `https://`와 정확한 hostname으로 지정하고 끝의 `/`는 넣지 않습니다. `QUANTA_AUTH_MODE=owner-token`을 명시하고 `QUANTA_OWNER_TOKEN`은 안전한 난수 32 bytes에서 생성한 **소문자 16진수 64자**로 바꿉니다. 예시 placeholder는 유효한 토큰이 아니므로 시작을 거부합니다. 토큰은 root 소유 0600 앱 환경 파일에 보관하고 URL·소스·Caddy 설정·로그에 넣지 않습니다. Caddy 환경에는 hostname만 전달합니다. 인증 모드를 생략하면 계속 `access`가 기본입니다. 기존 서버의 계정 업그레이드는 이 환경 파일과 소유자 키를 유지합니다.

앱 0.12.0 브라우저에서는 이메일 인증 가입을 마친 뒤 아이디·비밀번호와 선택형 이메일 추가 인증으로 로그인합니다. 정적 화면과 `/ui/auth`는 로그인 전에도 열리지만 계산·기록·준비 상태 API에는 유효한 계정 세션 또는 운영용 소유자 bearer가 필요합니다. 계정 세션의 새로고침·로그아웃·만료 동작은 [계정 안내](account-login.md)를 따릅니다. API의 Host·Origin 검사는 유지되므로 Caddy가 Host나 Origin을 loopback 주소로 바꾸면 안 됩니다.

운영·비공개 초기 설정용 bearer는 기존 내부 소유자 `local`에 연결하며 그 자체로 이메일 소유를 증명하지 않습니다. 앱 0.11.0의 브라우저 토큰 입력·연결 해제·새로고침 재입력은 당시 메모리 인증 방식의 동작입니다. 앱 0.12.0의 일반 계정 로그인은 이메일 확인과 서버 세션을 사용합니다. 기존 bearer를 폐기하는 작업은 서버 비공개 환경 파일의 키 교체·앱 재시작이며 계정 세션의 로그아웃·폐기와 구분합니다. 최초 토큰은 OCI 내부의 비공개 파일에 생성하고, 사용자가 기존의 신뢰한 PuTTY 세션으로 한 번 확인해 초기 설정에 사용할 수 있습니다. 이를 위해 GitHub secret을 추가할 필요는 없습니다. 이 문서는 토큰 생성·조회·교체를 실행하지 않습니다.

## 실제 배포 확인과 다음 단계

[고정 전환 실행 42125582058](https://github.com/Hyunwoo1205/quanta/actions/runs/42125582058)은 2026-11-05 22:57:03 UTC에 성공했습니다. ZeroSSL 인증서 발급, DNS 일치, HTTP 308의 정확한 HTTPS 전환, HTTPS 화면 200, owner-token 인증 안내 200, 익명·잘못된 토큰의 API 401을 확인했습니다. 과거 이메일 누락·공유 등록 도메인 발급 한도는 이 성공 이전의 이력입니다. [ACME 실행 기록](oci_acme_configuration_verification.json)에 이전 실패와 후속 성공을 구분해 보존합니다.

이 공개 검사는 올바른 소유자 접속키를 사용하지 않았으며, 그 자체로 소유자 브라우저·계산 합격을 뜻하지 않습니다. 이후 앱 0.11.0의 [소유자 브라우저 기록](oci_owner_browser_verification.json)에서 저장·실행·결과·다운로드·재실행·취소·새로고침 재인증을 별도로 확인했습니다. 후속 [모바일 사용자 확인](oci_mobile_verification.json), [실제 OS 재부팅 복구](oci_reboot_recovery_verification.json), [일회성 외부 SQLite 복원](oci_off_host_backup_verification.json)은 각 근거의 수행 범위로 구분합니다. 관리형 백업 정책의 콘솔 직접 확인과 전체 볼륨 복원은 미확인입니다. 계정 업그레이드 이후 확인은 [별도 배포 기록](oci_accounts_upgrade_verification.json)을 따릅니다. 키를 Actions나 채팅으로 가져오거나 기존 설치·방화벽·인증서 작업을 반복하지 않습니다.

## Caddy 설정 준비

[Caddyfile.example](../deploy/oci/Caddyfile.example)은 `QUANTA_PUBLIC_HOST`를 한 개의 ASCII DNS hostname으로 받습니다. 이 값은 앱 origin의 hostname과 정확히 일치해야 하며 scheme·경로·port·wildcard·공백을 포함하지 않습니다. 다음 명령은 예시 hostname과 설정을 검사하기 위한 것이며 서비스를 시작하지 않습니다. 실제 배포에는 검증한 Caddy 버전과 배포 파일 SHA256을 고정하고 동일한 버전으로 검사합니다. 로컬 확인에는 공식 릴리스 [v2.11.9](https://github.com/caddyserver/caddy/releases/tag/v2.11.9)를 사용했습니다.

```bash
export QUANTA_PUBLIC_HOST=app.example.net
python3 - <<'PY'
import os
import re
host = os.environ["QUANTA_PUBLIC_HOST"]
labels = host.split(".")
if (len(host) > 253 or len(labels) < 2 or any(
    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
    for label in labels
)):
    raise SystemExit("QUANTA_PUBLIC_HOST must be one lowercase DNS hostname")
print("Expected application origin: https://" + host)
PY
caddy adapt --config deploy/oci/Caddyfile.example --adapter caddyfile --validate >/dev/null
```

실제 Caddy 서비스에도 같은 `QUANTA_PUBLIC_HOST`를 명시적으로 공급합니다. 대화형 shell의 `export`가 systemd 서비스에 자동 전달된다고 가정하지 않습니다. Caddy 인증서 data directory는 쓰기 가능하고 재시작 후에도 보존되어야 합니다. 최초 발급 전에 해당 hostname의 모든 A/AAAA 레코드가 올바른 서버로 향하는지, OCI와 호스트 방화벽의 TCP 80·443 및 기존 서비스의 포트 점유를 확인합니다. 이 예시는 **HTTP/1.1만** 제공하며 브라우저의 HTTP/2 제안은 HTTP/1.1로 연결됩니다. HTTP/2 전용 연결과 HTTP/3은 지원하지 않습니다.

Caddy의 자동 HTTPS는 DNS·포트·CA 검증이 성공한 뒤에만 사용할 수 있습니다. 인증서·DNS·외부 접근을 실제로 검사하기 전에는 배포 완료로 기록하지 않습니다.

## HTTP framing과 확인 범위

Quanta는 `Transfer-Encoding`을 거부합니다. Caddy의 `request_body`는 앱과 같은 1,048,576-byte 상한을 적용하며 `request_buffers 2MiB`는 이 상한보다 큰 buffer를 사용합니다. 공식 문서의 전체 buffering과 Content-Length 설정만으로 chunked 입력의 Transfer-Encoding까지 제거되지는 않는 것을 실제 v2.11.9에서 확인했습니다. 따라서 프록시는 Transfer-Encoding이 있는 요청을 앱에 보내기 전에 400으로 거부합니다. HTTP/1.1 chunked·trailer 입력을 지원하지 않으며, HTTP/2를 비활성화해 별도의 trailer 전송 경로도 열지 않습니다. 일반적인 브라우저 JSON 요청은 알려진 Content-Length로 전달합니다.

upstream도 HTTP/1.1을 사용합니다. Host·Origin·Authorization은 재작성하지 않고 전달하며 토큰을 프록시가 대신 주입하지 않습니다. 스트리밍 입력은 제공하지 않으며 `Incremental: ?1` 요청은 Caddy의 buffering 정책에 따라 거부될 수 있습니다.

2026-11-06에 공식 `caddy_2.11.9_linux_amd64.tar.gz`의 SHA256 `5b8cb7faf8726a2028ad96a66e54e6e81e8f361bc6175e5d22bbd997cc5177fb`를 확인한 뒤 Caddy 실행 파일만 임시 경로에 풀었습니다. 실제 예시의 `adapt --validate`와 [독립 framing 검사](../scripts/verify_caddy.py)를 실행했습니다. 검사는 임시 내부 CA를 신뢰한 로컬 TLS와 별도의 loopback dummy upstream을 사용하며, 공개 CA 요청이나 OS 신뢰 저장소 변경을 하지 않습니다.

```bash
python3 scripts/verify_caddy.py --caddy /path/to/verified/caddy
```

| 입력 | 실제 로컬 결과 |
|---|---|
| HTTP/1.1 POST, JSON 본문·빈 본문 | upstream HTTP/1.1, 정확한 Content-Length, Transfer-Encoding 없음 |
| HTTP/1.1 chunked 및 Trailer 헤더를 포함한 chunked | 프록시 400, upstream 도달 없음 |
| HTTP/2를 제안하는 일반 클라이언트 | HTTP/1.1로 연결되어 일반 JSON 요청 성공 |
| HTTP/2 전용 ALPN | TLS handshake 거부, upstream 도달 없음; 같은 CA·hostname의 후속 HTTP/1.1 요청 성공 |
| 정확히 1 MiB / 1 MiB 초과 본문 | 경계 크기 전달 / 413 거부 |
| Host·Origin·Authorization | 원래 공개 hostname·origin·합성 테스트 bearer 보존 |

최종 로컬 검사는 설정 검사와 요청 9개 사례를 통과했습니다. HTTP/2 전용 연결의 음성 검사는 OpenSSL 오류 문구에 의존하지 않고 TLS handshake 실패를 기록합니다. 이어서 동일한 Python TLS context·CA·hostname에서 HTTP/1.1 POST가 정상 전달되는지 검사해 일반 TLS 실패나 서버 중단을 합격으로 처리하지 않습니다.

실제 운영 검증에는 외부 HTTPS 인증서 신뢰·HTTP→HTTPS 이동, 토큰 없는 API 401, 잘못된 토큰 401, 올바른 토큰의 준비 상태·계산·조회·다운로드, 다른 Host·Origin 거부, 재시작 후 단일 worker와 데이터 보존을 포함합니다. 브라우저에서 인증한 실제 동작과 단순한 TLS 연결 성공을 구분합니다.

## 앱 0.11.0 당시의 실제 OCI 확인 범위

2026-11-06의 [누적 ACME 기록](oci_acme_configuration_verification.json)은 명시적 ZeroSSL 발급과 공개 HTTPS·HTTP 308·익명 및 잘못된 토큰의 401을 확인했습니다. 이 공개 자동검사는 올바른 소유자 키를 사용하지 않았습니다.

이어 사용자가 비공개 인증 입력으로 연결한 실제 데스크톱 브라우저에서 입력 검증·저장, 입자 평가·정적 탐색·양자 상태·다단계 계산, 기록·재실행·취소와 결과·산출물 다운로드를 확인했습니다. [소유자 브라우저 기록](oci_owner_browser_verification.json)은 5개 검증 실험·8개 실행의 실제 UUID와 결과·미확인 범위를 보존합니다. 키 값을 에이전트·로그·저장소로 가져오지 않았으며 원래 앱·인증 방식·배포 소스는 변경하지 않았습니다.

강제 취소 뒤 같은 서비스의 새 입자 재실행, 실제 새로고침의 인증 해제와 비공개 재인증, 저장 실험 5개·실행 8개 보존까지 확인했습니다. 잘못 입력한 키의 거부도 확인했으며 사용자 입력 오류를 앱 결함으로 분류하지 않습니다. 이 데스크톱 확인 당시에는 모바일·OS 재부팅·off-host 또는 관리형 볼륨 복구를 포함하지 않았으며 후속 확인은 위 개별 기록으로 구분합니다. 이 과거 bearer 흐름을 앱 0.12.0의 실제 이메일 수신·계정 가입·추가 인증 검증으로 대신하지 않습니다. 현재 계정 확인 범위는 [계정 배포 기록](oci_accounts_upgrade_verification.json)을 따르며 물리 검증 상태는 계속 `unvalidated`입니다.

공식 참고: [Caddy reverse_proxy와 buffer·header·HTTP transport](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), [요청 본문 상한](https://caddyserver.com/docs/caddyfile/directives/request_body), [요청 matcher](https://caddyserver.com/docs/caddyfile/matchers), [HTTP 프로토콜 설정](https://caddyserver.com/docs/caddyfile/options#protocols), [환경 변수 치환](https://caddyserver.com/docs/caddyfile/concepts#environment-variables), [설정 검사](https://caddyserver.com/docs/command-line#caddy-adapt), [자동 HTTPS 조건](https://caddyserver.com/docs/automatic-https).

