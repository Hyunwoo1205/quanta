# OCI 직접 HTTPS 선택 구성

2026-11-06 · 선택 배포안 · 실제 공개 TLS 미검증

Cloudflare Access·Tunnel의 기본 구성은 유지합니다. 이 문서는 외부 DNS의 A/AAAA 레코드로 OCI에 직접 연결하고, Caddy가 HTTPS를 종료하며 Quanta가 단일 소유자 bearer 토큰을 검사하는 대안을 설명합니다. 이 파일과 예시는 서버 설치·방화벽 개방·인증 방식 전환을 실행하지 않습니다.

## 연결과 인증

브라우저는 Caddy의 HTTPS 443에 연결하고 Caddy는 같은 호스트의 `127.0.0.1:8765`에 전달합니다. 앱은 기존 단일 worker·loopback listener·systemd 재시작 정책을 사용합니다. 8765를 외부에 공개하거나 두 번째 Quanta worker를 실행하지 않습니다. 기존 Caddy나 다른 웹 서비스가 있으면 설정을 대조해 병합하며 기존 설정을 예시로 덮어쓰지 않습니다.

[owner-token 환경 예시](../deploy/oci/app.owner-token.env.example)를 `/etc/quanta/app.env`의 출발점으로 사용합니다. 실제 공개 origin은 `https://`와 정확한 hostname으로 지정하고 끝의 `/`는 넣지 않습니다. `QUANTA_AUTH_MODE=owner-token`을 명시하고 `QUANTA_OWNER_TOKEN`은 안전한 난수 32 bytes에서 생성한 **소문자 16진수 64자**로 바꿉니다. 예시 placeholder는 유효한 토큰이 아니므로 시작을 거부합니다. 토큰은 root 소유 0600 앱 환경 파일에 보관하고 URL·소스·Caddy 설정·로그에 넣지 않습니다. Caddy 환경에는 hostname만 전달합니다. 인증 모드를 생략하면 계속 `access`가 기본입니다.

브라우저에서는 HTTPS 화면의 토큰 입력으로 API 인증을 시작합니다. 정적 화면과 `/ui/auth`는 입력 전에도 열리지만 계산·기록·준비 상태 API에는 올바른 bearer 토큰이 필요합니다. API의 Host·Origin 검사는 유지되므로 Caddy가 Host나 Origin을 loopback 주소로 바꾸면 안 됩니다.

이 방식에서는 토큰을 가진 사람이 같은 소유자로 인증됩니다. 이메일 계정의 신원 확인은 하지 않으며, 화면의 연결 해제는 해당 브라우저에서 토큰을 지울 뿐입니다. 기존 토큰을 폐기하려면 서버의 비공개 환경 파일에서 새 난수 토큰으로 교체하고 앱을 재시작합니다. 최초 토큰은 배포 단계에서 OCI 내부의 비공개 파일에 생성하고, 사용자가 기존의 신뢰한 PuTTY 세션으로 한 번 확인해 사용할 수 있습니다. 이를 위해 GitHub secret을 추가할 필요는 없습니다. 이 문서는 토큰 생성·조회·교체를 실행하지 않습니다.

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

공식 참고: [Caddy reverse_proxy와 buffer·header·HTTP transport](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), [요청 본문 상한](https://caddyserver.com/docs/caddyfile/directives/request_body), [요청 matcher](https://caddyserver.com/docs/caddyfile/matchers), [HTTP 프로토콜 설정](https://caddyserver.com/docs/caddyfile/options#protocols), [환경 변수 치환](https://caddyserver.com/docs/caddyfile/concepts#environment-variables), [설정 검사](https://caddyserver.com/docs/command-line#caddy-adapt), [자동 HTTPS 조건](https://caddyserver.com/docs/automatic-https).
