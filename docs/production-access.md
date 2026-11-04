# 외부 로그인과 운영용 HTTP

2026-11-05 · 패키지 0.9.0 · 입력 계약 0.2.0

Cloudflare Access로 본인 한 명만 인증한 뒤 named Tunnel을 통해 OCI의 루프백 ASGI 서버에 연결하는 어댑터입니다. 화면·API·계산·SQLite는 같은 OCI 호스트에서 실행합니다. 개발용 `quanta serve`의 메모리 bearer 인증은 계속 사용할 수 있습니다.

구현·자동 시험과 실제 외부 서비스를 구분합니다. 서명 검증과 실제 Uvicorn·계산 프로세스의 통합 시험에는 메모리에서 생성한 임시 RSA 키와 JWKS를 사용합니다. 이 시험은 실제 이메일 코드 발송·Cloudflare 계정·공개 TLS·OCI·모바일 브라우저 검증이 아닙니다. 현재 결과는 [검증 기록](production_access_verification.json)에 남깁니다.

## 설정과 실행

설치와 아키텍처 선택은 [ARM 실행 프로필](arm-runtime.md)을 따릅니다. 의존성 27개를 두 CPU별 버전·wheel 해시로 잠급니다. 기존 20개의 버전·배포 파일은 유지하고 Uvicorn·PyJWT와 RSA 검증 의존성을 추가했습니다.

필수 설정은 다음 네 개입니다. 값은 설명용 예시이며 실제 계정·도메인을 지정하기 전에는 외부 로그인이 동작하지 않습니다. 이 네 값은 비밀번호가 아니지만 실제 이메일이나 운영 설정을 공유 소스·로그에 불필요하게 남기지 않습니다. 요청의 JWT·쿠키와 Tunnel 자격 증명은 저장소에 넣지 않습니다.

```bash
export QUANTA_PUBLIC_ORIGIN=https://quanta.example.com
export QUANTA_ACCESS_TEAM_DOMAIN=your-team.cloudflareaccess.com
export QUANTA_ACCESS_AUDIENCE=your-application-audience-tag
export QUANTA_ALLOWED_EMAIL=owner@example.com
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
quanta serve-production --store /srv/quanta/data --port 8765
```

`PUBLIC_ORIGIN`은 경로·끝 슬래시·쿼리가 없는 소문자 HTTPS origin입니다. 명시적인 기본 포트 `:443`은 생략하고, 비기본 포트가 있다면 실제 브라우저 origin·Host와 일치시킵니다. 팀 도메인은 `<team>.cloudflareaccess.com`, audience는 해당 Access 애플리케이션의 AUD tag, 이메일은 허용할 하나의 주소입니다. 신원은 검증한 issuer·audience·이메일에 따라 기존 내부 소유자 `local`로만 연결합니다. 요청의 owner·role·이메일 헤더를 기본 계정으로 승격하지 않습니다.

명령은 `127.0.0.1`에 Uvicorn 프로세스 하나와 계산 감독자 하나를 실행합니다. 외부 전달 헤더·`WEB_CONCURRENCY`로 소유권이나 프로세스 수를 바꾸지 않습니다. 자동 reload·HTTP access log를 끄고 32개 동시 요청, 10초 본문 수신, 1 MiB 본문, 20초 HTTP 정상 종료 상한을 적용합니다. 계산 자식의 기존 시간·메모리·취소 정책은 유지합니다.

실제 OCI에서는 데이터 볼륨 마운트 확인·비 root 실행·재시작 정책·백업 복구를 구성한 뒤 공개 경로를 연결합니다. 이 명령 자체가 볼륨 마운트·백업 설정을 대신하지 않습니다. Docker 이미지의 기본 명령은 여전히 계약 검사입니다.

## Access와 Tunnel 연결 순서

1. 도메인을 준비하고 Access의 자체 호스팅 애플리케이션을 먼저 만듭니다. 허용 정책에는 본인 이메일 하나만 넣고 이메일 일회용 코드 또는 선택한 기존 인증 공급자를 구성합니다.
2. 해당 앱의 팀 도메인·AUD와 서버의 네 필수 설정을 맞춥니다. 알려진 팀의 `/cdn-cgi/access/certs`만 HTTPS로 조회하며 JWT에 포함된 URL로 공개키를 선택하지 않습니다.
3. named Tunnel의 공개 hostname을 `http://127.0.0.1:8765`에 연결합니다. 서버가 검사하는 공개 도메인으로 HTTP Host를 유지하거나 명시적으로 설정합니다. 정적 파일·`/ui/auth`·API·산출물 전체를 Access 애플리케이션 범위에 포함합니다.
4. 원본 설정에서 `Protect with Access`를 켜고 아래 설정과 동일한 팀·AUD를 적용합니다. 현재 어댑터는 청크 본문을 거부하므로 `disableChunkedEncoding`도 켭니다.
5. OCI에 앱 HTTP 포트를 외부로 열지 않고 허용·다른 계정·만료 세션·직접 접근을 실제 브라우저로 확인합니다. 외부 연결 전 앱을 임시 공개하지 않습니다.

로컬 관리 Tunnel의 설명용 `originRequest` 예시입니다. 실제 Tunnel ID·자격 증명 파일은 별도 관리합니다.

```yaml
originRequest:
  httpHostHeader: quanta.example.com
  disableChunkedEncoding: true
  access:
    required: true
    teamName: your-team
    audTag:
      - your-application-audience-tag
```

## 검증과 화면 동작

앱은 `Cf-Access-Jwt-Assertion`의 RS256 서명·issuer·audience·exp·iat·nbf·앱 토큰 유형·허용 이메일·subject를 확인합니다. JWT·JWKS의 중복 키, 잘못된 알고리즘·키 유형·외부 키 URL·비정상 크기를 거부합니다. 키 캐시는 300초, 조회 시도 간격은 최소 30초이며 새 키 교체 반영이 최대 이 간격만큼 지연될 수 있습니다. 조회는 3초·256 KiB로 제한하고 만료 캐시로 인증을 허용하지 않습니다.

Host와 Origin은 설정값을 검사하고, 변경 요청은 같은 Origin을 필수로 받습니다. API 도구로 변경 요청을 보낼 때도 `Origin: <설정된 HTTPS origin>`이 필요합니다. 원본 JSON bytes를 기존 파서에 보내므로 중복 키·비유한 수 거부와 숫자·`-0` 보존을 유지합니다. 다른 출처를 허용하는 CORS 헤더를 추가하지 않습니다.

화면은 `/ui/auth`로 개발 bearer·운영 Access 모드를 확인합니다. Access에서는 같은 출처의 로그인 쿠키를 사용하며 API 토큰을 입력·영구 저장하지 않습니다. 로그인 만료·로그인 HTML·리다이렉트를 계산 결과로 읽지 않습니다. 인증 실패 또는 연결 불확실 시 polling과 비공개 결과를 정리하고 편집 중인 입력·제목은 현재 화면에 유지합니다. 재로그인·로그아웃 이동 전에는 JSON 내보내기를 안내합니다. 재로그인 시 기록을 조회하고 계산을 자동 재제출하지 않습니다. 로그아웃이 서버 계산을 취소하지 않습니다.

`GET /health/ready`는 인증 후 계산 감독자 상태·DB 쓰기 트랜잭션 접근·디스크 여유 128 MiB를 확인합니다. 실패 시 503을 반환하고 새 변경 요청을 받지 않습니다. 기존 결과 조회는 감독자 장애 시에도 유지합니다. 상세 파일 경로·원본 오류·JWT는 외부 응답에 넣지 않습니다.

```bash
python scripts/verify_production.py --output .cache/production_verification.json
```

P01~P06은 실제 HTTP·서명·저장·중복 제출·자식 계산·독립 해석식·원본 산출물 SHA·로그인 갱신·작업자 상태를 측정합니다. 주입한 상태 오류 검사를 실제 프로세스 crash 검증으로 표시하지 않습니다. 기존 A·SI·B·WF·S·W 기준과 물리 검증 `unvalidated`를 유지합니다. 구현·잠금이 바뀌었으므로 업그레이드 전 실행 수락 중지·작업 비우기·기존 이미지 보존은 [배포 계획](deployment-plan.md)을 따릅니다.

공식 참고: [Access JWT](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), [앱 토큰 필드](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/), [Tunnel 원본 설정](https://developers.cloudflare.com/tunnel/reference/origin-parameters/), [Uvicorn 설정](https://uvicorn.dev/settings/), [ASGI 수명 관리](https://asgi.readthedocs.io/en/stable/specs/lifespan.html).
