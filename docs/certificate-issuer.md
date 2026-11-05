# 인증서 발급 한도와 명시적 ACME 전환

2026-11-06 · 앱 0.11.0 · 입력 계약 0.2.0

현재 OCI의 앱·IPv4 웹 포트·HTTP redirect는 확인됐습니다. [읽기 전용 진단](oci_certificate_diagnostics.json)은 Let’s Encrypt의 등록 도메인 발급 한도를 확인했습니다. 로그의 600초는 Caddy의 재시도 간격이며 CA 한도가 풀리는 시각을 뜻하지 않습니다. 실제 개인 도메인·이메일·IP·원본 로그·개인키는 이 기록에 보존하지 않습니다.

발급을 계속 기다리는 기본 설정과 별도로, 사용자가 연락용 이메일을 명시적으로 제공하면 ZeroSSL의 무료 ACME endpoint를 선택할 수 있습니다. 대상은 `https://acme.zerossl.com/v2/DV90`이며 별도 유료 REST issuer를 사용하지 않습니다. Caddy v2.11.9는 이메일로 ZeroSSL EAB 계정을 자동 설정할 수 있습니다. 연락 이메일은 이 인증기관에 전달되므로 사용자가 정한 값을 사용합니다.

GitHub의 `oci-preflight` 환경 Secret `QUANTA_ACME_EMAIL`로 값을 공급합니다. 이메일은 저장소·공개 로그에 넣지 않고 필요한 전환 작업에만 전달합니다. 실제 전환은 기존 Caddy 설정·비공개 환경·보호된 설치 기록을 검증하고 알려진 설정만 새 후보로 바꿉니다. 앱 접속키·DB·SSH 키·인증서 기존 상태는 유지하며 Quanta HTTPS 서비스만 재시작합니다. 공급한 이메일이 없으면 전환하지 않습니다.

발급 완료는 시스템 CA 신뢰를 사용한 TLS와 공개 HTTP→HTTPS 전환·화면·인증 모드·인증 없는 API 및 잘못된 토큰 401을 확인한 뒤 기록합니다. 실제 소유자 브라우저 로그인은 별도 사용자 확인 범위입니다.

공식 근거: [Caddy v2.11.9 기본 issuer](https://github.com/caddyserver/caddy/blob/v2.11.9/modules/caddytls/automation.go#L480), [이메일을 사용하는 ZeroSSL EAB](https://github.com/caddyserver/caddy/blob/v2.11.9/modules/caddytls/acmeissuer.go#L367), [ZeroSSL 무료 ACME](https://zerossl.com/documentation/acme).
