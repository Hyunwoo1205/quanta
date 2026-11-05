# PC 없이 OCI 연결을 검증하는 첫 단계

## 선택한 실행 경로

현재 대화·기존 SSH 키·서버 구성을 유지하고 초기 설정을 줄이기 위해 GitHub 클라우드 실행기를 선택합니다. OCI에 Tailscale을 설치하거나 새 Codex Cloud 환경으로 작업을 옮기지 않습니다. Plink는 GitHub 실행기에서만 준비하며 서버의 기존 SSH와 PPK를 사용합니다.

반복 작업의 실행 버튼을 줄이기 위해 `ops/oci` 브랜치의 `.github/oci/request.json` 변경으로 시작하는 자동 실행 경로를 추가했습니다. 첫 검증은 `runner-check` 요청만 허용하며 환경 secret·개인키·SSH·OCI 명령을 사용하지 않습니다. 운영 요청 브랜치는 무거운 계산 CI의 push 검사에서만 제외하고 main·PR·수동 계산 검사는 유지합니다. 키를 사용하는 자동 작업은 이 첫 검사에 포함하지 않습니다.

사용자의 Run workflow 조작 없이 연결 도구의 branch update로 시작한 [실행 42009404699](https://github.com/Hyunwoo1205/quanta/actions/runs/42009404699)는 `completed/success`입니다. 실제 로그의 고유 요청 UUID·checkout commit을 대조했습니다. 같은 요청 commit에는 이 workflow만 관측됐고 전체 계산 CI는 시작하지 않았습니다. [검증 기록](oci_runner_control_verification.json)에 주소·키 없이 보존합니다. 이는 자동 실행·결과 회수 경로의 근거이며 실제 SSH 로그인·설치·배포 성공은 아닙니다. 원격 명령 자동화는 기존 키 인증을 확인한 뒤 필요한 고정 작업별로 추가합니다.

이 문서는 GitHub Actions를 별도의 CI/CD 실행기로 사용하는 연결 준비 절차입니다. 현재 대화의 네트워크를 프록시나 터널로 바꾸지 않습니다. GitHub 실행기가 서버의 22번 포트에 도달하는지 먼저 검사하며, 성공해도 SSH 인증·서버 명령·설치가 가능한 것으로 표시하지 않습니다.

## 현재 확인한 한계

작업 컨테이너의 직접 SSH는 `Network is unreachable`입니다. 이번 대화에서 별도 클라우드 브라우저도 확인했지만 OCI 콘솔이 `Site Unavailable`로 열리지 않았고 한 차례 reload 후에도 같았습니다. 과거 사용자의 연결된 Chrome에서는 OCI 콘솔·Cloud Shell에 접근했으나 현재 그 로컬 브라우저 연결은 제공되지 않습니다. 서버 쪽의 사용자 PuTTY 접속 성공과는 다른 실행 환경입니다.

따라서 키 변환만으로 대화의 직접 서버 연결이 보장되지 않습니다. 별도의 GitHub 클라우드 실행기 경로는 아래 실제 검사에서 TCP·SSH 배너 응답을 확인했습니다.

## 실제 연결 검사 결과

2026-11-05 18:28 KST에 사용자가 실행한 [검사 42002630779](https://github.com/Hyunwoo1205/quanta/actions/runs/42002630779)는 `completed/success`입니다. 실행 commit `4574fd2`의 실제 job 로그에서 `status=reachable`, `authentication_attempted=false`, `server_modified=false`를 확인했습니다. 설정된 주소의 22번 포트와 SSH 배너가 응답했다는 근거이며, 서버 신원·개인키 일치·로그인·서버 내부 명령·배포는 아직 확인하지 않았습니다. 주소·배너·개인키 없이 [검증 기록](oci_transport_verification.json)을 보존합니다. 이미 검사를 마친 사용자는 첫 검사를 반복할 필요가 없습니다.

## 등록 후 로그인 검사 현황

최초 세 시도는 서버 지문 표기의 형식 검사에서 인증 전에 멈췄습니다. 사용자가 secret을 수정한 뒤 2026-11-06 00:20 KST [실행 42013432968의 attempt 2](https://github.com/Hyunwoo1205/quanta/actions/runs/42013432968/attempts/2)가 `completed/success`입니다. 실제 job 로그에서 기존 PPK·고정한 호스트 키를 사용한 `authentication_attempted=true`, `requested_command=true`, `status=success`를 확인했습니다. 서버 지문을 새로 수집하거나 키를 교체하지 않았습니다. [검증 기록](oci_login_verification.json)에 과거 실패와 실제 로그인 성공을 함께 보존합니다. 설치·sudo·Quanta 실행·배포는 이 검사 범위가 아닙니다.

## 인증된 서버 상태 점검

고정된 `host-inventory` 요청으로 시작한 [실행 42056158077](https://github.com/Hyunwoo1205/quanta/actions/runs/42056158077)는 `completed/success`입니다. Ubuntu 26.04·ARM64·논리 CPU 2개·메모리 11.65 GiB, 루트 파일시스템 192.69 GiB·여유 187.66 GiB를 관측했습니다. Docker CLI·Git·systemctl이 존재하고 Quanta 관련 unit은 비활성, `/srv/quanta`는 없습니다. Docker 엔진·sudo·UUID·앱 구동·배포는 아직 검사하지 않았습니다.

이 작업은 `.github/oci/inventory-request.json`에 정확히 `schema_version=1`, `operation=host-inventory`, 정규 UUID인 `request_id`만 허용합니다. 고정된 Python 표준 라이브러리 코드만 SSH로 실행하며 원본 출력은 8 KiB·20초로 제한합니다. 정확한 필드·타입·범위를 통과한 JSON만 공개하고 호스트명·IP·UUID·키·원본 설정은 수집하지 않습니다. [검증 기록](oci_host_inventory_verification.json)에 수집 범위와 미확인 항목을 구분합니다.

## 첫 검사는 주소만 사용

GitHub의 `Hyunwoo1205/quanta` 저장소에서 웹 또는 모바일 브라우저로 설정할 수 있습니다. 인스턴스·방화벽·SSH 공개키를 바꾸지 않습니다.

1. 저장소 **Settings → Environments**에서 `oci-preflight` 환경을 만듭니다. 가능하면 배포 가능 브랜치는 `main`으로 제한하고 required reviewer를 설정합니다. 보이는 옵션은 계정·저장소 요금제와 권한에 따라 다를 수 있습니다.
2. 이 환경의 secret에 이름 `QUANTA_OCI_HOST`, 값은 연결할 인스턴스의 퍼블릭 IPv4를 저장합니다. 개인키·암호·OTP는 이 단계에서 등록하지 않습니다.
3. 저장소 **Actions → OCI network check (no private key) → Run workflow**에서 `main`으로 실행합니다. 이 workflow는 수동 실행만 허용하며 push·PR로 자동 시작하지 않습니다.
4. 완료한 실행 링크를 대화에 알려주면 결과를 조회합니다. 현재 연결된 GitHub 도구에는 새 workflow를 dispatch하는 동작이 없어 첫 실행 버튼은 사용자가 눌러야 합니다. PC 앱이나 PuTTY를 계속 켜둘 필요는 없습니다.

검사는 주소 유효성을 확인한 뒤 한 주소의 22번 포트에 한 번만 연결하고 SSH 배너를 제한된 길이·시간 안에서 읽습니다. SSH 인증·로그인·명령 전송은 하지 않습니다. 호스트·배너·원본 오류를 stdout이나 artifact에 보관하지 않으며 결과는 고정된 상태 코드와 JSON으로만 표시합니다. Python 표준 라이브러리를 사용하는 네트워크 진단이며 Quanta 수치 기준 환경을 검증하는 작업은 아닙니다.

`reachable`은 TCP와 SSH 배너를 확인했다는 의미입니다. 서버 신원·개인키 일치·sudo 권한·실제 명령 성공을 뜻하지 않습니다. 실패하면 자동 재시도·주소 탐색·포트 변경·방화벽 확장을 하지 않습니다.

## 기존 PPK로 로그인만 검사하는 준비

PPK를 직접 읽는 Unix Plink를 사용하므로 `.key` export나 새 공개키 등록 없이 기존 PPK로 인증을 검사할 수 있습니다. `OCI login check (existing PPK)`는 main에서 명시적으로 선택한 수동 실행 또는 `ops/oci`의 고정된 로그인 요청을 허용합니다. 수동 실행의 `confirm_key_use` 기본값은 false입니다. 아래 secret과 신뢰한 호스트 키가 모두 있어야 연결을 시도합니다. 실제 성공 여부는 해당 실행 로그로 확인합니다.

이 작업이 요청하는 서버 명령은 고정된 `true` 하나입니다. 성공은 핀으로 지정한 서버의 비자명한 SSH 인증과 해당 명령의 종료 코드 0을 뜻합니다. sudo 권한·설치·Quanta 동작·배포는 검증하지 않습니다. SSH 로그인 자체로 서버의 정상 접속·감사 로그가 남을 수 있습니다.

키를 사용하려면 **GitHub와 저장소 workflow에 기존 SSH 키를 맡긴다는 선택**이 필요합니다. 개인키를 GitHub secret에 등록하면 GitHub와 그 저장소 workflow에 기존 SSH 계정 권한을 맡깁니다. 이 선택을 마치기 전에는 아래 secret을 등록하거나 인증 검사를 실행하지 않습니다. 고정 명령을 준비해도 키 자체의 ubuntu/sudo 권한이 줄어드는 것은 아니며, 저장소의 코드를 수정할 수 있는 사람은 workflow를 바꾸어 키를 사용할 수 있습니다.

### 선택 후 직접 등록할 환경 secret

`oci-preflight` 환경에 이미 있는 `QUANTA_OCI_HOST`는 그대로 사용합니다. 별도로 필요한 두 값은 다음과 같습니다.

| 이름 | 값 |
| --- | --- |
| `QUANTA_OCI_PPK` | 기존 PPK 파일 전체 텍스트. base64 변환·export 없이 줄바꿈을 포함하여 그대로 입력 |
| `QUANTA_OCI_HOST_KEY` | 신뢰할 경로에서 확인한 서버 호스트 키의 `SHA256:…` 지문 한 개. 알고리즘 이름이나 앞뒤 설명은 제외 |

PPK·암호는 대화·소스 파일·issue·로그·artifact에 붙이지 않습니다. PPK 파일을 새로 만들거나 공개키를 서버에 등록하는 절차가 아닙니다. 현재 연결 도구는 secret을 등록할 수 없으므로 사용자가 GitHub의 환경 설정에서 직접 입력합니다.

### 서버 호스트 키 지문

인증 단계에서는 사용자가 신뢰하는 채널에서 얻은 **서버 호스트 키**가 필요합니다. PuTTYgen에 표시되는 사용자의 로그인 키 지문과 서버 호스트 키 지문은 서로 다릅니다. 검사를 끄거나 실행기가 처음 본 호스트 키를 자동 신뢰하지 않습니다. 검증한 기존 PuTTY의 Event Log나 신뢰한 기존 서버 세션에서 값을 확인할 수 있습니다. 이미 서버에 인증된 신뢰하는 터미널이 있을 때만 다음 읽기 전용 명령을 사용할 수 있습니다.

```sh
ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ed25519_key.pub
```

출력 중 `SHA256:…` 부분만 해당 secret에 입력합니다. 이는 공개 호스트 키의 지문이며 서버의 개인 호스트 키 파일을 읽지 않습니다. 해당 공개키 파일이 없다면 다른 알고리즘의 검증된 공개 호스트 키를 사용하며 새로운 호스트 키를 만들지 않습니다. 신뢰할 지문이 아직 없으면 인증 검사를 실행하지 않습니다. 이 명령을 GitHub 실행기의 로컬 셸에서 실행하면 OCI 서버 지문을 구한 것이 아닙니다.

지문 입력은 `SHA256:…` 정규형을 권장합니다. 도구는 외곽 ASCII 공백, 접두사 없는 정규 43자 digest, 표준 `ssh-keygen` 출력 한 줄도 같은 32바이트 SHA256 지문으로 정리해 읽습니다. 최대 1024자·한 줄·한 지문만 허용하고 주석·비트 수는 클라이언트에 전달하지 않습니다. 지문을 새 값으로 교체하거나 서버에서 처음 받은 키를 신뢰하는 과정이 아닙니다.

### 실행과 결과

선택과 지문 확인·secret 등록이 끝나면 **Actions → OCI login check (existing PPK) → Run workflow → main**에서 `confirm_key_use`를 선택하고 수동 실행할 수 있습니다. 선택하지 않으면 연결 전에 실패하며 개인키를 사용하지 않습니다.

이 대화의 작업자는 별도 실행 버튼 대신 `ops/oci`의 `.github/oci/login-request.json`에 고유한 고정 요청을 올려 검사를 시작할 수 있습니다. 이 요청은 최대 1024바이트이며 정확히 `schema_version=1`, `operation=login-check`, 정규 UUID인 `request_id`만 허용합니다. 잘못된 event·ref·요청은 설치와 개인키 단계 전에 거부합니다. 요청 파일에는 주소·키·명령 문자열을 넣지 않습니다. 이 경로도 `true` 이외의 서버 명령은 요청하지 않습니다. 기존 runner-only 검사와는 다른 파일을 사용합니다.

환경의 배포 가능 브랜치를 제한했다면 `ops/oci`가 허용되어 있어야 합니다. 기존 reviewer·승인 정책은 그대로 따릅니다. 차단되더라도 secret을 다른 보관처로 옮기거나 승인을 자동 해제하지 않습니다. PR·fork 이벤트는 인증 작업을 시작하지 않습니다.

도구는 공개 IPv4·32바이트 SHA256 지문·최대 32 KiB의 PPK v2/v3 형식과 `Encryption: none`을 먼저 확인합니다. Plink는 key 내용을 실제로 검증하며, 형식 검사만으로 키 일치나 인증 성공을 판정하지 않습니다. 임시 개인 디렉터리와 0600 키 파일을 만들고 원본 bytes를 그대로 사용합니다. 다른 키·인증 에이전트·포워딩·접속 공유를 끄고, 새 HOME과 최소 환경변수를 적용합니다. 서버 출력·원본 Plink 오류는 모두 버리고 고정 JSON 결과만 표시합니다. 실행 제한은 15초이고 정상·실패·timeout 종료 뒤 임시 파일을 정리합니다. 실행기 자체가 강제 종료되면 정리는 임시 실행기의 폐기 경계에 의존합니다.

성공은 `status=success`로 확인합니다. `encrypted_key`면 키 잠금 해제 방식을 별도로 준비해야 하며 기존 키의 암호화를 제거하지 않습니다. 실패는 자동 재시도하지 않습니다. 원본 오류를 숨기므로 일반 실패만으로 호스트 키·사용자 키·서버 정책 중 원인을 단정하지 않습니다.

`not_configured`면 인증 전에 멈춘 것입니다. 명시적으로 승인한 실행에서는 `configuration_issues`에 누락·형식 오류인 항목 이름만 표시합니다. `host_missing`/`host_invalid`는 주소, `host_key_missing`/`host_key_invalid`는 서버 지문, `private_key_missing`/`private_key_format_invalid`는 PPK secret을 확인합니다. 여러 항목이 잘못되면 함께 표시하며 값·길이·키 내용·원본 오류는 표시하지 않습니다. 이 진단은 키 일치나 서버 응답을 검사한 결과가 아닙니다.

사용자가 PuTTY에서 암호 입력 없이 접속했다고 답했지만, 로컬 에이전트에 잠금 해제 상태가 있었을 가능성이 있으므로 그것만으로 무암호 키라고 확정하지 않습니다. 이 검사는 실제 PPK의 `Encryption: none`을 확인하며 암호화된 키는 연결 전에 거부합니다. 암호화된 PPK는 새 실행기에서 잠금을 푸는 추가 절차가 필요합니다. Plink의 `-pwfile`은 개인키 암호 옵션으로 사용하지 않습니다. 서버 키의 신뢰 근거·실제 연결 결과가 확인되기 전에는 로그인 성공을 보장하지 않습니다.

키·암호는 대화·소스·로그·artifact에 넣지 않습니다. 이 문서의 첫 TCP·SSH 배너 검사에는 개인키가 필요하지 않습니다.

공식 참고: [GitHub 수동 실행](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow), [GitHub secret](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets), [PuTTY 명령 옵션](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/Chapter3.html), [Plink 자동 실행](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/Chapter7.html).
