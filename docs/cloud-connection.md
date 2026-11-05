# PC 없이 OCI 연결을 검증하는 첫 단계

이 문서는 GitHub Actions를 별도의 CI/CD 실행기로 사용하는 연결 준비 절차입니다. 현재 대화의 네트워크를 프록시나 터널로 바꾸지 않습니다. GitHub 실행기가 서버의 22번 포트에 도달하는지 먼저 검사하며, 성공해도 SSH 인증·서버 명령·설치가 가능한 것으로 표시하지 않습니다.

## 현재 확인한 한계

작업 컨테이너의 직접 SSH는 `Network is unreachable`입니다. 이번 대화에서 별도 클라우드 브라우저도 확인했지만 OCI 콘솔이 `Site Unavailable`로 열리지 않았고 한 차례 reload 후에도 같았습니다. 과거 사용자의 연결된 Chrome에서는 OCI 콘솔·Cloud Shell에 접근했으나 현재 그 로컬 브라우저 연결은 제공되지 않습니다. 서버 쪽의 사용자 PuTTY 접속 성공과는 다른 실행 환경입니다.

따라서 키 변환만으로 대화의 직접 서버 연결이 보장되지 않습니다. 별도의 GitHub 클라우드 실행기 경로는 아래 실제 검사에서 TCP·SSH 배너 응답을 확인했습니다.

## 실제 연결 검사 결과

2026-11-05 18:28 KST에 사용자가 실행한 [검사 42002630779](https://github.com/Hyunwoo1205/quanta/actions/runs/42002630779)는 `completed/success`입니다. 실행 commit `4574fd2`의 실제 job 로그에서 `status=reachable`, `authentication_attempted=false`, `server_modified=false`를 확인했습니다. 설정된 주소의 22번 포트와 SSH 배너가 응답했다는 근거이며, 서버 신원·개인키 일치·로그인·서버 내부 명령·배포는 아직 확인하지 않았습니다. 주소·배너·개인키 없이 [검증 기록](oci_transport_verification.json)을 보존합니다. 이미 검사를 마친 사용자는 첫 검사를 반복할 필요가 없습니다.

## 첫 검사는 주소만 사용

GitHub의 `Hyunwoo1205/quanta` 저장소에서 웹 또는 모바일 브라우저로 설정할 수 있습니다. 인스턴스·방화벽·SSH 공개키를 바꾸지 않습니다.

1. 저장소 **Settings → Environments**에서 `oci-preflight` 환경을 만듭니다. 가능하면 배포 가능 브랜치는 `main`으로 제한하고 required reviewer를 설정합니다. 보이는 옵션은 계정·저장소 요금제와 권한에 따라 다를 수 있습니다.
2. 이 환경의 secret에 이름 `QUANTA_OCI_HOST`, 값은 연결할 인스턴스의 퍼블릭 IPv4를 저장합니다. 개인키·암호·OTP는 이 단계에서 등록하지 않습니다.
3. 저장소 **Actions → OCI network check (no private key) → Run workflow**에서 `main`으로 실행합니다. 이 workflow는 수동 실행만 허용하며 push·PR로 자동 시작하지 않습니다.
4. 완료한 실행 링크를 대화에 알려주면 결과를 조회합니다. 현재 연결된 GitHub 도구에는 새 workflow를 dispatch하는 동작이 없어 첫 실행 버튼은 사용자가 눌러야 합니다. PC 앱이나 PuTTY를 계속 켜둘 필요는 없습니다.

검사는 주소 유효성을 확인한 뒤 한 주소의 22번 포트에 한 번만 연결하고 SSH 배너를 제한된 길이·시간 안에서 읽습니다. SSH 인증·로그인·명령 전송은 하지 않습니다. 호스트·배너·원본 오류를 stdout이나 artifact에 보관하지 않으며 결과는 고정된 상태 코드와 JSON으로만 표시합니다. Python 표준 라이브러리를 사용하는 네트워크 진단이며 Quanta 수치 기준 환경을 검증하는 작업은 아닙니다.

`reachable`은 TCP와 SSH 배너를 확인했다는 의미입니다. 서버 신원·개인키 일치·sudo 권한·실제 명령 성공을 뜻하지 않습니다. 실패하면 자동 재시도·주소 탐색·포트 변경·방화벽 확장을 하지 않습니다.

## 인증은 이후 별도 결정

PPK를 직접 읽는 Unix Plink를 사용할 수 있으므로 기존 키를 반드시 `.key`로 export해야 하는 것은 아닙니다. 다만 이 저장소에는 아직 키를 사용하는 workflow를 추가하지 않았습니다. 인증 단계에서는 사용자가 신뢰하는 채널에서 얻은 **서버 호스트 키**와 기존 개인키를 안전하게 연결해야 합니다. PuTTYgen에 표시되는 사용자의 로그인 키 지문과 서버 호스트 키 지문은 서로 다릅니다. 검사를 끄거나 runner가 처음 본 호스트 키를 자동 신뢰하지 않습니다.

암호화된 PPK는 새 실행기에서 잠금을 푸는 추가 절차가 필요합니다. Plink의 `-pwfile`을 개인키 암호 옵션으로 간주하거나 기존 키의 암호화를 조용히 제거하지 않습니다. 암호 유무·서버 키의 신뢰 근거·실제 연결 결과가 확인되기 전에는 접속 성공을 보장하지 않습니다.

개인키를 GitHub secret에 등록하면 GitHub와 그 저장소 workflow에 기존 SSH 계정 권한을 맡기는 별도 보관·사용 관계가 생깁니다. 읽기 전용 명령을 준비해도 개인키 자체의 ubuntu/sudo 권한이 줄어드는 것은 아닙니다. 이 선택은 사용자 동의와 직접 secret 입력 후에만 진행하며, 키·암호는 대화·소스·로그·artifact에 넣지 않습니다. 이 문서의 첫 단계에는 개인키가 필요하지 않습니다.

공식 참고: [GitHub 수동 실행](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow), [GitHub secret](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets), [PuTTY 명령 옵션](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/Chapter3.html), [Plink 자동 실행](https://the.earth.li/~sgtatham/putty/0.85/htmldoc/Chapter7.html).
