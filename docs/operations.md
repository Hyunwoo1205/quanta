# OCI 운영 배포와 SQLite 복구

2026-11-06 · 패키지 0.11.0 · 입력 계약 0.2.0

화면·API·계산·DB를 OCI 한 대에서 운영하는 파일럿 구성입니다. 배포 파일은 `deploy/oci/`에 있습니다. 현재 실제 배포는 부트 200 GB 단독 저장소, Caddy 직접 HTTPS, 명시적 owner-token 모드입니다. 아래 설치 명령은 최초 구성의 예시이며 이미 운영 중인 서버에 재실행하는 절차가 아닙니다.

## 현재 확인된 상태와 다음 점검

앱 소스 `1738107301ef873bfe5e01f930866c2a74e4ec3f`의 OCI ARM 설치·서버 내부 준비 상태·일관된 SQLite 백업과 같은 부트 안의 분리 복원·앱 자동 시작·일일 백업 timer 활성화, 공개 HTTPS, 실제 소유자 데스크톱 계산을 확인했습니다. 실제 모바일은 2026-11-06 사용자가 모든 기능의 정상 작동을 보고했습니다. 각 범위는 [작업 현황](../WORKPLAN.md), [실제 백업](oci_backup_verification.json), [데스크톱](oci_owner_browser_verification.json), [모바일 사용자 확인](oci_mobile_verification.json)을 기준으로 구분합니다.

운영 현황 읽기 전용 점검·활성 timer를 보존한 새 백업/분리 복원과 일회성 외부 SQLite 사본의 실제 다운로드/복호화/분리 복원을 확인했습니다. [외부 사본 검증](oci_off_host_backup_verification.json)은 자동 off-host 일정이나 전체 서버 복원을 뜻하지 않습니다. 실제 OS 재부팅과 OCI 관리형 볼륨 백업·전체 볼륨 복원은 아직 별도 미확인 범위입니다. 초기 설치용 `verify-backup` operation은 inactive timer를 요구하므로 활성 timer 상태에서 그대로 반복하지 않습니다. 배포 앱 소스와 새로운 운영 코드 소스·CI를 따로 고정하여 검증 후 사용합니다.

확인된 호스트는 Ubuntu 26.04·ARM64·논리 CPU 2개·명목 메모리 12 GB와 부트 볼륨 200 GB 한 개이며 추가 블록 볼륨은 없습니다. 기존 PPK·고정 호스트 지문과 GitHub Actions 경로를 유지합니다. 정확한 CPython 3.12.14·의존성 27개는 고정 이미지와 아키텍처별 wheel 잠금을 사용하고 호스트 Python은 운영 도구의 표준 라이브러리만 실행합니다. 비밀값·원본 DB·정제하지 않은 원격 출력은 공개 저장소와 로그에 넣지 않습니다.

## 백업 기본 방침

2026-11-06 사용자가 OCI 콘솔에서 일일 자동백업을 이미 설정했다고 확인했습니다. [보고 근거](oci_managed_backup_user_report.json)에 사용자 확인과 에이전트 콘솔 미확인을 구분합니다. 현재 부트200GB의 정책 연결·최근성공·보존기간은 직접 확인하지 못했습니다. 일상 백업은 이 OCI 정책을 기본으로 하고, 정기 Drive/외부 백업을 추가 필수화하지 않습니다. 기존 일일 SQLite 스냅샷과 이미 확인한 일회성 외부 사본은 보존하며 새 반복 외부 작업을 만들지 않습니다.

재부팅 검증은 외부 사본을 매번 현재 DB와 동일하게 만드는 작업과 분리합니다. Caddy 수락과 앱을 중지한 직후 현재 DB·산출물을 기준으로 고정하고 실제 부팅 후 정확한 보존을 확인합니다. 새 기준은 private schema2이며 OCI 정책 근거는 사용자 보고이고 서버의 직접 콘솔 확인은 false입니다. 부트 볼륨 전체 복원과 실제 OS 재부팅 후 서비스 복구도 서로 다른 검증입니다.

## 운영 중 복구 점검의 고정 작업

`audit-recovery`는 설치·서비스·백업 일정·단일 작업자 잠금·DB 현황·다른 컨테이너 재시작 정책을 읽기 전용으로 수집합니다. 수집 성공과 재부팅 준비를 구분하고, 이 작업은 외부 백업이나 실제 재부팅 성공을 주장하지 않습니다.

`prepare-recovery`는 활성 timer를 유지한 채 기존 `quanta-backup-boot.service`를 시작합니다. 새 스냅샷을 검증하고 운영 DB를 마운트하지 않는 별도 컨테이너/새 경로에 복원해 bytes를 대조한 뒤, root0600 `/etc/quanta/recovery-backup.json`에 복구 기준을 최초 저장합니다. 기존 기준 파일이 있으면 덮어쓰지 않고 거부합니다.

`export-recovery`는 그 기준의 같은 부트·24시간 이내·DB 크기/해시를 확인하고 스냅샷의 DB와 manifest 두 파일만 암호화합니다. 서버 환경·접속키·SSH 키는 내보내지 않습니다. 고정 수신자 공개 인증서와 OpenSSL CMS AES-256-GCM/RSA-OAEP SHA256을 사용하며 개인키는 서버·실행기·공개 저장소에 공급하지 않습니다. 공개 Actions 산출물에는 암호화된 CMS만 허용합니다. 복호화·manifest/DB 검증과 비공개 외부 보관 확인까지 끝나기 전에는 off-host 복구 성공으로 기록하지 않습니다. 전송은 최대128MiB, DB는 암호화 여유를 뺀124MiB로 명시적으로 제한합니다.

`reboot-recovery`는 사용자 OCI 일일백업을 기본으로 한 고정 재부팅 작업입니다. 설치·서비스·작업자 독점·무대기 계산·기존 컨테이너·디스크 여유를 확인합니다. Caddy 수락과 활성 timer를 잠시 중지하고 계산/백업 유휴를 재확인한 뒤 앱을 중지합니다. 그 시점의 **현재 live DB 여섯 표/산출물 BLOB의 typed 행 해시**와 설정·기존 컨테이너를 private schema2 기준으로 최초 저장하고10초 지연 재부팅을 예약합니다. 이전 외부/SQLite 사본과의 동일성·신선도를 요구하지 않습니다. 실패 시 앱·HTTPS·timer를 복구하고 준비 상태를 확인하며180초 복구 watchdog을 둡니다. enabled 설정은 바꾸지 않습니다. 미로드 임시 unit은 이미 정리된 것으로 인정하되 실제 active 상태가 남으면 실패로 기록합니다. 재부팅 요청 응답이 끊겼다고 같은 요청을 반복하지 않습니다.

`verify-reboot`는 실제 부트 ID 변경, 서비스/활성 timer/작업자 독점 잠금, 이전의 모든 DB 행·산출물 BLOB, 운영 설정, 기존 peer 컨테이너의 ID·이미지·정책·설정·실행 상태를 비교합니다. Quanta는 새 컨테이너가 생성될 수 있으므로 앱 컨테이너 ID의 동일성을 요구하지 않습니다. 서버가 외부 보관을 직접 검증한 것으로 표시하지 않습니다.

`post-reboot-compute`는 보존 비교를 완료한 **다음** 서버 내부 루프백 API로 기존 입자 입력을 같은 revision/새 실행으로 재실행합니다. 부트와 원본 실행에 고정한 멱등성 키를 사용하고 원본 및 독립 에너지/힘 기준을 비교합니다. 키는 서버 내부 인증 헤더에만 사용하며 공개 probe/실행기에 공급하지 않습니다. 이 작업은 의도적으로 실행·event·산출물 기록을 추가하므로, 그 이후의 DB 전체 일치 비교는 재부팅 직후 보존 확인과 구분합니다. 물리 검증은 unvalidated입니다.

`compare-recovery`는 이전 SQLite 사본과 현재 live DB의 표별 행 수·의미 일치, 부트/서비스/임시 unit 상태를 읽기 전용으로 수집합니다. 서로 다른 세대의 사본이 불일치하는 것은 데이터 손실의 증거가 아닙니다. 수집 성공과 동일성 결과를 구분합니다.

`refresh-recovery`는 선택적 명시 작업입니다. 새 백업/분리 복원 성공 후 기존 비공개 기준을 별도 불변 archive에 보존하고 기대한 원본 bytes/metadata가 같을 때만 현재 기준 파일을 원자 갱신합니다. 기존 사본·운영 DB는 바꾸지 않습니다. 사용자 OCI 일일백업 방침 이후 이 작업과 추가 export는 실제 실행하지 않았습니다.

고정 여덟 작업 모두 기존 4필드 요청·고정 앱 소스를 유지하고, 새 운영 코드는 별도 main 커밋/성공한 두 아키텍처 CI에서 checkout한 bytes만 실행합니다. SSH 비밀값은 두 검증이 성공한 뒤에만 공급합니다. 새 작업은 지원된 operation만 받으며 자유 명령/임의 경로를 받지 않습니다. 새로운 수집/백업/내보내기를 실제 실행한 범위는 WORKPLAN과 정제한 검증 기록을 따릅니다.

암호화 참고: [OpenSSL CMS](https://docs.openssl.org/3.5/man1/openssl-cms/). 복호화 환경은 알려진 CMS 보안 수정이 포함된 버전을 사용합니다([3.5.7 수정 기록](https://www.openssl-library.org/news/openssl-3.5-notes/index.html)).

## 데이터 배치와 컨테이너

별도 데이터 볼륨을 사용하는 기존 `dedicated` 모드에서는 `/srv/quanta`를 별도 ext4 또는 XFS 파일시스템으로 마운트합니다. `/etc/quanta/deployment.json`의 `filesystem_uuid`에 실제 UUID를 지정하고 `image`에는 검증한 로컬 `sha256:...` 이미지 ID 또는 digest가 붙은 저장소 이미지명을 지정합니다. `--pull=never`를 사용하므로 해당 이미지가 실제로 로컬에 있어야 합니다. 예시 UUID·태그를 그대로 사용하지 않습니다.

서비스는 systemd의 마운트 assertion·의존성에 더해 호스트 `findmnt`의 정확한 mountpoint·UUID·읽기/쓰기 파일시스템을 검사합니다. 마운트 루트는 `root:root 0755`로 두어 경로 접근을 허용하고 group/world 쓰기를 금지하며, 부트 루트와 다른 파일시스템이어야 합니다. `/srv/quanta/data`, `/srv/quanta/backups`는 정확히 0700·UID/GID 10001 소유의 실제 디렉터리로 사전에 준비합니다. 각 디렉터리와 기존 DB·lock도 해당 파일시스템에 속해야 합니다. 루트나 다른 볼륨의 빈 디렉터리를 데이터 볼륨으로 대체하지 않습니다. wrapper는 자동 포맷·마운트·권한 재귀 변경·DB 생성을 수행하지 않습니다. 새 볼륨이 실제 마운트된 것을 확인한 뒤에만 새 디렉터리를 만들고, 기존 데이터가 있으면 먼저 백업·소유권을 점검합니다.

부트 볼륨 200 GB 한 개를 사용하는 경우에는 `deployment.boot.json.example`의 **명시적 `storage_mode: "boot"`**와 boot 전용 unit을 사용합니다. 기존 2개 필드 설정과 기본 CLI는 계속 dedicated 모드이며, 데이터 마운트가 사라졌다고 boot 모드로 자동 전환하지 않습니다. boot 모드는 `/srv/quanta`와 그 상위 경로의 root 소유권·쓰기 권한, `/`의 실제 장치·UUID·ext4/XFS·rw·파일시스템 루트를 확인합니다. data/backups와 기존 DB도 같은 장치에 있어야 합니다. 디스크 분할·축소·재생성은 수행하지 않습니다.

두 배치에서 설정의 `filesystem_uuid`는 실제 저장 파일시스템의 UUID입니다. boot에서는 `findmnt --target /srv/quanta -o TARGET,UUID,FSTYPE`의 대상이 `/`인지 확인합니다. 배포 wrapper와 해당 mode 옵션이 다르면 시작을 거부합니다.

이미지 빌드 예시는 다음과 같습니다. 컨테이너 기본 명령은 계약 검사이고 기본 UID/GID는 10001:10001입니다.

```bash
sudo docker build --file Dockerfile.aarch64 --tag quanta:0.11.0 .
sudo docker image inspect --format '{{.Id}}' quanta:0.11.0
```

앱은 host network의 `127.0.0.1:8765`에서만 듣습니다. 이 고정 loopback listener에는 일반 포트 publish 대신 host network를 사용합니다. 현재 배포에서는 host의 Caddy가 HTTPS를 전달하며 OCI 방화벽에 앱 HTTP 포트를 공개하지 않습니다. Cloudflare Tunnel은 대체 지원 구성입니다. 읽기 전용 이미지, private `/tmp` tmpfs, capabilities 제거, `no-new-privileges`, 2 CPU·2 GiB·PID 제한을 적용합니다. 전체 2 GiB 제한은 초기 구성값이며 A1 실측 후 조정할 수 있습니다. 계산 자식의 1,024 MiB·120초·단일 수치 스레드 정책은 별개로 유지합니다.

## 설정 설치와 시작

root 소유의 `/usr/local/lib/quanta/runtime.py`, `/etc/quanta/deployment.json`, `/etc/quanta/app.env`와 systemd unit을 설치합니다. 설정 파일은 group/world 쓰기를 허용하지 않으며 앱 env는 비공개로 둡니다. 기본 Access 구성은 `app.env.example`의 네 설정을 실제 origin·팀·AUD·허용 이메일에 맞춥니다. JWT·쿠키·Tunnel 자격 증명은 예시 파일에 넣지 않습니다. Access·Tunnel 연결 순서는 [운영 인증](production-access.md)을 따릅니다. Cloudflare에 등록하지 않은 도메인은 [직접 HTTPS](direct-https.md) 절차와 `app.owner-token.env.example`을 명시적으로 선택합니다. 실제 접속키는 예시·저장소·공개 로그에 넣지 않습니다.

최초 설치의 파일 배치 예시입니다. 기존 설정 파일이 있으면 예시로 덮어쓰지 않고 내용을 대조합니다. 설정 예시는 실제 UUID·검증 이미지 ID·Access 값으로 수정한 후 검사합니다.

```bash
sudo install -d -m 0755 /usr/local/lib/quanta
sudo install -m 0755 deploy/oci/runtime.py /usr/local/lib/quanta/runtime.py
sudo install -d -m 0700 /etc/quanta
sudo install -m 0600 deploy/oci/deployment.json.example /etc/quanta/deployment.json
sudo install -m 0600 deploy/oci/app.env.example /etc/quanta/app.env
sudo install -m 0644 deploy/oci/quanta.service deploy/oci/quanta-backup.service deploy/oci/quanta-backup.timer /etc/systemd/system/
```

배포 파일을 설치한 뒤 실행합니다.

```bash
sudo python3 /usr/local/lib/quanta/runtime.py check
sudo systemctl daemon-reload
sudo systemctl enable --now quanta.service
sudo systemctl status quanta.service
sudo journalctl -u quanta.service --since today
```

위 설치·시작 예시는 dedicated 모드입니다. 부트 단독 배치는 `deployment.boot.json.example`을 설정의 출발점으로 삼고, `quanta-boot.service`, `quanta-backup-boot.service`, `quanta-backup-boot.timer`를 같은 systemd 디렉터리에 설치합니다. 기존 설정·데이터가 있으면 먼저 내용과 백업을 확인합니다. 점검·시작은 다음과 같습니다.

```bash
sudo python3 /usr/local/lib/quanta/runtime.py check --storage-mode boot
sudo systemctl daemon-reload
sudo systemctl enable --now quanta-boot.service
sudo systemctl status quanta-boot.service
```

기존 배치에서 전환할 때는 새 실행 수락을 중지하고 작업·백업을 비운 다음 이전 앱과 timer를 disable/stop한 뒤 선택한 배치만 enable합니다. 두 배치를 함께 enable하지 않습니다. unit의 상호 충돌과 종료/시작 순서는 중복 컨테이너를 방지하는 보조 경계입니다. boot 모드는 별도 `srv-quanta.mount`를 요구하지 않으며 root 파일시스템 identity 검사를 대신 수행합니다.

실제 unit의 설치 경로와 wrapper 하위 명령은 `deploy/oci/` 파일을 기준으로 합니다. systemd만 재시작을 관리하고 Docker 자체 재시작은 끕니다. 감독자가 치명적으로 중단되면 운영 CLI가 HTTP 정상 종료·작업자 정리를 거쳐 종료 코드 2로 나갑니다. 반복 실패는 systemd 시작 횟수 제한으로 멈추므로 로그·마운트·설정을 수정하고 원인을 확인합니다. 새 worker는 기존 독점 lock을 획득한 뒤에만 중단 실행을 복구하며, 이미 실행한 계산의 부분 체크포인트를 이어가는 기능은 없습니다.

## 일관된 백업과 새 경로 복구

설치 패키지에는 다음 명령을 제공합니다. 운영 데이터와 같은 UID/GID 10001로 실행해 복구 파일의 소유권을 유지합니다. 목적지의 부모 디렉터리는 사전에 있어야 하고 목적지 자체는 비어 있는 디렉터리라도 이미 존재하면 거부합니다. 소스와 목적지는 서로 포함하지 않는 별도 트리여야 하며 symlink 경로를 허용하지 않습니다.

```bash
quanta backup-store --store /srv/quanta/data --output /srv/quanta/backups/manual-001
quanta verify-backup /srv/quanta/backups/manual-001
quanta restore-store /srv/quanta/backups/manual-001 --output /srv/quanta/backups/restore-check-001
```

호스트에 Quanta Python 환경을 따로 설치하지 않았다면 동일한 검증 이미지의 비 root 컨테이너에서 실행합니다. 데이터·백업 bind mount와 UID를 맞추고 운영 앱과 같은 DB에 두 번째 계산 worker를 시작하지 않습니다. 일일 backup unit은 이 컨테이너 호출을 자동 구성합니다. 복구 시험용 새 부모 경로도 실제 데이터 볼륨 위에서 준비하고 충분한 여유 공간을 확인합니다.

백업은 live SQLite backup API로 WAL의 committed 변경을 포함하는 일관된 사본을 만듭니다. 임시 비공개 디렉터리에서 journal을 닫고 SQLite integrity·foreign key·정확한 지원 스키마·소유권 관계·기록 식별자·산출물 bytes SHA를 확인합니다. DB 크기·SHA, 스키마 해시·생성 시각·도구 버전·레코드 개수를 manifest에 보존하고 fsync 후 Linux의 원자적인 덮어쓰기 금지 rename으로 새 목적지를 공개합니다.

기본 전체 시간 상한은 60초이며 SQLite 진행·검증·파일 복사 중 확인합니다. 사본 크기와 추가 여유 128 MiB가 부족하거나 검사에 실패하면 성공 백업으로 공개하지 않습니다. CLI가 성공한 사본만 복구 대상으로 삼고 실패한 일일 백업은 journal에서 확인합니다. 해시는 우발적 변조를 검출하지만 manifest와 DB 둘 다 바꿀 수 있는 공격자를 인증하지 않습니다. 백업은 운영 데이터와 같은 비공개 권한으로 보관합니다.

복구는 백업 bytes와 manifest를 다시 검사한 다음 새 디렉터리에 DB만 복원합니다. 운영 DB·worker lock·WAL/SHM을 덮어쓰거나 삭제하지 않고 worker를 자동 시작하지 않습니다. 복원 직후의 RUNNING·CANCEL_REQUESTED 상태도 원본 그대로이며, 명시적으로 서비스가 시작되어 독점 lock을 얻은 시점에 기존 중단 복구 정책을 적용합니다. 이전 버전 기록을 현재 계산 결과로 다시 해석하거나 새 계획으로 바꾸지 않습니다.

`quanta-backup.timer`는 일일 스냅샷을 새 시각/UUID 경로에 저장합니다. 초기에는 수동 백업·검증·분리 복구 시험 후 timer를 활성화합니다. 누적 사본은 디스크를 사용하고 이 버전은 오래된 백업을 자동 삭제하지 않습니다. 디스크 예산과 검증한 복구 지점을 확인한 후 관리합니다.

```bash
sudo systemctl start quanta-backup.service
sudo journalctl -u quanta-backup.service --since today
sudo systemctl enable --now quanta-backup.timer
sudo systemctl list-timers quanta-backup.timer
```

boot 단독 배치에서는 위 백업 명령의 unit 이름을 `quanta-backup-boot.service`·`quanta-backup-boot.timer`로 바꿉니다.

timer는 매일 UTC 03:00, 최대 5분 분산 지연으로 실행하며 꺼져 있던 동안의 누락은 다음 기동 때 한 번 보완합니다. 실행 실패·용량 부족을 자동으로 해결하지 않으므로 백업 성공 시각과 여유 공간을 확인합니다.

## 호스트 밖 백업과 업데이트

같은 볼륨의 DB 사본은 볼륨 손실에 대비한 사본이 아닙니다. SQLite 스냅샷 성공 뒤 OCI 관리형 볼륨 백업을 별도로 구성합니다. 관리형 백업은 부트·데이터 합계 5개 무료 한도와 기존 계정 사용량을 점검하며, 앱 내부 일일 timer가 OCI 관리형 백업까지 실행했다고 표시하지 않습니다.

부트 200 GB 단독 배치 또는 부트 50 GB·데이터 150 GB 배치에서 새 복원 볼륨을 동시에 추가하면 할당 200 GB를 넘습니다. 초기 시험은 현재 데이터 파일시스템의 새 디렉터리에 복구하고 전체 볼륨 복원과 구분합니다. RPO 24시간·RTO 1시간은 실제 OCI 복구 시험 전의 목표입니다.

업데이트 전 새 실행 수락을 중지하고 대기·실행 작업을 비웁니다. 이전 image ID·CPU·잠금·검증 백업을 보존한 뒤 단일 서비스를 멈추고 image 설정을 교체합니다. 0.10.0은 전체 구현 해시가 바뀌므로 과거 frozen plan의 엄밀한 replay는 이전의 일치하는 신뢰 환경이 필요합니다. 여러 버전을 같은 DB에 동시에 실행하지 않습니다. 스키마가 다른 백업은 명시적인 호환성 검토 없이 복원·자동 migration하지 않습니다.

## 확인 범위

`scripts/verify_operations.py`는 실제 계산·SQLite·백업·분리 복구·원본 artifact 비교와 재시작 복구를 측정합니다. 기존 A·SI·B·WF·S·W·P와 물리 검증 `unvalidated`를 유지합니다. 실제 OCI에서는 볼륨 미장착 시작 거부, OS 재부팅 후 단일 서비스 복구, 감독자·자식 종료, 백업·복구·조회·다운로드 시간과 외부 인증 브라우저를 별도로 확인해야 파일럿 완료입니다.

구현 commit `07e26a2`의 [네이티브 CI](https://github.com/Hyunwoo1205/quanta/actions/runs/41874725509)에서 ARM·x86 각각 Python 621개·Node 33개, 여덟 측정·설치 패키지 컨테이너와 비 root 읽기 전용 복구 검사를 통과했습니다. 원본 20개 파일·ZIP 해시·450개 코드 해시 참조와 로컬 설치 wheel 근거는 [운영 검증 기록](operations_verification.json)에 있습니다. 전체 실행 API 표시 지연과 실제 단계별 합격을 구분하며, 이 문장의 원래 확인 범위는 해당 0.10.0 CI 시점입니다. 이후 OCI 설치·같은 부트 내 백업 복원·HTTPS·실제 소유자 계산과 모바일 사용자 확인은 위 최신 근거로 갱신됐으며, OS 재부팅·전체 볼륨 복원은 여전히 별도 미확인 범위입니다. 부트 단독 모드 보완은 별도의 [배포 검사](boot_storage_verification.json)에 기록하며 이전 네이티브 계산·컨테이너 근거와 구분합니다.

공식 참고: [SQLite online backup](https://www.sqlite.org/backup.html), [Python sqlite3 backup](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup), [SQLite 검사](https://www.sqlite.org/pragma.html), [systemd unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html), [Docker bind mount](https://docs.docker.com/engine/storage/bind-mounts/), [Docker 재시작](https://docs.docker.com/engine/containers/start-containers-automatically/).
