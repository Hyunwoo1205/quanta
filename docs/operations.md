# OCI 운영 배포와 SQLite 복구

2026-11-05 · 패키지 0.10.0 · 입력 계약 0.2.0

화면·API·계산·DB를 OCI 한 대에서 운영하는 파일럿 구성입니다. 배포 파일은 `deploy/oci/`에 있습니다. 실제 인스턴스의 OS·접속·볼륨 UUID와 Access 설정은 현장에서 확인해야 합니다. 자동 시험의 로컬 파일시스템·컨테이너 검증을 OCI 재부팅·볼륨 복원·외부 로그인 합격으로 표시하지 않습니다.

## 먼저 확인할 상태

사용자가 OCI 준비 완료를 알렸습니다. 아직 IP/호스트명, SSH 사용자, OS와 안전한 인증 경로, 실제 부트·데이터 볼륨 배치를 전달받지 못했습니다. 비밀키 내용을 채팅·저장소에 넣지 않습니다. 연결할 수 있는 경로가 마련되면 먼저 읽기 전용으로 `uname -m`, OS 버전, `lsblk -f`, `findmnt`, 여유 공간과 기존 서비스·데이터를 확인합니다. 기존 디스크 포맷·데이터 삭제·새 유료 자원 생성은 이 배포 파일에 포함하지 않습니다.

구성은 Linux ARM64 A1, systemd, Docker Engine, `findmnt`를 대상으로 합니다. 정확한 CPython 3.12.14·의존성 27개는 digest 고정 기반 이미지와 두 CPU별 기존 wheel 잠금을 사용합니다. 호스트 Python은 배포 wrapper의 표준 라이브러리만 실행합니다. 실제 OS에 맞는 Docker 설치와 데이터 볼륨 연결·fstab은 점검 후 수행합니다.

## 데이터 볼륨과 컨테이너

`/srv/quanta`를 별도 ext4 또는 XFS 파일시스템으로 마운트합니다. `/etc/quanta/deployment.json`의 `filesystem_uuid`에 실제 UUID를 지정하고 `image`에는 검증한 로컬 `sha256:...` 이미지 ID 또는 digest가 붙은 저장소 이미지명을 지정합니다. `--pull=never`를 사용하므로 해당 이미지가 실제로 로컬에 있어야 합니다. 예시 UUID·태그를 그대로 사용하지 않습니다.

서비스는 systemd의 마운트 assertion·의존성에 더해 호스트 `findmnt`의 정확한 mountpoint·UUID·읽기/쓰기 파일시스템을 검사합니다. 마운트 루트는 `root:root 0755`로 두어 경로 접근을 허용하고 group/world 쓰기를 금지하며, 부트 루트와 다른 파일시스템이어야 합니다. `/srv/quanta/data`, `/srv/quanta/backups`는 정확히 0700·UID/GID 10001 소유의 실제 디렉터리로 사전에 준비합니다. 각 디렉터리와 기존 DB·lock도 해당 파일시스템에 속해야 합니다. 루트나 다른 볼륨의 빈 디렉터리를 데이터 볼륨으로 대체하지 않습니다. wrapper는 자동 포맷·마운트·권한 재귀 변경·DB 생성을 수행하지 않습니다. 새 볼륨이 실제 마운트된 것을 확인한 뒤에만 새 디렉터리를 만들고, 기존 데이터가 있으면 먼저 백업·소유권을 점검합니다.

이미지 빌드 예시는 다음과 같습니다. 컨테이너 기본 명령은 계약 검사이고 기본 UID/GID는 10001:10001입니다.

```bash
sudo docker build --file Dockerfile.aarch64 --tag quanta:0.10.0 .
sudo docker image inspect --format '{{.Id}}' quanta:0.10.0
```

앱은 host network의 `127.0.0.1:8765`에서만 듣습니다. 이 고정 loopback listener에는 일반 포트 publish 대신 host network를 사용합니다. host의 cloudflared가 연결하며 OCI 방화벽에 앱 HTTP 포트를 공개하지 않습니다. 읽기 전용 이미지, private `/tmp` tmpfs, capabilities 제거, `no-new-privileges`, 2 CPU·2 GiB·PID 제한을 적용합니다. 전체 2 GiB 제한은 초기 구성값이며 A1 실측 후 조정할 수 있습니다. 계산 자식의 1,024 MiB·120초·단일 수치 스레드 정책은 별개로 유지합니다.

## 설정 설치와 시작

root 소유의 `/usr/local/lib/quanta/runtime.py`, `/etc/quanta/deployment.json`, `/etc/quanta/app.env`와 systemd unit을 설치합니다. 설정 파일은 group/world 쓰기를 허용하지 않으며 앱 env는 비공개로 둡니다. `app.env.example`의 네 Access 설정을 실제 origin·팀·AUD·허용 이메일에 맞춥니다. JWT·쿠키·Tunnel 자격 증명은 예시 파일에 넣지 않습니다. Access·Tunnel 연결 순서는 [운영 인증](production-access.md)을 따릅니다.

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

timer는 매일 UTC 03:00, 최대 5분 분산 지연으로 실행하며 꺼져 있던 동안의 누락은 다음 기동 때 한 번 보완합니다. 실행 실패·용량 부족을 자동으로 해결하지 않으므로 백업 성공 시각과 여유 공간을 확인합니다.

## 호스트 밖 백업과 업데이트

같은 볼륨의 DB 사본은 볼륨 손실에 대비한 사본이 아닙니다. SQLite 스냅샷 성공 뒤 OCI 관리형 볼륨 백업을 별도로 구성합니다. 관리형 백업은 부트·데이터 합계 5개 무료 한도와 기존 계정 사용량을 점검하며, 앱 내부 일일 timer가 OCI 관리형 백업까지 실행했다고 표시하지 않습니다.

부트 50 GB·데이터 150 GB 기본안에서 새 복원 볼륨을 동시에 추가하면 할당 200 GB를 넘습니다. 초기 시험은 현재 데이터 파일시스템의 새 디렉터리에 복구하고 전체 볼륨 복원과 구분합니다. RPO 24시간·RTO 1시간은 실제 OCI 복구 시험 전의 목표입니다.

업데이트 전 새 실행 수락을 중지하고 대기·실행 작업을 비웁니다. 이전 image ID·CPU·잠금·검증 백업을 보존한 뒤 단일 서비스를 멈추고 image 설정을 교체합니다. 0.10.0은 전체 구현 해시가 바뀌므로 과거 frozen plan의 엄밀한 replay는 이전의 일치하는 신뢰 환경이 필요합니다. 여러 버전을 같은 DB에 동시에 실행하지 않습니다. 스키마가 다른 백업은 명시적인 호환성 검토 없이 복원·자동 migration하지 않습니다.

## 확인 범위

`scripts/verify_operations.py`는 실제 계산·SQLite·백업·분리 복구·원본 artifact 비교와 재시작 복구를 측정합니다. 기존 A·SI·B·WF·S·W·P와 물리 검증 `unvalidated`를 유지합니다. 실제 OCI에서는 볼륨 미장착 시작 거부, OS 재부팅 후 단일 서비스 복구, 감독자·자식 종료, 백업·복구·조회·다운로드 시간과 외부 인증 브라우저를 별도로 확인해야 파일럿 완료입니다.

구현 commit `07e26a2`의 [네이티브 CI](https://github.com/Hyunwoo1205/quanta/actions/runs/41874725509)에서 ARM·x86 각각 Python 621개·Node 33개, 여덟 측정·설치 패키지 컨테이너와 비 root 읽기 전용 복구 검사를 통과했습니다. 원본 20개 파일·ZIP 해시·450개 코드 해시 참조와 로컬 설치 wheel 근거는 [운영 검증 기록](operations_verification.json)에 있습니다. 전체 실행 API 표시 지연과 실제 단계별 합격을 구분하며, 실제 OCI 접속·마운트·재부팅·외부 로그인은 아직 확인하지 않았습니다.

공식 참고: [SQLite online backup](https://www.sqlite.org/backup.html), [Python sqlite3 backup](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup), [SQLite 검사](https://www.sqlite.org/pragma.html), [systemd unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html), [Docker bind mount](https://docs.docker.com/engine/storage/bind-mounts/), [Docker 재시작](https://docs.docker.com/engine/containers/start-containers-automatically/).
