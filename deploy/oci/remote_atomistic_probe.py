#!/usr/bin/env python3
"""One isolated A03 operation; never deploy, restart or read app.env/auth data."""
from __future__ import annotations
import base64
import fcntl
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time
import uuid

OPERATION = 'benchmark-atomistic'
PARENT = Path('/srv/quanta/atomistic-probes')
DATABASE = Path('/srv/quanta/data/jobs.sqlite3')
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
MAX_ARCHIVE = 65536
MAX_EXPANDED = 3 * 1024**2
MAX_FILE = 512 * 1024
MAX_REPORT = 131072
REQUIRED = frozenset({'scripts/verify_atomistic_a03.py', 'scripts/atomistic_a03_inputs.py',
    'scripts/check_atomistic_a02.py', 'docs/design/atomistic-a01-v0.1/profile.json',
    'docs/design/atomistic-a02-v0.1/manifest.json', 'docs/design/atomistic-a02-v0.1/engine-lock.json',
    'docs/design/atomistic-a03-v0.1/probe-policy.json'})
STAGES = frozenset({'config', 'lock', 'preflight', 'archive', 'benchmark', 'preservation', 'complete'})


class ProbeError(Exception):
    pass


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def validate_config(value):
    if (not isinstance(value, dict) or set(value) != {'source_sha', 'request_id', 'archive_sha256'}
            or not isinstance(value['source_sha'], str) or not re.fullmatch('[0-9a-f]{40}', value['source_sha'])
            or not isinstance(value['archive_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['archive_sha256'])
            or not isinstance(value['request_id'], str)):
        raise ValueError('fixed configuration denied')
    identifier = uuid.UUID(value['request_id'])
    if str(identifier) != value['request_id'] or identifier.version != 4:
        raise ValueError('fixed configuration denied')
    return dict(value)


def _parents(path):
    for parent in reversed(path.parents):
        st = parent.lstat()
        if parent == Path('/srv/quanta/data'):
            valid = stat.S_ISDIR(st.st_mode) and st.st_uid == 10001 and st.st_gid == 10001 and stat.S_IMODE(st.st_mode) == 0o700
        else:
            valid = stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
        if not valid:
            raise ProbeError('unsafe_parent')


def _file(path, limit=MAX_FILE):
    _parents(path)
    before = path.lstat()
    owner = 10001 if path in (DATABASE, Path(str(DATABASE) + '-wal')) else 0
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
            or before.st_uid != owner or before.st_gid != owner or before.st_mode & 0o022
            or (owner == 10001 and before.st_mode & 0o077)):
        raise ProbeError('unsafe_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ProbeError('file_race')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ProbeError('file_size')
    return raw


def _run(args, timeout=15):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=timeout, check=False, shell=False,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'HOME': '/nonexistent',
            'DOCKER_CONFIG': '/nonexistent', 'DOCKER_HOST': 'unix:///var/run/docker.sock'})
    if result.returncode or len(result.stdout) > 65536:
        raise ProbeError('command_failed')
    return result.stdout


def active_jobs(path=DATABASE):
    # The sole private-data query returns only an aggregate load guard, no row data.
    _parents(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 10001 or st.st_mode & 0o077:
        raise ProbeError('database_guard')
    with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True, timeout=1) as db:
        db.execute('PRAGMA query_only=ON')
        value = db.execute("SELECT count(*) FROM runs WHERE status IN ('QUEUED','RUNNING','CANCEL_REQUESTED')").fetchone()[0]
    if type(value) is not int or value < 0:
        raise ProbeError('database_guard')
    return value


def memory_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise ProbeError('memory_unknown')


def resource_preflight(active, available, disk):
    if active != 0 or available < 6 * 1024**3 or disk < 10 * 1024**3:
        raise ProbeError('resource_preflight')


def web_boundary():
    status = []
    elapsed = []
    for route in ('/', '/v1/capabilities'):
        started = time.monotonic()
        connection = http.client.HTTPConnection('127.0.0.1', 8765, timeout=2)
        try:
            connection.request('GET', route, headers={'Host': 'quanta.kro.kr', 'Origin': 'https://quanta.kro.kr'})
            response = connection.getresponse()
            status.append(response.status)
            response.read(1024)
        finally:
            connection.close()
        elapsed.append(time.monotonic() - started)
    if status != [200, 401]:
        raise ProbeError('service_boundary')
    return {'web_status': status[0], 'anonymous_capabilities_status': status[1], 'latency_seconds': elapsed}


def snapshot():
    service = _run(['/usr/bin/systemctl', 'is-active', 'quanta-boot.service', 'quanta-https.service'])
    if service != b'active\nactive\n':
        raise ProbeError('service_inactive')
    identity = _run(DOCKER + ['inspect', '--type', 'container', '--format',
        '{{.Id}} {{.State.Pid}} {{.Image}} {{.State.StartedAt}} {{.State.Running}}', 'quanta'])
    if not identity.rstrip().endswith(b' true'):
        raise ProbeError('container_inactive')
    # Configuration and scientific database bytes are fingerprinted only; no content emitted.
    configs = [Path('/etc/quanta/deployment.json'), Path('/etc/quanta/installed.json'),
               Path('/usr/local/lib/quanta/runtime.py')]
    config_sha = [hashlib.sha256(_file(path)).hexdigest() for path in configs]
    database_sha = []
    for path in (DATABASE, Path(str(DATABASE) + '-wal')):
        database_sha.append(hashlib.sha256(_file(path, 512 * 1024**2)).hexdigest() if path.exists() else None)
    return {'identity': hashlib.sha256(identity).hexdigest(), 'config_sha': config_sha,
            'database_sha': database_sha, 'active_jobs': active_jobs(), 'web': web_boundary()}


def allowed_path(name):
    path = PurePosixPath(name)
    return (str(path) == name and not path.is_absolute() and '..' not in path.parts
        and (name in REQUIRED or name.startswith('docs/design/atomistic-a01-v0.1/')
             or name.startswith('docs/design/atomistic-a02-v0.1/')))


def archive_files(raw, expected):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARCHIVE or hashlib.sha256(raw).hexdigest() != expected:
        raise ProbeError('archive_hash')
    result = {}
    size = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            if (len(result) >= 160 or member.name in result or not member.isfile()
                    or not allowed_path(member.name) or member.size > MAX_FILE or member.size < 1
                    or member.pax_headers):
                raise ProbeError('archive_member')
            size += member.size
            if size > MAX_EXPANDED:
                raise ProbeError('archive_size')
            with archive.extractfile(member) as stream:
                value = stream.read(MAX_FILE + 1)
            if len(value) != member.size:
                raise ProbeError('archive_member_size')
            result[member.name] = value
    if not REQUIRED <= result.keys():
        raise ProbeError('archive_required')
    return result


def prepare(config, archive, user):
    _parents(PARENT)
    if not PARENT.exists():
        PARENT.mkdir(mode=0o755)
    st = PARENT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o755:
        raise ProbeError('probe_parent')
    directory = PARENT / config['request_id']
    # New UUID only: never overwrite an existing or partial result.
    directory.mkdir(mode=0o700)
    os.chown(directory, user.pw_uid, user.pw_gid)
    files = archive_files(archive, config['archive_sha256'])
    source = directory / 'source'
    source.mkdir(mode=0o700)
    os.chown(source, user.pw_uid, user.pw_gid)
    for name, raw in files.items():
        path = source / name
        for parent in reversed(path.parents):
            if parent == source or source not in parent.parents:
                continue
            if not parent.exists():
                parent.mkdir(mode=0o700)
                os.chown(parent, user.pw_uid, user.pw_gid)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchown(stream.fileno(), user.pw_uid, user.pw_gid)
    return directory, source


def cleanup_containers(output):
    # Every runner container is labeled with this exact newly-created output path.
    raw = _run(DOCKER + ['ps', '-aq', '--filter', 'label=org.quanta.atomistic-a03=' + str(output)])
    identifiers = raw.decode('ascii').split()
    if not all(re.fullmatch('[0-9a-f]{12,64}', value) for value in identifiers):
        raise ProbeError('container_cleanup')
    if identifiers:
        _run(DOCKER + ['rm', '-f', *identifiers], timeout=30)
    return len(identifiers)


def execute(config, archive):
    stage = 'config'
    value = {'scope': 'oci_atomistic_a03', 'operation': OPERATION, 'status': 'failed',
        'stage': stage, 'production_restart_attempted': False, 'production_configuration_written': False,
        'private_environment_read': False, 'physical_validation_status': 'unvalidated'}
    directory = output = process = None
    lockfd = None
    baseline = None
    try:
        config = validate_config(config)
        value['source_sha'] = config['source_sha']
        value['request_id'] = config['request_id']
        if os.geteuid() != 0 or platform.machine() != 'aarch64':
            raise ProbeError('native_root_required')
        stage = 'lock'
        lockpath = Path('/run/quanta-application-upgrade.lock')
        _parents(lockpath)
        lockfd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        st = os.fstat(lockfd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise ProbeError('lock_metadata')
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage = 'preflight'
        baseline = snapshot()
        available = memory_available()
        disk = shutil.disk_usage('/srv/quanta').free
        resource_preflight(baseline['active_jobs'], available, disk)
        value['preflight'] = {'active_jobs': 0, 'memory_available_bytes': available, 'disk_free_bytes': disk,
            'web': baseline['web']}
        user = pwd.getpwnam('ubuntu')
        if user.pw_uid == 0 or user.pw_gid == 0:
            raise ProbeError('runtime_user')
        stage = 'archive'
        directory, source = prepare(config, archive, user)
        output = directory / 'run'
        stage = 'benchmark'
        groups = os.getgrouplist(user.pw_name, user.pw_gid)
        def demote():
            os.setgroups(groups)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
            os.umask(0o077)
            os.nice(10)
        with (directory / 'runner.stdout').open('xb') as stdout, (directory / 'runner.stderr').open('xb') as stderr:
            process = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(source / 'scripts/verify_atomistic_a03.py'),
                '--output-dir', str(output), '--case-timeout', '180', '--web-origin', 'http://127.0.0.1:8765',
                '--production-web-boundary'],
                cwd=source, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False,
                start_new_session=True, preexec_fn=demote,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(directory),
                    'DOCKER_CONFIG': str(directory / 'docker-config'), 'DOCKER_HOST': 'unix:///var/run/docker.sock',
                    'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1',
                    'QUANTA_A03_SOURCE_SHA': config['source_sha']})
            deadline = time.monotonic() + 900
            samples = 0
            minimum_memory = available
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ProbeError('benchmark_timeout')
                minimum_memory = min(minimum_memory, memory_available())
                if minimum_memory < 2 * 1024**3 or active_jobs() != 0:
                    raise ProbeError('resource_guard')
                if shutil.disk_usage('/srv/quanta').free < 2 * 1024**3:
                    raise ProbeError('disk_guard')
                if sum(p.stat().st_size for p in directory.rglob('*') if p.is_file()) > 512 * 1024**2:
                    raise ProbeError('output_guard')
                web_boundary()
                samples += 1
                time.sleep(2)
            value['benchmark_exit_code'] = process.returncode
            value['load_guard_samples'] = samples
            value['minimum_memory_available_bytes'] = minimum_memory
        report_path = output / 'report.json'
        st = report_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_REPORT or st.st_uid != user.pw_uid:
            raise ProbeError('report_size')
        raw = report_path.read_bytes()
        report = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(report, dict):
            raise ProbeError('report_shape')
        value['benchmark'] = report
        value['report_sha256'] = hashlib.sha256(raw).hexdigest()
        value['report_bytes'] = len(raw)
        stage = 'preservation'
        cleanup_containers(output)
        after = snapshot()
        value['container_preserved'] = after['identity'] == baseline['identity']
        value['configuration_preserved'] = after['config_sha'] == baseline['config_sha']
        value['database_bytes_preserved'] = after['database_sha'] == baseline['database_sha']
        value['postflight'] = {'active_jobs': after['active_jobs'], 'web': after['web']}
        if (process.returncode != 0 or not value['container_preserved'] or not value['configuration_preserved']
                or not value['database_bytes_preserved'] or after['active_jobs'] != 0):
            raise ProbeError('benchmark_or_preservation')
        stage = 'complete'
        value['status'] = 'success'
        value['public_quota_capacity_verified'] = False
        value['reservation'] = 'One isolated 1CPU/2GiB probe at idle, not a concurrent public-user load test'
    except Exception as error:
        value['failure_reason'] = str(error) if isinstance(error, ProbeError) else 'operation_failed'
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except Exception:
                    pass
        if output is not None:
            try:
                value['remaining_probe_containers_removed'] = cleanup_containers(output)
            except Exception:
                value['probe_cleanup_failed'] = True
                value['status'] = 'failed'
        if baseline is not None:
            try:
                final = snapshot()
                value['container_preserved'] = final['identity'] == baseline['identity']
                value['configuration_preserved'] = final['config_sha'] == baseline['config_sha']
                value['database_bytes_preserved'] = final['database_sha'] == baseline['database_sha']
                value['postflight'] = {'active_jobs': final['active_jobs'], 'web': final['web']}
                value['postflight_verified'] = True
                if not value['container_preserved'] or not value['configuration_preserved'] or not value['database_bytes_preserved']:
                    value['status'] = 'failed'
            except Exception:
                value['postflight_verified'] = False
                value['status'] = 'failed'
        if lockfd is not None:
            os.close(lockfd)
        value['stage'] = stage
        if directory is not None:
            try:
                path = directory / 'oci-summary.json'
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(encoded(value))
            except Exception:
                value['evidence_save_failed'] = True
                value['status'] = 'failed'
    return value


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or len(raw) > 196608:
            return None
        value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (not isinstance(value, dict) or value.get('scope') != 'oci_atomistic_a03'
                or value.get('operation') != OPERATION or value.get('status') not in {'success', 'failed'}
                or value.get('stage') not in STAGES or value.get('physical_validation_status') != 'unvalidated'):
            return None
        return value
    except Exception:
        return None


def main():
    try:
        if len(sys.argv) != 4 or sys.argv[1] != OPERATION or len(sys.argv[2]) > 2048 or len(sys.argv[3]) > 87384:
            raise ValueError()
        config_raw = base64.b64decode(sys.argv[2], validate=True)
        config = validate_config(json.loads(config_raw))
        if encoded(config) != config_raw:
            raise ValueError()
        archive = base64.b64decode(sys.argv[3], validate=True)
        def interrupted(*_):
            raise ProbeError('interrupted')
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, interrupted)
        result = execute(config, archive)
    except Exception:
        result = {'scope': 'oci_atomistic_a03', 'operation': OPERATION, 'status': 'failed', 'stage': 'config',
            'physical_validation_status': 'unvalidated'}
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
