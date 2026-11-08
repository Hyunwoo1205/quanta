#!/usr/bin/env python3
"""Fixed isolated atomistic probes; never deploy, restart or read app.env/auth data."""
from __future__ import annotations
import base64
import fcntl
import hashlib
import http.client
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import selectors
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
TRACE_OPERATION = 'trace-atomistic-old-he'
A04_OPERATION = 'benchmark-atomistic-a04'
TRACE_SUBJECT_SHA = 'b7bfa8f90a7d5d05e74f7d8fefefe3be72cfc379'
TRACE_SCRIPT = 'scripts/trace_cp2k_sigill.py'
CANDIDATE_SCRIPT = 'scripts/atomistic_a03_candidate.py'
A04_SCRIPT = 'scripts/run_atomistic_a04_native_arm.py'
A04_CANDIDATE = {
    'schema_version': 1,
    'source_sha': '5dd1e90c8332366c1f95f5b58b260ce966af5e84',
    'image_ref': 'quanta/a03-armv8a:5dd1e90c8332366c1f95f5b58b260ce966af5e84',
    'archive_bytes': 838924288,
    'archive_sha256': 'c7a60fc4da430a40d60af0fa18ad5c4d1dc1f727dceb84752b7a8471f33e0ec0',
    'config_sha256': '3c31b88484c7d077a5c3d2cabb4985b77b6e79ac3d0512a8dbb7f7fa9c05b792',
    'binary_sha256': 'af665277ebd21d4397448d49a9ce666756a05ebcf401a9967e19c32af9c9b60f',
}
A04_CANDIDATE_MANIFEST_SHA256 = 'ad3350e1fa394ab34b406fdab4131fbe2d814ede5b1e6ef2f444ac0d04ff770c'
PARENT = Path('/srv/quanta/atomistic-probes')
DATABASE = Path('/srv/quanta/data/jobs.sqlite3')
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
MAX_ARCHIVE = 65536
A04_MAX_ARCHIVE = 80 * 1024
MAX_EXPANDED = 3 * 1024**2
MAX_FILE = 512 * 1024
MAX_REPORT = 131072
MAX_CANDIDATE = 2 * 1024**3
CANDIDATE_TIMEOUT = 240
REQUIRED = frozenset({'scripts/verify_atomistic_a03.py', 'scripts/atomistic_a03_inputs.py',
    'scripts/check_atomistic_a02.py', 'docs/design/atomistic-a01-v0.1/profile.json',
    'docs/design/atomistic-a02-v0.1/manifest.json', 'docs/design/atomistic-a02-v0.1/engine-lock.json',
    'docs/design/atomistic-a03-v0.1/probe-policy.json'})
A04_REQUIRED = frozenset({
    A04_SCRIPT, CANDIDATE_SCRIPT, 'scripts/run_atomistic_a04_resource_ci.py',
    'scripts/run_atomistic_a04_gapw_ci.py', 'scripts/atomistic_a03_inputs.py',
    'scripts/atomistic_a04_resources.py', 'scripts/verify_atomistic_a03.py',
    'docs/design/atomistic-a01-v0.1/fixtures.json', 'docs/design/atomistic-a01-v0.1/profile.json',
    'docs/design/atomistic-a01-v0.1/reference-data.json', 'docs/design/atomistic-a01-v0.1/validation-plan.json',
    'docs/design/atomistic-a02-v0.1/density-and-units.json', 'docs/design/atomistic-a02-v0.1/engine-lock.json',
    'docs/design/atomistic-a02-v0.1/assets/cc-pVDZ.cp2k', 'docs/design/atomistic-a02-v0.1/assets/ALL_POTENTIALS',
    'docs/design/atomistic-a04-v0.1/native-arm-qualification.json', 'docs/design/atomistic-a04-v0.1/boundary-fixtures.json',
    'docs/verification/atomistic-a03/armv8a-retry-20261107.json',
    'docs/verification/atomistic-a04/h2-boundary-accuracy-42450193275.json',
    'docs/verification/atomistic-a04/fixed-fixture-accuracy-42448653582.json',
    'docs/verification/atomistic-a04/one-factor-refinement-42447627356.json',
})
A04_CASES = ('h2-short', 'h2-reference', 'h2', 'h2-long', 'he')
A04_REPORT_SCOPE = 'isolated_oci_arm_A04_same_input_qualification'
STAGES = frozenset({'config', 'lock', 'preflight', 'archive', 'benchmark', 'preservation', 'complete'})


class ProbeError(Exception):
    pass


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def validate_config(value, *, a04=False):
    required = {'source_sha', 'request_id', 'archive_sha256'}
    if (not isinstance(value, dict) or set(value) not in (required, required | {'candidate'})
            or not isinstance(value['source_sha'], str) or not re.fullmatch('[0-9a-f]{40}', value['source_sha'])
            or not isinstance(value['archive_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['archive_sha256'])
            or not isinstance(value['request_id'], str)):
        raise ValueError('fixed configuration denied')
    identifier = uuid.UUID(value['request_id'])
    if str(identifier) != value['request_id'] or identifier.version != 4:
        raise ValueError('fixed configuration denied')
    if a04:
        candidate = value.get('candidate')
        if (candidate != A04_CANDIDATE or type(candidate['schema_version']) is not int
                or type(candidate['archive_bytes']) is not int):
            raise ValueError('A04 candidate configuration denied')
    elif 'candidate' in value:
        candidate = value['candidate']
        if (not isinstance(candidate, dict) or set(candidate) != {'schema_version', 'source_sha',
                'archive_sha256', 'archive_bytes', 'image_ref', 'config_sha256', 'binary_sha256'}
                or type(candidate['schema_version']) is not int or candidate['schema_version'] != 1
                or candidate['source_sha'] != value['source_sha']
                or candidate['image_ref'] != 'quanta/a03-armv8a:' + value['source_sha']
                or type(candidate['archive_bytes']) is not int or not 0 < candidate['archive_bytes'] <= MAX_CANDIDATE
                or not all(isinstance(candidate[key], str) and re.fullmatch('[0-9a-f]{64}', candidate[key])
                           for key in ('archive_sha256', 'config_sha256', 'binary_sha256'))):
            raise ValueError('candidate configuration denied')
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


def docker_child_groups(user):
    """Grant only this reviewed child access to the existing root-owned socket.

    /var/run is the normal system symlink to /run. No user/group database,
    socket permission, service or persistent host configuration is changed.
    """
    canonical = Path('/run/docker.sock')
    if Path('/var/run').resolve(strict=True) != Path('/run'):
        raise ProbeError('docker_socket_path')
    _parents(canonical)
    info = canonical.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid <= 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o660):
        raise ProbeError('docker_socket_metadata')
    groups = os.getgrouplist(user.pw_name, user.pw_gid)
    return sorted(set([*groups, info.st_gid])), info.st_gid not in groups


def resource_preflight(active, available, disk, *, a04=False):
    if active != 0 or available < (8 if a04 else 6) * 1024**3 or disk < 10 * 1024**3:
        raise ProbeError('resource_preflight')


def a04_docker_data_root():
    raw = _run(DOCKER + ['info', '--format', '{{.DockerRootDir}}']).decode('ascii')
    root = Path(raw.rstrip('\n'))
    if (not raw.endswith('\n') or str(root) != raw[:-1] or not root.is_absolute()
            or root == Path('/') or '..' in root.parts or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root))):
        raise ProbeError('docker_storage_unverified')
    _parents(root / 'probe')
    return root


def available_disk(docker_root=None):
    free = shutil.disk_usage('/srv/quanta').free
    return min(free, shutil.disk_usage(docker_root).free) if docker_root is not None else free


def a04_image_present():
    ref = A04_CANDIDATE['image_ref']
    listing = _run(DOCKER + ['image', 'ls', '--no-trunc', '--filter', 'reference=' + ref,
                             '--format', '{{.Repository}}:{{.Tag}} {{.ID}}'])
    identities = (A04_CANDIDATE['config_sha256'], A04_CANDIDATE_MANIFEST_SHA256)
    if listing and listing not in {f'{ref} sha256:{digest}\n'.encode('ascii') for digest in identities}:
        raise ProbeError('candidate_image_identity')
    return bool(listing)


def a04_restore_image_tag(originally_present):
    present = a04_image_present()
    if not originally_present and present:
        # Only the exact reviewed tag introduced by this trial. Never force or prune.
        _run(DOCKER + ['image', 'rm', '--no-prune', A04_CANDIDATE['image_ref']], timeout=30)
        present = a04_image_present()
    if present != originally_present:
        raise ProbeError('candidate_image_preservation')


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


def require_a04_web(web):
    if (web['web_status'] != 200 or web['anonymous_capabilities_status'] != 401
            or len(web['latency_seconds']) != 2 or not all(0 <= t <= 2 for t in web['latency_seconds'])):
        raise ProbeError('service_boundary')


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


def allowed_path(name, *, trace=False, candidate=False, a04=False):
    if a04:
        return name in A04_REQUIRED
    path = PurePosixPath(name)
    return (str(path) == name and not path.is_absolute() and '..' not in path.parts
        and (name in REQUIRED or trace and name == TRACE_SCRIPT or candidate and name == CANDIDATE_SCRIPT
             or name.startswith('docs/design/atomistic-a01-v0.1/')
             or name.startswith('docs/design/atomistic-a02-v0.1/')))


def archive_files(raw, expected, *, trace=False, candidate=False, a04=False):
    if trace and (candidate or a04):
        raise ProbeError('candidate_and_trace_are_exclusive')
    limit = A04_MAX_ARCHIVE if a04 else MAX_ARCHIVE
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= limit or hashlib.sha256(raw).hexdigest() != expected:
        raise ProbeError('archive_hash')
    mode = 'r:gz'
    if a04:
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=32 * 1024**2)
            raw = decoder.decompress(raw, max_length=MAX_EXPANDED + 192 * 1024)
        except lzma.LZMAError as error:
            raise ProbeError('archive_format') from error
        if not decoder.eof or decoder.unused_data:
            raise ProbeError('archive_size')
        mode = 'r:'
    result = {}
    size = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as archive:
        for member in archive:
            if (len(result) >= 160 or member.name in result or not member.isfile()
                    or not allowed_path(member.name, trace=trace, candidate=candidate, a04=a04)
                    or member.size > MAX_FILE or member.size < 1
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
    required = A04_REQUIRED if a04 else REQUIRED
    if trace:
        required = required | {TRACE_SCRIPT}
    if candidate and not a04:
        required = required | {CANDIDATE_SCRIPT}
    if not required <= result.keys():
        raise ProbeError('archive_required')
    return result


def prepare(config, archive, user, *, trace=False, a04=False):
    _parents(PARENT)
    if not PARENT.exists():
        PARENT.mkdir(mode=0o755)
    st = PARENT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o755:
        raise ProbeError('probe_parent')
    directory = PARENT / config['request_id']
    # New UUID only: never overwrite an existing or partial result.
    directory.mkdir(mode=0o710 if a04 else 0o700)
    owner = 0 if a04 else user.pw_uid
    os.chown(directory, owner, user.pw_gid)
    files = archive_files(archive, config['archive_sha256'], trace=trace, candidate='candidate' in config, a04=a04)
    source = directory / 'source'
    source_mode = 0o750 if a04 else 0o700
    source.mkdir(mode=source_mode)
    os.chown(source, owner, user.pw_gid)
    for name, raw in files.items():
        path = source / name
        for parent in reversed(path.parents):
            if parent == source or source not in parent.parents:
                continue
            if not parent.exists():
                parent.mkdir(mode=source_mode)
                os.chown(parent, owner, user.pw_gid)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640 if a04 else 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchown(stream.fileno(), owner, user.pw_gid)
            if a04:
                os.fchmod(stream.fileno(), 0o640)
    if a04:
        # Preserve group traversal even when SSH/sudo supplies a restrictive umask.
        directory.chmod(0o710)
        for path in (source, *(path for path in source.rglob('*') if path.is_dir())):
            path.chmod(source_mode)
    return directory, source


def relay_candidate(directory, metadata, input_stream, user, *, docker_root=None):
    if input_stream is None:
        raise ProbeError('candidate_stream_missing')
    directory.mkdir(mode=0o700)
    a04 = docker_root is not None
    owner = 0 if a04 else user.pw_uid
    image = directory / 'candidate-image.tar'
    remaining = metadata['archive_bytes']
    digest = hashlib.sha256()
    deadline = time.monotonic() + CANDIDATE_TIMEOUT
    next_guard = 0
    fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output, selectors.DefaultSelector() as selector:
        stream_fd = input_stream.fileno()
        selector.register(stream_fd, selectors.EVENT_READ)
        while remaining:
            now = time.monotonic()
            if now >= deadline:
                raise ProbeError('candidate_transfer_timeout')
            if now >= next_guard:
                if memory_available() < (8 if a04 else 2) * 1024**3 or active_jobs() != 0:
                    raise ProbeError('resource_guard')
                if available_disk(docker_root) < 10 * 1024**3:
                    raise ProbeError('disk_guard')
                web = web_boundary()
                if a04:
                    require_a04_web(web)
                next_guard = now + 2
            if not selector.select(min(1, deadline - now)):
                continue
            chunk = os.read(stream_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ProbeError('candidate_transfer_short')
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if not selector.select(min(2, max(0, deadline - time.monotonic()))) or os.read(stream_fd, 1):
            raise ProbeError('candidate_transfer_length')
        if digest.hexdigest() != metadata['archive_sha256']:
            raise ProbeError('candidate_transfer_hash')
        os.fchown(output.fileno(), owner, user.pw_gid)
        if a04:
            os.fchmod(output.fileno(), 0o640)
    manifest = directory / 'candidate-image.json'
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(encoded(metadata))
        os.fchown(output.fileno(), owner, user.pw_gid)
        if a04:
            os.fchmod(output.fileno(), 0o640)
    os.chown(directory, owner, user.pw_gid)
    if a04:
        directory.chmod(0o750)


def cleanup_containers(output, *, a04=False):
    # Every runner container is labeled with this exact newly-created output path.
    label = 'org.quanta.atomistic-a04' if a04 else 'org.quanta.atomistic-a03'
    raw = _run(DOCKER + ['ps', '-aq', '--filter', f'label={label}={output}'])
    identifiers = raw.decode('ascii').split()
    if not all(re.fullmatch('[0-9a-f]{12,64}', value) for value in identifiers):
        raise ProbeError('container_cleanup')
    if identifiers:
        _run(DOCKER + ['rm', '-f', *identifiers], timeout=30)
    return len(identifiers)


def probe_output_bytes(directory, candidate_archive):
    total = 0
    for path in directory.rglob('*'):
        if path != candidate_archive:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # A temporary engine output or work directory was removed between samples.
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def scope_operation(*, trace, a04):
    if a04:
        return 'oci_atomistic_a04', A04_OPERATION
    return ('oci_atomistic_sigill', TRACE_OPERATION) if trace else ('oci_atomistic_a03', OPERATION)


def a04_benchmark_passed(report, source_sha):
    cases = report.get('cases')
    return (type(report.get('schema_version')) is int and report['schema_version'] == 1
            and report.get('scope') == A04_REPORT_SCOPE
            and report.get('quanta_source') == source_sha and report.get('status') == 'measured'
            and report.get('all_cross_build_checks_passed') is True and report.get('scratch_removed') is True
            and isinstance(cases, list) and all(isinstance(case, dict) for case in cases)
            and tuple(case.get('system') for case in cases) == A04_CASES
            and all(a04_case_passed(case) for case in cases))


def a04_case_passed(case):
    he = case['system'] == 'he'
    cap = (6 if he else 3) * 1024**3
    if (case.get('status') != 'measured' or case.get('settings') != ([12, 800, 80] if he else [12, 400, 40])
            or case.get('cap_bytes') != cap or case.get('comparison', {}).get('passed') is not True):
        return False
    attempt = case.get('attempt', {})
    controls = attempt.get('container_controls', {})
    engine = attempt.get('engine_resource', {})
    return (attempt.get('container_removed') is True
            and attempt.get('observed_mpi_ranks') == attempt.get('observed_omp_threads') == 1
            and controls.get('memory_bytes') == controls.get('memory_swap_bytes') == cap
            and controls.get('cpus') == 1 and engine.get('final_cgroup_memory_max_bytes') == cap
            and engine.get('final_cgroup_swap_max_bytes') == engine.get('final_cgroup_swap_peak_bytes') == 0)


def execute(config, archive, input_stream=None, *, trace=False, a04=False):
    stage = 'config'
    scope, operation = scope_operation(trace=trace, a04=a04)
    value = {'scope': scope, 'operation': operation, 'status': 'failed',
        'stage': stage, 'production_restart_attempted': False, 'production_configuration_written': False,
        'private_environment_read': False, 'physical_validation_status': 'unvalidated'}
    directory = runtime = output = process = candidate_archive = None
    lockfd = None
    baseline = docker_root = original_image = None
    try:
        if trace and a04:
            raise ProbeError('candidate_and_trace_are_exclusive')
        config = validate_config(config, a04=a04)
        if trace and (config['source_sha'] != TRACE_SUBJECT_SHA or 'candidate' in config):
            raise ProbeError('trace_subject_mismatch')
        value['source_sha'] = config['source_sha']
        value['request_id'] = config['request_id']
        if trace or a04:
            value['archive_sha256'] = config['archive_sha256']
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
        disk = available_disk()
        resource_preflight(baseline['active_jobs'], available, disk, a04=a04)
        if a04:
            require_a04_web(baseline['web'])
            docker_root = a04_docker_data_root()
            disk = available_disk(docker_root)
            original_image = a04_image_present()
            value['docker_storage_verified'] = True
            value['candidate_image_preexisting'] = original_image
        candidate = config.get('candidate')
        if candidate is not None and disk - 2 * candidate['archive_bytes'] < 10 * 1024**3:
            raise ProbeError('candidate_disk_preflight')
        value['preflight'] = {'active_jobs': 0, 'memory_available_bytes': available, 'disk_free_bytes': disk,
            'web': baseline['web']}
        user = pwd.getpwnam('ubuntu')
        if user.pw_uid == 0 or user.pw_gid == 0:
            raise ProbeError('runtime_user')
        groups, added_group = docker_child_groups(user)
        value['docker_socket_verified'] = True
        value['ephemeral_docker_group_added'] = added_group
        stage = 'archive'
        directory, source = prepare(config, archive, user, trace=trace, a04=a04)
        runtime = directory
        if a04:
            runtime = directory / 'workspace'
            runtime.mkdir(mode=0o700)
            os.chown(runtime, user.pw_uid, user.pw_gid)
        output = runtime / 'run'
        command = ['/usr/bin/python3', '-I', '-B', str(source / 'scripts/verify_atomistic_a03.py'),
                   '--output-dir', str(output), '--case-timeout', '105' if trace else '180', '--web-origin', 'http://127.0.0.1:8765',
                   '--production-web-boundary']
        if a04:
            command = ['/usr/bin/python3', '-I', '-B', str(source / A04_SCRIPT),
                       '--fixed-oci-a04', '--output-dir', str(output)]
        elif trace:
            command.append('--trace-old-he')
        if candidate is not None:
            candidate_dir = directory / 'candidate'
            candidate_archive = candidate_dir / 'candidate-image.tar'
            relay_candidate(candidate_dir, candidate, input_stream, user, docker_root=docker_root)
            value['candidate_transfer'] = {'archive_sha256': candidate['archive_sha256'],
                                           'archive_bytes': candidate['archive_bytes']}
            command.extend(['--candidate-dir', str(candidate_dir)])
        if a04:
            available = memory_available()
            disk = available_disk(docker_root)
            resource_preflight(active_jobs(), available, disk, a04=True)
            if not original_image and disk - candidate['archive_bytes'] < 10 * 1024**3:
                raise ProbeError('candidate_disk_preflight')
            web = web_boundary()
            require_a04_web(web)
            value['admission'] = {'active_jobs': 0, 'memory_available_bytes': available,
                                  'disk_free_bytes': disk, 'web': web}
        stage = 'benchmark'
        def demote():
            os.setgroups(groups)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
            os.umask(0o077)
            os.nice(10)
        with (directory / 'runner.stdout').open('xb') as stdout, (directory / 'runner.stderr').open('xb') as stderr:
            process = subprocess.Popen(command,
                cwd=source, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False,
                start_new_session=True, preexec_fn=demote,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(runtime),
                    'DOCKER_CONFIG': str(runtime / 'docker-config'), 'DOCKER_HOST': 'unix:///var/run/docker.sock',
                    'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1',
                    ('QUANTA_A04_SOURCE_SHA' if a04 else 'QUANTA_A03_SOURCE_SHA'): config['source_sha']})
            deadline = time.monotonic() + (180 if trace else 900)
            samples = 0
            minimum_memory = available
            minimum_disk = disk
            maximum_web_latency = 0
            output_limit = (2 * 1024**3 if a04 else 0) + 512 * 1024**2
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ProbeError('benchmark_timeout')
                minimum_memory = min(minimum_memory, memory_available())
                if minimum_memory < 2 * 1024**3 or active_jobs() != 0:
                    raise ProbeError('resource_guard')
                minimum_disk = min(minimum_disk, available_disk(docker_root))
                if minimum_disk < (10 if a04 else 2) * 1024**3:
                    raise ProbeError('disk_guard')
                if probe_output_bytes(directory, candidate_archive) > output_limit:
                    raise ProbeError('output_guard')
                web = web_boundary()
                if a04:
                    require_a04_web(web)
                    maximum_web_latency = max(maximum_web_latency, *web['latency_seconds'])
                samples += 1
                time.sleep(2)
            value['benchmark_exit_code'] = process.returncode
            value['load_guard_samples'] = samples
            value['minimum_memory_available_bytes'] = minimum_memory
            if a04:
                value['minimum_disk_free_bytes'] = minimum_disk
                value['maximum_sampled_web_latency_seconds'] = maximum_web_latency
        report_path = output / 'report.json'
        st = report_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_REPORT or st.st_uid != user.pw_uid:
            raise ProbeError('report_size')
        raw = report_path.read_bytes()
        report = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(report, dict):
            raise ProbeError('report_shape')
        value['diagnostic' if trace else 'benchmark'] = report
        value['report_sha256'] = hashlib.sha256(raw).hexdigest()
        value['report_bytes'] = len(raw)
        stage = 'preservation'
        removed = cleanup_containers(output, a04=a04)
        after = snapshot()
        if a04:
            require_a04_web(after['web'])
        value['container_preserved'] = after['identity'] == baseline['identity']
        value['configuration_preserved'] = after['config_sha'] == baseline['config_sha']
        value['database_bytes_preserved'] = after['database_sha'] == baseline['database_sha']
        value['postflight'] = {'active_jobs': after['active_jobs'], 'web': after['web']}
        value['first_postflight_gate'] = {
            'runner_exit_code': process.returncode,
            'active_jobs': after['active_jobs'],
            'container_preserved': value['container_preserved'],
            'configuration_preserved': value['configuration_preserved'],
            'database_bytes_preserved': value['database_bytes_preserved'],
        }
        if (process.returncode != 0 or trace and report.get('trace_diagnostic_passed') is not True
                or a04 and (removed or not samples or not a04_benchmark_passed(report, config['source_sha']))
                or not value['container_preserved'] or not value['configuration_preserved']
                or not value['database_bytes_preserved'] or after['active_jobs'] != 0):
            raise ProbeError('benchmark_or_preservation')
        stage = 'complete'
        value['status'] = 'success'
        value['public_quota_capacity_verified'] = False
        value['reservation'] = ('Five sequential 1 CPU probes at idle, 3 GiB H2 or 6 GiB He, zero swap' if a04
                                else 'One isolated 1CPU/2GiB probe at idle, not a concurrent public-user load test')
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
                value['remaining_probe_containers_removed'] = cleanup_containers(output, a04=a04)
                if a04 and value['remaining_probe_containers_removed']:
                    value['status'] = 'failed'
            except Exception:
                value['probe_cleanup_failed'] = True
                value['status'] = 'failed'
        if a04 and runtime is not None:
            try:
                remaining = list(runtime.glob('quanta-a04-native-arm-*'))
                for scratch in remaining:
                    shutil.rmtree(scratch)
                value['remaining_probe_scratch_removed'] = len(remaining)
                if remaining:
                    value['status'] = 'failed'
            except OSError:
                value['probe_scratch_cleanup_failed'] = True
                value['status'] = 'failed'
        if original_image is not None:
            try:
                if a04_docker_data_root() != docker_root:
                    raise ProbeError('docker_storage_unverified')
                a04_restore_image_tag(original_image)
                value['candidate_image_tag_preserved'] = True
            except Exception:
                value['candidate_image_tag_preserved'] = False
                value['status'] = 'failed'
        if candidate_archive is not None:
            try:
                candidate_archive.unlink(missing_ok=True)
                value['candidate_transfer_archive_removed'] = True
            except OSError:
                value['candidate_transfer_archive_removed'] = False
                value['status'] = 'failed'
        if baseline is not None:
            try:
                final = snapshot()
                if a04:
                    require_a04_web(final['web'])
                value['container_preserved'] = final['identity'] == baseline['identity']
                value['configuration_preserved'] = final['config_sha'] == baseline['config_sha']
                value['database_bytes_preserved'] = final['database_sha'] == baseline['database_sha']
                value['postflight'] = {'active_jobs': final['active_jobs'], 'web': final['web']}
                value['postflight_verified'] = True
                if (not value['container_preserved'] or not value['configuration_preserved']
                        or not value['database_bytes_preserved'] or a04 and final['active_jobs'] != 0):
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


def sanitize_report(raw, *, trace=False, a04=False):
    try:
        if not isinstance(raw, bytes) or len(raw) > 196608:
            return None
        value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        scope, operation = scope_operation(trace=trace, a04=a04)
        if (not isinstance(value, dict) or value.get('scope') != scope or value.get('operation') != operation
                or value.get('status') not in {'success', 'failed'}
                or value.get('stage') not in STAGES or value.get('physical_validation_status') != 'unvalidated'):
            return None
        return value
    except Exception:
        return None


def main():
    trace = len(sys.argv) >= 2 and sys.argv[1] == TRACE_OPERATION
    a04 = len(sys.argv) >= 2 and sys.argv[1] == A04_OPERATION
    archive_limit = A04_MAX_ARCHIVE if a04 else MAX_ARCHIVE
    try:
        if (len(sys.argv) != 4 or sys.argv[1] not in (OPERATION, TRACE_OPERATION, A04_OPERATION)
                or len(sys.argv[2]) > 2048 or len(sys.argv[3]) > 4 * ((archive_limit + 2) // 3)):
            raise ValueError()
        config_raw = base64.b64decode(sys.argv[2], validate=True)
        config = validate_config(json.loads(config_raw), a04=a04)
        if encoded(config) != config_raw:
            raise ValueError()
        archive = base64.b64decode(sys.argv[3], validate=True)
        def interrupted(*_):
            raise ProbeError('interrupted')
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, interrupted)
        result = execute(config, archive, sys.stdin.buffer if 'candidate' in config else None, trace=trace, a04=a04)
    except Exception:
        scope, operation = scope_operation(trace=trace, a04=a04)
        result = {'scope': scope, 'operation': operation, 'status': 'failed', 'stage': 'config',
            'physical_validation_status': 'unvalidated'}
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
