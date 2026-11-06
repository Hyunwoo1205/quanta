#!/usr/bin/env python3
"""Fixed, guarded app upgrade for server-managed accounts; no data replacement.

The separately pinned runner gate verifies the requested app commit's full CI.
Only one existing boot installation may be upgraded. A private immutable journal
captures the quiescent scientific store and both old configuration byte strings.
No key, scientific input, raw result, email or password is emitted.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
import zlib

OLD_SOURCE = '1738107301ef873bfe5e01f930866c2a74e4ec3f'
ROOT = Path('/srv/quanta')
DATA = ROOT / 'data'
ETC = Path('/etc/quanta')
JOURNAL = ETC / 'accounts-upgrade.json'
JOURNAL_STAGING = ETC / '.accounts-upgrade.publish'
LOCK = Path('/run/quanta-accounts-upgrade.lock')
ROLLBACK_SCRIPT = Path('/usr/local/lib/quanta/accounts-rollback.py')
RUNTIME = Path('/usr/local/lib/quanta/runtime.py')
SYSTEMD = Path('/etc/systemd/system')
APP = 'quanta-boot.service'
HTTPS = 'quanta-https.service'
TIMER = 'quanta-backup-boot.timer'
WATCHDOG = 'quanta-accounts-rollback'
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
TRUSTED = {
    'runtime': '88a865b2755c1ecf4a16a0bee18b4d233c63bc937064a6431e50c052ac1abc38',
    APP: 'e2e0ffcb3de234abe263d9e50084f616036abfab3a7d77065035354301893ce7',
    'quanta-backup-boot.service': '4c8e703a69d332f588c3cd020bfa9da50f9b0a08258f8068fff4c7eb8dc0fa14',
    TIMER: 'f19f55776c6763b0c0d3480e2b9ba78f3951780095b0870bcf35dafde594a491',
    HTTPS: '06e60b65101d1321297d55fc396573b35d1e4eafbe9f93166c11ca683f460eab',
}
SOURCE_FILES = {
    'Dockerfile.aarch64': '2bcfb6192445451d1efcaabba2c59b14e3f91582cae695133e1aeb6e433c47b6',
    'requirements.aarch64.lock.txt': '2bbe3c935e671dee374d73635d8d2677aed927ba92c5ee9b73a49b33c8b5dc9f',
    'deploy/oci/runtime.py': TRUSTED['runtime'],
}
TABLES = ('artifacts', 'events', 'experiments', 'idempotency', 'revisions', 'runs')
TERMINAL = frozenset({'SUCCEEDED', 'FAILED', 'CANCELLED'})
OPERATIONS = frozenset({'upgrade-accounts', 'verify-accounts'})
BOOLS = ('old_installation_verified', 'new_installation_verified', 'source_staged', 'image_built',
    'image_smoke_passed', 'admission_paused', 'application_stopped', 'backup_timer_paused',
    'private_journal_saved', 'configuration_switched', 'database_preserved', 'settings_preserved',
    'services_ready', 'worker_exclusive', 'account_discovery_verified', 'auth_boundaries_verified',
    'public_https_verified', 'rollback_attempted', 'rollback_succeeded', 'server_modified',
    'mail_delivery_verified', 'new_calculation_verified', 'commit_visible_after_error',
    'gmail_smtp_tls_checked', 'gmail_smtp_tls_ready', 'actual_email_delivery_verified')
COUNTS = ('experiments', 'revisions', 'runs', 'artifacts', 'peer_containers')
STAGES = frozenset({'configuration', 'lock', 'preflight', 'source', 'build', 'smoke', 'barrier',
    'stop', 'journal', 'switch', 'readiness', 'preservation', 'public', 'complete'})
FIELDS = frozenset(('scope', 'operation', 'status', 'stage', 'failure_reason', 'application_version',
    'mail_configured', 'registration', *BOOLS, *COUNTS))
MAX_OUTPUT = 8192
MAX_DOWNLOAD = 32 * 1024**2
MAX_EXPANDED = 64 * 1024**2
MAX_FILE = 8 * 1024**2
MAX_DATABASE_BYTES = 512 * 1024**2
MAX_VALUE_BYTES = 64 * 1024**2


class UpgradeError(Exception):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UpgradeError()
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(UpgradeError()))


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def validate_config(value):
    if (not isinstance(value, dict) or set(value) != {'source_sha', 'public_origin', 'auth_mode', 'request_id'}
            or not isinstance(value['source_sha'], str) or not re.fullmatch(r'[0-9a-f]{40}', value['source_sha'])
            or value['source_sha'] == OLD_SOURCE or value['auth_mode'] != 'owner-token'
            or not isinstance(value['public_origin'], str) or not isinstance(value['request_id'], str)):
        raise ValueError('invalid fixed upgrade configuration')
    host = value['public_origin'][8:] if value['public_origin'].startswith('https://') else ''
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    if not 3 <= len(host) <= 253 or not re.fullmatch(label + r'(?:\.' + label + r')+', host):
        raise ValueError('invalid fixed upgrade configuration')
    identifier = uuid.UUID(value['request_id'])
    if str(identifier) != value['request_id'] or identifier.version != 4:
        raise ValueError('invalid fixed upgrade configuration')
    return dict(value)


def _argument(value):
    raw = base64.b64decode(value, validate=True)
    result = validate_config(_json(raw))
    if len(raw) > 4096 or _encoded(result) != raw or base64.b64encode(raw).decode() != value:
        raise ValueError('invalid fixed upgrade configuration')
    return result


@contextmanager
def _deadline(seconds):
    def expired(*_):
        raise UpgradeError()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(.001, previous_timer[0] - time.monotonic() + started), previous_timer[1])


@contextmanager
def _interruptions():
    def interrupted(*_):
        raise UpgradeError()
    previous = {s: signal.getsignal(s) for s in (signal.SIGHUP, signal.SIGTERM)}
    try:
        for s in previous:
            signal.signal(s, interrupted)
        yield
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


def _parents(path):
    for item in reversed(path.parents):
        info = os.lstat(item)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise UpgradeError()


def _file(path, *, uid=0, mode=0o600, limit=16384):
    if uid == 0:
        _parents(path)
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_gid != uid
            or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1 or before.st_size > limit):
        raise UpgradeError()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise UpgradeError()
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise UpgradeError()
    return raw


def _new_file(path, raw, mode=0o600):
    _parents(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _replace(path, raw, expected):
    current_bytes = (lambda: _journal_bytes()) if path == JOURNAL else (lambda: _file(path))
    if current_bytes() != expected:
        raise UpgradeError()
    temporary = path.with_name(path.name + '.accounts-' + uuid.uuid4().hex)
    _new_file(temporary, raw)
    try:
        if current_bytes() != expected:
            raise UpgradeError()
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def _lock():
    _parents(LOCK)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        linked = os.lstat(LOCK)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
            raise UpgradeError()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _environment(*, build=False):
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': str(ROOT / 'docker-config'),
        'DOCKER_CONFIG': str(ROOT / 'docker-config'), 'DOCKER_HOST': 'unix:///var/run/docker.sock'}
    if build:
        environment['DOCKER_BUILDKIT'] = '0'
    return environment


def _quiet(command, *, timeout=10, cwd='/', build=False):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, shell=False, env=_environment(build=build), cwd=cwd, timeout=timeout, check=False)
    if result.returncode != 0:
        raise UpgradeError()


def _capture(command, *, limit=8192, timeout=10):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, shell=False, env=_environment(), cwd='/', timeout=timeout, check=False)
    if result.returncode != 0 or len(result.stdout) > limit:
        raise UpgradeError()
    return result.stdout


def _unit(unit, properties):
    raw = _capture(['/usr/bin/systemctl', 'show', '--all', '--no-pager',
        '--property=' + ','.join(properties), unit], limit=4096)
    result = {}
    for line in raw.decode('ascii').splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in properties or key in result:
            raise UpgradeError()
        result[key] = value
    if set(result) != set(properties):
        raise UpgradeError()
    return result


def _services():
    for unit in (APP, HTTPS, TIMER, 'docker.service'):
        if _unit(unit, ('ActiveState', 'UnitFileState')) != {'ActiveState': 'active', 'UnitFileState': 'enabled'}:
            raise UpgradeError()
    for unit in ('quanta-backup-boot.service', 'quanta-backup.service'):
        props = _unit(unit, ('ActiveState', 'LoadState'))
        if props['LoadState'] == 'not-found' and props['ActiveState'] == 'inactive':
            continue
        if props['LoadState'] != 'loaded' or props['ActiveState'] not in {'inactive', 'failed'}:
            raise UpgradeError()


def _installation(config, *, new=False):
    if os.geteuid() != 0 or platform.machine() != 'aarch64':
        raise UpgradeError()
    installed_raw = _file(ETC / 'installed.json')
    installed = _json(installed_raw)
    expected = {'source_sha': config['source_sha'] if new else OLD_SOURCE,
        'public_origin': config['public_origin'], 'auth_mode': 'owner-token'}
    if installed != expected:
        raise UpgradeError()
    deployment_raw = _file(ETC / 'deployment.json')
    deployment = _json(deployment_raw)
    if (not isinstance(deployment, dict) or set(deployment) != {'storage_mode', 'filesystem_uuid', 'image'}
            or deployment['storage_mode'] != 'boot' or not isinstance(deployment['image'], str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', deployment['image'])
            or str(uuid.UUID(deployment['filesystem_uuid'])) != deployment['filesystem_uuid']):
        raise UpgradeError()
    root_info = os.lstat(ROOT)
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_mode & 0o022
            or root_info.st_dev != os.lstat('/').st_dev):
        raise UpgradeError()
    filesystem = _json(_capture(['/usr/bin/findmnt', '--json', '--target', str(ROOT), '--output', 'TARGET,UUID,FSTYPE,OPTIONS,FSROOT']))
    fs = filesystem.get('filesystems') if isinstance(filesystem, dict) else None
    if (not isinstance(fs, list) or len(fs) != 1 or fs[0].get('target') != '/' or fs[0].get('fsroot') != '/'
            or fs[0].get('uuid') != deployment['filesystem_uuid'] or fs[0].get('fstype') not in {'ext4', 'xfs'}
            or 'rw' not in fs[0].get('options', '').split(',')):
        raise UpgradeError()
    for directory in (DATA, ROOT / 'backups'):
        info = os.lstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 10001 or info.st_gid != 10001
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != root_info.st_dev):
            raise UpgradeError()
    settings = {}
    for label, expected_hash in TRUSTED.items():
        path = RUNTIME if label == 'runtime' else SYSTEMD / label
        raw = _file(path, mode=0o755 if label == 'runtime' else 0o644)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise UpgradeError()
        settings[str(path)] = expected_hash
        if label != 'runtime' and _unit(label, ('FragmentPath', 'DropInPaths')) != {'FragmentPath': str(path), 'DropInPaths': ''}:
            raise UpgradeError()
    for name in ('app.env', 'https.env', 'Caddyfile'):
        raw = _file(ETC / name)
        settings[str(ETC / name)] = hashlib.sha256(raw).hexdigest()
    environment = _file(ETC / 'app.env')
    prefix = ('QUANTA_PUBLIC_ORIGIN=' + config['public_origin'] + '\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=').encode()
    if not environment.startswith(prefix) or not re.fullmatch(rb'[0-9a-f]{64}\n', environment[len(prefix):]):
        raise UpgradeError()
    token = environment[len(prefix):-1].decode('ascii')
    return deployment, deployment_raw, installed_raw, settings, token


def _containers(image):
    raw = _capture(DOCKER + ['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'])
    ids = raw.decode('ascii').splitlines()
    if len(ids) != 1 or not re.fullmatch(r'[0-9a-f]{64}', ids[0]):
        raise UpgradeError()
    expected = ids[0] + ' /quanta ' + image + ' true no false false false\n'
    template = '{{.Id}} {{.Name}} {{.Image}} {{.State.Running}} {{.HostConfig.RestartPolicy.Name}} {{.State.Paused}} {{.State.Restarting}} {{.State.Dead}}'
    if _capture(DOCKER + ['container', 'inspect', '--format', template, ids[0]]) != expected.encode():
        raise UpgradeError()


def _worker():
    path = DATA / 'worker.lock'
    _file(path, uid=10001, limit=1024)
    info = os.lstat(path)
    holders = 0
    for row in _file(Path('/proc/locks'), mode=0o444, limit=1024**2).decode('ascii').splitlines():
        match = re.fullmatch(r'[0-9]+:[ \t]+FLOCK[ \t]+ADVISORY[ \t]+WRITE[ \t]+[0-9]+[ \t]+([0-9a-f]+):([0-9a-f]+):([0-9]+)[ \t]+0[ \t]+EOF', row)
        if match and (int(match[1], 16), int(match[2], 16), int(match[3])) == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino):
            holders += 1
    if holders != 1:
        raise UpgradeError()


@contextmanager
def _store_identity():
    if os.getuid() != 0 or os.geteuid() != 0:
        raise UpgradeError()
    uid, gid = os.geteuid(), os.getegid()
    @contextmanager
    def transition():
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGHUP, signal.SIGTERM})
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    try:
        with transition():
            os.setegid(10001)
            os.seteuid(10001)
        yield
    finally:
        with transition():
            try:
                os.seteuid(uid)
            finally:
                os.setegid(gid)


def _typed(value):
    if value is None:
        return b'n'
    if isinstance(value, bytes):
        if len(value) > MAX_VALUE_BYTES:
            raise UpgradeError()
        return b'b' + struct.pack('>Q', len(value)) + value
    if isinstance(value, str):
        encoded = value.encode('utf-8')
        if len(encoded) > MAX_VALUE_BYTES:
            raise UpgradeError()
        return b's' + struct.pack('>Q', len(encoded)) + encoded
    if type(value) is int:
        return b'i' + struct.pack('>q', value)
    if type(value) is float and math.isfinite(value):
        return b'f' + struct.pack('>d', value)
    raise UpgradeError()


def _database():
    path = DATA / 'jobs.sqlite3'
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 10001 or before.st_gid != 10001
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > MAX_DATABASE_BYTES):
        raise UpgradeError()
    result = {'tables': {}, 'nonterminal_runs': 0}
    with _store_identity():
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2, isolation_level=None)
        try:
            expires = time.monotonic() + 30
            connection.set_progress_handler(lambda: int(time.monotonic() > expires), 1000)
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('BEGIN')
            if connection.execute('PRAGMA quick_check(1)').fetchall() != [('ok',)] or connection.execute('PRAGMA foreign_key_check').fetchone() is not None:
                raise UpgradeError()
            schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if names != set(TABLES):
                raise UpgradeError()
            result['schema_sha256'] = hashlib.sha256(_encoded(schema)).hexdigest()
            total = 0
            for table in TABLES:
                cursor = connection.execute('SELECT * FROM ' + table)
                digest = hashlib.sha256()
                for column in cursor.description:
                    digest.update(_typed(column[0]))
                rows = []
                for row in cursor:
                    total += 1
                    if total > 1_000_000 or time.monotonic() > expires:
                        raise UpgradeError()
                    current = hashlib.sha256(struct.pack('>Q', len(row)))
                    for value in row:
                        current.update(_typed(value))
                    rows.append(current.digest())
                for current in sorted(rows):
                    digest.update(current)
                result['tables'][table] = {'rows': len(rows), 'sha256': digest.hexdigest()}
            statuses = connection.execute('SELECT status,count(*) FROM runs GROUP BY status').fetchall()
            if any(status not in TERMINAL | {'QUEUED', 'RUNNING', 'CANCEL_REQUESTED'} or type(count) is not int for status, count in statuses):
                raise UpgradeError()
            result['nonterminal_runs'] = sum(count for status, count in statuses if status not in TERMINAL)
            connection.execute('ROLLBACK')
        finally:
            connection.close()
    after = os.lstat(path)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or result['nonterminal_runs']:
        raise UpgradeError()
    for suffix in ('-wal', '-shm'):
        auxiliary = Path(str(path) + suffix)
        try:
            info = os.lstat(auxiliary)
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 10001 or info.st_gid != 10001
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_dev != before.st_dev):
            raise UpgradeError()
    return result


def _http(config, path, token=None):
    connection = http.client.HTTPConnection('127.0.0.1', 8765, timeout=3)
    headers = {'Host': config['public_origin'][8:], 'Origin': config['public_origin'], 'Connection': 'close'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    try:
        connection.request('GET', path, headers=headers)
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise UpgradeError()
        return response.status, _json(raw)
    finally:
        connection.close()


def _readiness(config, token, *, accounts, report):
    expires = time.monotonic() + 45
    while True:
        try:
            status, value = _http(config, '/health/ready', token)
            if status == 200 and value == {'status': 'ready'}:
                break
        except Exception:
            pass
        if time.monotonic() >= expires:
            raise UpgradeError()
        time.sleep(.25)
    for credential in (None, ('0' if token[0] != '0' else '1') + token[1:]):
        if _http(config, '/v1/experiments', credential)[0] != 401:
            raise UpgradeError()
    report['auth_boundaries_verified'] = True
    status, capabilities = _http(config, '/v1/capabilities', token)
    if status != 200 or not isinstance(capabilities, dict):
        raise UpgradeError()
    version = capabilities.get('package_version')
    if accounts and version != '0.12.0' or not accounts and version != '0.11.0':
        raise UpgradeError()
    report['application_version'] = version if isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) else 'unobserved'
    if accounts:
        status, discovery = _http(config, '/ui/auth')
        if (status != 200 or not isinstance(discovery, dict) or discovery.get('mode') != 'account'
                or discovery.get('authenticated') is not False or type(discovery.get('mail_configured')) is not bool
                or discovery.get('registration') != 'open'):
            raise UpgradeError()
        report['account_discovery_verified'] = True
        report['mail_configured'] = discovery['mail_configured']
        report['registration'] = 'open'
    report['services_ready'] = True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _download(config):
    url = 'https://codeload.github.com/Hyunwoo1205/quanta/tar.gz/' + config['source_sha']
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    output = bytearray()
    with opener.open(urllib.request.Request(url, headers={'User-Agent': 'Quanta-fixed-account-upgrade'}), timeout=10) as response:
        if response.status != 200 or response.geturl() != url:
            raise UpgradeError()
        length = response.headers.get('Content-Length')
        if length is not None and (not re.fullmatch(r'[0-9]{1,10}', length) or int(length) > MAX_DOWNLOAD):
            raise UpgradeError()
        while True:
            part = response.read(min(65536, MAX_DOWNLOAD + 1 - len(output)))
            if not part:
                break
            output.extend(part)
            if len(output) > MAX_DOWNLOAD:
                raise UpgradeError()
    return bytes(output)


def _archive(raw, source_sha):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_DOWNLOAD:
        raise UpgradeError()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = bytearray()
    for offset in range(0, len(raw), 65536):
        expanded.extend(decoder.decompress(raw[offset:offset + 65536], MAX_EXPANDED + 1 - len(expanded)))
        if len(expanded) > MAX_EXPANDED or decoder.unconsumed_tail:
            raise UpgradeError()
    if not decoder.eof or decoder.unused_data:
        raise UpgradeError()
    archive = tarfile.open(fileobj=io.BytesIO(expanded), mode='r:')
    members, seen, total = [], set(), 0
    try:
        for member in archive:
            parts = member.name.rstrip('/').split('/')
            if (len(members) >= 5000 or len(member.name) > 512 or '\\' in member.name
                    or any(ord(c) < 32 or ord(c) == 127 for c in member.name)
                    or any(part in {'', '.', '..'} for part in parts)
                    or parts[0] != 'quanta-' + source_sha or not (member.isdir() or member.isfile())
                    or member.sparse is not None or any(key.startswith('GNU.sparse') for key in member.pax_headers)
                    or not 0 <= member.size <= MAX_FILE):
                raise UpgradeError()
            relative = tuple(parts[1:])
            if relative in seen or not relative and not member.isdir():
                raise UpgradeError()
            seen.add(relative)
            total += member.size
            if total > MAX_EXPANDED:
                raise UpgradeError()
            members.append((relative, member))
        kinds = {parts: member.isdir() for parts, member in members}
        if not members or any(any(parts[:i] in kinds and not kinds[parts[:i]] for i in range(1, len(parts))) for parts in kinds):
            raise UpgradeError()
        return archive, members
    except Exception:
        archive.close()
        raise


def _stage(config, report=None):
    source_parent = ROOT / 'accounts-source'
    _parents(source_parent)
    try:
        os.mkdir(source_parent, 0o755)
        if report is not None:
            report['server_modified'] = True
    except FileExistsError:
        info = os.lstat(source_parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise UpgradeError()
    directory = source_parent / config['source_sha']
    _parents(directory)
    archive, members = _archive(_download(config), config['source_sha'])
    # Network/archive validation happens before creating the private staging tree.
    try:
        os.mkdir(directory, 0o755)
        if report is not None:
            report['server_modified'] = True
        created = {directory}
        for parts, member in members:
            if not parts:
                continue
            destination = directory.joinpath(*parts)
            ancestors = (*reversed(destination.parents), destination) if member.isdir() else tuple(reversed(destination.parents))
            for ancestor in ancestors:
                if ancestor == directory or directory in ancestor.parents:
                    if ancestor not in created:
                        os.mkdir(ancestor, 0o755)
                        created.add(ancestor)
            if member.isfile():
                with archive.extractfile(member) as stream:
                    raw = stream.read(MAX_FILE + 1)
                if len(raw) != member.size:
                    raise UpgradeError()
                _new_file(destination, raw, 0o644)
        for relative, digest in SOURCE_FILES.items():
            if hashlib.sha256(_file(directory / relative, mode=0o644, limit=MAX_FILE)).hexdigest() != digest:
                raise UpgradeError()
        version = _file(directory / 'src/quanta/__init__.py', mode=0o644, limit=1024)
        if not re.search(rb'^__version__ = [\'"]0\.12\.0[\'"]$', version, re.M):
            raise UpgradeError()
    finally:
        archive.close()
    return directory


def _build(config, directory):
    tag = 'quanta:' + config['source_sha']
    if _capture(DOCKER + ['image', 'ls', '--filter', 'reference=' + tag, '--format', '{{.ID}}'], limit=128) != b'':
        raise UpgradeError()
    memory = _file(Path('/proc/meminfo'), mode=0o444, limit=65536)
    available = re.search(rb'^MemAvailable:\s+([0-9]{1,12})\s+kB$', memory, re.M)
    if shutil.disk_usage(ROOT).free < 10 * 1024**3 or available is None or int(available[1]) < 4 * 1048576:
        raise UpgradeError()
    _quiet(DOCKER + ['build', '--platform', 'linux/arm64', '--file', 'Dockerfile.aarch64', '--tag', tag,
        '--label', 'org.quanta.accounts.source=' + config['source_sha'], '--force-rm', '--memory', '2g',
        '--memory-swap', '2g', '--cpu-period', '100000', '--cpu-quota', '200000', '--cpuset-cpus', '0,1', '.'],
        timeout=600, cwd=directory, build=True)
    raw = _capture(DOCKER + ['image', 'inspect', '--format', '{{.Id}} {{.Architecture}} {{.Os}}', tag], limit=128)
    match = re.fullmatch(rb'(sha256:[0-9a-f]{64}) arm64 linux\n', raw)
    if not match:
        raise UpgradeError()
    return match[1].decode()


def _smoke(image):
    common = DOCKER + ['run', '--rm', '--pull=never', '--network', 'none', '--user', '10001:10001',
        '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges=true', '--cpus', '2', '--memory', '2g', '--memory-swap', '2g',
        '--pids-limit', '128', '--workdir', '/tmp', image, 'python', '-m', 'quanta']
    _quiet(common + ['check-contracts'], timeout=45)
    _quiet(common + ['evaluate', '/app/examples/pair_energy_forces.json', '--format', 'text'], timeout=45)


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _journal_bytes():
    # os.link publishes complete bytes without replacing a previous journal.
    # SIGKILL after linking but before unlinking staging can leave nlink=2.
    # Only this exact private sibling/inode pair is a valid publication window.
    before = os.lstat(JOURNAL)
    if before.st_nlink == 1:
        return _file(JOURNAL, limit=1024**2)
    _parents(JOURNAL)
    staging = os.lstat(JOURNAL_STAGING)
    for info in (before, staging):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 2 or info.st_size > 1024**2):
            raise UpgradeError()
    if (before.st_dev, before.st_ino, before.st_size) != (staging.st_dev, staging.st_ino, staging.st_size):
        raise UpgradeError()
    descriptor = os.open(JOURNAL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise UpgradeError()
        raw = stream.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise UpgradeError()
    return raw


def _write_journal(value):
    raw = _encoded(value)
    _parents(JOURNAL)
    descriptor = os.open(JOURNAL_STAGING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    owned = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        linked = os.lstat(JOURNAL_STAGING)
        if (linked.st_dev, linked.st_ino) != (owned.st_dev, owned.st_ino):
            raise UpgradeError()
        os.link(JOURNAL_STAGING, JOURNAL, follow_symlinks=False)
        if _journal_bytes() != raw:
            raise UpgradeError()
        _sync_directory(JOURNAL.parent)
    finally:
        try:
            linked = os.lstat(JOURNAL_STAGING)
            if (linked.st_dev, linked.st_ino) == (owned.st_dev, owned.st_ino):
                JOURNAL_STAGING.unlink()
                _sync_directory(JOURNAL.parent)
        except FileNotFoundError:
            pass


def _journal():
    value = _json(_journal_bytes())
    required = {'schema_version', 'request_id', 'source_sha', 'created_at', 'status', 'database', 'settings',
        'old_deployment', 'new_deployment', 'old_installed', 'new_installed'}
    if (not isinstance(value, dict) or set(value) != required or value['schema_version'] != 1
            or value['status'] not in {'switching', 'complete', 'rolled_back'}
            or not re.fullmatch(r'[0-9a-f]{40}', value['source_sha'])
            or str(uuid.UUID(value['request_id'])) != value['request_id']
            or not isinstance(value['database'], dict) or not isinstance(value['settings'], dict)):
        raise UpgradeError()
    for name in ('old_deployment', 'new_deployment', 'old_installed', 'new_installed'):
        raw = base64.b64decode(value[name], validate=True)
        if len(raw) > 8192 or not isinstance(_json(raw), dict):
            raise UpgradeError()
    return value


def _journal_status(value, status):
    raw = _encoded(value)
    updated = {**value, 'status': status}
    _replace(JOURNAL, _encoded(updated), raw)
    return updated


def _restore(value):
    captured = {}
    for label in ('deployment', 'installed'):
        path = ETC / (label + '.json')
        current = _file(path)
        old = base64.b64decode(value['old_' + label], validate=True)
        new = base64.b64decode(value['new_' + label], validate=True)
        if current not in {old, new}:
            raise UpgradeError()
        captured[label] = current
    _quiet(['/usr/bin/systemctl', 'stop', APP], timeout=55)
    try:
        # A deliberate operator change during stop is not an expected old/new
        # upgrade value. Never adopt that arbitrary current value as a CAS base.
        if any(_file(ETC / (label + '.json')) != captured[label] for label in captured):
            raise UpgradeError()
        for label, expected in captured.items():
            old = base64.b64decode(value['old_' + label], validate=True)
            if expected != old:
                _replace(ETC / (label + '.json'), old, expected)
    except BaseException:
        try:
            _quiet(['/usr/bin/systemctl', 'start', APP, HTTPS, TIMER], timeout=60)
        except BaseException:
            pass
        raise
    _quiet(['/usr/bin/systemctl', 'start', APP, HTTPS, TIMER], timeout=60)
    _journal_status(value, 'rolled_back')


def _watchdog_source():
    # This fixed root helper has no input path or command parameters. It can only
    # restore the exact old bytes in the private journal while state=switching.
    return '''import base64,fcntl,json,os,pathlib,stat,subprocess,uuid
P=pathlib.Path('/etc/quanta/accounts-upgrade.json'); E=P.parent
S=E/'.accounts-upgrade.publish'
L=pathlib.Path('/run/quanta-accounts-upgrade.lock')
def read(p):
 for q in reversed(p.parents):
  s=q.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise ValueError()
 s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>1048576: raise ValueError()
 if s.st_nlink!=1:
  if p!=P or s.st_nlink!=2: raise ValueError()
  try: t=S.lstat()
  except FileNotFoundError: raise ValueError()
  if not stat.S_ISREG(t.st_mode) or t.st_uid!=0 or t.st_gid!=0 or stat.S_IMODE(t.st_mode)!=0o600 or t.st_nlink!=2 or (t.st_dev,t.st_ino,t.st_size)!=(s.st_dev,s.st_ino,s.st_size): raise ValueError()
 f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(f,'rb') as v:
  t=os.fstat(v.fileno())
  if (t.st_dev,t.st_ino)!=(s.st_dev,s.st_ino): raise ValueError()
  b=v.read(1048577)
 if len(b)>1048576: raise ValueError()
 return b
def syncdir():
 f=os.open(E,os.O_RDONLY|os.O_DIRECTORY)
 try: os.fsync(f)
 finally: os.close(f)
def put(p,b,expected):
 if read(p)!=expected: raise ValueError()
 t=p.with_name(p.name+'.rollback-'+uuid.uuid4().hex)
 f=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(f,'wb') as w: w.write(b);w.flush();os.fsync(w.fileno())
 if read(p)!=expected: raise ValueError()
 os.replace(t,p);syncdir()
def ctl(*args):
 r=subprocess.run(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=65,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C'})
 if r.returncode: raise ValueError()
f=os.open(L,os.O_RDWR|os.O_NOFOLLOW);s=os.fstat(f)
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError()
fcntl.flock(f,fcntl.LOCK_EX)
try: journal_raw=read(P);v=json.loads(journal_raw)
except FileNotFoundError:
 ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer');os.close(f);raise SystemExit(0)
if v.get('status')=='switching':
 captured={}
 for n in ('deployment','installed'):
  captured[n]=read(E/(n+'.json'))
  if captured[n] not in (base64.b64decode(v['old_'+n],validate=True),base64.b64decode(v['new_'+n],validate=True)): raise ValueError()
 ctl('stop','quanta-boot.service')
 try:
  if any(read(E/(n+'.json'))!=captured[n] for n in captured): raise ValueError()
  for n in ('deployment','installed'): put(E/(n+'.json'),base64.b64decode(v['old_'+n],validate=True),captured[n])
 except BaseException:
  try: ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer')
  except BaseException: pass
  raise
 ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer')
 v['status']='rolled_back';put(P,json.dumps(v,sort_keys=True,separators=(',',':')).encode(),journal_raw)
os.close(f)
'''.encode()


def _arm_watchdog():
    raw = _watchdog_source()
    try:
        existing = _file(ROLLBACK_SCRIPT)
    except FileNotFoundError:
        _new_file(ROLLBACK_SCRIPT, raw)
    else:
        if existing != raw:
            raise UpgradeError()
    for unit in (WATCHDOG + '.timer', WATCHDOG + '.service'):
        props = _unit(unit, ('LoadState', 'ActiveState'))
        if props != {'LoadState': 'not-found', 'ActiveState': 'inactive'}:
            raise UpgradeError()
    _quiet(['/usr/bin/systemd-run', '--unit=' + WATCHDOG, '--on-active=180s',
        '--timer-property=AccuracySec=1s', '--property=Type=oneshot', '--property=TimeoutStartSec=180s', '--collect',
        '/usr/bin/python3', '-I', '-B', str(ROLLBACK_SCRIPT)], timeout=10)


def _cancel_watchdog():
    for unit in (WATCHDOG + '.timer', WATCHDOG + '.service'):
        props = _unit(unit, ('LoadState', 'ActiveState'))
        if props == {'LoadState': 'not-found', 'ActiveState': 'inactive'}:
            continue
        _quiet(['/usr/bin/systemctl', 'stop', unit], timeout=10)


def _public(config):
    host = config['public_origin'][8:]
    connection = http.client.HTTPSConnection(host, 443, timeout=5, context=ssl.create_default_context())
    try:
        connection.request('GET', '/', headers={'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(1024**2 + 1)
        if response.status != 200 or not 1 <= len(raw) <= 1024**2 or b'Quanta' not in raw:
            raise UpgradeError()
    finally:
        connection.close()



def _gmail_smtp_tls(report):
    """Observe fixed Gmail TLS/greeting only; never authenticate or send mail."""
    report['gmail_smtp_tls_checked'] = True
    report['gmail_smtp_tls_ready'] = False
    try:
        with _deadline(12):
            context = ssl.create_default_context()
            with socket.create_connection(('smtp.gmail.com', 465), timeout=5) as connection:
                with context.wrap_socket(connection, server_hostname='smtp.gmail.com') as secure:
                    secure.settimeout(5)
                    greeting = bytearray()
                    while len(greeting) < 512:
                        chunk = secure.recv(min(64, 512 - len(greeting)))
                        if not chunk:
                            break
                        greeting.extend(chunk)
                        if b'\n' in chunk:
                            break
                    first = bytes(greeting).split(b'\n', 1)[0] + b'\n'
                    report['gmail_smtp_tls_ready'] = (b'\n' in greeting and first.startswith(b'220 ')
                        and first.endswith(b'\r\n') and all(32 <= byte < 127 for byte in first[:-2]))
    except Exception:
        # Network readiness is distinct from application health and actual mail.
        report['gmail_smtp_tls_ready'] = False


def _initial(operation):
    return {'scope': 'accounts_application_upgrade', 'operation': operation, 'status': 'failed',
        'stage': 'configuration', 'failure_reason': 'refused', 'application_version': 'unobserved',
        'mail_configured': False, 'registration': 'unobserved',
        **dict.fromkeys(BOOLS, False), **dict.fromkeys(COUNTS, 0)}


def _upgrade(config, report):
    report['stage'] = 'preflight'
    try:
        os.lstat(JOURNAL)
    except FileNotFoundError:
        pass
    else:
        raise UpgradeError()
    deployment, old_deployment, old_installed, settings, token = _installation(config)
    _services(); _containers(deployment['image']); _worker(); _database()
    report['old_installation_verified'] = True
    report['stage'] = 'source'
    with _deadline(90):
        source = _stage(config, report)
    report.update(source_staged=True, server_modified=True)
    report['stage'] = 'build'
    image = _build(config, source)
    report['image_built'] = True
    report['stage'] = 'smoke'
    _smoke(image)
    report['image_smoke_passed'] = True
    # Recheck every old identity after building while the original app runs.
    current = _installation(config)
    if current[:4] != (deployment, old_deployment, old_installed, settings):
        raise UpgradeError()
    _services(); _containers(deployment['image']); _worker(); _database()
    journal = None
    watchdog = False
    paused = False
    try:
        with _deadline(120):
            _arm_watchdog(); watchdog = True
            report['stage'] = 'barrier'
            paused = True
            _quiet(['/usr/bin/systemctl', 'stop', HTTPS], timeout=15)
            report['admission_paused'] = True
            time.sleep(11)
            _database()
            _quiet(['/usr/bin/systemctl', 'stop', TIMER], timeout=10)
            report['backup_timer_paused'] = True
            for unit in ('quanta-backup-boot.service', 'quanta-backup.service'):
                props = _unit(unit, ('LoadState', 'ActiveState'))
                if props != {'LoadState': 'not-found', 'ActiveState': 'inactive'} and not (
                        props['LoadState'] == 'loaded' and props['ActiveState'] in {'inactive', 'failed'}):
                    raise UpgradeError()
            database = _database()
            if _database() != database:
                raise UpgradeError()
            new_deployment = _encoded({**deployment, 'image': image})
            new_installed = _encoded({'source_sha': config['source_sha'], 'public_origin': config['public_origin'], 'auth_mode': 'owner-token'})
            journal = {'schema_version': 1, 'request_id': config['request_id'], 'source_sha': config['source_sha'],
                'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'status': 'switching',
                'database': database, 'settings': settings,
                'old_deployment': base64.b64encode(old_deployment).decode(), 'new_deployment': base64.b64encode(new_deployment).decode(),
                'old_installed': base64.b64encode(old_installed).decode(), 'new_installed': base64.b64encode(new_installed).decode()}
            report['stage'] = 'journal'
            _write_journal(journal)
            report['private_journal_saved'] = True
            report['stage'] = 'stop'
            _quiet(['/usr/bin/systemctl', 'stop', APP], timeout=55)
            report['application_stopped'] = True
            if _database() != database:
                raise UpgradeError()
            report['stage'] = 'switch'
            _replace(ETC / 'deployment.json', new_deployment, old_deployment)
            _replace(ETC / 'installed.json', new_installed, old_installed)
            report['configuration_switched'] = True
            _quiet(['/usr/bin/systemctl', 'start', APP], timeout=30)
            report['stage'] = 'readiness'
            _readiness(config, token, accounts=True, report=report)
            _containers(image); _worker()
            report['worker_exclusive'] = True
            report['stage'] = 'preservation'
            if _database() != database:
                raise UpgradeError()
            report['database_preserved'] = True
            new_identity = _installation(config, new=True)
            if new_identity[3] != settings:
                raise UpgradeError()
            report['new_installation_verified'] = True
            report['settings_preserved'] = True
            _quiet(['/usr/bin/systemctl', 'start', HTTPS, TIMER], timeout=30)
            _services()
            report['stage'] = 'public'
            _public(config)
            report['public_https_verified'] = True
            journal = _journal_status(journal, 'complete')
            # A late cleanup error must not roll back a committed, verified app.
            # The watchdog checks complete and becomes a no-op before exiting.
            try:
                _cancel_watchdog()
            except Exception:
                pass
            watchdog = False
            for name in COUNTS[:-1]:
                report[name] = database['tables'][name]['rows']
    except BaseException:
        # A directory-fsync error after atomic publication can leave the commit
        # visible even though _journal_status did not return. Do not undo an
        # already verified app and then collide with its complete journal.
        try:
            committed = _journal() if journal is not None else None
        except BaseException:
            committed = None
        if (journal is not None and committed == {**journal, 'status': 'complete'}
                and all(report[name] for name in ('configuration_switched', 'new_installation_verified',
                    'database_preserved', 'settings_preserved', 'public_https_verified'))):
            report['commit_visible_after_error'] = True
            raise
        if journal is not None and not report['private_journal_saved']:
            try:
                os.lstat(JOURNAL)
            except FileNotFoundError:
                # Atomic publication failed before exposing any journal. The
                # configuration switch cannot yet have started, so resume the
                # unchanged services instead of trying to update a missing log.
                journal = None
        report['rollback_attempted'] = True
        try:
            if journal is not None:
                _restore(journal)
            elif paused:
                _quiet(['/usr/bin/systemctl', 'start', APP, HTTPS, TIMER], timeout=65)
            _readiness(config, token, accounts=False, report=_initial('upgrade-accounts'))
            _services()
            if journal is not None and _database() != journal['database']:
                raise UpgradeError()
            report['rollback_succeeded'] = True
            if watchdog:
                _cancel_watchdog()
        except BaseException:
            pass
        raise
    report.update(status='success', stage='complete', failure_reason='none')


def _verify(config, report):
    report['stage'] = 'preflight'
    journal = _journal()
    if journal['source_sha'] != config['source_sha'] or journal['status'] != 'complete':
        raise UpgradeError()
    deployment, _, _, settings, token = _installation(config, new=True)
    report['new_installation_verified'] = True
    _services(); _containers(deployment['image']); _worker()
    report['worker_exclusive'] = True
    report['stage'] = 'readiness'
    _readiness(config, token, accounts=True, report=report)
    report['stage'] = 'preservation'
    database = _database()
    if database != journal['database'] or settings != journal['settings']:
        raise UpgradeError()
    report.update(database_preserved=True, settings_preserved=True)
    for name in COUNTS[:-1]:
        report[name] = database['tables'][name]['rows']
    report['stage'] = 'public'
    _public(config)
    report['public_https_verified'] = True
    _gmail_smtp_tls(report)
    report.update(status='success', stage='complete', failure_reason='none')


def run(config, operation):
    report = _initial(operation if isinstance(operation, str) and operation in OPERATIONS else 'upgrade-accounts')
    try:
        config = validate_config(config)
        if operation not in OPERATIONS:
            raise ValueError()
    except Exception:
        return report
    try:
        report['stage'] = 'lock'
        with _deadline(1020), _interruptions(), _lock():
            if operation == 'upgrade-accounts':
                _upgrade(config, report)
            else:
                _verify(config, report)
    except BaseException:
        report['status'] = 'failed'
    return report


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value['scope'] != 'accounts_application_upgrade'
            or not isinstance(value['operation'], str) or value['operation'] not in OPERATIONS
            or not isinstance(value['status'], str) or value['status'] not in {'success', 'failed'}
            or not isinstance(value['stage'], str) or value['stage'] not in STAGES
            or not isinstance(value['failure_reason'], str) or value['failure_reason'] not in {'none', 'refused'}
            or any(type(value[name]) is not bool for name in (*BOOLS, 'mail_configured'))
            or any(type(value[name]) is not int or not 0 <= value[name] <= 1_000_000 for name in COUNTS)
            or not isinstance(value['application_version'], str)
            or not re.fullmatch(r'(?:unobserved|[0-9]+\.[0-9]+\.[0-9]+)', value['application_version'])
            or not isinstance(value['registration'], str) or value['registration'] not in {'open', 'unobserved'}
            or value['mail_delivery_verified'] or value['actual_email_delivery_verified'] or value['new_calculation_verified']
            or (value['status'] == 'success') != (value['stage'] == 'complete')
            or (value['status'] == 'success') != (value['failure_reason'] == 'none')):
        raise ValueError('invalid account upgrade report')
    if value['status'] == 'success' and not all(value[name] for name in (
            'new_installation_verified', 'database_preserved', 'settings_preserved', 'services_ready',
            'worker_exclusive', 'account_discovery_verified', 'auth_boundaries_verified', 'public_https_verified')):
        raise ValueError('incomplete account upgrade report')
    if value['status'] == 'success' and value['operation'] == 'upgrade-accounts' and not all(value[name] for name in (
            'old_installation_verified', 'source_staged', 'image_built', 'image_smoke_passed', 'admission_paused',
            'application_stopped', 'backup_timer_paused', 'private_journal_saved', 'configuration_switched', 'server_modified')):
        raise ValueError('incomplete account upgrade report')
    if value['operation'] == 'verify-accounts' and any(value[name] for name in (
            'source_staged', 'image_built', 'admission_paused', 'application_stopped', 'backup_timer_paused',
            'configuration_switched', 'rollback_attempted', 'server_modified')):
        raise ValueError('invalid read-only verification report')
    if value['gmail_smtp_tls_ready'] and not value['gmail_smtp_tls_checked']:
        raise ValueError('invalid Gmail network observation')
    if value['operation'] == 'upgrade-accounts' and (value['gmail_smtp_tls_checked'] or value['gmail_smtp_tls_ready']):
        raise ValueError('Gmail network check must remain outside critical upgrade')
    if value['operation'] == 'verify-accounts' and value['status'] == 'success' and not value['gmail_smtp_tls_checked']:
        raise ValueError('Gmail network observation was not attempted')
    if value['rollback_succeeded'] and not value['rollback_attempted']:
        raise ValueError('invalid account upgrade rollback report')
    if value['commit_visible_after_error'] and (value['status'] != 'failed' or value['rollback_attempted']
            or not all(value[name] for name in ('configuration_switched', 'new_installation_verified',
                'database_preserved', 'settings_preserved', 'public_https_verified'))):
        raise ValueError('invalid account upgrade commit report')
    return dict(value)


def sanitize_report(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_OUTPUT:
            return None
        return validate_report(_json(raw))
    except Exception:
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        result = run(_argument(argv[0]), argv[1]) if len(argv) == 2 else _initial('upgrade-accounts')
        result = validate_report(result)
    except Exception:
        result = _initial('upgrade-accounts')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
