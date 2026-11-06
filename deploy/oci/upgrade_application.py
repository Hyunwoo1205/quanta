#!/usr/bin/env python3
"""Fixed 0.15-to-0.16 application upgrade; no database or credential replacement.

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

OLD_SOURCE = 'be398c636bbb9ba18590a7edec601bbcb5f9b1f4'
TARGET_SOURCE = '5723290fc5f4ec9a6fa3b167f00745b18fc03a59'
OLD_VERSION = '0.15.0'
TARGET_VERSION = '0.16.0'
ROOT = Path('/srv/quanta')
DATA = ROOT / 'data'
ETC = Path('/etc/quanta')
JOURNAL = ETC / 'application-upgrade-0.16.json'
JOURNAL_STAGING = ETC / '.application-upgrade-0.16.publish'
LOCK = Path('/run/quanta-application-upgrade.lock')
ROLLBACK_SCRIPT = Path('/usr/local/lib/quanta/application-rollback-0.16.py')
RUNTIME = Path('/usr/local/lib/quanta/runtime.py')
SYSTEMD = Path('/etc/systemd/system')
APP = 'quanta-boot.service'
HTTPS = 'quanta-https.service'
TIMER = 'quanta-backup-boot.timer'
WATCHDOG = 'quanta-application-rollback-0-16'
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
# Fixed candidate package bytes. These hashes prove installation, not browser rendering.
WEB_ASSETS = {'/': {'size_bytes': 21922, 'sha256': '79c8660cd4502aea16d39e3eefb6a77e770306f39b6001812122cc1a4350b6ff'}, '/assets/app.js': {'size_bytes': 64196, 'sha256': 'f833b472d5f8dbf60070fa4ef817e4c1890321a04fc9a6e52b7516ae2f82f586'}, '/assets/view-model.mjs': {'size_bytes': 21052, 'sha256': 'a3d5b92478fa9cc449b2eb11860346fc74ec68d51602ce4d10af8c970385b0c6'}, '/assets/dynamics-evidence.mjs': {'size_bytes': 2325, 'sha256': '7ab9c6d4778e4dd475b334afb692c54d0bfc02a15a0d00713445efb876fae1c1'}, '/assets/dynamics-model.mjs': {'size_bytes': 14952, 'sha256': '715ea0dc8d0424bf2f91f5aece4e3252fde742c3eb0b4c41474b730e9ae516fc'}, '/assets/dynamics-viewer.mjs': {'size_bytes': 29484, 'sha256': 'b11bf6db20bc93603568ed680558444f9484b55a6c7e6e80c4f0fb52c499a04d'}, '/assets/dynamics-viewer.css': {'size_bytes': 6139, 'sha256': '0bbb4e1042074cf70aa1c0babd4b8b4ce423d9d8cd6939acbf8ac18ecf40c549'}}
TABLES = ('artifacts', 'events', 'experiments', 'idempotency', 'revisions', 'runs')
TERMINAL = frozenset({'SUCCEEDED', 'FAILED', 'CANCELLED'})
OPERATIONS = frozenset({'audit-application', 'upgrade-application', 'verify-application', 'smoke-application'})
BOOLS = ('old_installation_verified', 'new_installation_verified', 'source_staged', 'image_built',
    'image_smoke_passed', 'admission_paused', 'application_stopped', 'backup_timer_paused',
    'private_journal_saved', 'configuration_switched', 'database_preserved', 'settings_preserved',
    'services_ready', 'worker_exclusive', 'account_discovery_verified', 'auth_boundaries_verified',
    'public_https_verified', 'rollback_attempted', 'rollback_succeeded', 'server_modified',
    'mail_delivery_verified', 'new_calculation_verified', 'commit_visible_after_error',
    'gmail_smtp_tls_checked', 'gmail_smtp_tls_ready', 'actual_email_delivery_verified',
    'auth_database_preserved', 'mail_settings_preserved', 'dynamics_capability_verified',
    'existing_rows_preserved', 'scientific_smoke_verified', 'committed_resume')
COUNTS = ('experiments', 'revisions', 'runs', 'artifacts', 'auth_accounts', 'auth_sessions', 'active_runs', 'peer_containers')
STAGES = frozenset({'configuration', 'lock', 'preflight', 'source', 'build', 'smoke', 'barrier',
    'stop', 'journal', 'switch', 'readiness', 'preservation', 'public', 'complete'})
FIELDS = frozenset(('scope', 'operation', 'status', 'stage', 'failure_reason', 'application_version',
    'mail_configured', 'registration', 'preservation_scope', 'smoke_preservation_scope', *BOOLS, *COUNTS))
MAX_OUTPUT = 8192
MAX_DOWNLOAD = 32 * 1024**2
MAX_EXPANDED = 64 * 1024**2
MAX_FILE = 8 * 1024**2
MAX_DATABASE_BYTES = 512 * 1024**2
MAX_VALUE_BYTES = 64 * 1024**2
AUTH_TABLES = ('accounts', 'challenges', 'meta', 'rate_windows', 'sessions')
MAIL_FILES = ('gmail-smtp.json', 'gmail-budget.json', 'gmail-mail.lock')
MAX_HTTP = 4 * 1024**2


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
            or not isinstance(value['source_sha'], str) or value['source_sha'] != TARGET_SOURCE
            or value['source_sha'] != TARGET_SOURCE or value['auth_mode'] != 'owner-token'
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


def _database_file(path, tables, *, jobs=False, require_idle=True, include_rows=False):
    before = os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 10001 or before.st_gid != 10001
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > MAX_DATABASE_BYTES):
        raise UpgradeError()
    result = {'tables': {}, 'pragmas': {}, 'nonterminal_runs': 0}
    with _store_identity():
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2, isolation_level=None)
        try:
            expires = time.monotonic()+30
            connection.set_progress_handler(lambda: int(time.monotonic() > expires), 1000)
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('BEGIN')
            if connection.execute('PRAGMA quick_check(1)').fetchall() != [('ok',)] or connection.execute('PRAGMA foreign_key_check').fetchone() is not None:
                raise UpgradeError()
            schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            if names - {'sqlite_sequence'} != set(tables):
                raise UpgradeError()
            result['schema_sha256'] = hashlib.sha256(_encoded(schema)).hexdigest()
            for pragma in ('user_version', 'application_id'):
                value = connection.execute('PRAGMA '+pragma).fetchone()[0]
                if type(value) is not int:
                    raise UpgradeError()
                result['pragmas'][pragma] = value
            total = 0
            for table in sorted(names):
                if table not in set(tables) | {'sqlite_sequence'}:
                    raise UpgradeError()
                cursor = connection.execute('SELECT * FROM '+table)
                digest = hashlib.sha256()
                for column in cursor.description:
                    digest.update(_typed(column[0]))
                rows = []
                sequence = {}
                for row in cursor:
                    total += 1
                    if total > 1_000_000 or time.monotonic() > expires:
                        raise UpgradeError()
                    current = hashlib.sha256(struct.pack('>Q', len(row)))
                    for value in row:
                        current.update(_typed(value))
                    rows.append(current.digest())
                    if table == 'sqlite_sequence':
                        if len(row) != 2 or not isinstance(row[0],str) or type(row[1]) is not int or row[1] < 0:
                            raise UpgradeError()
                        sequence[row[0]]=row[1]
                for current in sorted(rows):
                    digest.update(current)
                value = {'rows':len(rows), 'sha256':digest.hexdigest()}
                if include_rows:
                    value['row_hashes']=[x.hex() for x in sorted(rows)]
                result['tables'][table]=value
                if table == 'sqlite_sequence':
                    result['sequence']=sequence
            if jobs:
                statuses = connection.execute('SELECT status,count(*) FROM runs GROUP BY status').fetchall()
                if any(status not in TERMINAL | {'QUEUED','RUNNING','CANCEL_REQUESTED'} or type(count) is not int for status,count in statuses):
                    raise UpgradeError()
                result['nonterminal_runs']=sum(count for status,count in statuses if status not in TERMINAL)
            connection.execute('ROLLBACK')
        finally:
            connection.close()
    after=os.lstat(path)
    if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino) or require_idle and result['nonterminal_runs']:
        raise UpgradeError()
    for suffix in ('-wal','-shm'):
        try:info=os.lstat(Path(str(path)+suffix))
        except FileNotFoundError:continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=10001 or info.st_gid!=10001
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_dev!=before.st_dev):
            raise UpgradeError()
    return result


def _database(*, require_idle=True, include_rows=False):
    return _database_file(DATA/'jobs.sqlite3',TABLES,jobs=True,require_idle=require_idle,include_rows=include_rows)


def _auth_database(*, include_rows=False):
    return _database_file(DATA/'auth.sqlite3',AUTH_TABLES,require_idle=False,include_rows=include_rows)


def _databases(*, require_idle=True, include_rows=False):
    return {'jobs':_database(require_idle=require_idle,include_rows=include_rows),
            'auth':_auth_database(include_rows=include_rows)}


def _mail_settings():
    result={}
    for name in MAIL_FILES:
        path=DATA/name
        try:
            info=os.lstat(path)
        except FileNotFoundError:
            result[name]={'present':False}
            continue
        raw=_file(path,uid=10001,mode=0o600,limit=16384)
        result[name]={'present':True,'uid':info.st_uid,'gid':info.st_gid,
                      'mode':stat.S_IMODE(info.st_mode),'sha256':hashlib.sha256(raw).hexdigest()}
    return result


def _counts(database, report):
    for name in ('experiments','revisions','runs','artifacts'):
        report[name]=database['jobs']['tables'][name]['rows']
    report['auth_accounts']=database['auth']['tables']['accounts']['rows']
    report['auth_sessions']=database['auth']['tables']['sessions']['rows']
    report['active_runs']=database['jobs']['nonterminal_runs']


def _api(config, method, path, token=None, body=None, *, maximum=MAX_HTTP, raw_response=False, key=None):
    connection=http.client.HTTPConnection('127.0.0.1',8765,timeout=30)
    headers={'Host':config['public_origin'][8:],'Origin':config['public_origin'],'Connection':'close'}
    if token is not None:headers['Authorization']='Bearer '+token
    if body is not None:headers['Content-Type']='application/json'
    if key is not None:headers['Idempotency-Key']=key
    try:
        connection.request(method,path,headers=headers,body=None if body is None else _encoded(body))
        response=connection.getresponse()
        raw=response.read(maximum+1)
        if len(raw)>maximum:raise UpgradeError()
        return response.status,raw if raw_response else _json(raw)
    finally:connection.close()


def _http(config, path, token=None):
    return _api(config,'GET',path,token,maximum=1024**2)


def _check_web_asset(path, status, raw):
    expected = WEB_ASSETS[path]
    if (status != 200 or not isinstance(raw, bytes) or len(raw) != expected['size_bytes']
            or hashlib.sha256(raw).hexdigest() != expected['sha256']):
        raise UpgradeError()


def _web_assets(config):
    # Public static shell only, with no bearer or cookie: no account-session write.
    for path, expected in WEB_ASSETS.items():
        status, raw = _api(config, 'GET', path, maximum=expected['size_bytes'], raw_response=True)
        _check_web_asset(path, status, raw)


def _readiness(config, token, *, new, report):
    expires=time.monotonic()+45
    while True:
        try:
            status,value=_http(config,'/health/ready',token)
            if status==200 and value=={'status':'ready'}:break
        except Exception:pass
        if time.monotonic()>=expires:raise UpgradeError()
        time.sleep(.25)
    for credential in (None,('0' if token[0]!='0' else '1')+token[1:]):
        if _http(config,'/v1/experiments',credential)[0]!=401:raise UpgradeError()
    report['auth_boundaries_verified']=True
    status,capabilities=_http(config,'/v1/capabilities',token)
    if status!=200 or not isinstance(capabilities,dict) or capabilities.get('package_version')!=(TARGET_VERSION if new else OLD_VERSION):
        raise UpgradeError()
    if capabilities.get('contract_version')!='0.2.0':raise UpgradeError()
    if new:
        contracts=capabilities.get('experiment_contracts')
        if (capabilities.get('supported_experiment_versions')!=['0.2.0','0.4.0'] or not isinstance(contracts,dict)
                or contracts.get('0.4.0',{}).get('implemented_operations')!={'quanta.pair_dynamics@0.1.0':['integrate']}):
            raise UpgradeError()
        _web_assets(config)
        report['dynamics_capability_verified']=True
    report['application_version']=TARGET_VERSION if new else OLD_VERSION
    status,discovery=_http(config,'/ui/auth')
    if (status!=200 or not isinstance(discovery,dict) or discovery.get('mode')!='account'
            or discovery.get('authenticated') is not False or type(discovery.get('mail_configured')) is not bool
            or discovery.get('registration')!='open'):
        raise UpgradeError()
    report['account_discovery_verified']=True
    report['mail_configured']=discovery['mail_configured']
    report['registration']='open'
    report['services_ready']=True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


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
    source_parent = ROOT / 'application-source'
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
        for path, expected in WEB_ASSETS.items():
            relative = 'src/quanta/web/index.html' if path == '/' else 'src/quanta/web/' + path.rsplit('/', 1)[1]
            raw = _file(directory / relative, mode=0o644, limit=MAX_FILE)
            _check_web_asset(path, 200, raw)
        version = _file(directory / 'src/quanta/__init__.py', mode=0o644, limit=1024)
        if not re.search(rb'^__version__ = [\'"]0\.16\.0[\'"]$', version, re.M):
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
        '--label', 'org.quanta.application.source=' + config['source_sha'], '--force-rm', '--memory', '2g',
        '--memory-swap', '2g', '--cpu-period', '100000', '--cpu-quota', '200000', '--cpuset-cpus', '0,1', '.'],
        timeout=600, cwd=directory, build=True)
    raw = _capture(DOCKER + ['image', 'inspect', '--format', '{{.Id}} {{.Architecture}} {{.Os}}', tag], limit=128)
    match = re.fullmatch(rb'(sha256:[0-9a-f]{64}) arm64 linux\n', raw)
    if not match:
        raise UpgradeError()
    return match[1].decode()


def _smoke(image):
    common=DOCKER+['run','--rm','--pull=never','--network','none','--user','10001:10001',
        '--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777','--cap-drop','ALL',
        '--security-opt','no-new-privileges=true','--cpus','2','--memory','2g','--memory-swap','2g',
        '--pids-limit','128','--workdir','/tmp',image,'python','-m','quanta']
    _quiet(common+['check-contracts'],timeout=45)
    _quiet(common+['check-contracts','--contract-version','0.4.0'],timeout=45)
    _quiet(common+['evaluate','/app/examples/pair_energy_forces.json','--format','text'],timeout=45)
    _quiet(common+['run','/app/contracts/v0.4.0/examples/free_revision.json','--format','text'],timeout=90)


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
    if len(raw)>1024**2:raise UpgradeError()
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
        'old_deployment', 'new_deployment', 'old_installed', 'new_installed', 'mail_settings'}
    if (not isinstance(value, dict) or set(value) != required or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['status'] not in {'switching', 'complete', 'rolled_back'}
            or value['source_sha'] != TARGET_SOURCE
            or str(uuid.UUID(value['request_id'])) != value['request_id']
            or not isinstance(value['database'], dict) or not isinstance(value['settings'], dict)
            or not isinstance(value['mail_settings'], dict)):
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


def _expected_settings_modes():
    return {RUNTIME:0o755, **{SYSTEMD/name:0o644 for name in TRUSTED if name!='runtime'},
            **{ETC/name:0o600 for name in ('app.env','https.env','Caddyfile')}}


def _watchdog_source():
    source = "import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,uuid\nP=pathlib.Path('/etc/quanta/application-upgrade.json'); E=P.parent\nS=E/'.application-upgrade.publish'\nL=pathlib.Path('/run/quanta-application-upgrade.lock')\ndef read(p,mode=0o600):\n for q in reversed(p.parents):\n  s=q.lstat()\n  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise ValueError()\n s=p.lstat()\n if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=mode or s.st_size>1048576: raise ValueError()\n if s.st_nlink!=1:\n  if p!=P or s.st_nlink!=2: raise ValueError()\n  try: t=S.lstat()\n  except FileNotFoundError: raise ValueError()\n  if not stat.S_ISREG(t.st_mode) or t.st_uid!=0 or t.st_gid!=0 or stat.S_IMODE(t.st_mode)!=0o600 or t.st_nlink!=2 or (t.st_dev,t.st_ino,t.st_size)!=(s.st_dev,s.st_ino,s.st_size): raise ValueError()\n f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n with os.fdopen(f,'rb') as v:\n  t=os.fstat(v.fileno())\n  if (t.st_dev,t.st_ino)!=(s.st_dev,s.st_ino): raise ValueError()\n  b=v.read(1048577)\n if len(b)>1048576: raise ValueError()\n return b\ndef syncdir():\n f=os.open(E,os.O_RDONLY|os.O_DIRECTORY)\n try: os.fsync(f)\n finally: os.close(f)\ndef put(p,b,expected):\n if read(p)!=expected: raise ValueError()\n t=p.with_name(p.name+'.rollback-'+uuid.uuid4().hex)\n f=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(f,'wb') as w: w.write(b);w.flush();os.fsync(w.fileno())\n if read(p)!=expected: raise ValueError()\n os.replace(t,p);syncdir()\ndef ctl(*args):\n r=subprocess.run(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=65,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C'})\n if r.returncode: raise ValueError()\nf=os.open(L,os.O_RDWR|os.O_NOFOLLOW);s=os.fstat(f)\nif not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError()\nfcntl.flock(f,fcntl.LOCK_EX)\ntry: journal_raw=read(P);v=json.loads(journal_raw)\nexcept FileNotFoundError:\n ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer');os.close(f);raise SystemExit(0)\nif v.get('status')=='complete':\n if v.get('source_sha')!=TARGET: raise ValueError()\n for n in ('deployment','installed'):\n  if read(E/(n+'.json'))!=base64.b64decode(v['new_'+n],validate=True): raise ValueError()\n if not isinstance(v.get('settings'),dict) or set(v['settings'])!=set(M): raise ValueError()\n for n,mode in M.items():\n  if hashlib.sha256(read(pathlib.Path(n),mode)).hexdigest()!=v['settings'][n]: raise ValueError()\n ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer')\nif v.get('status')=='switching':\n captured={}\n for n in ('deployment','installed'):\n  captured[n]=read(E/(n+'.json'))\n  if captured[n] not in (base64.b64decode(v['old_'+n],validate=True),base64.b64decode(v['new_'+n],validate=True)): raise ValueError()\n ctl('stop','quanta-boot.service')\n try:\n  if any(read(E/(n+'.json'))!=captured[n] for n in captured): raise ValueError()\n  for n in ('deployment','installed'): put(E/(n+'.json'),base64.b64decode(v['old_'+n],validate=True),captured[n])\n except BaseException:\n  try: ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer')\n  except BaseException: pass\n  raise\n ctl('start','quanta-boot.service','quanta-https.service','quanta-backup-boot.timer')\n v['status']='rolled_back';put(P,json.dumps(v,sort_keys=True,separators=(',',':')).encode(),journal_raw)\nos.close(f)\n"
    source=source.replace("P=pathlib.Path('/etc/quanta/application-upgrade.json'); E=P.parent", 'P=pathlib.Path('+repr(str(JOURNAL))+'); E=P.parent')
    source=source.replace("S=E/'.application-upgrade.publish'", 'S=pathlib.Path('+repr(str(JOURNAL_STAGING))+')')
    source=source.replace("L=pathlib.Path('/run/quanta-application-upgrade.lock')", 'L=pathlib.Path('+repr(str(LOCK))+')')
    source='TARGET='+repr(TARGET_SOURCE)+'\nM='+repr({str(path):mode for path,mode in _expected_settings_modes().items()})+'\n'+source
    return source.encode()


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
    _quiet(['/usr/bin/systemd-run', '--unit=' + WATCHDOG, '--on-active=300s',
        '--timer-property=AccuracySec=1s', '--property=Type=oneshot', '--property=TimeoutStartSec=1800s', '--collect',
        '/usr/bin/python3', '-I', '-B', str(ROLLBACK_SCRIPT)], timeout=10)


def _cancel_watchdog():
    for unit in (WATCHDOG + '.timer', WATCHDOG + '.service'):
        props = _unit(unit, ('LoadState', 'ActiveState'))
        if props == {'LoadState': 'not-found', 'ActiveState': 'inactive'}:
            continue
        _quiet(['/usr/bin/systemctl', 'stop', unit], timeout=10)


def _public(config, new=False):
    host = config['public_origin'][8:]
    paths = WEB_ASSETS if new else {'/': {'size_bytes': 1024**2}}
    for path, expected in paths.items():
        connection = http.client.HTTPSConnection(host, 443, timeout=5, context=ssl.create_default_context())
        try:
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(expected['size_bytes'] + 1)
            if new:
                _check_web_asset(path, response.status, raw)
            elif response.status != 200 or not 1 <= len(raw) <= 1024**2 or b'Quanta' not in raw:
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
    return {'scope': 'application_upgrade', 'operation': operation, 'status': 'failed',
        'stage': 'configuration', 'failure_reason': 'refused', 'application_version': 'unobserved',
        'mail_configured': False, 'registration': 'unobserved', 'preservation_scope': 'unmeasured', 'smoke_preservation_scope': 'unmeasured',
        **dict.fromkeys(BOOLS, False), **dict.fromkeys(COUNTS, 0)}


def _current(config):
    try:return False,_installation(config,new=False)
    except UpgradeError:return True,_installation(config,new=True)


def _proof_report(report, *, scope):
    report.update(database_preserved=True,auth_database_preserved=True,mail_settings_preserved=True,
                  settings_preserved=True,preservation_scope=scope)


def _audit(config, report):
    report['stage']='preflight'
    new,identity=_current(config)
    deployment,_,_,_,token=identity
    report['new_installation_verified' if new else 'old_installation_verified']=True
    _services();_containers(deployment['image']);_worker()
    report['worker_exclusive']=True
    _readiness(config,token,new=new,report=report)
    database=_databases(require_idle=False);_mail_settings();_counts(database,report)
    report['stage']='public';_public(config,new);report['public_https_verified']=True
    report.update(status='success',stage='complete',failure_reason='none')


def _committed_identity(config, journal):
    identity=_installation(config,new=True)
    if (identity[1]!=base64.b64decode(journal['new_deployment'],validate=True)
            or identity[2]!=base64.b64decode(journal['new_installed'],validate=True)
            or identity[3]!=journal['settings']):raise UpgradeError()
    return identity


def _resume(config, report, journal):
    # A committed image is never automatically rolled back after public
    # admission may have accepted new-version input. Resume fixed services only.
    report.update(committed_resume=True,commit_visible_after_error=False)
    if journal['source_sha']!=TARGET_SOURCE or journal['status']!='complete':raise UpgradeError()
    deployment,_,_,settings,token=_committed_identity(config,journal)
    report.update(new_installation_verified=True,private_journal_saved=True)
    _proof_report(report,scope='committed_upgrade')
    report['server_modified']=True
    _quiet(['/usr/bin/systemctl','start',APP],timeout=30)
    _readiness(config,token,new=True,report=report)
    _containers(deployment['image']);_worker();report['worker_exclusive']=True
    _counts(_databases(require_idle=False),report);_mail_settings()
    _quiet(['/usr/bin/systemctl','start',HTTPS,TIMER],timeout=30)
    _services();report['stage']='public';_public(config,True);report['public_https_verified']=True
    try:_cancel_watchdog()
    except Exception:pass
    report.update(status='success',stage='complete',failure_reason='none')


def _upgrade(config, report):
    report['stage']='preflight'
    try:existing=_journal()
    except FileNotFoundError:existing=None
    if existing is not None:
        if existing['status']=='complete':return _resume(config,report,existing)
        raise UpgradeError()
    deployment,old_deployment,old_installed,settings,token=_installation(config)
    _services();_containers(deployment['image']);_worker();_databases();_mail_settings()
    _readiness(config,token,new=False,report=report)
    prior_mail_configured=report['mail_configured']
    report['old_installation_verified']=True
    report['stage']='source'
    with _deadline(90):source=_stage(config,report)
    report.update(source_staged=True,server_modified=True)
    report['stage']='build';image=_build(config,source);report['image_built']=True
    report['stage']='smoke';_smoke(image);report['image_smoke_passed']=True
    current=_installation(config)
    if current[:4]!=(deployment,old_deployment,old_installed,settings):raise UpgradeError()
    _services();_containers(deployment['image']);_worker();_databases()
    journal=None;watchdog=False;paused=False
    try:
        with _deadline(240):
            _arm_watchdog();watchdog=True
            report['stage']='barrier';paused=True
            _quiet(['/usr/bin/systemctl','stop',HTTPS],timeout=15)
            report['admission_paused']=True
            time.sleep(11)
            _databases()
            _quiet(['/usr/bin/systemctl','stop',TIMER],timeout=10)
            report['backup_timer_paused']=True
            for unit in ('quanta-backup-boot.service','quanta-backup.service'):
                props=_unit(unit,('LoadState','ActiveState'))
                if props!={'LoadState':'not-found','ActiveState':'inactive'} and not (
                        props['LoadState']=='loaded' and props['ActiveState'] in {'inactive','failed'}):raise UpgradeError()
            report['stage']='stop';_quiet(['/usr/bin/systemctl','stop',APP],timeout=55)
            report['application_stopped']=True
            if _unit(APP,('ActiveState',))!={'ActiveState':'inactive'}:raise UpgradeError()
            # Definitive baseline is quiescent: no old worker or auth request can
            # mutate a row between this capture and the new image startup.
            database=_databases();mail=_mail_settings()
            if _databases()!=database or _mail_settings()!=mail:raise UpgradeError()
            new_deployment=_encoded({**deployment,'image':image})
            new_installed=_encoded({'source_sha':TARGET_SOURCE,'public_origin':config['public_origin'],'auth_mode':'owner-token'})
            journal={'schema_version':1,'request_id':config['request_id'],'source_sha':TARGET_SOURCE,
                'created_at':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),'status':'switching',
                'database':database,'mail_settings':mail,'settings':settings,
                'old_deployment':base64.b64encode(old_deployment).decode(),'new_deployment':base64.b64encode(new_deployment).decode(),
                'old_installed':base64.b64encode(old_installed).decode(),'new_installed':base64.b64encode(new_installed).decode()}
            report['stage']='journal';_write_journal(journal);report['private_journal_saved']=True
            report['stage']='switch'
            _replace(ETC/'deployment.json',new_deployment,old_deployment)
            _replace(ETC/'installed.json',new_installed,old_installed)
            report['configuration_switched']=True
            _quiet(['/usr/bin/systemctl','start',APP],timeout=30)
            report['stage']='readiness';_readiness(config,token,new=True,report=report)
            if report['mail_configured'] is not prior_mail_configured:raise UpgradeError()
            _containers(image);_worker();report['worker_exclusive']=True
            report['stage']='preservation'
            if _databases()!=database or _mail_settings()!=mail:raise UpgradeError()
            new_identity=_installation(config,new=True)
            if new_identity[1]!=new_deployment or new_identity[2]!=new_installed or new_identity[3]!=settings:raise UpgradeError()
            report['new_installation_verified']=True
            _proof_report(report,scope='private_barrier')
            # This commit is before opening public admission. Once complete,
            # new-version writes may exist, so no automatic old-image rollback.
            journal=_journal_status(journal,'complete')
            _quiet(['/usr/bin/systemctl','start',HTTPS,TIMER],timeout=30)
            _services();report['stage']='public';_public(config,True);report['public_https_verified']=True
            try:_cancel_watchdog()
            except Exception:pass
            watchdog=False;_counts(database,report)
    except BaseException:
        try:committed=_journal() if journal is not None else None
        except BaseException:committed=None
        if committed is not None and committed.get('status')=='complete' and committed.get('source_sha')==TARGET_SOURCE:
            report['commit_visible_after_error']=True
            # The watchdog completes service reopening if this process dies.
            raise
        if journal is not None and not report['private_journal_saved']:
            try:os.lstat(JOURNAL)
            except FileNotFoundError:journal=None
        report['rollback_attempted']=True
        try:
            if journal is not None:_restore(journal)
            elif paused:_quiet(['/usr/bin/systemctl','start',APP,HTTPS,TIMER],timeout=65)
            _readiness(config,token,new=False,report=_initial('upgrade-application'))
            _services()
            if journal is not None and (_databases()!=journal['database'] or _mail_settings()!=journal['mail_settings']):raise UpgradeError()
            report['rollback_succeeded']=True
            if watchdog:_cancel_watchdog()
        except BaseException:pass
        raise
    report.update(status='success',stage='complete',failure_reason='none')


def _verify(config, report):
    report['stage']='preflight';journal=_journal()
    if journal['source_sha']!=TARGET_SOURCE or journal['status']!='complete':raise UpgradeError()
    deployment,_,_,settings,token=_committed_identity(config,journal)
    report['new_installation_verified']=True
    _services();_containers(deployment['image']);_worker();report['worker_exclusive']=True
    _readiness(config,token,new=True,report=report)
    # This verifies the committed point-in-time transition proof. Normal live
    # sessions, new experiments and Gmail quotas may legitimately change later.
    _proof_report(report,scope='committed_upgrade')
    _counts(_databases(require_idle=False),report);_mail_settings()
    report['stage']='public';_public(config,True);report['public_https_verified']=True
    report.update(status='success',stage='complete',failure_reason='none')


def _smoke_definition():
    return {'unit_system':'SI','scales':{'length_m':1,'energy_j':1,'time_s':1},
        'system':{'module_id':'quanta.pair_dynamics','module_version':'0.1.0','representation':'particles_phase_space_3d',
            'boundary':'nonperiodic','min_distance_m':0.1,'particles':[
                {'id':'left','position_m':[-1,0,0],'velocity_m_per_s':[0.125,0,0],'mass_kg':1},
                {'id':'right','position_m':[1,0,0],'velocity_m_per_s':[0,0,0],'mass_kg':3}],
            'potential':{'expression':{'op':'const','value':0},'parameters':{}}},
        'numerics':{'integrator':'velocity_verlet_forward_ad','dt_s':0.125,'steps':8,'sample_stride':1,'refinement':'none',
            'energy_drift_atol':1e-12,'momentum_drift_atol':1e-10,'angular_momentum_drift_atol':1e-10,'state_atol':1e-6,'state_rtol':1e-6},
        'protocol':{'steps':[{'step_id':'motion','operation':'integrate','source':'initial','overrides':[]}],'sweep':{'axes':[]}},
        'observables':['trajectory','conservation_diagnostics'],'extensions':{}}


def _uuid(value):
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value) is not None


def _append_only(before, after):
    from collections import Counter
    a,b=before['jobs'],after['jobs']
    if a['schema_sha256']!=b['schema_sha256'] or a['pragmas']!=b['pragmas']:raise UpgradeError()
    # Initial idle admission makes every old run terminal. Public users may
    # append new work and touch auth/session/Gmail/idempotency state meanwhile.
    for table in ('experiments','revisions','runs','events','artifacts'):
        old=a['tables'][table];new=b['tables'].get(table)
        if new is None or Counter(old['row_hashes'])-Counter(new['row_hashes']):raise UpgradeError()
    oldseq=a.get('sequence',{});newseq=b.get('sequence',{})
    if set(newseq)-set(oldseq)-{'experiments','events','runs'}:raise UpgradeError()
    if any(newseq.get(table,0)<value for table,value in oldseq.items()):raise UpgradeError()


def _smoke_application(config, report):
    report['stage']='preflight';journal=_journal()
    if journal['source_sha']!=TARGET_SOURCE or journal['status']!='complete':raise UpgradeError()
    deployment,_,_,settings,token=_committed_identity(config,journal)
    _services();_containers(deployment['image']);_worker()
    report.update(new_installation_verified=True,worker_exclusive=True)
    _readiness(config,token,new=True,report=report)
    try:
        before=_databases(include_rows=True)
        report['stage']='smoke'
        report['server_modified']=True
        status,exp=_api(config,'POST','/v1/experiments',token,{'title':'Quanta verified application upgrade'})
        if status!=201 or not _uuid(exp.get('experiment_id')):raise UpgradeError()
        status,rev=_api(config,'POST','/v1/experiments/'+exp['experiment_id']+'/revisions',token,
            {'schema_version':'0.4.0','title':'Verified free dynamics','definition':_smoke_definition()})
        if status!=201 or not _uuid(rev.get('revision_id')) or rev.get('definition')!=_smoke_definition():raise UpgradeError()
        status,run=_api(config,'POST','/v1/runs',token,{'revision_id':rev['revision_id']},key='application-smoke-'+config['request_id'])
        if status!=202 or not _uuid(run.get('run_id')):raise UpgradeError()
        deadline=time.monotonic()+120
        while True:
            status,terminal=_api(config,'GET','/v1/runs/'+run['run_id'],token)
            if status!=200:raise UpgradeError()
            if terminal.get('execution_status') in TERMINAL:break
            if time.monotonic()>deadline:raise UpgradeError()
            time.sleep(.25)
        if terminal['execution_status']!='SUCCEEDED':raise UpgradeError()
        status,result=_api(config,'GET','/v1/runs/'+run['run_id']+'/result',token)
        if (status!=200 or result.get('schema_version')!='0.4.0' or result.get('execution_status')!='SUCCEEDED'
                or result.get('physical_validation_status')!='unvalidated' or result.get('partial') is not False):raise UpgradeError()
        steps=result.get('steps');states=result.get('states')
        if not isinstance(steps,list) or len(steps)!=1 or not isinstance(states,list):raise UpgradeError()
        step=steps[0];payload=step.get('payload')
        if not isinstance(payload,dict) or payload.get('partial') is not False or payload.get('primary_refinement_factor')!=1:raise UpgradeError()
        if payload.get('particle_ids')!=['left','right'] or payload.get('masses_kg')!=[1,3]:raise UpgradeError()
        if step.get('outcome')!='SUCCEEDED' or step.get('numerical_status')!='pass' or step.get('resolution_status')!='not_checked':raise UpgradeError()
        legs=payload.get('legs')
        if not isinstance(legs,list) or len(legs)!=1:raise UpgradeError()
        leg=legs[0];frames=leg.get('sampled_frames')
        if (leg.get('completed_steps')!=8 or leg.get('completed_force_evaluations')!=9 or not isinstance(frames,list) or len(frames)!=9):raise UpgradeError()
        for index,frame in enumerate(frames):
            t=index*.125
            if (frame.get('step_index')!=index or frame.get('time_s')!=t
                    or frame.get('positions_m')!=[[-1+.125*t,0,0],[1,0,0]]
                    or frame.get('velocities_m_per_s')!=[[.125,0,0],[0,0,0]]):raise UpgradeError()
        final=next((state for state in states if state.get('state_id')==step.get('state_ref')),None)
        if final is None or final.get('physical_time')!={'value':1,'unit':'s'} or final.get('data',{}).get('time_s')!=1:raise UpgradeError()
        expected_system=_smoke_definition()['system']
        expected_system['particles'][0]['position_m']=[-.875,0,0]
        if final.get('data',{}).get('system')!=expected_system:raise UpgradeError()
        status,manifest=_api(config,'GET','/v1/runs/'+run['run_id']+'/artifacts',token)
        artifacts=manifest.get('artifacts')
        if status!=200 or not isinstance(artifacts,list) or not 1<=len(artifacts)<=1024:raise UpgradeError()
        if len({a.get('artifact_id') for a in artifacts})!=len(artifacts) or result.get('artifacts')!=artifacts:raise UpgradeError()
        for artifact in artifacts:
            if (not _uuid(artifact.get('artifact_id')) or type(artifact.get('size_bytes')) is not int
                    or not 0<=artifact['size_bytes']<=32*1024**2 or not isinstance(artifact.get('sha256'),str)
                    or re.fullmatch(r'[0-9a-f]{64}',artifact['sha256']) is None):raise UpgradeError()
            status,raw=_api(config,'GET','/v1/artifacts/'+artifact['artifact_id'],token,
                            maximum=32*1024**2,raw_response=True)
            if status!=200 or len(raw)!=artifact['size_bytes'] or hashlib.sha256(raw).hexdigest()!=artifact['sha256']:raise UpgradeError()
        after=_databases(include_rows=True,require_idle=False)
        _append_only(before,after)
        _mail_settings()
        report.update(new_calculation_verified=True,scientific_smoke_verified=True,existing_rows_preserved=True)
        _proof_report(report,scope='committed_upgrade')
        report['smoke_preservation_scope']='immutable_jobs_cohort'
        _counts(after,report)
    finally:
        pass
    _services();report['stage']='public';_public(config,True);report['public_https_verified']=True
    report.update(status='success',stage='complete',failure_reason='none')


def run(config, operation):
    report=_initial(operation if isinstance(operation,str) and operation in OPERATIONS else 'upgrade-application')
    try:
        config=validate_config(config)
        if operation not in OPERATIONS:raise ValueError()
    except Exception:return report
    try:
        report['stage']='lock'
        duration=1320 if operation=='upgrade-application' else 300 if operation=='smoke-application' else 180
        with _deadline(duration),_interruptions(),_lock():
            {'audit-application':_audit,'upgrade-application':_upgrade,
             'verify-application':_verify,'smoke-application':_smoke_application}[operation](config,report)
    except BaseException:report['status']='failed'
    return report


def validate_report(value):
    if (not isinstance(value,dict) or set(value)!=FIELDS or value['scope']!='application_upgrade'
            or value['operation'] not in OPERATIONS or value['status'] not in {'success','failed'}
            or value['stage'] not in STAGES or value['failure_reason'] not in {'none','refused'}
            or any(type(value[name]) is not bool for name in (*BOOLS,'mail_configured'))
            or any(type(value[name]) is not int or not 0<=value[name]<=1_000_000 for name in COUNTS)
            or value['application_version'] not in {'unobserved',OLD_VERSION,TARGET_VERSION}
            or value['registration'] not in {'open','unobserved'}
            or value['preservation_scope'] not in {'unmeasured','private_barrier','committed_upgrade'}
            or value['smoke_preservation_scope'] not in {'unmeasured','immutable_jobs_cohort'}
            or value['mail_delivery_verified'] or value['actual_email_delivery_verified']
            or value['gmail_smtp_tls_checked'] or value['gmail_smtp_tls_ready']
            or (value['status']=='success')!=(value['stage']=='complete')
            or (value['status']=='success')!=(value['failure_reason']=='none')):raise ValueError('invalid fixed application report')
    if value['status']=='success':
        if value['operation']!='audit-application' and value['application_version']!=TARGET_VERSION:raise ValueError('wrong verified application version')
        required=('services_ready','worker_exclusive','account_discovery_verified','auth_boundaries_verified','public_https_verified')
        if not all(value[name] for name in required):raise ValueError('incomplete health proof')
        if value['operation']!='audit-application':
            if not all(value[name] for name in ('new_installation_verified','database_preserved','auth_database_preserved','mail_settings_preserved','settings_preserved','dynamics_capability_verified')):raise ValueError('incomplete transition proof')
        elif not (value['old_installation_verified'] or value['new_installation_verified']):raise ValueError('missing installation proof')
        if value['operation']=='upgrade-application' and not value['committed_resume'] and not all(value[name] for name in (
            'old_installation_verified','source_staged','image_built','image_smoke_passed','admission_paused',
            'application_stopped','backup_timer_paused','private_journal_saved','configuration_switched','server_modified')):raise ValueError('incomplete switch proof')
        if value['operation']=='smoke-application' and not all(value[name] for name in ('new_calculation_verified','scientific_smoke_verified','existing_rows_preserved')):raise ValueError('incomplete scientific smoke')
    if value['operation'] in {'audit-application','verify-application'} and any(value[name] for name in (
        'source_staged','image_built','admission_paused','application_stopped','backup_timer_paused','configuration_switched','rollback_attempted','server_modified')):raise ValueError('read-only operation modified server')
    if value['committed_resume'] and (value['operation']!='upgrade-application' or value['preservation_scope']!='committed_upgrade'):raise ValueError('invalid resume claim')
    if value['existing_rows_preserved'] and value['smoke_preservation_scope']!='immutable_jobs_cohort':raise ValueError('invalid immutable-cohort claim')
    if value['new_calculation_verified'] and value['operation']!='smoke-application':raise ValueError('unexpected calculation claim')
    if value['rollback_succeeded'] and not value['rollback_attempted']:raise ValueError('invalid rollback claim')
    if value['commit_visible_after_error'] and (value['status']!='failed' or value['rollback_attempted']):raise ValueError('invalid committed failure')
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
        result = run(_argument(argv[0]), argv[1]) if len(argv) == 2 else _initial('upgrade-application')
        result = validate_report(result)
    except Exception:
        result = _initial('upgrade-application')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
