#!/usr/bin/env python3
"""Transfer one bounded reviewed A03 program/bundle over the existing pinned PPK."""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile
import tempfile
import zlib

OPERATION = 'benchmark-atomistic'
MAX_ARGUMENT = 120000
MAX_SOURCE = 65536
MAX_COMPRESSED = 32768
MAX_ARCHIVE = 65536
ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = '''import base64,hashlib,sys,zlib
if len(sys.argv)!=5 or len(sys.argv[1])>43692:raise ValueError('fixed program denied')
p=base64.b64decode(sys.argv[1],validate=True)
if len(p)>32768:raise ValueError('fixed program denied')
d=zlib.decompressobj();r=d.decompress(p,65537)
if len(r)>65536 or d.unconsumed_tail or not d.eof or d.unused_data:raise ValueError('fixed program denied')
if hashlib.sha256(r).hexdigest()!='__SOURCE_SHA256__':raise ValueError('fixed program denied')
sys.argv=['<fixed-atomistic-probe>',sys.argv[2],sys.argv[3],sys.argv[4]]
exec(compile(r.decode('utf-8'),'<fixed-atomistic-probe>','exec'),{'__name__':'__main__','__file__':'<fixed-atomistic-probe>'})
'''


def module(name):
    spec = importlib.util.spec_from_file_location('quanta_a03_' + name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bundle(root=ROOT):
    controller = module('remote_atomistic_probe')
    paths = [root / p for p in controller.REQUIRED if not p.startswith('docs/design/atomistic-a01-') and not p.startswith('docs/design/atomistic-a02-')]
    for name in ('atomistic-a01-v0.1', 'atomistic-a02-v0.1'):
        paths.extend(p for p in (root / 'docs/design' / name).rglob('*') if p.is_file())
    members = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if (not controller.allowed_path(relative) or any(p.is_symlink() for p in path.parents)
                or path.is_symlink() or not path.is_file()):
            raise ValueError('bundle file denied')
        raw = path.read_bytes()
        if not 1 <= len(raw) <= controller.MAX_FILE:
            raise ValueError('bundle size denied')
        members[relative] = raw
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
    result = stream.getvalue()
    digest = hashlib.sha256(result).hexdigest()
    controller.archive_files(result, digest)
    return result, digest


def remote_command(source, config, archive):
    controller = module('remote_atomistic_probe')
    if not isinstance(source, str) or not isinstance(config, dict) or not isinstance(archive, bytes):
        raise ValueError('fixed program denied')
    config = controller.validate_config(config)
    controller.archive_files(archive, config['archive_sha256'])
    raw = source.encode('utf-8')
    if not 1 <= len(raw) <= MAX_SOURCE or b'\0' in raw:
        raise ValueError('fixed program denied')
    compile(source, '<fixed-atomistic-probe>', 'exec')
    packed = zlib.compress(raw, 9)
    if len(packed) > MAX_COMPRESSED:
        raise ValueError('fixed program denied')
    bootstrap = BOOTSTRAP.replace('__SOURCE_SHA256__', hashlib.sha256(raw).hexdigest())
    args = [base64.b64encode(packed).decode(), OPERATION,
            base64.b64encode(controller.encoded(config)).decode(), base64.b64encode(archive).decode()]
    command = '/usr/bin/sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(bootstrap)
    command += ' ' + ' '.join(shlex.quote(argument) for argument in args)
    if len(command.encode()) > MAX_ARGUMENT:
        raise ValueError('fixed program denied')
    return command


def report(status, attempted=False, result=None):
    value = {'scope': 'ssh_atomistic_probe', 'operation': OPERATION, 'status': status,
             'authentication_attempted': attempted}
    if result is not None:
        value['result'] = result
    return value


def probe(environ=None, *, runner=None, authorizer=None, root=ROOT):
    env = os.environ if environ is None else environ
    if env.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true' or env.get('QUANTA_ATOMISTIC_OPERATION') != OPERATION:
        return report('not_configured')
    try:
        gate = module('authorize_atomistic_probe')
        # Recheck CI and the clean pinned checkout immediately before using SSH keys.
        authorized = gate.authorize(env) if authorizer is None else authorizer(env)
        if (authorized.get('status') != 'authorized'
                or authorized.get('source_sha') != env.get('QUANTA_ATOMISTIC_SOURCE_SHA')
                or authorized.get('request_id') != env.get('QUANTA_ATOMISTIC_REQUEST_ID')
                or authorized.get('operation') != OPERATION):
            raise ValueError()
        archive, digest = bundle(root)
        controller = module('remote_atomistic_probe')
        config = {'source_sha': authorized['source_sha'], 'request_id': authorized['request_id'], 'archive_sha256': digest}
        source = (Path(__file__).with_name('remote_atomistic_probe.py')).read_text()
        remote = remote_command(source, config, archive)
        login = module('probe_login')
        transport = module('probe_inventory')
        host = env.get('QUANTA_OCI_HOST')
        pin = login._normalized_host_key(env.get('QUANTA_OCI_HOST_KEY'))
        error, key = login._key_bytes(env.get('QUANTA_OCI_PPK'))
        if not login._global_ipv4(host) or pin is None or error is not None:
            return report('not_configured')
    except Exception:
        return report('configuration_invalid')
    capture = (lambda cmd, environ, directory: transport._capture(cmd, environ, directory,
        timeout=960, limit=196608)) if runner is None else runner
    attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix='quanta-a03-') as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / 'identity.ppk'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(key)
            command = [login.PLINK, '-ssh', '-2', '-4', '-batch', '-noagent', '-no-trivial-auth',
                '-a', '-x', '-T', '-noshare', '-P', '22', '-l', 'ubuntu', '-i', str(path), '-hostkey', pin, host, remote]
            environment = {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
            status, raw, attempted = capture(command, environment, directory)
            value = controller.sanitize_report(raw) if status in {'success', 'failed'} else None
            if value is not None and value.get('source_sha') == authorized['source_sha'] and value.get('request_id') == authorized['request_id']:
                return report('success' if status == 'success' and value['status'] == 'success' else 'remote_failed', attempted, value)
            return report(status if status in {'timeout', 'output_limit'} else 'remote_failed', attempted)
    except Exception:
        return report('failed', attempted)


def main():
    result = probe() if len(sys.argv) == 1 else report('configuration_invalid')
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
