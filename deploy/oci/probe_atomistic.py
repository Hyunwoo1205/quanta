#!/usr/bin/env python3
"""Transfer a bounded reviewed atomistic program over the existing pinned PPK."""
from __future__ import annotations
import base64
from contextlib import ExitStack
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
TRACE_OPERATION = 'trace-atomistic-old-he'
A04_OPERATION = 'benchmark-atomistic-a04'
MAX_ARGUMENT = 120000
MAX_SOURCE = 65536
MAX_COMPRESSED = 32768
MAX_ARCHIVE = 65536
ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_DIRECTORY = Path('.cache/armv8a-candidate')
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


def candidate_helper(root):
    path = root / 'scripts' / 'atomistic_a03_candidate.py'
    spec = importlib.util.spec_from_file_location('quanta_a03_candidate', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bundle(root=ROOT, *, trace=False, candidate=False, a04=False):
    controller = module('remote_atomistic_probe')
    if a04:
        paths = [root / path for path in controller.A04_REQUIRED]
    else:
        paths = [root / p for p in controller.REQUIRED if not p.startswith('docs/design/atomistic-a01-') and not p.startswith('docs/design/atomistic-a02-')]
        if trace:
            paths.append(root / controller.TRACE_SCRIPT)
        if candidate:
            paths.append(root / controller.CANDIDATE_SCRIPT)
        for name in ('atomistic-a01-v0.1', 'atomistic-a02-v0.1'):
            paths.extend(p for p in (root / 'docs/design' / name).rglob('*') if p.is_file())
    members = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if (not controller.allowed_path(relative, trace=trace, candidate=candidate, a04=a04) or any(p.is_symlink() for p in path.parents)
                or path.is_symlink() or not path.is_file()):
            raise ValueError('bundle file denied')
        raw = path.read_bytes()
        if not 1 <= len(raw) <= controller.MAX_FILE:
            raise ValueError('bundle size denied')
        members[relative] = raw
    stream = io.BytesIO()
    mode = 'w:xz' if a04 else 'w:gz'
    with tarfile.open(fileobj=stream, mode=mode, format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
    result = stream.getvalue()
    digest = hashlib.sha256(result).hexdigest()
    controller.archive_files(result, digest, trace=trace, candidate=candidate, a04=a04)
    return result, digest


def remote_command(source, config, archive, *, trace=False, a04=False):
    controller = module('remote_atomistic_probe')
    if not isinstance(source, str) or not isinstance(config, dict) or not isinstance(archive, bytes):
        raise ValueError('fixed program denied')
    config = controller.validate_config(config, a04=a04)
    controller.archive_files(archive, config['archive_sha256'], trace=trace, candidate='candidate' in config, a04=a04)
    raw = source.encode('utf-8')
    if not 1 <= len(raw) <= MAX_SOURCE or b'\0' in raw:
        raise ValueError('fixed program denied')
    compile(source, '<fixed-atomistic-probe>', 'exec')
    packed = zlib.compress(raw, 9)
    if len(packed) > MAX_COMPRESSED:
        raise ValueError('fixed program denied')
    bootstrap = BOOTSTRAP.replace('__SOURCE_SHA256__', hashlib.sha256(raw).hexdigest())
    operation = A04_OPERATION if a04 else TRACE_OPERATION if trace else OPERATION
    args = [base64.b64encode(packed).decode(), operation,
            base64.b64encode(controller.encoded(config)).decode(), base64.b64encode(archive).decode()]
    command = '/usr/bin/sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(bootstrap)
    command += ' ' + ' '.join(shlex.quote(argument) for argument in args)
    if len(command.encode()) > MAX_ARGUMENT:
        raise ValueError('fixed program denied')
    return command


def report(status, attempted=False, result=None, *, trace=False, a04=False):
    value = {'scope': 'ssh_atomistic_a04' if a04 else 'ssh_atomistic_sigill' if trace else 'ssh_atomistic_probe',
             'operation': A04_OPERATION if a04 else TRACE_OPERATION if trace else OPERATION, 'status': status,
             'authentication_attempted': attempted}
    if result is not None:
        value['result'] = result
    return value


def probe(environ=None, *, runner=None, authorizer=None, root=ROOT, trace=False, a04=False):
    env = os.environ if environ is None else environ
    prefix = 'QUANTA_ATOMISTIC_A04' if a04 else 'QUANTA_ATOMISTIC_SIGILL' if trace else 'QUANTA_ATOMISTIC'
    operation = A04_OPERATION if a04 else TRACE_OPERATION if trace else OPERATION
    def outcome(status, attempted=False, result=None):
        return report(status, attempted, result, trace=trace, a04=a04)

    if (env.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true' or env.get(prefix + '_OPERATION') != operation
            or trace and (authorizer is None or a04)):
        return outcome('not_configured')
    candidate = helper = None
    try:
        # Recheck CI and the clean pinned checkout immediately before using SSH keys.
        if authorizer is None:
            name = 'authorize_atomistic_a04_probe' if a04 else 'authorize_atomistic_probe'
            authorizer = module(name).authorize
        authorized = authorizer(env)
        if (authorized.get('status') != 'authorized'
                or authorized.get('source_sha') != env.get(prefix + '_SOURCE_SHA')
                or authorized.get('request_id') != env.get(prefix + '_REQUEST_ID')
                or authorized.get('operation') != operation):
            raise ValueError()
        has_candidate = 'candidate_artifact_id' in authorized
        if (trace and has_candidate) or (a04 and not has_candidate):
            raise ValueError('candidate relay mode denied')
        archive, digest = bundle(root, trace=trace, candidate=has_candidate, a04=a04)
        controller = module('remote_atomistic_probe')
        config = {'source_sha': authorized['source_sha'], 'request_id': authorized['request_id'], 'archive_sha256': digest}
        if has_candidate:
            if (str(authorized['candidate_artifact_id']) != env.get(prefix + '_CANDIDATE_ARTIFACT_ID')
                    or authorized['candidate_artifact_digest'] != env.get(prefix + '_CANDIDATE_ARTIFACT_DIGEST')):
                raise ValueError('candidate artifact changed after download')
            helper = candidate_helper(root)
            subject = authorized['candidate_source_sha'] if a04 else authorized['source_sha']
            candidate = helper.read_metadata(CANDIDATE_DIRECTORY, subject)
            config['candidate'] = candidate
        source = (Path(__file__).with_name('remote_atomistic_probe.py')).read_text()
        remote = remote_command(source, config, archive, trace=trace, a04=a04)
        login = module('probe_login')
        transport = module('probe_inventory')
        host = env.get('QUANTA_OCI_HOST')
        pin = login._normalized_host_key(env.get('QUANTA_OCI_HOST_KEY'))
        error, key = login._key_bytes(env.get('QUANTA_OCI_PPK'))
        if not login._global_ipv4(host) or pin is None or error is not None:
            return outcome('not_configured')
    except Exception:
        return outcome('configuration_invalid')
    attempted = False
    try:
        with ExitStack() as resources:
            input_stream = None
            if candidate is not None:
                input_stream = resources.enter_context(helper.open_regular(CANDIDATE_DIRECTORY / helper.ARCHIVE_NAME, helper.MAX_ARCHIVE))
                helper.check_archive(input_stream, candidate)
                input_stream.seek(0)
            directory = resources.enter_context(tempfile.TemporaryDirectory(prefix='quanta-a03-'))
            os.chmod(directory, 0o700)
            path = Path(directory) / 'identity.ppk'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(key)
            command = [login.PLINK, '-ssh', '-2', '-4', '-batch', '-noagent', '-no-trivial-auth',
                '-a', '-x', '-T', '-noshare', '-P', '22', '-l', 'ubuntu', '-i', str(path), '-hostkey', pin, host, remote]
            environment = {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
            if runner is None:
                timeout = 240 if trace else (1260 if candidate is not None else 960)
                status, raw, attempted = transport._capture(command, environment, directory,
                    timeout=timeout, limit=196608, input_stream=input_stream)
            else:
                status, raw, attempted = runner(command, environment, directory)
            value = controller.sanitize_report(raw, trace=trace, a04=a04) if status in {'success', 'failed'} else None
            if value is not None and value.get('source_sha') == authorized['source_sha'] and value.get('request_id') == authorized['request_id']:
                if candidate is not None:
                    value['candidate_native_artifact_id'] = authorized['candidate_artifact_id']
                    value['candidate_native_artifact_digest'] = authorized['candidate_artifact_digest']
                if a04:
                    value['control_ci_run'] = authorized['control_ci_run']
                    value['qualification_run'] = authorized['qualification_run']
                    value['candidate_native_run'] = authorized['candidate_native_run']
                return outcome('success' if status == 'success' and value['status'] == 'success' else 'remote_failed', attempted, value)
            return outcome(status if status in {'timeout', 'output_limit'} else 'remote_failed', attempted)
    except Exception:
        return outcome('failed', attempted)


def main(*, a04=False):
    result = probe(a04=a04) if len(sys.argv) == 1 else report('configuration_invalid', a04=a04)
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
