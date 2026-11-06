#!/usr/bin/env python3
"""Transport only the reviewed fixed application operations over existing PPK."""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import zlib

OPERATIONS = frozenset({'audit-application', 'upgrade-application', 'verify-application', 'smoke-application'})
MAX_ARGUMENT = 120000
MAX_SOURCE = 196608
MAX_COMPRESSED = 65536

_BOOTSTRAP = '''import base64,hashlib,sys,zlib
if len(sys.argv)!=4 or len(sys.argv[1])>87384:raise ValueError('fixed program denied')
packed=base64.b64decode(sys.argv[1],validate=True)
if len(packed)>65536:raise ValueError('fixed program denied')
decoder=zlib.decompressobj()
raw=decoder.decompress(packed,196609)
if len(raw)>196608 or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:raise ValueError('fixed program denied')
if hashlib.sha256(raw).hexdigest()!='__SOURCE_SHA256__':raise ValueError('fixed program denied')
text=raw.decode('utf-8',errors='strict')
sys.argv=['<fixed-application-upgrade>',sys.argv[2],sys.argv[3]]
exec(compile(text,'<fixed-application-upgrade>','exec'),{'__name__':'__main__','__file__':'<fixed-application-upgrade>'})
'''


def _module(name):
    spec = importlib.util.spec_from_file_location('quanta_application_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def remote_command(source, config, operation):
    """One bounded program argument; no request-provided command or path."""
    if not isinstance(source, str) or not isinstance(operation, str) or operation not in OPERATIONS or not isinstance(config, bytes):
        raise ValueError('fixed program denied')
    raw = source.encode('utf-8', errors='strict')
    if not 1 <= len(raw) <= MAX_SOURCE or b'\0' in raw:
        raise ValueError('fixed program denied')
    compile(source, '<fixed-application-upgrade>', 'exec')
    packed = zlib.compress(raw, 9)
    if len(packed) > MAX_COMPRESSED:
        raise ValueError('fixed program denied')
    bootstrap = _BOOTSTRAP.replace('__SOURCE_SHA256__', hashlib.sha256(raw).hexdigest())
    command = '/usr/bin/sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(bootstrap)
    command += ' ' + shlex.quote(base64.b64encode(packed).decode('ascii'))
    command += ' ' + shlex.quote(base64.b64encode(config).decode('ascii'))
    command += ' ' + operation
    if len(command.encode('utf-8')) > MAX_ARGUMENT:
        raise ValueError('fixed program denied')
    return command


def report(status, *, attempted=False, operation=None, result=None):
    value = {'scope': 'ssh_application_upgrade', 'status': status, 'authentication_attempted': attempted}
    if isinstance(operation, str) and operation in OPERATIONS:
        value['operation'] = operation
    if result is not None:
        value['result'] = result
    return value


def probe(environ=None, *, runner=None):
    env = os.environ if environ is None else environ
    operation = env.get('QUANTA_APPLICATION_OPERATION')
    if env.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true' or not isinstance(operation, str) or operation not in OPERATIONS:
        return report('not_configured')
    try:
        gate = _module('authorize_application_upgrade')
        if not gate.control_checkout_matches(env):
            raise ValueError()
        request = gate.read_request(environ=env)
        if (request['operation'] != operation or request['source_sha'] != env.get('QUANTA_APPLICATION_SOURCE_SHA')
                or request['request_id'] != env.get('QUANTA_APPLICATION_REQUEST_ID')):
            raise ValueError()
        controller = _module('upgrade_application')
        config = controller.validate_config({'source_sha': request['source_sha'],
            'request_id': request['request_id'], 'public_origin': env.get('QUANTA_PUBLIC_ORIGIN', ''),
            'auth_mode': env.get('QUANTA_AUTH_MODE', '')})
        source = Path(__file__).with_name('upgrade_application.py').read_text(encoding='utf-8')
        # Validate the fixed program before touching any SSH credential.
        remote = remote_command(source, controller._encoded(config), operation)
        login = _module('probe_login')
        transport = _module('probe_inventory')
        host = env.get('QUANTA_OCI_HOST')
        pin = login._normalized_host_key(env.get('QUANTA_OCI_HOST_KEY'))
        error, key = login._key_bytes(env.get('QUANTA_OCI_PPK'))
        if not login._global_ipv4(host) or pin is None or error is not None:
            return report('not_configured', operation=operation)
    except Exception:
        return report('configuration_invalid', operation=operation)
    attempted = False
    capture = (lambda command, environment, directory: transport._capture(command, environment,
        directory, timeout=1500 if operation in {'upgrade-application', 'smoke-application'} else 240, limit=8192)) if runner is None else runner
    try:
        with tempfile.TemporaryDirectory(prefix='quanta-application-') as directory:
            os.chmod(directory, 0o700)
            key_path = Path(directory) / 'identity.ppk'
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(key)
            command = [login.PLINK, '-ssh', '-2', '-4', '-batch', '-noagent', '-no-trivial-auth',
                '-a', '-x', '-T', '-noshare', '-P', '22', '-l', 'ubuntu', '-i', str(key_path), '-hostkey', pin, host, remote]
            environment = {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
            status, raw, attempted = capture(command, environment, directory)
            if status in {'success', 'failed'}:
                value = controller.sanitize_report(raw)
                if value is not None and value['operation'] == operation:
                    success = status == 'success' and value['status'] == 'success'
                    return report('success' if success else 'remote_failed', attempted=attempted, operation=operation, result=value)
                return report('invalid_output' if status == 'success' else 'remote_failed', attempted=attempted, operation=operation)
            return report(status if status in {'timeout', 'output_limit'} else 'remote_failed', attempted=attempted, operation=operation)
    except Exception:
        return report('failed', attempted=attempted, operation=operation)


def main():
    result = probe() if len(sys.argv) == 1 else report('configuration_invalid')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
