#!/usr/bin/env python3
"""Use only the reviewed fixed account updater over the existing PPK transport."""
from __future__ import annotations
import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile

OPERATIONS = frozenset({'upgrade-accounts', 'verify-accounts'})
MAX_ARGUMENT = 120000


def _module(name):
    spec = importlib.util.spec_from_file_location('quanta_accounts_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report(status, *, attempted=False, operation=None, result=None):
    value = {'scope': 'ssh_accounts_upgrade', 'status': status, 'authentication_attempted': attempted}
    if isinstance(operation, str) and operation in OPERATIONS:
        value['operation'] = operation
    if result is not None:
        value['result'] = result
    return value


def probe(environ=None, *, runner=None):
    env = os.environ if environ is None else environ
    operation = env.get('QUANTA_ACCOUNTS_OPERATION')
    if env.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true' or not isinstance(operation, str) or operation not in OPERATIONS:
        return report('not_configured')
    try:
        gate = _module('authorize_accounts_upgrade')
        if not gate.control_checkout_matches(env):
            raise ValueError()
        request = gate.read_request(environ=env)
        if (request['operation'] != operation or request['source_sha'] != env.get('QUANTA_ACCOUNTS_SOURCE_SHA')
                or request['request_id'] != env.get('QUANTA_ACCOUNTS_REQUEST_ID')):
            raise ValueError()
        controller = _module('upgrade_accounts')
        config = controller.validate_config({'source_sha': request['source_sha'],
            'request_id': request['request_id'], 'public_origin': env.get('QUANTA_PUBLIC_ORIGIN', ''),
            'auth_mode': env.get('QUANTA_AUTH_MODE', '')})
        source = Path(__file__).with_name('upgrade_accounts.py').read_text(encoding='utf-8')
        login = _module('probe_login')
        transport = _module('probe_inventory')
        host = env.get('QUANTA_OCI_HOST')
        pin = login._normalized_host_key(env.get('QUANTA_OCI_HOST_KEY'))
        error, key = login._key_bytes(env.get('QUANTA_OCI_PPK'))
        if not login._global_ipv4(host) or pin is None or error is not None:
            return report('not_configured', operation=operation)
        encoded = base64.b64encode(controller._encoded(config)).decode('ascii')
        remote = '/usr/bin/sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(source) + ' ' + shlex.quote(encoded) + ' ' + operation
        if len(remote.encode('utf-8')) > MAX_ARGUMENT:
            raise ValueError()
    except Exception:
        return report('configuration_invalid', operation=operation)
    attempted = False
    capture = (lambda command, environment, directory: transport._capture(command, environment,
        directory, timeout=1200 if operation == 'upgrade-accounts' else 180, limit=8192)) if runner is None else runner
    try:
        with tempfile.TemporaryDirectory(prefix='quanta-accounts-') as directory:
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
