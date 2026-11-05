#!/usr/bin/env python3
"""Run one fixed installer through the existing pinned, private PPK transport."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import tempfile

_spec = importlib.util.spec_from_file_location('quanta_install_transport', Path(__file__).with_name('probe_inventory.py'))
transport = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(transport)

INSTALLERS = {'install-app': 'install_app', 'install-https': 'install_https',
              'configure-web-firewall': 'configure_web_firewall', 'verify-backup': 'verify_backup',
              'diagnose-https': 'diagnose_https', 'configure-acme': 'configure_acme'}
SOURCE_SHA = '1738107301ef873bfe5e01f930866c2a74e4ec3f'
CONFIGURATION_FAILURES = frozenset({'installer_module_load_failed', 'base_configuration_invalid',
                                    'acme_email_missing', 'acme_email_invalid',
                                    'installer_preparation_failed'})


def report(status, attempted=False, *, operation=None, result=None, failure_reason=None):
    value = {'scope': 'ssh_fixed_installation', 'status': status,
             'authentication_attempted': attempted}
    if operation in INSTALLERS:
        value['requested_operation'] = operation
    if result is not None:
        value['result'] = result
    if (status == 'configuration_invalid' and isinstance(failure_reason, str)
            and failure_reason in CONFIGURATION_FAILURES):
        value['failure_reason'] = failure_reason
    return value


def probe(environ=None, *, runner=None):
    environ = os.environ if environ is None else environ
    operation = environ.get('QUANTA_OCI_INSTALL_OPERATION')
    if (environ.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true'
            or type(operation) is not str or operation not in INSTALLERS):
        return report('not_configured')
    login = transport._module('probe_login')
    host = environ.get('QUANTA_OCI_HOST')
    pin = login._normalized_host_key(environ.get('QUANTA_OCI_HOST_KEY'))
    error, key = login._key_bytes(environ.get('QUANTA_OCI_PPK'))
    if not login._global_ipv4(host) or pin is None or error is not None:
        return report('not_configured', operation=operation)
    module_name = INSTALLERS[operation]
    try:
        installer = transport._module(module_name)
        base_validator = transport._module('install_https') if operation == 'configure-acme' else installer
    except Exception:
        return report('configuration_invalid', operation=operation, failure_reason='installer_module_load_failed')
    config = {'source_sha': SOURCE_SHA, 'public_origin': environ.get('QUANTA_PUBLIC_ORIGIN', ''),
              'auth_mode': environ.get('QUANTA_AUTH_MODE', '')}
    try:
        base_validator.validate_config(config)
    except Exception:
        return report('configuration_invalid', operation=operation, failure_reason='base_configuration_invalid')
    if operation == 'configure-acme':
        email = environ.get('QUANTA_ACME_EMAIL', '')
        if email == '':
            return report('configuration_invalid', operation=operation, failure_reason='acme_email_missing')
        config['acme_email'] = email
        try:
            installer.validate_config(config)
        except Exception:
            return report('configuration_invalid', operation=operation, failure_reason='acme_email_invalid')
    try:
        encoded = base64.b64encode(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).decode('ascii')
        source = Path(__file__).with_name(module_name + '.py').read_text(encoding='utf-8')
    except Exception:
        return report('configuration_invalid', operation=operation, failure_reason='installer_preparation_failed')
    remote = '/usr/bin/sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(source) + ' ' + shlex.quote(encoded)
    runner = (lambda command, environment, directory: transport._capture(
        command, environment, directory, timeout=900, limit=8192)) if runner is None else runner
    attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix='quanta-fixed-install-') as directory:
            os.chmod(directory, 0o700)
            key_path = Path(directory) / 'identity.ppk'
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(key)
            command = [login.PLINK, '-ssh', '-2', '-4', '-batch', '-noagent',
                       '-no-trivial-auth', '-a', '-x', '-T', '-noshare',
                       '-P', '22', '-l', 'ubuntu', '-i', str(key_path), '-hostkey', pin, host, remote]
            environment = {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
            status, raw, attempted = runner(command, environment, directory)
            if status in {'success', 'failed'}:
                result = installer.sanitize_report(raw)
                if result is not None:
                    success = status == 'success' and result.get('status') == 'success'
                    return report('success' if success else 'remote_failed', attempted, operation=operation, result=result)
                return report('invalid_output' if status == 'success' else 'remote_failed', attempted, operation=operation)
            return report(status if status in {'timeout', 'output_limit'} else 'failed', attempted, operation=operation)
    except Exception:
        return report('failed', attempted, operation=operation)


def main():
    try:
        value = probe()
    except Exception:
        value = report('failed')
    print(json.dumps(value, sort_keys=True, separators=(',', ':')))
    return 0 if value['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
