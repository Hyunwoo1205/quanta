#!/usr/bin/env python3
"""One fixed, pinned SSH inventory; no arbitrary command or raw output logging."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import tempfile
import time


TIMEOUT = 20
MAX_OUTPUT = 8192
COLLECTORS = {
    'host_inventory': ('ssh_host_inventory', 'host-inventory', 'inventory'),
    'deployment_preflight': ('ssh_deployment_preflight', 'deployment-preflight', 'preflight'),
}


def _module(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('quanta_oci_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _capture(command, environment, directory, *, timeout=TIMEOUT, limit=MAX_OUTPUT, input_stream=None):
    """Read at most limit+1 bytes under one deadline; discard client stderr."""
    process = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL if input_stream is None else input_stream, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, env=environment, cwd=directory,
        )
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return 'timeout', b'', True
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not chunk:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return 'timeout', b'', True
                    code = process.wait(timeout=remaining)
                    return ('success' if code == 0 else 'failed'), bytes(output), True
                output.extend(chunk)
                if len(output) > limit:
                    return 'output_limit', b'', True
    except subprocess.TimeoutExpired:
        return 'timeout', b'', process is not None
    except Exception:
        return 'failed', b'', process is not None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=2)
            except Exception:
                pass
            if process.stdout is not None:
                process.stdout.close()


def _report(status, attempted=False, inventory=None, *, collector='host_inventory'):
    scope, operation, field = COLLECTORS[collector]
    result = {'scope': scope, 'status': status,
              'authentication_attempted': attempted, 'requested_operation': operation}
    if inventory is not None:
        result[field] = inventory
    return result


def probe(environ=None, *, runner=None, collector='host_inventory'):
    if type(collector) is not str or collector not in COLLECTORS:
        return _report('not_configured')
    def report(status, attempted=False, inventory=None):
        return _report(status, attempted, inventory, collector=collector)
    environ = os.environ if environ is None else environ
    if environ.get('QUANTA_OCI_AUTH_CONFIRMED') != 'true':
        return report('not_configured')
    login = _module('probe_login')
    host = environ.get('QUANTA_OCI_HOST')
    pin = login._normalized_host_key(environ.get('QUANTA_OCI_HOST_KEY'))
    error, key = login._key_bytes(environ.get('QUANTA_OCI_PPK'))
    if not login._global_ipv4(host) or pin is None or error is not None:
        return report('not_configured')
    inventory_module = _module(collector)
    source = Path(__file__).with_name(collector + '.py').read_text(encoding='utf-8')
    remote_command = '/usr/bin/python3 -I -B -c ' + shlex.quote(source)
    runner = _capture if runner is None else runner
    attempted = False
    try:
        with tempfile.TemporaryDirectory(prefix='quanta-inventory-') as directory:
            os.chmod(directory, 0o700)
            key_path = Path(directory) / 'identity.ppk'
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as key_file:
                key_file.write(key)
            command = [login.PLINK, '-ssh', '-2', '-4', '-batch', '-noagent',
                       '-no-trivial-auth', '-a', '-x', '-T', '-noshare',
                       '-P', '22', '-l', 'ubuntu', '-i', str(key_path),
                       '-hostkey', pin, host, remote_command]
            child_environment = {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
            status, raw, attempted = runner(command, child_environment, directory)
            if status != 'success':
                return report(status if status in {'failed', 'timeout', 'output_limit'} else 'failed', attempted)
            inventory = inventory_module.sanitize_report(raw)
            if inventory is None:
                return report('invalid_output', attempted)
            return report('success', attempted, inventory)
    except Exception:
        return report('failed', attempted)


def main():
    arguments = sys.argv[1:]
    collector = 'deployment_preflight' if arguments == ['--deployment-preflight'] else 'host_inventory'
    try:
        result = probe(collector=collector) if not arguments or arguments == ['--deployment-preflight'] else _report('not_configured')
    except Exception:
        result = _report('failed', collector=collector)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'success' else 2


if __name__ == '__main__':
    raise SystemExit(main())
