#!/usr/bin/env python3
"""Authorize and run the fixed, isolated trace of the old ARM64 He-D case."""
import importlib.util
import os
from pathlib import Path
import sys


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


shared = module('diagnose_atomistic_image')
transport = module('probe_atomistic')
POLICY = shared.DiagnosticPolicy(
    'trace-atomistic-old-he', Path('.github/oci/atomistic-sigill-request.json'),
    'QUANTA_ATOMISTIC_SIGILL', 'atomistic_sigill', 'b7bfa8f90a7d5d05e74f7d8fefefe3be72cfc379',
    42337645536, 42337645488, '.github/workflows/oci-atomistic-sigill-tests.yml',
    frozenset({'atomistic SIGILL diagnostic (x86_64)', 'atomistic SIGILL diagnostic (aarch64)'}),
)


def main():
    if sys.argv[1:] == ['--authorize']:
        result = shared.authorize(policy=POLICY)
        if result['status'] == 'authorized':
            try:
                with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                    for key in ('operation', 'source_sha', 'request_id'):
                        stream.write(key + '=' + result[key] + '\n')
            except Exception:
                result = {'scope': POLICY.scope + '_request', 'status': 'denied', 'stage': 'output'}
    elif len(sys.argv) == 1:
        result = transport.probe(authorizer=lambda env: shared.authorize(env, policy=POLICY), trace=True)
    else:
        result = transport.report('configuration_invalid', trace=True)
    print(shared.encoded(result).decode('ascii'))
    return 0 if result['status'] in {'success', 'authorized'} else 2


if __name__ == '__main__':
    raise SystemExit(main())
