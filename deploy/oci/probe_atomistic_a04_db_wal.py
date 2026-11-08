#!/usr/bin/env python3
"""Authorize and relay the fixed read-only A04 DB/WAL diagnostic."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
REQUEST = Path('.github/oci/atomistic-a04-db-request.json')
OPERATION = 'inspect-atomistic-a04-db-wal'
PREFIX = 'QUANTA_A04_DB_WAL'
SCOPE = 'atomistic_a04_db_wal'
BASELINE_SHA = '66940c3de634d077b6a26a4a6089094d753ec4b8'
BASELINE_CI_RUN = 42475116959
CONTROL_WORKFLOW = '.github/workflows/oci-atomistic-a04-db-diagnostic-tests.yml'
CONTROL_JOBS = frozenset({'atomistic A04 DB/WAL diagnostic (x86_64)', 'atomistic A04 DB/WAL diagnostic (aarch64)'})
CONTROL_FILES = frozenset({
    '.github/workflows/oci-atomistic-a04-db-diagnostic.yml',
    CONTROL_WORKFLOW,
    'deploy/oci/probe_atomistic_a04_db_wal.py',
    'deploy/oci/remote_atomistic_a04_db_wal.py',
    'tests/test_oci_atomistic_a04_db_wal.py',
    'tests/test_oci_atomistic_a04_db_wal_transport.py',
})
ALLOWED_FILES = CONTROL_FILES | {
    'WORKPLAN.md',
    'docs/design/atomistic-a04-v0.1/oci-isolated-qualification.md',
    'docs/design/research-roadmap-v1.json',
    'docs/verification/atomistic-a04/oci-qualification-42477399912.json',
}


def _module(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('quanta_a04_db_wal_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = _module('diagnose_atomistic_image')


def _policy(sha):
    # The existing relay only needs the fixed request, operation, scope and source.
    # Its image-specific authorization is replaced by the diagnostic gate below.
    return shared.DiagnosticPolicy(OPERATION, REQUEST, PREFIX, SCOPE, sha, None, None,
                                   CONTROL_WORKFLOW, CONTROL_JOBS)


def _control_environ(env):
    return dict(env, QUANTA_APPLICATION_CONTROL_SHA=env.get(PREFIX + '_CONTROL_SHA'),
                QUANTA_APPLICATION_CONTROL_CI_RUN=env.get(PREFIX + '_CONTROL_CI_RUN'))


def _control_changes_allowed(sha, *, runner=None):
    run = subprocess.run if runner is None else runner
    git = ['/usr/bin/git', '-C', str(ROOT)]
    common = dict(stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False, timeout=5, check=False,
                  env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C',
                       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'})
    ancestry = run(git + ['merge-base', '--is-ancestor', BASELINE_SHA, sha], stdout=subprocess.DEVNULL, **common)
    if ancestry.returncode != 0:
        return False
    changed = run(git + ['diff', '--name-only', '--no-renames', '--no-ext-diff', '--no-textconv', '-z',
                         BASELINE_SHA, sha, '--'], stdout=subprocess.PIPE, **common)
    if changed.returncode != 0 or not changed.stdout.endswith(b'\x00'):
        return False
    paths = set(changed.stdout[:-1].decode('utf-8').split('\x00'))
    return CONTROL_FILES <= paths <= ALLOWED_FILES


def _denied(stage):
    return {'scope': SCOPE + '_request', 'status': 'denied', 'stage': stage}


def authorize(environ=None, *, path=REQUEST, opener=None, runner=None):
    env = os.environ if environ is None else environ
    stage = 'request'
    try:
        if env.get('GITHUB_RUN_ATTEMPT') != '1':
            raise ValueError('request denied')
        base = shared.module('authorize_application_upgrade')
        mapped = _control_environ(env)
        sha, ci_run = base.control_pin(mapped)
        request = shared.read_request(path, env, policy=_policy(sha))
        stage = 'control_checkout'
        if not base.control_checkout_matches(mapped, runner=runner, root=ROOT):
            raise ValueError('checkout denied')
        stage = 'control_scope'
        if not _control_changes_allowed(sha, runner=runner):
            raise ValueError('diagnostic scope denied')
        for stage, run_id, expected_sha, workflow, jobs in (
                ('control_ci', ci_run, sha, CONTROL_WORKFLOW, CONTROL_JOBS),
                ('baseline_ci', BASELINE_CI_RUN, BASELINE_SHA, base.APP_WORKFLOW, base.APP_JOB_NAMES)):
            run = base.api_get(f'/actions/runs/{run_id}', env, opener=opener)
            latest = base.api_get(f'/actions/runs/{run_id}/jobs?filter=latest&per_page=100', env, opener=opener)
            if not base.successful(run, expected_sha, workflow, run_id=run_id) or not base.successful_jobs(latest, run_id, jobs):
                raise ValueError('CI denied')
        return {'scope': SCOPE + '_request', 'status': 'authorized', **request,
                'control_sha': sha, 'control_ci_run': ci_run, 'baseline_ci_run': BASELINE_CI_RUN}
    except Exception:
        return _denied(stage)


def _remote_source():
    return Path(__file__).with_name('remote_atomistic_a04_db_wal.py').read_text(encoding='utf-8')


def _sanitize_remote(raw):
    return _module('remote_atomistic_a04_db_wal').sanitize_report(raw)


def probe(environ=None, *, runner=None):
    env = os.environ if environ is None else environ
    try:
        sha, _ = shared.module('authorize_application_upgrade').control_pin(_control_environ(env))
    except Exception:
        return _invalid()
    return shared.probe(env, authorizer=authorize, runner=runner, policy=_policy(sha),
                        source=_remote_source, sanitizer=_sanitize_remote)


def _invalid():
    return {'scope': 'ssh_' + SCOPE + '_diagnostic', 'operation': OPERATION,
            'status': 'configuration_invalid', 'authentication_attempted': False}


def main():
    if sys.argv[1:] == ['--authorize']:
        result = authorize()
        if result['status'] == 'authorized':
            try:
                with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                    for field in ('operation', 'source_sha', 'request_id'):
                        stream.write(f'{field}={result[field]}\n')
            except Exception:
                result = _denied('output')
    else:
        result = probe() if len(sys.argv) == 1 else _invalid()
    print(shared.encoded(result).decode('ascii'))
    return 0 if result['status'] in {'authorized', 'success'} else 2


if __name__ == '__main__':
    raise SystemExit(main())
