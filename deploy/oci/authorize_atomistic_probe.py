#!/usr/bin/env python3
"""Authorize only the reviewed same-source A03 benchmark after full/native CI."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
REQUEST = Path('.github/oci/atomistic-request.json')
REPOSITORY = 'Hyunwoo1205/quanta'
OPERATION = 'benchmark-atomistic'
NATIVE_WORKFLOW = '.github/workflows/atomistic-a03.yml'
NATIVE_JOBS = frozenset({'atomistic A03 (x86_64)', 'atomistic A03 (aarch64)'})
CANDIDATE_MODE = 'armv8a'
CANDIDATE_ARTIFACT_PREFIX = 'atomistic-a03-armv8a-image-'
MAX_CANDIDATE_ZIP = 2 * 1024**3 + 16 * 1024**2


def _base():
    spec = importlib.util.spec_from_file_location('quanta_atomistic_base_gate', Path(__file__).with_name('authorize_application_upgrade.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pins(environ):
    sha = environ.get('QUANTA_ATOMISTIC_CONTROL_SHA')
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('pin denied')
    runs = []
    for key in ('CONTROL_CI_RUN', 'SOURCE_CI_RUN', 'NATIVE_CI_RUN'):
        value = environ.get('QUANTA_ATOMISTIC_' + key)
        if not isinstance(value, str) or not re.fullmatch('[1-9][0-9]{0,18}', value) or int(value) > 2**63-1:
            raise ValueError('pin denied')
        runs.append(int(value))
    if runs[0] != runs[1]:
        raise ValueError('same-source control must have same full CI')
    return sha, *runs


def read_request(path=REQUEST, environ=None):
    env = os.environ if environ is None else environ
    sha, *_ = pins(env)
    if (env.get('GITHUB_REPOSITORY') != REPOSITORY or env.get('GITHUB_REF') != 'refs/heads/ops/oci'
            or env.get('GITHUB_EVENT_NAME') != 'push' or any(p.is_symlink() for p in path.parents)):
        raise ValueError('request denied')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024:
        raise ValueError('request denied')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('request denied')
        raw = stream.read(1025)
    value = _base().parse(raw)
    if (len(raw) > 1024 or not isinstance(value, dict)
            or set(value) != {'schema_version', 'operation', 'source_sha', 'request_id'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] != OPERATION or value['source_sha'] != sha
            or not isinstance(value['request_id'], str)):
        raise ValueError('request denied')
    identifier = uuid.UUID(value['request_id'])
    if str(identifier) != value['request_id'] or identifier.version != 4:
        raise ValueError('request denied')
    return value


def checkout_matches(environ, *, runner=None):
    try:
        sha, full, *_ = pins(environ)
        env = dict(environ, QUANTA_APPLICATION_CONTROL_SHA=sha, QUANTA_APPLICATION_CONTROL_CI_RUN=str(full))
        return _base().control_checkout_matches(env, runner=runner, root=ROOT)
    except Exception:
        return False


def candidate_artifact(value, sha, native):
    if not isinstance(value, dict) or not isinstance(value.get('artifacts'), list):
        raise ValueError('candidate artifact list denied')
    name = CANDIDATE_ARTIFACT_PREFIX + sha
    matches = [row for row in value['artifacts'] if isinstance(row, dict) and row.get('name') == name]
    if len(matches) != 1:
        raise ValueError('require one candidate artifact from the exact native run')
    item = matches[0]
    workflow = item.get('workflow_run')
    digest = item.get('digest')
    if (type(item.get('id')) is not int or item['id'] <= 0 or item.get('expired') is not False
            or type(item.get('size_in_bytes')) is not int or not 0 < item['size_in_bytes'] <= MAX_CANDIDATE_ZIP
            or not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)
            or not isinstance(workflow, dict) or workflow.get('id') != native
            or workflow.get('head_sha') != sha or workflow.get('head_branch') != 'main'):
        raise ValueError('candidate artifact identity denied')
    return {'candidate_artifact_id': item['id'], 'candidate_artifact_digest': digest}


def authorize(environ=None, *, path=REQUEST, opener=None, runner=None):
    env = os.environ if environ is None else environ
    stage = 'request'
    try:
        request = read_request(path, env)
        sha, full, source, native = pins(env)
        base = _base()
        stage = 'control_checkout'
        if not checkout_matches(env, runner=runner):
            raise ValueError()
        for label, run_id, workflow, names in (
                ('full_ci', full, base.APP_WORKFLOW, base.APP_JOB_NAMES),
                ('native_ci', native, NATIVE_WORKFLOW, NATIVE_JOBS)):
            stage = label
            run = base.api_get('/actions/runs/' + str(run_id), env, opener=opener)
            jobs = base.api_get('/actions/runs/' + str(run_id) + '/jobs?filter=latest&per_page=100', env, opener=opener)
            if not base.successful(run, sha, workflow, run_id=run_id) or not base.successful_jobs(jobs, run_id, names):
                raise ValueError()
        result = {'scope': 'atomistic_probe_request', 'status': 'authorized', **request,
                  'source_ci_run': source, 'native_ci_run': native}
        mode = env.get('QUANTA_ATOMISTIC_CANDIDATE_MODE')
        if mode is not None:
            stage = 'candidate_artifact'
            if mode != CANDIDATE_MODE:
                raise ValueError('candidate mode denied')
            artifact = base.api_get('/actions/runs/' + str(native) + '/artifacts?per_page=100', env, opener=opener)
            result.update(candidate_artifact(artifact, sha, native))
        return result
    except Exception:
        return {'scope': 'atomistic_probe_request', 'status': 'denied', 'stage': stage}


def main():
    result = authorize() if len(sys.argv) == 1 else {'scope': 'atomistic_probe_request', 'status': 'denied', 'stage': 'request'}
    if result['status'] == 'authorized':
        try:
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                keys = ('operation', 'source_sha', 'request_id', 'source_ci_run', 'native_ci_run',
                        'candidate_artifact_id', 'candidate_artifact_digest')
                for key in keys:
                    if key not in result:
                        continue
                    stream.write(key + '=' + str(result[key]) + '\n')
        except Exception:
            result = {'scope': 'atomistic_probe_request', 'status': 'denied', 'stage': 'output'}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'authorized' else 2


if __name__ == '__main__':
    raise SystemExit(main())
