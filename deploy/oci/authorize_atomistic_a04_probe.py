#!/usr/bin/env python3
"""Authorize only the fixed A04 OCI trial from reviewed, successful main evidence."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
REQUEST = Path('.github/oci/atomistic-a04-request.json')
OPERATION = 'benchmark-atomistic-a04'
PREFIX = 'QUANTA_ATOMISTIC_A04'
QUALIFICATION_SHA = 'a5adac0cbf7ace845e514f6a9cdd977748565aea'
QUALIFICATION_RUN = 42456722645
QUALIFICATION_JOB = 128657215597
QUALIFICATION_RECEIPT = ROOT / 'docs/verification/atomistic-a04/native-arm-qualification-42456722645.json'
QUALIFICATION_RECEIPT_SHA = '57097c355287c4e67bc835913101f6efadc938da64533cf57ba367dc22354816'
QUALIFICATION_ARTIFACT = (13607539838, 'atomistic-a04-native-arm-' + QUALIFICATION_SHA, 58424,
                          'sha256:ecfe0930885c56add80f505b5903f56a8f18ee22eba4ab8e375b9de8813a1d71')
CANDIDATE_SHA = '5dd1e90c8332366c1f95f5b58b260ce966af5e84'
CANDIDATE_RUN = 42370042995
CANDIDATE_JOB = 128396088895
CANDIDATE_ARTIFACT = (13573889644, 'atomistic-a03-armv8a-image-' + CANDIDATE_SHA, 323258662,
                      'sha256:bb1e80caeb62e989a44e95d9b739b99ecffdf23191241c6802fc687d6b37538c')


def _base():
    path = Path(__file__).with_name('authorize_application_upgrade.py')
    spec = importlib.util.spec_from_file_location('quanta_a04_base_gate', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def control_environ(environ):
    return dict(environ, QUANTA_APPLICATION_CONTROL_SHA=environ.get(PREFIX + '_CONTROL_SHA'),
                QUANTA_APPLICATION_CONTROL_CI_RUN=environ.get(PREFIX + '_CONTROL_CI_RUN'))


def read_request(path, environ, base, source_sha):
    if (environ.get('GITHUB_REPOSITORY') != base.REPOSITORY
            or environ.get('GITHUB_REF') != 'refs/heads/ops/oci'
            or environ.get('GITHUB_EVENT_NAME') != 'push' or environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or any(parent.is_symlink() for parent in path.parents)):
        raise ValueError('request denied')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 1024:
        raise ValueError('request denied')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('request denied')
        raw = stream.read(1025)
    value = base.parse(raw)
    if (len(raw) > 1024 or not isinstance(value, dict)
            or set(value) != {'schema_version', 'operation', 'source_sha', 'request_id'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] != OPERATION or value['source_sha'] != source_sha
            or not isinstance(value['request_id'], str)):
        raise ValueError('request denied')
    identifier = uuid.UUID(value['request_id'])
    if str(identifier) != value['request_id'] or identifier.version != 4:
        raise ValueError('request denied')
    return value


def check_native_run(get, base, run_id, sha, workflow, job_id, job_name):
    run = get(f'/actions/runs/{run_id}')
    if not base.successful(run, sha, '.github/workflows/' + workflow, run_id=run_id):
        raise ValueError('native run denied')
    job = get(f'/actions/jobs/{job_id}')
    expected = {'id': job_id, 'run_id': run_id, 'head_sha': sha, 'name': job_name,
                'status': 'completed', 'conclusion': 'success'}
    if not isinstance(job, dict) or any(job.get(key) != value for key, value in expected.items()):
        raise ValueError('native job denied')


def check_artifact(get, lock, run_id, sha):
    identifier, name, size, digest = lock
    artifact = get(f'/actions/artifacts/{identifier}')
    if not isinstance(artifact, dict):
        raise ValueError('artifact denied')
    run = artifact.get('workflow_run')
    if (artifact.get('id') != identifier or artifact.get('name') != name
            or artifact.get('size_in_bytes') != size or artifact.get('digest') != digest
            or artifact.get('expired') is not False or not isinstance(run, dict)
            or run.get('id') != run_id or run.get('head_sha') != sha or run.get('head_branch') != 'main'):
        raise ValueError('artifact denied')


def authorize(environ=None, *, path=REQUEST, opener=None, runner=None):
    env = os.environ if environ is None else environ
    stage = 'request'
    try:
        base = _base()
        control = control_environ(env)
        sha, ci_run = base.control_pin(control)
        request = read_request(path, env, base, sha)
        stage = 'control_checkout'
        if not base.control_checkout_matches(control, runner=runner, root=ROOT):
            raise ValueError('control checkout denied')

        def get(path):
            return base.api_get(path, env, opener=opener)

        stage = 'control_ci'
        run = get(f'/actions/runs/{ci_run}')
        jobs = get(f'/actions/runs/{ci_run}/jobs?filter=latest&per_page=100')
        if (not base.successful(run, sha, base.APP_WORKFLOW, run_id=ci_run)
                or not base.successful_jobs(jobs, ci_run, base.APP_JOB_NAMES)):
            raise ValueError('control CI denied')
        stage = 'qualification'
        if hashlib.sha256(QUALIFICATION_RECEIPT.read_bytes()).hexdigest() != QUALIFICATION_RECEIPT_SHA:
            raise ValueError('native qualification receipt denied')
        check_native_run(get, base, QUALIFICATION_RUN, QUALIFICATION_SHA, 'atomistic-a04-native-arm.yml',
                         QUALIFICATION_JOB, 'Sequential fixed candidates (aarch64)')
        check_artifact(get, QUALIFICATION_ARTIFACT, QUALIFICATION_RUN, QUALIFICATION_SHA)
        stage = 'candidate'
        check_native_run(get, base, CANDIDATE_RUN, CANDIDATE_SHA, 'atomistic-a03.yml',
                         CANDIDATE_JOB, 'atomistic A03 (aarch64)')
        check_artifact(get, CANDIDATE_ARTIFACT, CANDIDATE_RUN, CANDIDATE_SHA)
        return {'scope': 'atomistic_a04_probe_request', 'status': 'authorized', **request,
                'control_ci_run': ci_run, 'qualification_run': QUALIFICATION_RUN,
                'candidate_native_run': CANDIDATE_RUN, 'candidate_artifact_id': CANDIDATE_ARTIFACT[0],
                'candidate_artifact_digest': CANDIDATE_ARTIFACT[3], 'candidate_source_sha': CANDIDATE_SHA}
    except Exception:
        return denied(stage)


def denied(stage):
    return {'scope': 'atomistic_a04_probe_request', 'status': 'denied', 'stage': stage}


def main():
    result = authorize() if len(sys.argv) == 1 else denied('request')
    if result['status'] == 'authorized':
        try:
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                for key in ('operation', 'source_sha', 'request_id', 'candidate_native_run',
                            'candidate_artifact_id', 'candidate_artifact_digest'):
                    stream.write(f'{key}={result[key]}\n')
        except Exception:
            result = denied('output')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'authorized' else 2


if __name__ == '__main__':
    raise SystemExit(main())
