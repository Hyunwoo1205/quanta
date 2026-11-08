"""Fixed A04 transport accepts only the qualified main and native ARM evidence."""
import base64
import importlib.util
import json
from pathlib import Path
import shlex
import uuid
import zlib

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    path = ROOT / 'deploy/oci' / (name + '.py')
    spec = importlib.util.spec_from_file_location('test_atomistic_a04_' + name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.fixture
def authorized_request(tmp_path, monkeypatch):
    gate = load('authorize_atomistic_a04_probe')
    base = gate._base()
    env = {'GITHUB_REPOSITORY': base.REPOSITORY, 'GITHUB_REF': 'refs/heads/ops/oci',
           'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1',
           'QUANTA_ATOMISTIC_A04_CONTROL_SHA': 'a' * 40, 'QUANTA_ATOMISTIC_A04_CONTROL_CI_RUN': '101'}
    request = {'schema_version': 1, 'operation': gate.OPERATION, 'source_sha': 'a' * 40,
               'request_id': str(uuid.uuid4())}
    path = tmp_path / 'request.json'
    path.write_text(json.dumps(request))
    responses = {}
    for run, sha, workflow in ((101, request['source_sha'], 'ci.yml'),
            (gate.QUALIFICATION_RUN, gate.QUALIFICATION_SHA, 'atomistic-a04-native-arm.yml'),
            (gate.CANDIDATE_RUN, gate.CANDIDATE_SHA, 'atomistic-a03.yml')):
        responses[f'/actions/runs/{run}'] = {'id': run, 'head_sha': sha, 'head_branch': 'main', 'event': 'push',
            'path': '.github/workflows/' + workflow, 'status': 'completed', 'conclusion': 'success'}
    responses['/actions/runs/101/jobs?filter=latest&per_page=100'] = {'total_count': 2, 'jobs': [
        {'id': 1000 + offset, 'run_id': 101, 'name': name, 'status': 'completed', 'conclusion': 'success'}
        for offset, name in enumerate(sorted(base.APP_JOB_NAMES))]}
    for run, sha, job, job_name, artifact in (
            (gate.QUALIFICATION_RUN, gate.QUALIFICATION_SHA, gate.QUALIFICATION_JOB,
             'Sequential fixed candidates (aarch64)', gate.QUALIFICATION_ARTIFACT),
            (gate.CANDIDATE_RUN, gate.CANDIDATE_SHA, gate.CANDIDATE_JOB, 'atomistic A03 (aarch64)', gate.CANDIDATE_ARTIFACT)):
        responses[f'/actions/jobs/{job}'] = {'id': job, 'run_id': run, 'head_sha': sha, 'name': job_name,
            'status': 'completed', 'conclusion': 'success'}
        artifact_id, name, size, digest = artifact
        responses[f'/actions/artifacts/{artifact_id}'] = {'id': artifact_id, 'name': name, 'size_in_bytes': size,
            'digest': digest, 'expired': False, 'workflow_run': {'id': run, 'head_sha': sha, 'head_branch': 'main'}}
    monkeypatch.setattr(gate, '_base', lambda: base)
    monkeypatch.setattr(base, 'control_checkout_matches', lambda control, **kwargs:
                        base.control_pin(control) == (request['source_sha'], 101))
    monkeypatch.setattr(base, 'api_get', lambda suffix, env, opener: responses[suffix])
    return gate, env, path, request, responses


def test_authorizes_exact_candidate_independent_of_control_source(authorized_request):
    gate, env, path, request, _ = authorized_request
    result = gate.authorize(env, path=path)
    assert result['status'] == 'authorized'
    assert result['source_sha'] == request['source_sha']
    assert result['qualification_run'] == gate.QUALIFICATION_RUN
    assert result['candidate_source_sha'] == gate.CANDIDATE_SHA
    assert result['candidate_artifact_id'] == gate.CANDIDATE_ARTIFACT[0]


@pytest.mark.parametrize(('suffix', 'field', 'value', 'stage'), [
    ('runs/101', 'head_sha', 'b' * 40, 'control_ci'),
    ('jobs/128657215597', 'conclusion', 'skipped', 'qualification'),
    ('artifacts/13607539838', 'expired', True, 'qualification'),
    ('jobs/128396088895', 'name', 'atomistic A03 (x86_64)', 'candidate'),
    ('artifacts/13573889644', 'digest', 'sha256:' + '0' * 64, 'candidate'),
])
def test_evidence_rejects_wrong_architecture_and_digest(authorized_request, suffix, field, value, stage):
    gate, env, path, _, responses = authorized_request
    responses['/actions/' + suffix][field] = value
    assert gate.authorize(env, path=path) == gate.denied(stage)


def test_denies_alternate_scope_or_rerun(authorized_request):
    gate, env, path, request, _ = authorized_request
    assert gate.authorize(dict(env, GITHUB_RUN_ATTEMPT='2'), path=path) == gate.denied('request')
    path.write_text(json.dumps(dict(request, operation='benchmark-atomistic')))
    assert gate.authorize(env, path=path) == gate.denied('request')


def test_real_a04_bundle_and_remote_command_fit_reviewed_transport():
    transport = load('probe_atomistic')
    controller = load('remote_atomistic_probe')
    source = (ROOT / 'deploy/oci/remote_atomistic_probe.py').read_text()
    archive, digest = transport.bundle(ROOT, candidate=True, a04=True)
    config = {'source_sha': 'a' * 40, 'request_id': str(uuid.uuid4()), 'archive_sha256': digest,
              'candidate': controller.A04_CANDIDATE}
    command = transport.remote_command(source, config, archive, a04=True)
    args = shlex.split(command)
    assert len(command.encode()) <= transport.MAX_ARGUMENT
    assert args[:6] == ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', '-c']
    assert args[8] == 'benchmark-atomistic-a04'
    assert zlib.decompress(base64.b64decode(args[7])).decode() == source
    assert json.loads(base64.b64decode(args[9])) == config
    assert set(controller.archive_files(base64.b64decode(args[10]), digest, candidate=True, a04=True)) == controller.A04_REQUIRED


def test_denied_reauthorization_never_reaches_ssh():
    transport = load('probe_atomistic')
    env = {'QUANTA_OCI_AUTH_CONFIRMED': 'true', 'QUANTA_ATOMISTIC_A04_OPERATION': transport.A04_OPERATION}
    result = transport.probe(env, a04=True, authorizer=lambda _: {'status': 'denied'},
                             runner=lambda *_: pytest.fail('SSH must not be attempted'))
    assert result['status'] == 'configuration_invalid' and result['authentication_attempted'] is False
