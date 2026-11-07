import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'a' * 40
BINARY = 'b' * 64


def module(relative):
    spec = importlib.util.spec_from_file_location(Path(relative).stem, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


candidate = module('scripts/atomistic_a03_candidate.py')


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return json.dumps(value, separators=(',', ':')).encode()


def make_archive(directory, *, tags=None, architecture='arm64', index_tag=None, tag_architecture='arm64'):
    tag = candidate.image_ref(SOURCE, architecture=tag_architecture)
    layer = b'a fixed synthetic layer'
    diff = digest(layer)
    runtime = {'Env': ['PATH=/usr/bin'], 'Entrypoint': None}
    config = json_bytes({'architecture': architecture, 'os': 'linux', 'config': runtime,
                         'rootfs': {'type': 'layers', 'diff_ids': [diff]}})
    config_descriptor = {'mediaType': candidate.OCI_CONFIG, 'digest': digest(config), 'size': len(config)}
    layer_descriptor = {'digest': diff, 'size': len(layer)}
    manifest = json_bytes({'schemaVersion': 2, 'mediaType': candidate.OCI_MANIFEST,
                           'config': config_descriptor, 'layers': [layer_descriptor]})
    descriptor = {'mediaType': candidate.OCI_MANIFEST, 'digest': digest(manifest), 'size': len(manifest),
                  'annotations': {'io.containerd.image.name': 'docker.io/' + (index_tag or tag),
                                  'org.opencontainers.image.ref.name': SOURCE}}

    def blob(sha):
        return 'blobs/sha256/' + sha.removeprefix('sha256:')

    contents = {blob(diff): layer, blob(descriptor['digest']): manifest,
                blob(config_descriptor['digest']): config,
                'index.json': json_bytes({'schemaVersion': 2, 'mediaType': candidate.OCI_INDEX,
                                         'manifests': [descriptor]}),
                'manifest.json': json_bytes([{'Config': blob(config_descriptor['digest']),
                    'RepoTags': tags if tags is not None else [tag], 'Layers': [blob(diff)]}])}
    path = directory / candidate.ARCHIVE_NAME
    with tarfile.open(path, 'w') as archive:
        for name, data in contents.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    image = {'Architecture': architecture, 'Os': 'linux', 'RepoTags': [tag], 'Id': config_descriptor['digest'],
             'RootFS': {'Type': 'layers', 'Layers': [diff]}, 'Config': runtime}
    return image, descriptor


@pytest.mark.parametrize('containerd', [False, True])
def test_relay_load_checks_both_store_ids(tmp_path, containerd):
    image, descriptor = make_archive(tmp_path)
    metadata = candidate.record(tmp_path, SOURCE, BINARY)
    if containerd:
        image['Id'] = descriptor['digest']
        image['Descriptor'] = descriptor
    calls = []

    def run(command, **options):
        calls.append(command[:3])
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 1, b'', b'No such image')
        if command[2] == 'load':
            assert digest(options['stdin'].read()) == 'sha256:' + metadata['archive_sha256']
            return subprocess.CompletedProcess(command, 0)
        return subprocess.CompletedProcess(command, 0, json_bytes([image]))

    bound, proof = candidate.load_candidate(tmp_path, SOURCE, run=run)
    assert bound == metadata
    assert proof['daemon_image_id'] == image['Id']
    assert proof['locked_config_digest'] == 'sha256:' + metadata['config_sha256']
    assert [row[2] for row in calls] == ['inspect', 'load', 'inspect']


def test_mismatch_does_not_invoke_docker_or_replace_existing_tag(tmp_path):
    image, _ = make_archive(tmp_path)
    candidate.record(tmp_path, SOURCE, BINARY)
    path = tmp_path / candidate.ARCHIVE_NAME
    data = path.read_bytes()
    path.write_bytes(b'x' + data[1:])
    with pytest.raises(ValueError, match='hash'):
        candidate.load_candidate(tmp_path, SOURCE, run=lambda *_a, **_k: pytest.fail('Docker invoked'))
    path.write_bytes(data)
    image['Id'] = 'sha256:' + 'c'*64

    def run(command, **_):
        assert command[2] == 'inspect'
        return subprocess.CompletedProcess(command, 0, json_bytes([image]))

    with pytest.raises(ValueError, match='identity'):
        candidate.load_candidate(tmp_path, SOURCE, run=run)


@pytest.mark.parametrize('case', ['wrong_architecture', 'extra_tag', 'foreign_oci_tag'])
def test_archive_must_contain_one_native_candidate(tmp_path, case):
    if case == 'wrong_architecture':
        make_archive(tmp_path, architecture='amd64')
    elif case == 'extra_tag':
        make_archive(tmp_path, tags=[candidate.image_ref(SOURCE), 'quanta/production:app'])
    else:
        make_archive(tmp_path, index_tag='quanta/production:app')
    with pytest.raises(ValueError):
        candidate.record(tmp_path, SOURCE, BINARY)


def test_amd64_requires_explicit_native_archive_binding(tmp_path):
    image, _ = make_archive(tmp_path, architecture='amd64', tag_architecture='amd64')
    metadata = candidate.record(tmp_path, SOURCE, BINARY, architecture='amd64')
    assert metadata['image_ref'] == f'quanta/a03-amd64:{SOURCE}'
    with pytest.raises(ValueError):
        candidate.load_candidate(tmp_path, SOURCE, run=lambda *_a, **_k: pytest.fail('Docker invoked'))

    def inspect(command, **_):
        assert command == ['docker', 'image', 'inspect', metadata['image_ref']]
        return subprocess.CompletedProcess(command, 0, json_bytes([image]))

    bound, proof = candidate.load_candidate(tmp_path, SOURCE, architecture='amd64', run=inspect)
    assert bound == metadata
    assert proof['already_loaded_identical_image'] is True
    image['Architecture'] = 'arm64'
    with pytest.raises(ValueError, match='architecture'):
        candidate.load_candidate(tmp_path, SOURCE, architecture='amd64', run=inspect)


def test_amd64_gapw_requires_the_same_passing_a03_execution(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'scripts'))
    gapw = module('scripts/run_atomistic_a04_gapw_ci.py')
    monkeypatch.setattr(gapw, 'BASE', tmp_path)
    report = tmp_path / 'a03' / 'report.json'
    report.parent.mkdir()
    cases = ('he-dz', 'h2-dz', 'h2-tz', 'h2-cancel', 'h2-after-cancel')
    evidence = {'source_sha': SOURCE, 'host': {'machine': 'x86_64'},
                'passed_execution_gates': True, 'engine_execution_gates_passed': True,
                'web_responsiveness': {'observer_scope': 'independent_native_ci_parent',
                                       'observer_complete': True},
                'image_candidate': {'binary_sha256': BINARY}, 'image_identity': {'source_bound': True},
                'binary': {'reported_revision': gapw.CP2K_SHA, 'reported_version': '2026.2',
                           'binary_sha256': BINARY},
                'cases': [{'case': case, 'passed_execution_gate': True} for case in cases]}
    report.write_bytes(json_bytes(evidence))
    assert gapw.approved_amd64_candidate(SOURCE) == (evidence['image_candidate'], evidence['image_identity'])
    with pytest.raises(ValueError):
        gapw.approved_amd64_candidate('d' * 40)
    evidence['cases'][3]['passed_execution_gate'] = False
    report.write_bytes(json_bytes(evidence))
    with pytest.raises(ValueError):
        gapw.approved_amd64_candidate(SOURCE)


@pytest.mark.parametrize(('payload', 'failure'), [(b'123', None), (b'12', 'short'),
                                                (b'1234', 'length'), (b'124', 'hash')])
def test_remote_relay_enforces_stream_length_and_sha(tmp_path, monkeypatch, payload, failure):
    remote = module('deploy/oci/remote_atomistic_probe.py')
    monkeypatch.setattr(remote, 'memory_available', lambda: 6*1024**3)
    monkeypatch.setattr(remote, 'active_jobs', lambda: 0)
    monkeypatch.setattr(remote.shutil, 'disk_usage', lambda _p: SimpleNamespace(free=20*1024**3))
    monkeypatch.setattr(remote, 'web_boundary', lambda: None)
    user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    read, write = os.pipe()
    with os.fdopen(write, 'wb') as sender:
        sender.write(payload)
    metadata = {'archive_bytes': 3, 'archive_sha256': hashlib.sha256(b'123').hexdigest()}
    directory = tmp_path / 'candidate'
    with os.fdopen(read, 'rb') as receiver:
        if failure is not None:
            with pytest.raises(remote.ProbeError, match=failure):
                remote.relay_candidate(directory, metadata, receiver, user)
        else:
            remote.relay_candidate(directory, metadata, receiver, user)
            assert (directory / candidate.ARCHIVE_NAME).read_bytes() == b'123'


def test_candidate_artifact_must_be_live_and_bound_to_authorized_native_run():
    gate = module('deploy/oci/authorize_atomistic_probe.py')
    artifact = {'name': gate.CANDIDATE_ARTIFACT_PREFIX + SOURCE, 'id': 17,
                'expired': False, 'size_in_bytes': 1000, 'digest': 'sha256:' + 'c'*64,
                'workflow_run': {'id': 22, 'head_branch': 'main', 'head_sha': SOURCE}}
    assert gate.candidate_artifact({'artifacts': [artifact]}, SOURCE, 22)['candidate_artifact_id'] == 17
    for items, run in (([artifact, artifact], 22), ([artifact], 23), ([dict(artifact, expired=True)], 22)):
        with pytest.raises(ValueError):
            gate.candidate_artifact({'artifacts': items}, SOURCE, run)


def test_transport_can_feed_bounded_regular_image_file(tmp_path):
    transport = module('deploy/oci/probe_inventory.py')
    path = tmp_path / candidate.ARCHIVE_NAME
    path.write_bytes(bytes(range(256)) * 65)
    command = [sys.executable, '-c',
               'import hashlib,sys; print(hashlib.file_digest(sys.stdin.buffer,"sha256").hexdigest())']
    with path.open('rb') as stream:
        state, output, attempted = transport._capture(command, os.environ, tmp_path, input_stream=stream)
    assert (state, output.strip(), attempted) == ('success', digest(path.read_bytes())[7:].encode(), True)
