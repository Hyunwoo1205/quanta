"""A03 fixed request/CI/transport/archive/resource boundaries, no real host access."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('test_a03_' + name, ROOT / 'deploy/oci' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def env():
    return {'GITHUB_REPOSITORY': 'Hyunwoo1205/quanta', 'GITHUB_REF': 'refs/heads/ops/oci',
        'GITHUB_EVENT_NAME': 'push', 'QUANTA_ATOMISTIC_CONTROL_SHA': 'a'*40,
        'QUANTA_ATOMISTIC_CONTROL_CI_RUN': '101', 'QUANTA_ATOMISTIC_SOURCE_CI_RUN': '101',
        'QUANTA_ATOMISTIC_NATIVE_CI_RUN': '102', 'QUANTA_CI_READ_TOKEN': 'test-token'}


@pytest.fixture
def request_file(tmp_path):
    path = tmp_path / 'request.json'
    path.write_text(json.dumps({'schema_version': 1, 'operation': 'benchmark-atomistic',
        'source_sha': 'a'*40, 'request_id': str(uuid.uuid4())}))
    return path


def test_exact_request(env, request_file):
    gate = load('authorize_atomistic_probe')
    assert gate.read_request(request_file, env)['operation'] == gate.OPERATION


@pytest.mark.parametrize('field,value', [('operation', 'ssh-command'), ('operation', 'deploy'),
    ('source_sha', 'b'*40), ('source_sha', '../bad'), ('schema_version', True),
    ('request_id', str(uuid.uuid1())), ('command', 'true'), ('path', '/tmp/run')])
def test_request_rejects_alternative_scope(env, request_file, field, value):
    gate = load('authorize_atomistic_probe')
    obj = json.loads(request_file.read_text()); obj[field] = value
    request_file.write_text(json.dumps(obj))
    with pytest.raises(ValueError):
        gate.read_request(request_file, env)


def test_duplicate_symlink_and_oversized_request(env, request_file):
    gate = load('authorize_atomistic_probe')
    before = request_file.read_text()
    request_file.write_text(before[:-1] + ',"operation":"benchmark-atomistic"}')
    with pytest.raises(ValueError): gate.read_request(request_file, env)
    request_file.write_text(' '*1025)
    with pytest.raises(ValueError): gate.read_request(request_file, env)
    request_file.unlink(); request_file.symlink_to('/nonexistent')
    with pytest.raises((ValueError, FileNotFoundError)): gate.read_request(request_file, env)


@pytest.mark.parametrize('key,value', [('GITHUB_REF','refs/heads/main'),
    ('GITHUB_REPOSITORY','attacker/quanta'), ('GITHUB_EVENT_NAME','pull_request'),
    ('QUANTA_ATOMISTIC_SOURCE_CI_RUN','103'), ('QUANTA_ATOMISTIC_NATIVE_CI_RUN','0')])
def test_context_and_pins_fail_closed(env, request_file, key, value):
    gate = load('authorize_atomistic_probe');env[key] = value
    assert gate.authorize(env, path=request_file)['status'] == 'denied'


def fixture_api(gate):
    full = gate._base()
    data = {}
    for identifier, workflow, names in [(101, full.APP_WORKFLOW, full.APP_JOB_NAMES),
            (102, gate.NATIVE_WORKFLOW, gate.NATIVE_JOBS)]:
        data['/actions/runs/' + str(identifier)] = {'id': identifier, 'head_sha': 'a'*40,
            'head_branch': 'main', 'event': 'push', 'path': workflow,
            'status': 'completed', 'conclusion': 'success'}
        data['/actions/runs/' + str(identifier) + '/jobs?filter=latest&per_page=100'] = {
            'total_count': 2, 'jobs': [{'id': identifier*10+i, 'run_id': identifier,
                'name': name, 'status':'completed','conclusion':'success'} for i,name in enumerate(sorted(names))]}
    full.api_get = lambda suffix, env, opener=None: data[suffix]
    return full, data


def test_requires_exact_successful_native_matrix(env, request_file, monkeypatch):
    gate = load('authorize_atomistic_probe');base,data = fixture_api(gate)
    monkeypatch.setattr(gate, '_base', lambda:base)
    monkeypatch.setattr(gate, 'checkout_matches', lambda env, runner=None:True)
    assert gate.authorize(env,path=request_file)['status'] == 'authorized'
    native = data['/actions/runs/102/jobs?filter=latest&per_page=100']
    native['jobs'][0]['conclusion'] = 'skipped'
    assert gate.authorize(env,path=request_file)['status'] == 'denied'
    native['jobs'][0]['conclusion'] = 'success'
    data['/actions/runs/102']['head_sha'] = 'b'*40
    assert gate.authorize(env,path=request_file)['status'] == 'denied'
    data['/actions/runs/102']['head_sha'] = 'a'*40
    native['jobs'][0]['name'] = 'atomistic A03 (emulated ARM)'
    assert gate.authorize(env,path=request_file)['status'] == 'denied'


def tar_bytes(files, symlink=None):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in files.items():
            info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
        if symlink:
            info=tarfile.TarInfo(symlink);info.type=tarfile.SYMTYPE;info.linkname='/etc/quanta/app.env';archive.addfile(info)
    return buffer.getvalue()


def minimal_archive(remote):
    return tar_bytes({name:b'{}\n' for name in remote.REQUIRED})


def test_archive_allowlist_integrity_and_no_links():
    remote=load('remote_atomistic_probe'); raw=minimal_archive(remote)
    assert set(remote.archive_files(raw,hashlib.sha256(raw).hexdigest())) == remote.REQUIRED
    with pytest.raises(remote.ProbeError):remote.archive_files(raw,'0'*64)
    for path in ('../app.env','/etc/quanta/app.env','scripts/arbitrary.py','docs/design/atomistic-a02-v0.1/../secrets'):
        bad=tar_bytes({**{name:b'{}' for name in remote.REQUIRED},path:b'x'})
        with pytest.raises(remote.ProbeError): remote.archive_files(bad,hashlib.sha256(bad).hexdigest())
    bad=tar_bytes({name:b'{}' for name in remote.REQUIRED},'docs/design/atomistic-a02-v0.1/link')
    with pytest.raises(remote.ProbeError):remote.archive_files(bad,hashlib.sha256(bad).hexdigest())


def test_archive_missing_and_size_bounds():
    remote=load('remote_atomistic_probe');bad=tar_bytes({'scripts/verify_atomistic_a03.py':b'pass'})
    with pytest.raises(remote.ProbeError):remote.archive_files(bad,hashlib.sha256(bad).hexdigest())
    bad=tar_bytes({**{name:b'{}' for name in remote.REQUIRED},'docs/design/atomistic-a02-v0.1/huge':b'x'*(remote.MAX_FILE+1)})
    with pytest.raises(remote.ProbeError):remote.archive_files(bad,hashlib.sha256(bad).hexdigest())


def test_only_fixed_transport_and_bounded_program():
    remote=load('remote_atomistic_probe');transport=load('probe_atomistic');raw=minimal_archive(remote)
    config={'source_sha':'a'*40,'request_id':str(uuid.uuid4()),'archive_sha256':hashlib.sha256(raw).hexdigest()}
    command=transport.remote_command('pass\n',config,raw)
    assert command.startswith('/usr/bin/sudo -n /usr/bin/python3 -I -B -c ')
    assert len(command.encode()) < transport.MAX_ARGUMENT
    for change in ({'operation':'deploy'}, {'source_sha':'$(cat /etc/quanta/app.env)'}, {'request_id':'../../other'}):
        with pytest.raises(ValueError):transport.remote_command('pass',dict(config,**change),raw)
    with pytest.raises(ValueError):transport.remote_command('x'*70000,config,raw)


def test_resource_reserve_and_active_load_fail_closed():
    remote=load('remote_atomistic_probe');GiB=1024**3
    remote.resource_preflight(0,6*GiB,10*GiB)
    for active,memory,disk in ((1,8*GiB,20*GiB),(0,6*GiB-1,20*GiB),(0,8*GiB,10*GiB-1)):
        with pytest.raises(remote.ProbeError):remote.resource_preflight(active,memory,disk)


def test_no_secret_material_in_unconfigured_transport():
    transport=load('probe_atomistic')
    def no_call(*args):raise AssertionError('transport touched')
    assert transport.probe({},runner=no_call,authorizer=no_call)['status']=='not_configured'


def test_foreign_arch_or_nonroot_never_reaches_host(monkeypatch):
    remote=load('remote_atomistic_probe')
    monkeypatch.setattr(remote.os,'geteuid',lambda:1000)
    monkeypatch.setattr(remote,'snapshot',lambda:pytest.fail('host read'))
    result=remote.execute({'source_sha':'a'*40,'request_id':str(uuid.uuid4()),'archive_sha256':'0'*64},b'')
    assert result['status']=='failed' and result['stage']=='config'
    assert result['production_restart_attempted'] is False
    assert result['private_environment_read'] is False


def test_failed_resource_preflight_still_checks_service_preservation(tmp_path, monkeypatch):
    remote=load('remote_atomistic_probe')
    import stat
    original_open=remote.os.open
    original_stat=remote.os.fstat
    lockfds=[]
    def fake_open(path, flags, mode=0o777):
        if str(path)=='/run/quanta-application-upgrade.lock':
            fd=original_open(tmp_path/'guard.lock', flags, mode);lockfds.append(fd);return fd
        return original_open(path, flags, mode)
    def fake_stat(fd):
        if fd in lockfds:
            return SimpleNamespace(st_mode=stat.S_IFREG|0o600, st_uid=0, st_nlink=1)
        return original_stat(fd)
    monkeypatch.setattr(remote.os,'open',fake_open)
    monkeypatch.setattr(remote.os,'fstat',fake_stat)
    monkeypatch.setattr(remote.os,'geteuid',lambda:0)
    monkeypatch.setattr(remote.platform,'machine',lambda:'aarch64')
    monkeypatch.setattr(remote,'_parents',lambda p:None)
    monkeypatch.setattr(remote.fcntl,'flock',lambda *args:None)
    count=[]
    def snapshot():
        count.append(True)
        return {'identity':'same','config_sha':['same'],'database_sha':['same'],'active_jobs':0,
                'web':{'web_status':200,'anonymous_capabilities_status':401}}
    monkeypatch.setattr(remote,'snapshot',snapshot)
    monkeypatch.setattr(remote,'memory_available',lambda:5*1024**3)
    monkeypatch.setattr(remote.shutil,'disk_usage',lambda path:SimpleNamespace(free=20*1024**3))
    monkeypatch.setattr(remote,'prepare',lambda *args:pytest.fail('must not stage'))
    result=remote.execute({'source_sha':'a'*40,'request_id':str(uuid.uuid4()),'archive_sha256':'0'*64},b'')
    assert result['status']=='failed' and result['failure_reason']=='resource_preflight'
    assert result['postflight_verified'] is True and result['container_preserved'] is True
    assert result['configuration_preserved'] is True and result['database_bytes_preserved'] is True
    assert len(count)==2
