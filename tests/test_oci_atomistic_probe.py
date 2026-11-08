"""Fixed atomistic request/CI/transport/archive/resource boundaries, no host access."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
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


def tar_bytes(files, symlink=None, mode='w:gz'):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode, format=tarfile.USTAR_FORMAT) as archive:
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
    def snapshot(*, a04=False):
        assert not a04
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


@pytest.mark.parametrize('kind,uid,gid,mode,nlink', [
    ('file',0,999,0o660,1),('socket',1000,999,0o660,1),('socket',0,0,0o660,1),
    ('socket',0,999,0o666,1),('socket',0,999,0o640,1),('socket',0,999,0o660,2)])
def test_child_docker_group_rejects_untrusted_socket(monkeypatch, kind, uid, gid, mode, nlink):
    remote=load('remote_atomistic_probe')
    import stat
    monkeypatch.setattr(remote,'_parents',lambda path:None)
    monkeypatch.setattr(remote.Path,'resolve',lambda path, strict=False:Path('/run'))
    monkeypatch.setattr(remote.Path,'lstat',lambda path:SimpleNamespace(
        st_mode=(stat.S_IFSOCK if kind=='socket' else stat.S_IFREG)|mode,
        st_uid=uid,st_gid=gid,st_nlink=nlink))
    monkeypatch.setattr(remote.os,'getgrouplist',lambda *args:[1000,27])
    with pytest.raises(remote.ProbeError):
        remote.docker_child_groups(SimpleNamespace(pw_name='ubuntu',pw_gid=1000))


def test_child_docker_group_is_ephemeral_and_only_verified_socket_gid(monkeypatch):
    remote=load('remote_atomistic_probe')
    import stat
    monkeypatch.setattr(remote,'_parents',lambda path:None)
    monkeypatch.setattr(remote.Path,'resolve',lambda path, strict=False:Path('/run'))
    monkeypatch.setattr(remote.Path,'lstat',lambda path:SimpleNamespace(
        st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=999,st_nlink=1))
    monkeypatch.setattr(remote.os,'getgrouplist',lambda *args:[1000,27])
    groups, added=remote.docker_child_groups(SimpleNamespace(pw_name='ubuntu',pw_gid=1000))
    assert groups==[27,999,1000] and added is True
    monkeypatch.setattr(remote.os,'getgrouplist',lambda *args:[1000,999,27])
    assert remote.docker_child_groups(SimpleNamespace(pw_name='ubuntu',pw_gid=1000))==([27,999,1000],False)
    monkeypatch.setattr(remote.Path,'resolve',lambda path, strict=False:Path('/unexpected'))
    with pytest.raises(remote.ProbeError):
        remote.docker_child_groups(SimpleNamespace(pw_name='ubuntu',pw_gid=1000))


def a04_config(remote, raw=b''):
    return {'source_sha': 'a' * 40, 'request_id': str(uuid.uuid4()),
            'archive_sha256': hashlib.sha256(raw).hexdigest(), 'candidate': dict(remote.A04_CANDIDATE)}


def test_a04_candidate_uses_reviewed_image_separate_from_control_source():
    remote = load('remote_atomistic_probe')
    config = a04_config(remote)
    assert remote.validate_config(config, a04=True) == config
    with pytest.raises(ValueError):
        remote.validate_config(config)
    for candidate in (None, dict(config['candidate'], source_sha=config['source_sha']),
                      dict(config['candidate'], archive_bytes=838924288.0),
                      dict(config['candidate'], schema_version=True)):
        with pytest.raises(ValueError):
            remote.validate_config(dict(config, candidate=candidate), a04=True)
    with pytest.raises(ValueError):
        remote.validate_config(dict(config, case='he'), a04=True)


def test_a04_archive_enforces_its_exact_files_and_bounded_xz():
    remote = load('remote_atomistic_probe')
    files = {name: b'{}\n' for name in remote.A04_REQUIRED}
    raw = tar_bytes(files, mode='w:xz')
    assert remote.archive_files(raw, hashlib.sha256(raw).hexdigest(), a04=True) == files
    for bad in (raw + b'x', tar_bytes(files),
                tar_bytes(dict(files, **{'docs/design/atomistic-a01-v0.1/arbitrary': b'x'}), mode='w:xz')):
        with pytest.raises(remote.ProbeError):
            remote.archive_files(bad, hashlib.sha256(bad).hexdigest(), a04=True)
    with pytest.raises(remote.ProbeError):
        remote.archive_files(raw, hashlib.sha256(raw).hexdigest(), a04=True, trace=True)


def test_a04_headroom_and_web_boundary():
    remote = load('remote_atomistic_probe')
    GiB = 1024**3
    remote.resource_preflight(0, 8 * GiB, 10 * GiB, a04=True)
    with pytest.raises(remote.ProbeError, match='resource_preflight'):
        remote.resource_preflight(0, 8 * GiB - 1, 10 * GiB, a04=True)
    good = {'web_status': 200, 'anonymous_capabilities_status': 401, 'latency_seconds': [0.01, 2.0]}
    remote.require_a04_web(good)
    for bad in (dict(good, latency_seconds=[0.01, 2.01]), dict(good, anonymous_capabilities_status=200)):
        with pytest.raises(remote.ProbeError, match='service_boundary'):
            remote.require_a04_web(bad)


def test_a04_cleanup_uses_only_exact_probe_label_and_pinned_new_image(monkeypatch):
    remote = load('remote_atomistic_probe')
    output = Path('/srv/quanta/atomistic-probes/request/workspace/run')
    ref = remote.A04_CANDIDATE['image_ref']
    native = f'{ref} sha256:{remote.A04_CANDIDATE["config_sha256"]}\n'.encode()
    oci = f'{ref} sha256:{remote.A04_CANDIDATE_MANIFEST_SHA256}\n'.encode()
    replies = iter([b'1234567890ab\n', b'', native, oci, oci, b'', b'foreign\n'])
    calls = []

    def run(args, **_):
        calls.append(args[len(remote.DOCKER):])
        return next(replies)

    monkeypatch.setattr(remote, '_run', run)
    assert remote.cleanup_containers(output, a04=True) == 1
    remote.a04_restore_image_tag(True)
    remote.a04_restore_image_tag(False)
    assert calls[0] == ['ps', '-aq', '--filter', f'label=org.quanta.atomistic-a04={output}']
    assert calls[1] == ['rm', '-f', '1234567890ab']
    assert calls[4] == ['image', 'rm', '--no-prune', ref]
    with pytest.raises(remote.ProbeError, match='candidate_image_identity'):
        remote.a04_image_present()


def test_a04_report_requires_all_cases_and_observed_caps():
    remote = load('remote_atomistic_probe')
    source = 'a' * 40
    report = {'schema_version': 1, 'scope': remote.A04_REPORT_SCOPE, 'quanta_source': source,
              'status': 'measured', 'all_cross_build_checks_passed': True, 'scratch_removed': True,
              'cases': []}
    for system in remote.A04_CASES:
        he = system == 'he'
        cap = (6 if he else 3) * 1024**3
        report['cases'].append({'system': system, 'status': 'measured', 'cap_bytes': cap,
            'settings': [12, 800, 80] if he else [12, 400, 40], 'comparison': {'passed': True},
            'attempt': {'container_removed': True, 'observed_mpi_ranks': 1, 'observed_omp_threads': 1,
                        'container_controls': {'memory_bytes': cap, 'memory_swap_bytes': cap, 'cpus': 1},
                        'engine_resource': {'final_cgroup_memory_max_bytes': cap,
                                            'final_cgroup_swap_max_bytes': 0, 'final_cgroup_swap_peak_bytes': 0}}})
    assert remote.a04_benchmark_passed(report, source)
    assert not remote.a04_benchmark_passed(dict(report, cases=report['cases'][:-1]), source)
    assert not remote.a04_benchmark_passed(dict(report, all_cross_build_checks_passed=False), source)
    report['cases'][-1]['attempt']['engine_resource']['final_cgroup_swap_max_bytes'] = 1
    assert not remote.a04_benchmark_passed(report, source)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _a04_snapshot(database):
    return {'identity': 'same container', 'config_sha': ['same configuration'], 'database': database}


@pytest.mark.parametrize('wal_before,wal_after,wal_preserved,empty_transition', [
    (('absent', None), ('absent', None), True, False),
    (('empty', _digest(b'')), ('empty', _digest(b'')), True, False),
    (('absent', None), ('empty', _digest(b'')), True, True),
    (('empty', _digest(b'')), ('absent', None), True, True),
    (('nonempty', _digest(b'one')), ('nonempty', _digest(b'one')), True, False),
    (('nonempty', _digest(b'one')), ('nonempty', _digest(b'two')), False, False),
    (('nonempty', _digest(b'one')), ('absent', None), False, False),
    (('absent', None), ('nonempty', _digest(b'one')), False, False),
    (('nonempty', _digest(b'one')), ('empty', _digest(b'')), False, False),
    (('empty', _digest(b'')), ('nonempty', _digest(b'one')), False, False),
])
def test_a04_preservation_only_normalizes_an_empty_wal_transition(
        wal_before, wal_after, wal_preserved, empty_transition):
    remote = load('remote_atomistic_probe')
    main = _digest(b'jobs')
    before = _a04_snapshot((main, *wal_before))
    after = _a04_snapshot((main, *wal_after))
    flags = remote.preservation(before, after, a04=True)
    assert flags['container_preserved'] is True
    assert flags['configuration_preserved'] is True
    assert flags['database_bytes_preserved'] is wal_preserved
    assert flags['database_preservation'] == {
        'main_bytes_preserved': True,
        'wal_content_preserved': wal_preserved,
        'before_wal_state': wal_before[0],
        'after_wal_state': wal_after[0],
        'empty_wal_transition': empty_transition,
    }


def test_a04_db_change_blocks_even_if_wal_transition_is_allowed():
    remote = load('remote_atomistic_probe')
    before = _a04_snapshot((_digest(b'original jobs'), 'empty', _digest(b'')))
    after = _a04_snapshot((_digest(b'updated jobs'), 'absent', None))
    flags = remote.preservation(before, after, a04=True)
    assert flags['database_bytes_preserved'] is False
    assert flags['database_preservation']['main_bytes_preserved'] is False
    assert flags['database_preservation']['wal_content_preserved'] is True
    assert flags['database_preservation']['empty_wal_transition'] is True


def test_legacy_preservation_still_distinguishes_empty_and_absent_wal():
    remote = load('remote_atomistic_probe')
    before = {'identity': 'same', 'config_sha': ['same'], 'database_sha': [_digest(b'jobs'), None]}
    after = dict(before, database_sha=[_digest(b'jobs'), _digest(b'')])
    assert remote.preservation(before, after) == {
        'container_preserved': True, 'configuration_preserved': True, 'database_bytes_preserved': False,
    }


@pytest.fixture
def a04_db_fixture(tmp_path, monkeypatch):
    remote = load('remote_atomistic_probe')
    database = tmp_path / 'jobs.sqlite3'
    database.write_bytes(b'private jobs bytes')
    wal = tmp_path / 'jobs.sqlite3-wal'
    monkeypatch.setattr(remote, '_parents', lambda path: None)

    def metadata(path):
        try:
            return path.lstat()
        except FileNotFoundError:
            return None

    monkeypatch.setattr(remote, '_database_metadata', metadata)
    return remote, database, wal, metadata


@pytest.mark.parametrize('wal_bytes,wal_state', [(None, 'absent'), (b'', 'empty'), (b'wal frames', 'nonempty')])
def test_a04_database_snapshot_reads_exact_stable_bytes_without_atime_updates(a04_db_fixture, wal_bytes, wal_state):
    remote, database, wal, _ = a04_db_fixture
    files = [database]
    if wal_bytes is not None:
        wal.write_bytes(wal_bytes)
        files.append(wal)
    for path in files:
        os.utime(path, ns=(1_000_000_000, path.stat().st_mtime_ns))
    atimes = [path.stat().st_atime_ns for path in files]
    main_sha, state, wal_sha = remote.a04_database_snapshot(database)
    assert main_sha == _digest(b'private jobs bytes')
    assert state == wal_state
    if wal_bytes is None:
        assert wal_sha is None and not wal.exists()
    elif wal_bytes:
        assert wal_sha == _digest(wal_bytes)
    assert [path.stat().st_atime_ns for path in files] == atimes


def test_a04_database_snapshot_retries_a_transient_stat_race(a04_db_fixture, monkeypatch):
    remote, database, _, metadata = a04_db_fixture
    raced = False
    sleeps = []

    def change_after_stat(path):
        nonlocal raced
        info = metadata(path)
        if path == database and not raced:
            database.write_bytes(b'new stable bytes')
            raced = True
        return info

    monkeypatch.setattr(remote, '_database_metadata', change_after_stat)
    monkeypatch.setattr(remote.time, 'sleep', sleeps.append)
    assert remote.a04_database_snapshot(database) == (_digest(b'new stable bytes'), 'absent', None)
    assert len(sleeps) == 1


def test_a04_database_snapshot_fails_after_five_racing_attempts(a04_db_fixture, monkeypatch):
    remote, database, _, metadata = a04_db_fixture
    sleeps = []
    stat_calls = []

    def keep_changing(path):
        info = metadata(path)
        if path == database:
            stat_calls.append(path)
            database.write_bytes(b'x' * (info.st_size + 1))
        return info

    monkeypatch.setattr(remote, '_database_metadata', keep_changing)
    monkeypatch.setattr(remote.time, 'sleep', sleeps.append)
    with pytest.raises(remote.ProbeError):
        remote.a04_database_snapshot(database)
    assert len(stat_calls) == 5
    assert len(sleeps) == 4


def test_a04_database_snapshot_rejects_missing_main_without_retry(a04_db_fixture, monkeypatch):
    remote, database, _, _ = a04_db_fixture
    database.unlink()
    monkeypatch.setattr(remote.time, 'sleep', lambda _: pytest.fail('must fail without retry'))
    with pytest.raises(remote.ProbeError):
        remote.a04_database_snapshot(database)


def test_a04_database_metadata_does_not_treat_dangling_wal_symlink_as_absent(tmp_path):
    remote = load('remote_atomistic_probe')
    wal = tmp_path / 'jobs.sqlite3-wal'
    assert remote._database_metadata(wal) is None
    wal.symlink_to(tmp_path / 'missing-wal')
    with pytest.raises(remote.ProbeError):
        remote._database_metadata(wal)


def test_a04_database_metadata_enforces_the_file_size_limit(monkeypatch):
    remote = load('remote_atomistic_probe')
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=10001, st_gid=10001,
                           st_size=remote.DATABASE_FILE_LIMIT)
    monkeypatch.setattr(remote.Path, 'lstat', lambda path: info)
    assert remote._database_metadata(remote.DATABASE) is info
    info.st_size += 1
    with pytest.raises(remote.ProbeError):
        remote._database_metadata(remote.DATABASE)


def test_a04_first_postflight_mismatch_remains_a_failure_after_final_match(tmp_path, monkeypatch):
    remote = load('remote_atomistic_probe')
    db_before, db_changed = _digest(b'baseline jobs'), _digest(b'updated jobs')
    web = {'web_status': 200, 'anonymous_capabilities_status': 401, 'latency_seconds': [0.01, 0.02]}
    observations = iter([(db_before, 'absent', None), (db_changed, 'absent', None),
                         (db_before, 'empty', _digest(b''))])

    def snapshot(*, a04=False):
        assert a04
        return {**_a04_snapshot(next(observations)), 'active_jobs': 0, 'web': web}

    real_open, real_fstat = remote.os.open, remote.os.fstat
    guard_fd = real_open(tmp_path / 'guard.lock', os.O_RDWR | os.O_CREAT, 0o600)
    original_guard = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)

    def open_file(path, *args):
        if str(path) == '/run/quanta-application-upgrade.lock':
            return guard_fd
        return real_open(path, *args)

    monkeypatch.setattr(remote.os, 'open', open_file)
    monkeypatch.setattr(remote.os, 'fstat', lambda fd: original_guard if fd == guard_fd else real_fstat(fd))
    monkeypatch.setattr(remote.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(remote.platform, 'machine', lambda: 'aarch64')
    monkeypatch.setattr(remote, '_parents', lambda path: None)
    monkeypatch.setattr(remote.fcntl, 'flock', lambda *args: None)
    monkeypatch.setattr(remote, 'snapshot', snapshot)
    monkeypatch.setattr(remote, 'memory_available', lambda: 10 * 1024**3)
    monkeypatch.setattr(remote, 'available_disk', lambda docker_root=None: 20 * 1024**3)
    monkeypatch.setattr(remote, 'a04_docker_data_root', lambda: tmp_path)
    monkeypatch.setattr(remote, 'a04_image_present', lambda: True)
    monkeypatch.setattr(remote, 'active_jobs', lambda: 0)
    monkeypatch.setattr(remote, 'web_boundary', lambda: web)
    monkeypatch.setattr(remote, 'cleanup_containers', lambda output, *, a04=False: 0)
    monkeypatch.setattr(remote.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    monkeypatch.setattr(remote, 'docker_child_groups', lambda user: ([], False))
    monkeypatch.setattr(remote.os, 'chown', lambda *args: None)
    monkeypatch.setattr(remote, 'relay_candidate', lambda *args, **kwargs: None)
    monkeypatch.setattr(remote, 'a04_benchmark_passed', lambda *args: True)
    monkeypatch.setattr(remote.time, 'sleep', lambda seconds: None)
    source = tmp_path / 'source'
    source.mkdir()
    monkeypatch.setattr(remote, 'prepare', lambda *args, **kwargs: (tmp_path, source))

    def run(*args, **kwargs):
        output = tmp_path / 'workspace' / 'run'
        output.mkdir()
        (output / 'report.json').write_text('{}')
        states = iter([None, 0])
        return SimpleNamespace(returncode=0, poll=lambda: next(states, 0))

    monkeypatch.setattr(remote.subprocess, 'Popen', run)
    archive = b'isolated test archive'
    result = remote.execute(a04_config(remote, archive), archive, a04=True)
    assert result['status'] == 'failed'
    assert result['failure_reason'] == 'benchmark_or_preservation'
    assert result['first_postflight_gate']['database_bytes_preserved'] is False
    assert result['first_postflight_gate']['database_preservation']['main_bytes_preserved'] is False
    assert result['database_bytes_preserved'] is True
    assert result['database_preservation']['empty_wal_transition'] is True
    assert result['postflight_verified'] is True
    assert db_before not in json.dumps(result) and db_changed not in json.dumps(result)
