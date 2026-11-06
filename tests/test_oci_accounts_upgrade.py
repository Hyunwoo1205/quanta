"""Fixed account-upgrade controls: real archive/SQLite/files; no remote changes."""
from __future__ import annotations
import base64
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('test_accounts_' + name, ROOT / 'deploy/oci' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


operation = load('upgrade_accounts')
gate = load('authorize_accounts_upgrade')
transport = load('probe_accounts_upgrade')
SHA = 'a' * 40
CONTROL = 'b' * 40
REQUEST_ID = '6265bde1-e559-45b3-87c2-14a41fd3251d'
OLD_IMAGE = 'sha256:' + 'c' * 64
NEW_IMAGE = 'sha256:' + 'd' * 64
TOKEN = 'e' * 64


def config():
    return {'source_sha': SHA, 'request_id': REQUEST_ID, 'public_origin': 'https://app.example.net', 'auth_mode': 'owner-token'}


def request():
    return {'schema_version': 1, 'operation': 'upgrade-accounts', 'source_sha': SHA, 'request_id': REQUEST_ID}


def environ():
    return {'GITHUB_REPOSITORY': gate.REPOSITORY, 'GITHUB_REF': 'refs/heads/ops/oci', 'GITHUB_EVENT_NAME': 'push',
        'QUANTA_ACCOUNTS_CONTROL_SHA': CONTROL, 'QUANTA_ACCOUNTS_CONTROL_CI_RUN': '123', 'QUANTA_CI_READ_TOKEN': 'synthetic-token'}


def database():
    return {'schema_sha256': 'a' * 64, 'nonterminal_runs': 0,
        'tables': {name: {'rows': index + 1, 'sha256': 'b' * 64} for index, name in enumerate(operation.TABLES)}}


def deployment():
    return {'storage_mode': 'boot', 'filesystem_uuid': '540c2fb0-7424-48d8-8b0a-fef3cb15b539', 'image': OLD_IMAGE}


def journal():
    return {'schema_version': 1, 'request_id': REQUEST_ID, 'source_sha': SHA, 'created_at': '2026-11-06T01:02:03Z',
        'status': 'switching', 'database': database(), 'settings': {'synthetic': 'f' * 64},
        'old_deployment': base64.b64encode(operation._encoded(deployment())).decode(),
        'new_deployment': base64.b64encode(operation._encoded({**deployment(), 'image': NEW_IMAGE})).decode(),
        'old_installed': base64.b64encode(operation._encoded({'source_sha': operation.OLD_SOURCE,
            'public_origin': config()['public_origin'], 'auth_mode': 'owner-token'})).decode(),
        'new_installed': base64.b64encode(operation._encoded({k: v for k, v in config().items() if k != 'request_id'})).decode()}


@contextmanager
def fake_upgrade():
    saved = journal()
    with ExitStack() as stack, tempfile.TemporaryDirectory() as temporary:
        stack.enter_context(patch.object(operation, 'JOURNAL', Path(temporary) / 'absent.json'))
        mocks = {}
        values = {'_lock': nullcontext(), '_interruptions': nullcontext(), '_services': None,
            '_containers': None, '_worker': None, '_database': database(), '_stage': Path('/synthetic/source'),
            '_build': NEW_IMAGE, '_smoke': None, '_quiet': None, '_write_journal': None,
            '_arm_watchdog': None, '_cancel_watchdog': None, '_replace': None, '_public': None, '_restore': None,
            '_unit': {'LoadState': 'not-found', 'ActiveState': 'inactive'}}
        for name, value in values.items():
            mocks[name] = stack.enter_context(patch.object(operation, name, return_value=value))
        def installation(_config, *, new=False):
            return ({**deployment(), 'image': NEW_IMAGE if new else OLD_IMAGE},
                base64.b64decode(saved['new_deployment' if new else 'old_deployment']),
                base64.b64decode(saved['new_installed' if new else 'old_installed']), saved['settings'], TOKEN)
        mocks['_installation'] = stack.enter_context(patch.object(operation, '_installation', side_effect=installation))
        def readiness(_config, token, *, accounts, report):
            report.update(services_ready=True, auth_boundaries_verified=True, application_version='0.12.0' if accounts else '0.11.0')
            if accounts:
                report.update(account_discovery_verified=True, registration='open')
        mocks['_readiness'] = stack.enter_context(patch.object(operation, '_readiness', side_effect=readiness))
        mocks['_gmail_smtp_tls'] = stack.enter_context(patch.object(operation, '_gmail_smtp_tls', side_effect=lambda report: report.update(gmail_smtp_tls_checked=True)))
        mocks['_journal_status'] = stack.enter_context(patch.object(operation, '_journal_status', side_effect=lambda value, status: {**value, 'status': status}))
        mocks['_journal'] = stack.enter_context(patch.object(operation, '_journal', return_value={**saved, 'status': 'complete'}))
        stack.enter_context(patch.object(operation, '_deadline', side_effect=lambda seconds: nullcontext()))
        stack.enter_context(patch.object(operation.time, 'sleep'))
        yield mocks


def successful_report():
    with fake_upgrade():
        return operation.run(config(), 'upgrade-accounts')


class GateTests(unittest.TestCase):
    def test_request_is_exact_four_field_uuid4_and_fixed_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'
            path.write_text(json.dumps(request()))
            self.assertEqual(gate.read_request(path, environ()), request())
            for update in ({'operation': 'run-command'}, {'operation': []}, {'schema_version': True},
                    {'source_sha': '../bad'}, {'request_id': 'not-a-uuid'}, {'command': 'id'}):
                path.write_text(json.dumps({**request(), **update}))
                with self.subTest(update=update), self.assertRaises((ValueError, TypeError)):
                    gate.read_request(path, environ())

    def test_request_rejects_wrong_repository_event_branch_symlink_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'
            path.write_text(json.dumps(request()))
            for field in ('GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF'):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    gate.read_request(path, {**environ(), field: 'wrong'})
            link = Path(directory) / 'link.json'; link.symlink_to(path)
            with self.assertRaises(ValueError): gate.read_request(link, environ())
            path.write_text('{"operation":"upgrade-accounts","operation":"verify-accounts"}')
            with self.assertRaises(ValueError): gate.read_request(path, environ())

    def test_control_checkout_uses_pinned_head_and_clean_tracked_bytes(self):
        runner = unittest.mock.Mock(side_effect=[types.SimpleNamespace(returncode=0, stdout=(CONTROL + '\n').encode()), types.SimpleNamespace(returncode=0)])
        self.assertTrue(gate.control_checkout_matches(environ(), runner=runner))
        runner = unittest.mock.Mock(return_value=types.SimpleNamespace(returncode=1, stdout=b''))
        self.assertFalse(gate.control_checkout_matches(environ(), runner=runner))
        self.assertFalse(gate.control_checkout_matches({**environ(), 'QUANTA_ACCOUNTS_CONTROL_SHA': 'main'}))

    def test_ci_gate_requires_exact_completed_main_push_paths_for_both_pins(self):
        control = {'id': 123, 'head_sha': CONTROL, 'head_branch': 'main', 'event': 'push',
            'path': gate.CONTROL_WORKFLOW, 'status': 'completed', 'conclusion': 'success'}
        app = {**control, 'id': 456, 'head_sha': SHA, 'path': gate.APP_WORKFLOW}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'; path.write_text(json.dumps(request()))
            with patch.object(gate, 'control_checkout_matches', return_value=True), patch.object(gate, 'api_get', side_effect=[control, {'workflow_runs': [app]}]):
                result = gate.authorize(environ(), path=path)
            self.assertEqual(result['status'], 'authorized'); self.assertEqual(result['app_ci_run'], 456)
            for field, bad in (('status', 'in_progress'), ('conclusion', 'failure'), ('event', 'workflow_dispatch'), ('head_branch', 'ops/oci'), ('path', gate.CONTROL_WORKFLOW), ('head_sha', CONTROL)):
                with self.subTest(field=field), patch.object(gate, 'control_checkout_matches', return_value=True), patch.object(gate, 'api_get', side_effect=[control, {'workflow_runs': [{**app, field: bad}]}]):
                    self.assertEqual(gate.authorize(environ(), path=path)['status'], 'denied')

    def test_redirect_and_oversized_ci_responses_fail_closed(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def geturl(self): return 'https://other.example.net/'
            def read(self, limit): return b'{}'
        with self.assertRaises(ValueError): gate.api_get('/actions/runs/123', environ(), opener=lambda *_args, **_kwargs: Response())
        response = Response(); response.geturl = lambda: gate.API_ROOT + '/actions/runs/123'; response.read = lambda limit: b'x' * (gate.MAX_RESPONSE + 1)
        with self.assertRaises(ValueError): gate.api_get('/actions/runs/123', environ(), opener=lambda *_args, **_kwargs: response)


class ControllerTests(unittest.TestCase):
    def test_config_and_encoded_argument_bind_source_origin_uuid_without_commands(self):
        value = operation._encoded(config()); encoded = base64.b64encode(value).decode()
        self.assertEqual(operation._argument(encoded), config())
        for update in ({'source_sha': operation.OLD_SOURCE}, {'source_sha': 'main'}, {'auth_mode': 'access'},
                {'public_origin': 'http://app.example.net'}, {'public_origin': 'https://app.example.net/path'}, {'request_id': 'bad'}, {'command': 'whoami'}):
            with self.subTest(update=update), self.assertRaises((ValueError, TypeError)):
                operation.validate_config({**config(), **update})
        with self.assertRaises(ValueError): operation._argument(base64.b64encode(json.dumps(config()).encode()).decode())

    def test_success_switches_only_after_armed_watchdog_and_private_baseline(self):
        with fake_upgrade() as mocks:
            events = []
            for name in ('_arm_watchdog', '_write_journal', '_replace', '_quiet'):
                mocks[name].side_effect = lambda *args, _name=name, **kwargs: events.append((_name, args))
            value = operation.run(config(), 'upgrade-accounts')
        self.assertEqual(value['status'], 'success')
        self.assertEqual(operation.validate_report(value), value)
        armed = next(i for i, event in enumerate(events) if event[0] == '_arm_watchdog')
        stop_https = next(i for i, event in enumerate(events) if event[0] == '_quiet' and event[1][0] == ['/usr/bin/systemctl', 'stop', operation.HTTPS])
        private = next(i for i, event in enumerate(events) if event[0] == '_write_journal')
        stop_app = next(i for i, event in enumerate(events) if event[0] == '_quiet' and event[1][0] == ['/usr/bin/systemctl', 'stop', operation.APP])
        switch = next(i for i, event in enumerate(events) if event[0] == '_replace')
        self.assertLess(armed, stop_https); self.assertLess(private, stop_app); self.assertLess(stop_app, switch)
        self.assertFalse(value['mail_delivery_verified']); self.assertFalse(value['new_calculation_verified'])

    def test_old_installation_or_busy_store_refusal_never_stops_services(self):
        for fail in ('_installation', '_services', '_containers', '_worker', '_database'):
            with self.subTest(fail=fail), fake_upgrade() as mocks:
                mocks[fail].side_effect = operation.UpgradeError()
                value = operation.run(config(), 'upgrade-accounts')
                self.assertEqual(value['status'], 'failed')
                mocks['_quiet'].assert_not_called(); mocks['_replace'].assert_not_called()

    def test_existing_journal_blocks_repeat_even_with_a_new_request_id(self):
        with fake_upgrade() as mocks, tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'journal'; path.write_text('{}')
            with patch.object(operation, 'JOURNAL', path): value = operation.run(config(), 'upgrade-accounts')
            self.assertEqual(value['status'], 'failed'); mocks['_stage'].assert_not_called()

    def test_failure_before_journal_restores_services_without_config_or_data_writes(self):
        with fake_upgrade() as mocks:
            mocks['_database'].side_effect = [database(), database(), operation.UpgradeError()]
            value = operation.run(config(), 'upgrade-accounts')
            self.assertEqual(value['status'], 'failed'); self.assertTrue(value['rollback_succeeded'])
            mocks['_replace'].assert_not_called(); mocks['_restore'].assert_not_called()
            self.assertIn(unittest.mock.call(['/usr/bin/systemctl', 'start', operation.APP, operation.HTTPS, operation.TIMER], timeout=65), mocks['_quiet'].call_args_list)

    def test_failure_after_switch_runs_exact_journal_rollback(self):
        with fake_upgrade() as mocks:
            mocks['_public'].side_effect = operation.UpgradeError()
            value = operation.run(config(), 'upgrade-accounts')
            self.assertEqual(value['status'], 'failed'); self.assertTrue(value['rollback_attempted']); self.assertTrue(value['rollback_succeeded'])
            saved = mocks['_restore'].call_args.args[0]
            self.assertEqual(saved['source_sha'], SHA)
            self.assertEqual(base64.b64decode(saved['old_deployment']), operation._encoded(deployment()))

    def test_rollback_never_claims_changed_scientific_data_was_restored(self):
        with fake_upgrade() as mocks:
            mocks['_public'].side_effect = operation.UpgradeError()
            def changed_after_failure():
                return {**database(), 'schema_sha256': 'c' * 64} if mocks['_restore'].called else database()
            mocks['_database'].side_effect = changed_after_failure
            value = operation.run(config(), 'upgrade-accounts')
            self.assertTrue(value['rollback_attempted']); self.assertFalse(value['rollback_succeeded'])
            mocks['_restore'].assert_called_once()

    def test_failed_rollback_is_not_reported_as_restoration_success(self):
        with fake_upgrade() as mocks:
            mocks['_public'].side_effect = operation.UpgradeError(); mocks['_restore'].side_effect = operation.UpgradeError()
            value = operation.run(config(), 'upgrade-accounts')
            self.assertTrue(value['rollback_attempted']); self.assertFalse(value['rollback_succeeded'])
            mocks['_cancel_watchdog'].assert_not_called()

    def test_commit_precedes_watchdog_cleanup_and_late_cleanup_failure_does_not_rollback(self):
        with fake_upgrade() as mocks:
            mocks['_cancel_watchdog'].side_effect = operation.UpgradeError()
            value = operation.run(config(), 'upgrade-accounts')
            self.assertEqual(value['status'], 'success'); self.assertFalse(value['rollback_attempted'])
            mocks['_journal_status'].assert_called_once(); mocks['_restore'].assert_not_called()

    def test_readonly_verify_checks_exact_saved_database_and_settings(self):
        with fake_upgrade() as mocks:
            value = operation.run(config(), 'verify-accounts')
            self.assertEqual(value['status'], 'success'); self.assertFalse(value['server_modified'])
            operation.validate_report(value)
            for name in ('_quiet', '_stage', '_build', '_replace', '_write_journal', '_restore', '_arm_watchdog'):
                mocks[name].assert_not_called()
        with fake_upgrade() as mocks:
            mocks['_database'].return_value = {**database(), 'schema_sha256': 'c' * 64}
            value = operation.run(config(), 'verify-accounts'); self.assertEqual(value['status'], 'failed')
            mocks['_replace'].assert_not_called()

    def test_restore_refuses_unexpected_operator_configuration_without_overwrite(self):
        with patch.object(operation, '_file', return_value=b'unexpected'), patch.object(operation, '_quiet') as quiet, patch.object(operation, '_replace') as replace:
            with self.assertRaises(operation.UpgradeError): operation._restore(journal())
            quiet.assert_not_called(); replace.assert_not_called()

    def test_root_file_reader_rejects_symlinks_hardlinks_and_loose_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private'; path.write_bytes(b'private'); path.chmod(0o600)
            self.assertEqual(operation._file(path, uid=os.geteuid()), b'private')
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises(operation.UpgradeError): operation._file(link, uid=os.geteuid())
            link.unlink(); os.link(path, link)
            with self.assertRaises(operation.UpgradeError): operation._file(path, uid=os.geteuid())
            link.unlink(); path.chmod(0o644)
            with self.assertRaises(operation.UpgradeError): operation._file(path, uid=os.geteuid())

    def test_replace_compares_expected_bytes_and_preserves_private_mode(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(operation, '_parents'):
            path = Path(directory) / 'private'; path.write_bytes(b'old'); path.chmod(0o600)
            original = operation._file
            with patch.object(operation, '_file', side_effect=lambda p, **kw: original(p, uid=os.geteuid(), **kw)):
                operation._replace(path, b'new', b'old')
                self.assertEqual(path.read_bytes(), b'new'); self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaises(operation.UpgradeError): operation._replace(path, b'bad', b'old')
                self.assertEqual(path.read_bytes(), b'new')

    def test_report_cannot_emit_secrets_or_inflate_email_compute_and_readonly_scope(self):
        valid = successful_report()
        for update in ({'owner_token': TOKEN}, {'mail_delivery_verified': True}, {'actual_email_delivery_verified': True}, {'new_calculation_verified': True},
                {'gmail_smtp_tls_ready': True},
                {'database_preserved': False}, {'status': []}, {'registration': []}, {'peer_containers': True}):
            with self.subTest(update=update):
                self.assertIsNone(operation.sanitize_report(operation._encoded({**valid, **update})))
        readonly = {**valid, 'operation': 'verify-accounts'}
        self.assertIsNone(operation.sanitize_report(operation._encoded(readonly)))

    def test_readiness_checks_bearer_denial_and_exact_new_account_mode(self):
        report = operation._initial('verify-accounts')
        values = [(200, {'status': 'ready'}), (401, {}), (401, {}),
            (200, {'package_version': '0.12.0'}), (200, {'mode': 'account', 'authenticated': False, 'mail_configured': False, 'registration': 'open'})]
        with patch.object(operation, '_http', side_effect=values): operation._readiness(config(), TOKEN, accounts=True, report=report)
        self.assertTrue(report['account_discovery_verified']); self.assertFalse(report['mail_configured'])
        values[-1] = (200, {'mode': 'account', 'authenticated': True, 'mail_configured': True, 'registration': 'open'})
        with patch.object(operation, '_http', side_effect=values), self.assertRaises(operation.UpgradeError):
            operation._readiness(config(), TOKEN, accounts=True, report=operation._initial('verify-accounts'))

    def test_watchdog_code_is_fixed_compileable_and_contains_no_secret_literal(self):
        source = operation._watchdog_source()
        compile(source, '<fixed-watchdog>', 'exec')
        self.assertNotIn(TOKEN.encode(), source)
        self.assertIn(b"v.get('status')=='switching'", source)
        self.assertIn(b'except FileNotFoundError:', source)
        self.assertNotIn(b'unlink(', source)
        self.assertNotIn(b'rmtree', source)


class ArchiveTests(unittest.TestCase):
    def archive(self, names):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:') as archive:
            root = tarfile.TarInfo('quanta-' + SHA); root.type = tarfile.DIRTYPE; archive.addfile(root)
            for name, kind, raw in names:
                member = tarfile.TarInfo(name); member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(raw); archive.addfile(member, io.BytesIO(raw))
                else:
                    member.linkname = '/private'; archive.addfile(member)
        return gzip.compress(stream.getvalue())

    def test_archive_accepts_bounded_regular_files_for_only_the_requested_source(self):
        raw = self.archive([('quanta-' + SHA + '/README.md', tarfile.REGTYPE, b'hello')])
        archive, members = operation._archive(raw, SHA)
        try:
            self.assertEqual(members[1][0], ('README.md',)); self.assertEqual(archive.extractfile(members[1][1]).read(), b'hello')
        finally: archive.close()

    def test_archive_refuses_path_escape_symlink_hardlink_duplicate_and_wrong_commit(self):
        cases = [('../escape', tarfile.REGTYPE), ('quanta-' + SHA + '/../escape', tarfile.REGTYPE),
            ('quanta-' + SHA + '/link', tarfile.SYMTYPE), ('quanta-' + SHA + '/link', tarfile.LNKTYPE),
            ('quanta-' + CONTROL + '/README.md', tarfile.REGTYPE)]
        for name, kind in cases:
            with self.subTest(name=name, kind=kind), self.assertRaises(operation.UpgradeError):
                operation._archive(self.archive([(name, kind, b'x')]), SHA)
        name = 'quanta-' + SHA + '/same'
        with self.assertRaises(operation.UpgradeError): operation._archive(self.archive([(name, tarfile.REGTYPE, b'x')] * 2), SHA)

    def test_archive_rejects_gzip_trailer_and_expansion_budget(self):
        raw = self.archive([('quanta-' + SHA + '/data', tarfile.REGTYPE, b'x' * 100)])
        with self.assertRaises(operation.UpgradeError): operation._archive(raw + b'junk', SHA)
        with patch.object(operation, 'MAX_EXPANDED', 128), self.assertRaises(operation.UpgradeError): operation._archive(raw, SHA)


class DatabaseTests(unittest.TestCase):
    @contextmanager
    def actual_store(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'jobs.sqlite3'
            with sqlite3.connect(path) as db:
                for name in operation.TABLES:
                    db.execute('CREATE TABLE ' + name + (' (status TEXT)' if name == 'runs' else ' (value BLOB)'))
                    db.execute('INSERT INTO ' + name + ' VALUES (?)', ('SUCCEEDED' if name == 'runs' else b'\x00original\xff',))
            path.chmod(0o600)
            original = os.lstat
            def private_info(p, *args, **kwargs):
                info = original(p, *args, **kwargs)
                if str(p).startswith(str(directory)):
                    values = list(info); values[4] = values[5] = 10001; return os.stat_result(values)
                return info
            with patch.object(operation, 'DATA', Path(directory)), patch.object(operation, '_store_identity', return_value=nullcontext()), patch.object(operation.os, 'lstat', side_effect=private_info):
                yield path

    def test_actual_sqlite_fingerprint_covers_every_table_and_binary_artifact(self):
        with self.actual_store() as path:
            first = operation._database(); self.assertEqual(first['tables']['artifacts']['rows'], 1)
            self.assertEqual(operation._database(), first)
            with sqlite3.connect(path) as db: db.execute('UPDATE artifacts SET value=?', (b'\x00changed\xff',))
            second = operation._database(); self.assertNotEqual(first, second)
            self.assertEqual(first['tables']['experiments'], second['tables']['experiments'])

    def test_actual_sqlite_refuses_nonterminal_runs_extra_tables_and_symbolic_store(self):
        with self.actual_store() as path:
            with sqlite3.connect(path) as db: db.execute("UPDATE runs SET status='RUNNING'")
            with self.assertRaises(operation.UpgradeError): operation._database()
            with sqlite3.connect(path) as db:
                db.execute("UPDATE runs SET status='SUCCEEDED'"); db.execute('CREATE TABLE unexpected(value)')
            with self.assertRaises(operation.UpgradeError): operation._database()

    def test_typed_row_encoding_does_not_collapse_signed_zero_or_blob_text(self):
        self.assertNotEqual(operation._typed(0.0), operation._typed(-0.0))
        self.assertNotEqual(operation._typed(b'a'), operation._typed('a'))
        for value in (True, float('nan'), float('inf'), {}):
            with self.subTest(value=value), self.assertRaises(operation.UpgradeError): operation._typed(value)

    def test_sqlite_identity_transitions_restore_root_on_errors(self):
        state = {'uid': 0, 'gid': 0}; events = []
        def setuid(value): state['uid'] = value; events.append(('uid', value))
        def setgid(value): state['gid'] = value; events.append(('gid', value))
        with patch.object(operation.os, 'getuid', return_value=0), patch.object(operation.os, 'geteuid', side_effect=lambda: state['uid']), patch.object(operation.os, 'getegid', side_effect=lambda: state['gid']), patch.object(operation.os, 'seteuid', side_effect=setuid), patch.object(operation.os, 'setegid', side_effect=setgid):
            with self.assertRaises(RuntimeError):
                with operation._store_identity():
                    self.assertEqual(state, {'uid': 10001, 'gid': 10001}); raise RuntimeError('synthetic')
            self.assertEqual(state, {'uid': 0, 'gid': 0})
        self.assertEqual(events, [('gid', 10001), ('uid', 10001), ('uid', 0), ('gid', 0)])


class TransportTests(unittest.TestCase):
    def fake_modules(self, request_value=None):
        approved = request() if request_value is None else request_value
        gate_stub = types.SimpleNamespace(control_checkout_matches=lambda env: True, read_request=lambda **kwargs: approved)
        login = types.SimpleNamespace(PLINK='/usr/bin/plink', _normalized_host_key=lambda value: 'SHA256:synthetic',
            _key_bytes=lambda value: (None, b'PRIVATE_SYNTHETIC_PPK'), _global_ipv4=lambda value: True)
        modules = {'authorize_accounts_upgrade': gate_stub, 'upgrade_accounts': operation,
            'probe_login': login, 'probe_inventory': types.SimpleNamespace()}
        return modules

    def transport_env(self):
        return {**environ(), 'QUANTA_OCI_AUTH_CONFIRMED': 'true', 'QUANTA_ACCOUNTS_OPERATION': 'upgrade-accounts',
            'QUANTA_ACCOUNTS_SOURCE_SHA': SHA, 'QUANTA_ACCOUNTS_REQUEST_ID': REQUEST_ID,
            'QUANTA_PUBLIC_ORIGIN': config()['public_origin'], 'QUANTA_AUTH_MODE': 'owner-token',
            'QUANTA_OCI_HOST': '192.0.2.1', 'QUANTA_OCI_HOST_KEY': 'synthetic', 'QUANTA_OCI_PPK': 'synthetic'}

    def test_transport_uses_private_ppk_fixed_program_and_sanitized_report(self):
        value = successful_report(); modules = self.fake_modules(); captured = {}
        def runner(command, environment, directory):
            captured.update(command=command, environment=environment)
            key_path = Path(command[command.index('-i') + 1]); self.assertEqual(key_path.read_bytes(), b'PRIVATE_SYNTHETIC_PPK')
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertLess(len(command[-1].encode()), transport.MAX_ARGUMENT)
            return 'success', operation._encoded(value), True
        with patch.object(transport, '_module', side_effect=lambda name: modules[name]): result = transport.probe(self.transport_env(), runner=runner)
        self.assertEqual(result['status'], 'success'); self.assertNotIn('PRIVATE_SYNTHETIC_PPK', json.dumps(result))
        self.assertIn('-noagent', captured['command']); self.assertNotIn('QUANTA_OCI_PPK', captured['environment'])

    def test_transport_rejects_mismatched_request_before_key_use_and_secret_output(self):
        modules = self.fake_modules({**request(), 'source_sha': CONTROL}); called = unittest.mock.Mock()
        with patch.object(transport, '_module', side_effect=lambda name: modules[name]):
            self.assertEqual(transport.probe(self.transport_env(), runner=called)['status'], 'configuration_invalid')
        called.assert_not_called()
        modules = self.fake_modules()
        with patch.object(transport, '_module', side_effect=lambda name: modules[name]):
            result = transport.probe(self.transport_env(), runner=lambda *_: ('success', b'{"password":"secret"}', True))
        self.assertEqual(result['status'], 'invalid_output'); self.assertNotIn('secret', json.dumps(result))

    def test_workflow_checks_both_ci_pins_before_ssh_credentials_and_shares_existing_lock(self):
        workflow = (ROOT / '.github/workflows/oci-accounts.yml').read_text()
        self.assertLess(workflow.index('authorize_accounts_upgrade.py'), workflow.index('secrets.QUANTA_OCI_PPK'))
        self.assertIn('group: quanta-oci-installation', workflow)
        self.assertIn('accounts-request.json', workflow)
        pinned = re.search(r'          ref: (CONTROL_SHA_LITERAL|[0-9a-f]{40})', workflow)
        self.assertIsNotNone(pinned)
        sha_pins = re.findall(r"QUANTA_ACCOUNTS_CONTROL_SHA: '(CONTROL_SHA_LITERAL|[0-9a-f]{40})'", workflow)
        ci_pins = re.findall(r"QUANTA_ACCOUNTS_CONTROL_CI_RUN: '(CONTROL_CI_LITERAL|[1-9][0-9]{0,18})'", workflow)
        self.assertEqual(sha_pins, [pinned[1]] * 2)
        self.assertEqual(len(ci_pins), 2); self.assertEqual(ci_pins[0], ci_pins[1])
        self.assertNotIn('QUANTA_OWNER_TOKEN:', workflow)


class WatchdogExecutionTests(unittest.TestCase):
    @contextmanager
    def sandbox(self, *, state='switching', have_journal=True, foreign=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            saved = journal(); saved['status'] = state
            journal_path = root / 'accounts-upgrade.json'
            lock_path = root / 'accounts.lock'; lock_path.write_bytes(b''); lock_path.chmod(0o600)
            if have_journal:
                journal_path.write_bytes(operation._encoded(saved)); journal_path.chmod(0o600)
            for name in ('deployment', 'installed'):
                path = root / (name + '.json')
                path.write_bytes(b'foreign-operator-change' if foreign and name == 'deployment' else base64.b64decode(saved['new_' + name]))
                path.chmod(0o600)
            source = operation._watchdog_source().decode().replace(
                "pathlib.Path('/etc/quanta/accounts-upgrade.json')", 'pathlib.Path(' + repr(str(journal_path)) + ')').replace(
                "pathlib.Path('/run/quanta-accounts-upgrade.lock')", 'pathlib.Path(' + repr(str(lock_path)) + ')')
            original_lstat, original_fstat = Path.lstat, os.fstat
            def rootlike(info):
                fields = list(info); fields[4] = fields[5] = 0
                if stat.S_ISDIR(fields[0]): fields[0] &= ~0o022
                return os.stat_result(fields)
            calls = []
            def ctl(command, **kwargs):
                self.assertEqual(command[0], '/usr/bin/systemctl')
                calls.append(command[1:]); return types.SimpleNamespace(returncode=0)
            with patch.object(Path, 'lstat', lambda path: rootlike(original_lstat(path))), patch.object(os, 'fstat', lambda fd: rootlike(original_fstat(fd))), patch.object(subprocess, 'run', side_effect=ctl):
                yield root, saved, source, calls

    def test_switching_watchdog_restores_actual_private_files_and_marks_rollback(self):
        with self.sandbox() as (root, saved, source, calls):
            exec(compile(source, '<fixed-watchdog-sandbox>', 'exec'), {})
            self.assertEqual((root / 'deployment.json').read_bytes(), base64.b64decode(saved['old_deployment']))
            self.assertEqual((root / 'installed.json').read_bytes(), base64.b64decode(saved['old_installed']))
            self.assertEqual(json.loads((root / 'accounts-upgrade.json').read_bytes())['status'], 'rolled_back')
            self.assertEqual(calls[0], ['stop', operation.APP])
            self.assertEqual(calls[1], ['start', operation.APP, operation.HTTPS, operation.TIMER])
            for name in ('deployment.json', 'installed.json', 'accounts-upgrade.json'):
                self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o600)

    def test_completed_watchdog_leaves_new_configuration_and_services_untouched(self):
        with self.sandbox(state='complete') as (root, saved, source, calls):
            before = (root / 'deployment.json').read_bytes()
            exec(compile(source, '<fixed-watchdog-sandbox>', 'exec'), {})
            self.assertEqual(calls, []); self.assertEqual((root / 'deployment.json').read_bytes(), before)

    def test_watchdog_before_journal_only_starts_existing_fixed_services(self):
        with self.sandbox(have_journal=False) as (root, saved, source, calls):
            before = (root / 'deployment.json').read_bytes()
            with self.assertRaises(SystemExit) as stopped: exec(compile(source, '<fixed-watchdog-sandbox>', 'exec'), {})
            self.assertEqual(stopped.exception.code, 0)
            self.assertEqual(calls, [['start', operation.APP, operation.HTTPS, operation.TIMER]])
            self.assertEqual((root / 'deployment.json').read_bytes(), before)

    def test_watchdog_refuses_a_concurrent_operator_configuration_change(self):
        with self.sandbox(foreign=True) as (root, saved, source, calls):
            with self.assertRaises(ValueError): exec(compile(source, '<fixed-watchdog-sandbox>', 'exec'), {})
            self.assertEqual(calls, []); self.assertEqual((root / 'deployment.json').read_bytes(), b'foreign-operator-change')


    def test_watchdog_preserves_operator_change_triggered_by_stop(self):
        with self.sandbox() as (root, saved, source, calls):
            previous_run = subprocess.run
            def stopping_change(command, **kwargs):
                result = previous_run(command, **kwargs)
                if command[1:] == ['stop', operation.APP]:
                    (root / 'installed.json').write_bytes(b'operator-change-after-stop')
                return result
            with patch.object(subprocess, 'run', side_effect=stopping_change):
                with self.assertRaises(ValueError): exec(compile(source, '<fixed-watchdog-sandbox>', 'exec'), {})
            self.assertEqual((root / 'installed.json').read_bytes(), b'operator-change-after-stop')
            self.assertEqual((root / 'deployment.json').read_bytes(), base64.b64decode(saved['new_deployment']))
            self.assertEqual(calls, [['stop', operation.APP], ['start', operation.APP, operation.HTTPS, operation.TIMER]])
            self.assertEqual(json.loads((root / 'accounts-upgrade.json').read_bytes())['status'], 'switching')

    def test_watchdog_recovers_link_publication_kill_window(self):
        with self.sandbox() as (root, saved, source, calls):
            os.link(root / 'accounts-upgrade.json', root / '.accounts-upgrade.publish')
            exec(compile(source, '<fixed-watchdog-sandbox>', 'exec'), {})
            self.assertEqual((root / 'deployment.json').read_bytes(), base64.b64decode(saved['old_deployment']))
            self.assertEqual(json.loads((root / 'accounts-upgrade.json').read_bytes())['status'], 'rolled_back')


class JournalPublicationTests(unittest.TestCase):
    @contextmanager
    def root_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_lstat, original_fstat = os.lstat, os.fstat
            def rootlike(info):
                values = list(info); values[4] = values[5] = 0
                return os.stat_result(values)
            with patch.object(operation, 'ETC', root), patch.object(operation, 'JOURNAL', root / 'accounts-upgrade.json'), patch.object(operation, 'JOURNAL_STAGING', root / '.accounts-upgrade.publish'), patch.object(operation, '_parents'), patch.object(os, 'lstat', lambda path, *a, **kw: rootlike(original_lstat(path, *a, **kw))), patch.object(os, 'fstat', lambda descriptor: rootlike(original_fstat(descriptor))):
                yield root

    def test_publish_exposes_only_complete_fsynced_bytes_with_no_replace(self):
        with self.root_sandbox() as root:
            value = journal(); expected = operation._encoded(value)
            original_link, original_sync = os.link, os.fsync
            synced = []
            def sync(descriptor):
                original_sync(descriptor)
                synced.append(stat.S_ISREG(os.fstat(descriptor).st_mode))
            def link(source, target, **kwargs):
                self.assertFalse(operation.JOURNAL.exists())
                self.assertEqual(Path(source).read_bytes(), expected)
                self.assertIn(True, synced)
                original_link(source, target, **kwargs)
                self.assertEqual(operation._journal_bytes(), expected)
            with patch.object(os, 'fsync', side_effect=sync), patch.object(os, 'link', side_effect=link):
                operation._write_journal(value)
            self.assertEqual(operation._journal(), value)
            self.assertEqual(operation.JOURNAL.stat().st_nlink, 1)
            self.assertFalse(operation.JOURNAL_STAGING.exists())
            self.assertEqual(stat.S_IMODE(operation.JOURNAL.stat().st_mode), 0o600)

    def test_partial_write_interruption_never_publishes_a_malformed_final_journal(self):
        with self.root_sandbox() as root:
            original = os.fdopen
            class InterruptedWriter:
                def __init__(self, descriptor): self.stream = original(descriptor, 'wb')
                def __enter__(self): return self
                def __exit__(self, *args): return self.stream.__exit__(*args)
                def fileno(self): return self.stream.fileno()
                def write(self, raw):
                    self.stream.write(raw[:len(raw) // 2]); self.stream.flush()
                    raise InterruptedError('synthetic partial journal write')
            with patch.object(os, 'fdopen', side_effect=lambda descriptor, mode: InterruptedWriter(descriptor) if mode == 'wb' else original(descriptor, mode)):
                with self.assertRaises(InterruptedError): operation._write_journal(journal())
            self.assertFalse(operation.JOURNAL.exists()); self.assertFalse(operation.JOURNAL_STAGING.exists())

    def test_existing_journal_or_staging_is_never_overwritten_or_removed(self):
        for name in ('accounts-upgrade.json', '.accounts-upgrade.publish'):
            with self.subTest(name=name), self.root_sandbox() as root:
                path = root / name; path.write_bytes(b'operator-owned-existing'); path.chmod(0o600)
                with self.assertRaises(FileExistsError): operation._write_journal(journal())
                self.assertEqual(path.read_bytes(), b'operator-owned-existing')

    def test_link_publication_kill_window_is_readable_only_for_exact_private_sibling(self):
        with self.root_sandbox() as root:
            raw = operation._encoded(journal())
            operation.JOURNAL_STAGING.write_bytes(raw); operation.JOURNAL_STAGING.chmod(0o600)
            os.link(operation.JOURNAL_STAGING, operation.JOURNAL)
            self.assertEqual(operation._journal(), journal())
            operation._journal_status(journal(), 'rolled_back')
            self.assertEqual(operation._journal()['status'], 'rolled_back')
        with self.root_sandbox() as root:
            operation.JOURNAL.write_bytes(operation._encoded(journal())); operation.JOURNAL.chmod(0o600)
            os.link(operation.JOURNAL, root / 'unrelated-hardlink')
            with self.assertRaises((FileNotFoundError, operation.UpgradeError)): operation._journal()

    def test_status_update_never_adopts_a_different_current_journal(self):
        with self.root_sandbox() as root:
            changed = {**journal(), 'status': 'complete'}
            operation._write_journal(changed)
            with self.assertRaises(operation.UpgradeError): operation._journal_status(journal(), 'rolled_back')
            self.assertEqual(operation._journal(), changed)

    def test_restore_preserves_operator_change_triggered_during_service_stop(self):
        with self.root_sandbox() as root:
            value = journal()
            for name in ('deployment', 'installed'):
                path = root / (name + '.json'); path.write_bytes(base64.b64decode(value['new_' + name])); path.chmod(0o600)
            def stop_changes(command, **kwargs):
                if command == ['/usr/bin/systemctl', 'stop', operation.APP]:
                    (root / 'deployment.json').write_bytes(b'operator-change-during-stop')
            with patch.object(operation, '_quiet', side_effect=stop_changes) as quiet, patch.object(operation, '_replace') as replace, patch.object(operation, '_journal_status') as status:
                with self.assertRaises(operation.UpgradeError): operation._restore(value)
                replace.assert_not_called(); status.assert_not_called()
                self.assertIn(unittest.mock.call(['/usr/bin/systemctl', 'start', operation.APP, operation.HTTPS, operation.TIMER], timeout=60), quiet.call_args_list)
            self.assertEqual((root / 'deployment.json').read_bytes(), b'operator-change-during-stop')
            self.assertEqual((root / 'installed.json').read_bytes(), base64.b64decode(value['new_installed']))

    def test_unpublished_journal_failure_resumes_original_services_without_a_fake_rollback_failure(self):
        with fake_upgrade() as mocks:
            mocks['_write_journal'].side_effect = InterruptedError('synthetic partial temporary write')
            mocks['_journal'].side_effect = FileNotFoundError()
            value = operation.run(config(), 'upgrade-accounts')
            self.assertEqual(value['status'], 'failed'); self.assertTrue(value['rollback_succeeded'])
            self.assertFalse(value['private_journal_saved']); self.assertFalse(value['configuration_switched'])
            mocks['_restore'].assert_not_called(); mocks['_replace'].assert_not_called()

    def test_visible_complete_marker_after_fsync_error_does_not_restore_old_app(self):
        with fake_upgrade() as mocks:
            def commit_then_fail(value, status):
                mocks['_journal'].return_value = {**value, 'status': status}
                raise OSError('synthetic directory fsync failure after commit')
            mocks['_journal_status'].side_effect = commit_then_fail
            value = operation.run(config(), 'upgrade-accounts')
            self.assertEqual(value['status'], 'failed'); self.assertTrue(value['commit_visible_after_error'])
            self.assertFalse(value['rollback_attempted']); mocks['_restore'].assert_not_called()
            operation.validate_report(value)

    def test_legacy_builder_selection_is_local_to_the_bounded_build_call(self):
        fake = types.SimpleNamespace(returncode=0)
        with patch.object(subprocess, 'run', return_value=fake) as run:
            operation._quiet(['/usr/bin/docker', 'build'], build=True)
            self.assertEqual(run.call_args.kwargs['env']['DOCKER_BUILDKIT'], '0')
            operation._quiet(['/usr/bin/systemctl', 'show'])
            self.assertNotIn('DOCKER_BUILDKIT', run.call_args.kwargs['env'])
        with patch.object(operation, '_capture', side_effect=[b'', (NEW_IMAGE + ' arm64 linux\n').encode()]), patch.object(operation, '_file', return_value=b'MemAvailable: 8000000 kB\n'), patch.object(operation.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=20 * 1024**3)), patch.object(operation, '_quiet') as quiet:
            operation._build(config(), Path('/synthetic/source'))
            self.assertTrue(quiet.call_args.kwargs['build'])
            command = quiet.call_args.args[0]
            for argument in ('--memory', '--memory-swap', '--cpu-period', '--cpu-quota', '--cpuset-cpus'):
                self.assertIn(argument, command)


class GmailTlsObservationTests(unittest.TestCase):
    def sockets(self, chunks):
        connection = unittest.mock.MagicMock()
        connection.__enter__.return_value = connection
        secure = unittest.mock.MagicMock()
        secure.__enter__.return_value = secure
        secure.recv.side_effect = chunks
        return connection, secure

    def test_fixed_gmail_tls_uses_default_certificate_validation_sni_and_no_smtp_commands(self):
        connection, secure = self.sockets([b'220 smtp.gmail', b'.com ESMTP ready\r\n'])
        context = operation.ssl.create_default_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, operation.ssl.CERT_REQUIRED)
        report = operation._initial('verify-accounts')
        with patch.object(operation.ssl, 'create_default_context', return_value=context), patch.object(context, 'wrap_socket', return_value=secure) as wrap, patch.object(operation.socket, 'create_connection', return_value=connection) as connect:
            operation._gmail_smtp_tls(report)
        connect.assert_called_once_with(('smtp.gmail.com', 465), timeout=5)
        wrap.assert_called_once_with(connection, server_hostname='smtp.gmail.com')
        secure.settimeout.assert_called_once_with(5)
        self.assertTrue(report['gmail_smtp_tls_checked']); self.assertTrue(report['gmail_smtp_tls_ready'])
        for endpoint in (connection, secure):
            endpoint.send.assert_not_called(); endpoint.sendall.assert_not_called(); endpoint.write.assert_not_called()
        self.assertFalse(report['actual_email_delivery_verified']); self.assertFalse(report['mail_delivery_verified'])

    def test_unavailable_outbound_tls_does_not_fail_an_otherwise_healthy_verify(self):
        actual_probe = operation._gmail_smtp_tls
        with fake_upgrade(), patch.object(operation, '_gmail_smtp_tls', side_effect=actual_probe), patch.object(operation.socket, 'create_connection', side_effect=OSError('synthetic unavailable network')):
            report = operation.run(config(), 'verify-accounts')
        self.assertEqual(report['status'], 'success')
        self.assertTrue(report['gmail_smtp_tls_checked']); self.assertFalse(report['gmail_smtp_tls_ready'])
        self.assertFalse(report['actual_email_delivery_verified']); self.assertFalse(report['mail_delivery_verified'])
        operation.validate_report(report)

    def test_greeting_is_bounded_and_wrong_or_unterminated_status_is_not_ready(self):
        for chunks in ([b'500 wrong greeting\r\n'], [b'x' * 64] * 8):
            with self.subTest(chunks=len(chunks)):
                connection, secure = self.sockets(chunks)
                context = operation.ssl.create_default_context()
                report = operation._initial('verify-accounts')
                with patch.object(operation.ssl, 'create_default_context', return_value=context), patch.object(context, 'wrap_socket', return_value=secure), patch.object(operation.socket, 'create_connection', return_value=connection):
                    operation._gmail_smtp_tls(report)
                self.assertTrue(report['gmail_smtp_tls_checked']); self.assertFalse(report['gmail_smtp_tls_ready'])
                self.assertLessEqual(secure.recv.call_count, 8)
                self.assertTrue(all(1 <= call.args[0] <= 64 for call in secure.recv.call_args_list))


if __name__ == '__main__':
    unittest.main()
