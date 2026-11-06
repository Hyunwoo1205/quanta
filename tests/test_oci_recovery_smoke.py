"""Post-reboot smoke uses synthetic credentials and bounded local fixtures."""
from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load('quanta_smoke_helper_test', ROOT / 'deploy/oci/verify_backup.py')
with patch.dict(sys.modules, {'quanta_fixed_backup': helper}):
    operation = load('quanta_smoke_test', ROOT / 'deploy/oci/recovery_smoke.py')

OLD_BOOT = '11111111-2222-4333-8444-555555555555'
BOOT = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
SOURCE = '12345678-1234-4234-8234-123456789abc'
REVISION = '23456789-2345-4345-8345-23456789abcd'
RUN = '3456789a-3456-4456-8456-3456789abcde'
TOKEN = 'e' * 64
VALUES = (3.999999999999998e-21, [[3.9999999999999985e-11, 0.0, 0.0], [-3.9999999999999985e-11, 0.0, 0.0]])


def config():
    return {'source_sha': operation.SOURCE_SHA, 'public_origin': 'https://app.example.net', 'auth_mode': 'owner-token'}


def summary(status='SUCCEEDED'):
    return {'run_id': RUN, 'revision_id': REVISION, 'replay_of': SOURCE, 'execution_status': status}


def result(run_id=RUN, replay_of=SOURCE):
    return {'run_id': run_id, 'revision_id': REVISION, 'execution_status': 'SUCCEEDED',
            'physical_validation_status': 'unvalidated', 'provenance': {'replay_of': replay_of},
            'steps': [{'module_id': 'quanta.pair_static', 'module_version': '0.1.0', 'outcome': 'SUCCEEDED',
                       'partial': False, 'payload': {'operation': 'energy_forces', 'energy_j': VALUES[0], 'forces_n': VALUES[1]}}]}


@contextlib.contextmanager
def fake_flow(responses=None):
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(operation, '_preflight', return_value=(BOOT, TOKEN)))
        stack.enter_context(patch.object(operation, '_source_run', return_value=(SOURCE, REVISION, VALUES)))
        stack.enter_context(patch.object(helper, '_deadline', side_effect=lambda n: contextlib.nullcontext()))
        request = stack.enter_context(patch.object(operation, '_request', side_effect=responses or [summary('QUEUED'), summary(), result()]))
        yield request


@contextlib.contextmanager
def simulated_identity(fail=None):
    state = {'uid': 0, 'gid': 77}
    calls = []
    def change(kind, value):
        calls.append((kind, value))
        if fail == (kind, value):
            raise PermissionError('synthetic identity failure')
        state[kind] = value
    with patch.object(operation.os, 'getuid', return_value=0), \
            patch.object(operation.os, 'geteuid', side_effect=lambda: state['uid']), \
            patch.object(operation.os, 'getegid', side_effect=lambda: state['gid']), \
            patch.object(operation.os, 'seteuid', side_effect=lambda value: change('uid', value)), \
            patch.object(operation.os, 'setegid', side_effect=lambda value: change('gid', value)):
        yield state, calls


class SmokeTests(unittest.TestCase):
    def test_existing_exact_config_and_invalid_inputs_never_submit(self):
        self.assertEqual(operation.validate_config(config()), config())
        for value in ({}, {**config(), 'command': 'anything'}, {**config(), 'source_sha': 'a' * 40},
                      {**config(), 'public_origin': 'http://app.example.net'}):
            with patch.object(operation, '_request') as request:
                self.assertEqual(operation.run(value)['stage'], 'configuration')
                request.assert_not_called()

    def test_success_is_one_new_replay_same_revision_source_and_fixed_reference(self):
        with fake_flow() as request:
            value = operation.run(config())
        self.assertEqual(value['status'], 'success')
        self.assertEqual(value['run_id'], RUN)
        self.assertTrue(all(value[field] for field in operation.BOOLEANS))
        self.assertEqual(value['physical_validation_status'], 'unvalidated')
        self.assertEqual(value['energy_j'], VALUES[0])
        self.assertEqual(len(request.call_args_list), 3)
        post = request.call_args_list[0]
        self.assertEqual(post.args, (config(), TOKEN, 'POST', '/v1/runs/' + SOURCE + '/replay'))
        expected = str(uuid.uuid5(uuid.NAMESPACE_URL, 'quanta:post-reboot-compute:' + BOOT + ':' + SOURCE))
        self.assertEqual(post.kwargs, {'key': expected})
        with fake_flow() as retry:
            self.assertEqual(operation.run(config())['run_id'], RUN)
        self.assertEqual(retry.call_args_list[0].kwargs, post.kwargs)

    def test_source_link_revision_and_terminal_failures_are_not_success(self):
        cases = [
            [{'run_id': SOURCE, 'revision_id': REVISION, 'replay_of': SOURCE}],
            [{**summary(), 'revision_id': SOURCE}],
            [summary('QUEUED'), summary('CANCELLED')],
            [summary('QUEUED'), {**summary(), 'replay_of': REVISION}],
            [summary('QUEUED'), summary(), {**result(), 'physical_validation_status': 'validated'}],
            [summary('QUEUED'), summary(), {**result(), 'revision_id': SOURCE}],
            [summary('QUEUED'), summary(), result(replay_of=REVISION)],
        ]
        for responses in cases:
            with self.subTest(case=responses), fake_flow(responses):
                self.assertEqual(operation.run(config())['status'], 'failed')

    def test_numeric_reference_shape_nonfinite_and_large_integer_rejection(self):
        self.assertTrue(operation._reference_matches(VALUES))
        for energy in (float('nan'), float('inf'), True, 10**1000, 8e-21):
            data = result()
            data['steps'][0]['payload'] = {'operation': 'energy_forces', 'energy_j': energy, 'forces_n': VALUES[1]}
            with self.subTest(energy_type=type(energy).__name__), fake_flow([summary(), summary(), data]):
                self.assertFalse(operation.run(config())['new_calculation_verified'])
        for forces in ([[1.0, 2.0, 3.0]], [[1, 2], [3, 4]], [[float('nan'), 0, 0], [0, 0, 0]]):
            data = result()
            data['steps'][0]['payload'] = {'operation': 'energy_forces', 'energy_j': VALUES[0], 'forces_n': forces}
            with fake_flow([summary(), summary(), data]):
                self.assertEqual(operation.run(config())['failure_reason'], 'result_mismatch')

    def test_poll_timeout_has_no_retry_submission_and_no_invented_result(self):
        with fake_flow([summary('QUEUED'), summary('RUNNING')]) as request, \
                patch.object(operation.time, 'monotonic', side_effect=[0, operation.POLL_SECONDS + 1]):
            value = operation.run(config())
        self.assertEqual(value['failure_reason'], 'replay_not_completed')
        self.assertEqual(value['run_id'], RUN)
        self.assertIsNone(value['energy_j'])
        self.assertFalse(value['new_calculation_verified'])
        self.assertEqual(sum(call.args[2] == 'POST' for call in request.call_args_list), 1)

    def test_exact_public_report_disallows_secrets_unbounded_junk_and_scope_inflation(self):
        with fake_flow():
            good = operation.run(config())
        self.assertEqual(operation.sanitize_report(json.dumps(good).encode()), good)
        bad_values = [{**good, 'token': TOKEN}, {**good, 'status': []}, {**good, 'stage': []},
                      {**good, 'failure_reason': []}, {**good, 'energy_j': float('nan')},
                      {**good, 'energy_j': 8e-21},
                      {**good, 'physical_validation_status': 'validated'}, {**good, 'run_id': 'PRIVATE'}]
        for field in operation.BOOLEANS:
            bad_values.append({**good, field: 1})
        for value in bad_values:
            with self.subTest(keys=list(value)):
                self.assertIsNone(operation.sanitize_report(json.dumps(value).encode()))
        for raw in (b'', b'\xff', b'x' * 8193, json.dumps(good).encode() + b'PRIVATE',
                    json.dumps(good).encode()[:-1] + b',"status":"success"}'):
            self.assertIsNone(operation.sanitize_report(raw))

    def test_http_stays_loopback_and_places_secret_only_in_authorization(self):
        response = types.SimpleNamespace(status=202, read=lambda n: json.dumps(summary('QUEUED')).encode())
        connection = unittest.mock.MagicMock()
        connection.getresponse.return_value = response
        with patch.object(operation.http.client, 'HTTPConnection', return_value=connection) as connect:
            self.assertEqual(operation._request(config(), TOKEN, 'POST', '/v1/runs/' + SOURCE + '/replay', key='fixed-idempotency'), summary('QUEUED'))
        connect.assert_called_once_with('127.0.0.1', 8765, timeout=3)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ('POST', '/v1/runs/' + SOURCE + '/replay'))
        self.assertEqual(kwargs['body'], b'{}')
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer ' + TOKEN)
        self.assertEqual(kwargs['headers']['Idempotency-Key'], 'fixed-idempotency')
        self.assertNotIn(TOKEN, args[1])
        connection.close.assert_called_once()
        for status, raw in ((401, b'PRIVATE'), (302, b''), (200, b'x' * (operation.MAX_HTTP_BYTES + 1))):
            response = types.SimpleNamespace(status=status, read=lambda n, raw=raw: raw)
            connection.getresponse.return_value = response
            with patch.object(operation.http.client, 'HTTPConnection', return_value=connection), self.assertRaises(Exception):
                operation._request(config(), TOKEN, 'GET', '/v1/runs/' + SOURCE)

    def test_preflight_requires_recent_baseline_changed_boot_and_exact_private_env(self):
        baseline = {'schema_version': 1, 'source_sha': operation.SOURCE_SHA, 'old_boot_id': OLD_BOOT,
                    'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
        env = ('QUANTA_PUBLIC_ORIGIN=' + config()['public_origin'] + '\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=' + TOKEN + '\n').encode()
        def reader(path, **kwargs):
            if path == operation.REBOOT_BASELINE:
                return json.dumps(baseline).encode()
            if path == operation.BOOT_ID:
                return (BOOT + '\n').encode()
            if path.name == 'app.env':
                return env
            return json.dumps(config()).encode()
        with patch.object(operation.os, 'geteuid', return_value=0), patch.object(helper, '_read_root', side_effect=reader):
            self.assertEqual(operation._preflight(config()), (BOOT, TOKEN))
            for mutation in ({'created_at': '2000-01-01T00:00:00Z'}, {'old_boot_id': BOOT}, {'source_sha': 'a' * 40}):
                original = dict(baseline)
                baseline.update(mutation)
                with self.assertRaises(Exception):
                    operation._preflight(config())
                baseline.clear(); baseline.update(original)
            for bad_env in (env + b'EXTRA=PRIVATE\n', env.replace(TOKEN.encode(), b'bad'), env.replace(b'owner-token', b'access')):
                saved = env
                env = bad_env
                with self.assertRaises(Exception):
                    operation._preflight(config())
                env = saved

    def test_schema2_supports_live_baseline_and_preserves_user_report_evidence_boundary(self):
        baseline = {'schema_version': 2, 'source_sha': operation.SOURCE_SHA, 'old_boot_id': OLD_BOOT,
                    'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'operation_id': '456789ab-4567-4567-8567-456789abcdef',
                    'database': {}, 'peers': {}, 'settings': {},
                    'database_basis': 'quiescent_live_store_before_os_reboot',
                    'backup_policy_basis': 'user_reported_oci_daily',
                    'backup_policy_console_verified': False}
        env = ('QUANTA_PUBLIC_ORIGIN=' + config()['public_origin'] + '\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=' + TOKEN + '\n').encode()
        def reader(path, **kwargs):
            if path == operation.REBOOT_BASELINE:
                return json.dumps(baseline).encode()
            if path == operation.BOOT_ID:
                return (BOOT + '\n').encode()
            if path.name == 'app.env':
                return env
            return json.dumps(config()).encode()
        with patch.object(operation.os, 'geteuid', return_value=0), patch.object(helper, '_read_root', side_effect=reader):
            self.assertEqual(operation._preflight(config()), (BOOT, TOKEN))
            cases = [{'backup_policy_console_verified': True}, {'backup_policy_console_verified': 0},
                     {'backup_policy_console_verified': None}, {'backup_policy_basis': 'agent_verified_oci_daily'},
                     {'database_basis': 'old_external_copy'}, {'operation_id': 'PRIVATE'}, {'database': []},
                     {'created_at': '2000-01-01T00:00:00Z'}, {'old_boot_id': BOOT},
                     {'schema_version': 3}, {'schema_version': True}, {'backup': {}}]
            for mutation in cases:
                original = dict(baseline)
                baseline.update(mutation)
                with self.subTest(mutation=mutation), self.assertRaises(Exception):
                    operation._preflight(config())
                baseline.clear(); baseline.update(original)
            del baseline['backup_policy_console_verified']
            with self.assertRaises(Exception):
                operation._preflight(config())

    def test_readonly_sqlite_chooses_oldest_supported_single_pair_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'jobs.sqlite3'
            connection = sqlite3.connect(path)
            connection.execute('CREATE TABLE runs(seq INTEGER PRIMARY KEY, run_id TEXT, revision_id TEXT, owner TEXT, status TEXT, report TEXT)')
            unsupported = result(run_id=SOURCE, replay_of=None)
            unsupported['steps'][0]['payload']['operation'] = 'relax'
            supported = result(run_id=SOURCE, replay_of=None)
            for seq, report in ((1, unsupported), (2, supported), (3, result())):
                connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', (seq, SOURCE if seq < 3 else RUN, REVISION, 'local', 'SUCCEEDED', json.dumps({'valid': True, 'result': report})))
            connection.commit(); connection.close()
            before = path.read_bytes()
            with patch.object(helper, 'DATA', Path(directory)), \
                    patch.object(operation, '_database_identity', side_effect=contextlib.nullcontext), \
                    patch.object(helper, '_private_file', side_effect=lambda p, d, **kw: p.stat()):
                self.assertEqual(operation._source_run(), (SOURCE, REVISION, VALUES))
            self.assertEqual(path.read_bytes(), before)

    def test_sqlite_identity_retains_real_root_and_restores_after_success_and_body_failure(self):
        for failure in (None, sqlite3.OperationalError('synthetic query failure'), helper.VerificationError()):
            with simulated_identity() as (state, calls):
                try:
                    with operation._database_identity():
                        self.assertEqual(state, {'uid': 10001, 'gid': 10001})
                        self.assertEqual(operation.os.getuid(), 0)
                        if failure is not None:
                            raise failure
                except Exception as caught:
                    self.assertIs(caught, failure)
                self.assertEqual(state, {'uid': 0, 'gid': 77})
                self.assertEqual(calls, [('gid', 10001), ('uid', 10001), ('uid', 0), ('gid', 77)])

    def test_sqlite_identity_partial_enter_and_nonroot_rejection_never_leak_identity(self):
        for failed_change in (('gid', 10001), ('uid', 10001)):
            with simulated_identity(fail=failed_change) as (state, calls), self.assertRaises(PermissionError):
                with operation._database_identity():
                    self.fail('partial identity change must not enter SQLite')
            self.assertEqual(state, {'uid': 0, 'gid': 77})
            self.assertEqual(calls[-2:], [('uid', 0), ('gid', 77)])
        for real, effective in ((10001, 10001), (10001, 0), (0, 10001)):
            with patch.object(operation.os, 'getuid', return_value=real), \
                    patch.object(operation.os, 'geteuid', return_value=effective), \
                    patch.object(operation.os, 'seteuid') as changed, self.assertRaises(operation.SmokeError):
                with operation._database_identity():
                    self.fail('nonroot caller must not enter SQLite')
            changed.assert_not_called()

    def test_real_alarm_deadline_restores_effective_identity_before_propagating(self):
        with simulated_identity() as (state, calls), self.assertRaises(helper.VerificationError):
            with helper._deadline(0.02):
                with operation._database_identity():
                    operation.time.sleep(0.2)
        self.assertEqual(state, {'uid': 0, 'gid': 77})
        self.assertEqual(calls[-2:], [('uid', 0), ('gid', 77)])

    def test_alarm_mask_covers_only_identity_transitions_and_preserves_previous_mask(self):
        alarm = operation.signal.SIGALRM
        previous = {operation.signal.SIGUSR1}
        mask = set(previous)
        changes = []
        def mask_call(how, requested):
            nonlocal mask
            original = set(mask)
            changes.append((how, set(requested)))
            mask = mask | set(requested) if how == operation.signal.SIG_BLOCK else set(requested)
            return original
        with simulated_identity() as (state, calls):
            uid_change, gid_change = operation.os.seteuid, operation.os.setegid
            def change(function, value):
                self.assertIn(alarm, mask)
                return function(value)
            with patch.object(operation.signal, 'pthread_sigmask', side_effect=mask_call), \
                    patch.object(operation.os, 'seteuid', side_effect=lambda value: change(uid_change, value)), \
                    patch.object(operation.os, 'setegid', side_effect=lambda value: change(gid_change, value)):
                with operation._database_identity():
                    self.assertEqual(mask, previous)
                    self.assertNotIn(alarm, mask)
                    self.assertEqual(state, {'uid': 10001, 'gid': 10001})
            self.assertEqual(mask, previous)
            self.assertEqual(state, {'uid': 0, 'gid': 77})
            self.assertEqual(changes, [(operation.signal.SIG_BLOCK, {alarm}),
                (operation.signal.SIG_SETMASK, previous), (operation.signal.SIG_BLOCK, {alarm}),
                (operation.signal.SIG_SETMASK, previous)])

    def test_sqlite_connect_query_and_deadline_failures_restore_root_and_close_as_app_uid(self):
        for failure_point in ('connect', 'query', 'deadline'):
            connection = unittest.mock.MagicMock()
            failure = sqlite3.OperationalError('query failed') if failure_point != 'deadline' else helper.VerificationError()
            with simulated_identity() as (state, calls), \
                    patch.object(operation.os, 'lstat', return_value=types.SimpleNamespace(st_dev=1)), \
                    patch.object(helper, '_private_file', return_value=types.SimpleNamespace(st_dev=1, st_ino=2)) as checked:
                def connect(*args, **kwargs):
                    self.assertEqual(state, {'uid': 10001, 'gid': 10001})
                    if failure_point == 'connect':
                        raise failure
                    return connection
                def execute(*args):
                    self.assertEqual(state, {'uid': 10001, 'gid': 10001})
                    raise failure
                connection.execute.side_effect = execute
                connection.close.side_effect = lambda: self.assertEqual(state, {'uid': 10001, 'gid': 10001})
                with patch.object(operation.sqlite3, 'connect', side_effect=connect), self.assertRaises(type(failure)):
                    operation._source_run()
                self.assertEqual(state, {'uid': 0, 'gid': 77})
                self.assertEqual(calls[-2:], [('uid', 0), ('gid', 77)])
                self.assertEqual(checked.call_count, 1)
                if failure_point == 'connect':
                    connection.close.assert_not_called()
                else:
                    connection.close.assert_called_once()

    def test_main_prints_only_sanitized_record_and_never_exception_or_secret(self):
        with patch.object(operation, '_perform', side_effect=Exception('PRIVATE-' + TOKEN)), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(operation.main([]), 2)
        self.assertNotIn('PRIVATE', output.getvalue())
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
