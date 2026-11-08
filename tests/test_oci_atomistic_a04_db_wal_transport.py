"""Fixed, reviewed transport for the read-only A04 DB/WAL diagnostic."""
import base64
import importlib.util
import json
from pathlib import Path
import shlex
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
import zlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('a04_db_wal_test_relay', ROOT / 'deploy/oci/probe_atomistic_a04_db_wal.py')
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.ci_run = 1000
        self.request = {'schema_version': 1, 'operation': relay.OPERATION,
                        'source_sha': self.sha, 'request_id': '29dd8452-6734-4d06-87bf-00f083d668e3'}
        self.env = {'GITHUB_REPOSITORY': 'Hyunwoo1205/quanta', 'GITHUB_REF': 'refs/heads/ops/oci',
                    'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1',
                    relay.PREFIX + '_CONTROL_SHA': self.sha,
                    relay.PREFIX + '_CONTROL_CI_RUN': str(self.ci_run)}
        self.base = relay.shared.module('authorize_application_upgrade')
        self.evidence = {}
        for run_id, sha, workflow, names in (
                (self.ci_run, self.sha, relay.CONTROL_WORKFLOW, relay.CONTROL_JOBS),
                (relay.BASELINE_CI_RUN, relay.BASELINE_SHA, self.base.APP_WORKFLOW, self.base.APP_JOB_NAMES)):
            path = f'/actions/runs/{run_id}'
            self.evidence[path] = {'id': run_id, 'head_sha': sha, 'head_branch': 'main', 'event': 'push',
                                   'path': workflow, 'status': 'completed', 'conclusion': 'success'}
            self.evidence[path + '/jobs?filter=latest&per_page=100'] = {'total_count': 2, 'jobs': [
                {'id': index + 1, 'run_id': run_id, 'name': name, 'status': 'completed', 'conclusion': 'success'}
                for index, name in enumerate(sorted(names))]}
        self.ancestor = True
        self.changed_paths = set(relay.ALLOWED_FILES)
        self.dirty = False

    def git(self, args, **_kwargs):
        self.assertEqual(args[:3], ['/usr/bin/git', '-C', str(relay.ROOT)])
        if args[3:] == ['rev-parse', '--verify', 'HEAD']:
            return CompletedProcess(args, 0, (self.sha + '\n').encode('ascii'))
        if args[3:] == ['diff', '--quiet', '--no-ext-diff', '--no-textconv', 'HEAD', '--']:
            return CompletedProcess(args, int(self.dirty))
        if args[3:] == ['merge-base', '--is-ancestor', relay.BASELINE_SHA, self.sha]:
            return CompletedProcess(args, int(not self.ancestor))
        self.assertEqual(args[3:], ['diff', '--name-only', '--no-renames', '--no-ext-diff', '--no-textconv',
                                    '-z', relay.BASELINE_SHA, self.sha, '--'])
        return CompletedProcess(args, 0, ''.join(path + '\x00' for path in sorted(self.changed_paths)).encode('utf-8'))

    def authorize(self, *, env=None, raw=None):
        with TemporaryDirectory() as directory:
            request = Path(directory) / 'request.json'
            request.write_text(json.dumps(self.request) if raw is None else raw, encoding='utf-8')
            with patch.object(relay.shared, 'module', return_value=self.base), patch.object(
                    self.base, 'api_get', side_effect=lambda suffix, _env, **_kwargs: self.evidence[suffix]):
                return relay.authorize(self.env if env is None else env, path=request, runner=self.git)

    def test_exact_source_ci_and_full_baseline_authorize(self):
        result = self.authorize()
        self.assertEqual(result, {'scope': 'atomistic_a04_db_wal_request', 'status': 'authorized', **self.request,
                                  'control_sha': self.sha, 'control_ci_run': self.ci_run,
                                  'baseline_ci_run': relay.BASELINE_CI_RUN})

    def test_request_rejects_retry_other_operation_and_duplicate_key(self):
        self.assertEqual(self.authorize(env=dict(self.env, GITHUB_RUN_ATTEMPT='2'))['stage'], 'request')
        self.assertEqual(self.authorize(raw=json.dumps(dict(self.request, operation='benchmark-atomistic-a04')))
                         ['stage'], 'request')
        duplicate = json.dumps(self.request)[:-1] + ',"source_sha":"' + self.sha + '"}'
        self.assertEqual(self.authorize(raw=duplicate)['stage'], 'request')

    def test_control_diff_requires_clean_checkout_ancestry_and_scope(self):
        self.dirty = True
        self.assertEqual(self.authorize()['stage'], 'control_checkout')
        self.dirty = False
        self.ancestor = False
        self.assertEqual(self.authorize()['stage'], 'control_scope')
        self.ancestor = True
        self.changed_paths.add('deploy/oci/diagnose_atomistic_image.py')
        self.assertEqual(self.authorize()['stage'], 'control_scope')

    def test_incorrect_diagnostic_source_or_baseline_job_denies(self):
        path = f'/actions/runs/{self.ci_run}'
        self.evidence[path]['head_sha'] = 'b' * 40
        self.assertEqual(self.authorize()['stage'], 'control_ci')
        self.evidence[path]['head_sha'] = self.sha
        path = f'/actions/runs/{relay.BASELINE_CI_RUN}/jobs?filter=latest&per_page=100'
        self.evidence[path]['jobs'][0]['conclusion'] = 'skipped'
        self.assertEqual(self.authorize()['stage'], 'baseline_ci')

    def test_failed_reauthorization_does_not_use_the_key_or_ssh(self):
        env = dict(self.env, QUANTA_OCI_AUTH_CONFIRMED='true')
        env.update({relay.PREFIX + '_OPERATION': relay.OPERATION})
        runner = Mock()
        with patch.object(relay, 'authorize', return_value=relay._denied('control_scope')):
            report = relay.probe(env, runner=runner)
        self.assertEqual(report['status'], 'configuration_invalid')
        self.assertIs(report['authentication_attempted'], False)
        runner.assert_not_called()

    def test_command_binds_the_exact_remote_program_and_request(self):
        cfg = {'source_sha': self.sha, 'control_sha': self.sha, 'request_id': self.request['request_id']}
        source = relay._remote_source()
        cmd = relay.shared.remote_command(source, cfg, policy=relay._policy(self.sha))
        args = shlex.split(cmd)
        self.assertEqual(args[:6], ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', '-c'])
        self.assertEqual(zlib.decompress(base64.b64decode(args[-2])).decode('utf-8'), source)
        self.assertEqual(json.loads(base64.b64decode(args[-1])), cfg)
        self.assertLess(len(cmd.encode('utf-8')), 120000)


if __name__ == '__main__':
    unittest.main()
