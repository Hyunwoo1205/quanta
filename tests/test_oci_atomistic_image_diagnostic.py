"""Unit checks of the fixed diagnostic; never contact a host or Docker."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'deploy/oci/diagnose_atomistic_image.py'
spec = importlib.util.spec_from_file_location('test_image_diagnostic', SOURCE)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.request_id = str(uuid.uuid4())
        self.control_sha = 'a' * 40
        self.request = {'schema_version': 1, 'operation': diag.OPERATION,
                        'source_sha': diag.SOURCE_SHA, 'request_id': self.request_id}
        self.cfg = {**{k: self.request[k] for k in ('source_sha', 'request_id')},
                    'control_sha': self.control_sha}
        self.env = {'GITHUB_REPOSITORY': diag.REPOSITORY, 'GITHUB_REF': 'refs/heads/ops/oci',
                    'GITHUB_EVENT_NAME': 'push', 'QUANTA_IMAGE_CONTROL_SHA': self.control_sha,
                    'QUANTA_IMAGE_CONTROL_CI_RUN': '12345', 'QUANTA_CI_READ_TOKEN': 'fixture'}
        self.image = {'Id': diag.IMAGE.split('@')[1], 'RepoDigests': [diag.IMAGE.removeprefix('docker.io/')],
                      'Architecture': 'arm64', 'Os': 'linux', 'RootFS': {'Type': 'layers', 'Layers': ['sha256:'+'c'*64]},
                      'Config': {'Entrypoint': ['/opt/cp2k/install/bin/launch'], 'WorkingDir': '/mnt'}}
        self.descriptor = {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                           'digest': self.image['Id'], 'size': 1234,
                           'platform': {'os': 'linux', 'architecture': 'arm64', 'variant': 'v8'}}

    def test_request_schema_and_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'request.json'
            path.write_bytes(diag.encoded(self.request))
            self.assertEqual(diag.read_request(path, self.env), self.request)
            for key, value in [('GITHUB_REPOSITORY', 'different/quanta'), ('GITHUB_REF', 'refs/heads/main'),
                               ('GITHUB_EVENT_NAME', 'pull_request')]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    diag.read_request(path, dict(self.env, **{key: value}))
            for change in ({'schema_version': True}, {'operation': 'benchmark-atomistic'}, {'source_sha': 'a'*40},
                           {'request_id': str(uuid.uuid1())}, {'request_id': '../bad'}, {'command': 'docker run'},
                           {'path': '/etc/quanta/app.env'}, {'image': 'quanta:latest'}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    path.write_bytes(diag.encoded(dict(self.request, **change)))
                    diag.read_request(path, self.env)
            path.write_bytes(diag.encoded(self.request)[:-1] + b',"schema_version":1}')
            with self.assertRaises(ValueError):
                diag.read_request(path, self.env)
            path.write_bytes(b' '*1025)
            with self.assertRaises(ValueError):
                diag.read_request(path, self.env)
            path.unlink()
            path.symlink_to('/nonexistent')
            with self.assertRaises(ValueError):
                diag.read_request(path, self.env)

    def test_three_exact_ci_gates_and_checkout(self):
        base = diag.module('authorize_application_upgrade')
        data = {}
        for run, sha, workflow, names in (
                (12345, self.control_sha, diag.CONTROL_WORKFLOW, diag.CONTROL_JOBS),
                (diag.SOURCE_CI, diag.SOURCE_SHA, base.APP_WORKFLOW, base.APP_JOB_NAMES),
                (diag.NATIVE_CI, diag.SOURCE_SHA, diag.NATIVE_WORKFLOW, diag.NATIVE_JOBS)):
            data['/actions/runs/'+str(run)] = {'id': run, 'head_sha': sha, 'head_branch': 'main',
                                              'event': 'push', 'path': workflow,
                                              'status': 'completed', 'conclusion': 'success'}
            data[f'/actions/runs/{run}/jobs?filter=latest&per_page=100'] = {
                'total_count': len(names), 'jobs': [{'id': i+1, 'run_id': run, 'name': n, 'status': 'completed',
                                                  'conclusion': 'success'} for i, n in enumerate(sorted(names))]}
        base.api_get = lambda suffix, *_args, **_kwargs: data[suffix]
        def checkout(mapped, *, runner, root):
            self.assertEqual(root, ROOT)
            return (mapped['QUANTA_APPLICATION_CONTROL_SHA'] == self.control_sha
                    and mapped['QUANTA_APPLICATION_CONTROL_CI_RUN'] == '12345')
        base.control_checkout_matches = checkout
        with tempfile.TemporaryDirectory() as tmp, patch.object(diag, 'module', return_value=base):
            path = Path(tmp) / 'request.json'
            path.write_bytes(diag.encoded(self.request))
            self.assertEqual(diag.authorize(self.env, path=path)['status'], 'authorized')
            for run, stage in [(12345, 'control_ci'), (diag.SOURCE_CI, 'source_ci'), (diag.NATIVE_CI, 'native_ci')]:
                with self.subTest(stage=stage):
                    job = data[f'/actions/runs/{run}/jobs?filter=latest&per_page=100']['jobs'][0]
                    job['conclusion'] = 'skipped'
                    self.assertEqual(diag.authorize(self.env, path=path)['stage'], stage)
                    job['conclusion'] = 'success'
                    run_value = data[f'/actions/runs/{run}']
                    old_sha = run_value['head_sha']
                    run_value['head_sha'] = 'd'*40
                    self.assertEqual(diag.authorize(self.env, path=path)['stage'], stage)
                    run_value['head_sha'] = old_sha
            base.control_checkout_matches = lambda *a, **k: False
            self.assertEqual(diag.authorize(self.env, path=path)['stage'], 'control_checkout')

    def remote_fixture(self, *, support_platform=True, changed=False, default_status='observed'):
        calls = []
        values = {diag.DEFAULT_COMMAND: self.image, diag.PLATFORM_COMMAND: self.image,
                  diag.DESCRIPTOR_COMMAND: self.descriptor, diag.PLATFORM_DESCRIPTOR_COMMAND: self.descriptor,
                  diag.SERVER_COMMAND: {'Version': '29.0.0', 'ApiVersion': '1.52',
                                        'MinAPIVersion': '1.44', 'Os': 'linux', 'Arch': 'arm64'},
                  diag.INFO_COMMAND: {'Driver': 'overlayfs', 'DriverStatus': [
                      ['driver-type', 'io.containerd.snapshotter.v1'], ['Data file', '/private/docker-path']]}}
        def run(cmd):
            calls.append(cmd)
            self.assertIn(cmd, diag.COMMANDS)
            if cmd == diag.SERVICE_COMMAND:
                return 'observed', b'active\nactive\n'
            if cmd == diag.CONTAINER_COMMAND:
                identity = b'b' if changed and calls.count(cmd) > 1 else b'a'
                return 'observed', identity*64+b' 123 sha256:'+b'd'*64+b' 2026-11-07T01:00:00.000Z true\n'
            if cmd == diag.HELP_COMMAND:
                return 'observed', b'Options:\n --platform string\n' if support_platform else b'Options:\n --format string\n'
            if cmd == diag.DEFAULT_COMMAND and default_status != 'observed':
                return default_status, b'fake secret error that must not appear'
            return 'observed', diag.encoded(values[cmd])
        lock = SimpleNamespace(parents=(SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0)),))
        lock_stat = SimpleNamespace(st_mode=stat.S_IFREG|0o600, st_uid=0, st_nlink=1)
        with patch.object(diag, 'LOCK', lock), patch.object(diag.os, 'geteuid', return_value=0), \
                patch.object(diag.platform, 'machine', return_value='aarch64'), \
                patch.object(diag.os, 'open', return_value=123) as op, \
                patch.object(diag.os, 'fstat', return_value=lock_stat), \
                patch.object(diag.os, 'close'), patch.object(diag.fcntl, 'flock'):
            receipt = diag.remote(self.cfg, run=run)
        self.assertEqual(op.call_args.args[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        return receipt, calls

    def test_readonly_diagnostic_preserves_observed_mismatch(self):
        receipt, calls = self.remote_fixture()
        self.assertEqual(receipt['status'], 'success')
        self.assertIs(receipt['observed_id_equals_expected_config'], False)
        self.assertIs(receipt['selected_repo_digest_present'], True)
        self.assertIs(receipt['production_container_preserved'], True)
        self.assertIs(receipt['database_read'], False)
        self.assertEqual(receipt['default_descriptor']['value'], self.descriptor)
        self.assertIn(diag.PLATFORM_COMMAND, calls)
        self.assertIn(diag.PLATFORM_DESCRIPTOR_COMMAND, calls)
        self.assertNotIn('/private/docker-path', diag.encoded(receipt).decode())
        self.assertEqual(diag.sanitize_report(diag.encoded(receipt)), receipt)
        for cmd in calls:
            self.assertFalse(set(cmd) & {'pull', 'run', 'create', 'start', 'stop', 'restart', 'rm', 'prune'})
        for cmd in (diag.DEFAULT_COMMAND, diag.PLATFORM_COMMAND, diag.DESCRIPTOR_COMMAND, diag.PLATFORM_DESCRIPTOR_COMMAND):
            self.assertEqual(cmd[-1], diag.IMAGE)
            self.assertNotIn('.Env', ' '.join(cmd))

    def test_optional_platform_and_failure_enums(self):
        receipt, calls = self.remote_fixture(support_platform=False)
        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(receipt['platform_inspect'], {'status': 'unsupported'})
        self.assertNotIn(diag.PLATFORM_COMMAND, calls)
        receipt, _ = self.remote_fixture(default_status='timeout')
        self.assertEqual(receipt['failure_reason'], 'diagnostic_incomplete')
        self.assertEqual(receipt['default_inspect'], {'status': 'timeout'})
        self.assertNotIn(b'secret error', diag.encoded(receipt))
        receipt, _ = self.remote_fixture(changed=True)
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['failure_reason'], 'production_changed')
        self.assertIs(receipt['production_container_preserved'], False)

    def test_secret_fields_and_unbounded_output_rejected(self):
        receipt, _ = self.remote_fixture()
        for location, key, value in (((), 'app_env', 'secret'),
                (('default_inspect', 'value', 'Config'), 'Env', ['TOKEN=secret']),
                (('default_descriptor', 'value'), 'annotations', {'secret': 'secret'}),
                (('docker_server', 'value'), 'RegistryConfig', 'secret'),
                (('docker_storage', 'value'), 'DockerRootDir', '/private')):
            modified = copy.deepcopy(receipt)
            target = modified
            for part in location:
                target = target[part]
            target[key] = value
            with self.subTest(key=key):
                self.assertIsNone(diag.sanitize_report(diag.encoded(modified)))
        annotated = dict(self.descriptor, annotations={'extra': 'not published'})
        self.assertEqual(diag.descriptor_value(annotated), self.descriptor)
        self.assertIsNone(diag.sanitize_report(b'x' * (diag.MAX_OUTPUT+1)))
        self.assertIsNone(diag.sanitize_report(diag.encoded(receipt)[:-1] + b',"status":"success"}'))
        with self.assertRaises(diag.DiagnosticError):
            diag.run_readonly(diag.DOCKER + ('pull', diag.IMAGE))

    def test_remote_command_is_bounded_and_rejects_arbitrary_request_inputs(self):
        source = SOURCE.read_text(encoding='utf-8')
        args = shlex.split(diag.remote_command(source, self.cfg))
        self.assertEqual(args[:6], ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', '-c'])
        self.assertEqual(zlib.decompress(base64.b64decode(args[-2])).decode(), source)
        self.assertEqual(json.loads(base64.b64decode(args[-1])), self.cfg)
        self.assertEqual(len(args), 9)
        self.assertLess(len(diag.remote_command(source, self.cfg).encode()), 120000)
        for change in ({'image': 'quanta:latest'}, {'path': '/etc/quanta/app.env'},
                       {'source_sha': '$(id)'}, {'request_id': str(uuid.uuid1())}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                diag.remote_command(source, dict(self.cfg, **change))
        with self.assertRaises(ValueError):
            diag.remote_command('x' * (diag.MAX_SOURCE+1), self.cfg)

    def test_transport_uses_ephemeral_key_and_validated_only_receipt(self):
        receipt, _ = self.remote_fixture()
        authorization = {'status': 'authorized', **self.request, 'control_sha': self.control_sha}
        env = dict(self.env, QUANTA_OCI_AUTH_CONFIRMED='true', QUANTA_IMAGE_OPERATION=diag.OPERATION,
                   QUANTA_IMAGE_SOURCE_SHA=diag.SOURCE_SHA, QUANTA_IMAGE_REQUEST_ID=self.request_id,
                   QUANTA_OCI_HOST='test-host', QUANTA_OCI_PPK='fake PPK secret', QUANTA_OCI_HOST_KEY='fixture-pin')
        login = SimpleNamespace(PLINK='/usr/bin/plink', _global_ipv4=lambda _: True,
                               _normalized_host_key=lambda p: p, _key_bytes=lambda p: (None, p.encode()))
        paths = []
        def capture(args, child_env, directory):
            key = Path(args[args.index('-i')+1]); paths.append(key)
            self.assertEqual(key.read_text(), 'fake PPK secret')
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
            self.assertNotIn('QUANTA_OCI_PPK', child_env)
            self.assertEqual(args[-2], 'test-host')
            self.assertNotIn('fake PPK secret', ' '.join(args))
            return 'success', diag.encoded(receipt), True
        with patch.object(diag, 'module', side_effect=lambda n: login if n == 'probe_login' else SimpleNamespace()):
            result = diag.probe(env, authorizer=lambda _: authorization, runner=capture)
        self.assertEqual(result['status'], 'success')
        self.assertIs(result['authentication_attempted'], True)
        self.assertEqual(result['result'], receipt)
        self.assertFalse(paths[0].exists())
        self.assertNotIn(b'fake PPK secret', diag.encoded(result))
        with patch.object(diag, 'module', side_effect=AssertionError('must not read credential')):
            denied = diag.probe(dict(env, QUANTA_IMAGE_REQUEST_ID=str(uuid.uuid4())),
                                authorizer=lambda _: authorization, runner=capture)
        self.assertIs(denied['authentication_attempted'], False)
        self.assertEqual(denied['status'], 'configuration_invalid')


if __name__ == '__main__':
    unittest.main()
