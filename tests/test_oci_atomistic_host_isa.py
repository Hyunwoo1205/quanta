"""Verify fixed ISA evidence and transport without SSH, Docker or production files."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('test_host_isa', ROOT / 'deploy/oci/diagnose_atomistic_host_isa.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)
shared = diag.shared


class HostIsaTests(unittest.TestCase):
    def setUp(self):
        self.config = {'source_sha': diag.POLICY.source_sha, 'request_id': str(uuid.uuid4()), 'control_sha': 'a'*40}
        self.log = (b'CP2K| version\nQS| atoms\nSCF WAVEFUNCTION OPTIMIZATION\n'
                    b'Program received signal SIGILL: Illegal instruction.\nBacktrace for this error:\n'
                    b'#0 __qs_scf_MOD\n#1 libxsmm.so\n#2 SECRET\n')

    def test_bound_file_rejects_different_bytes_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'cp2k.out'
            log.write_bytes(self.log)
            log.chmod(0o600)
            options = {'size': len(self.log), 'digest': hashlib.sha256(self.log).hexdigest(),
                       'owner': (os.getuid(), os.getgid())}
            self.assertEqual(diag.read_bound_log(root, (log.name,), **options), self.log)
            with self.assertRaisesRegex(shared.DiagnosticError, 'failure_log_mismatch'):
                diag.read_bound_log(root, (log.name,), **dict(options, digest='0'*64))
            with self.assertRaisesRegex(shared.DiagnosticError, 'failure_log_mismatch'):
                diag.read_bound_log(root, (log.name,), **dict(options, size=1))
            with self.assertRaises(OSError):
                (root / 'symlink').symlink_to(log)
                diag.read_bound_log(root, ('symlink',), **options)
            with self.assertRaises(OSError):
                (root / 'subdir').symlink_to(root, target_is_directory=True)
                diag.read_bound_log(root, ('subdir', log.name), **options)
            with self.assertRaisesRegex(shared.DiagnosticError, 'failure_log_unavailable'):
                os.link(log, root / 'hardlink')
                diag.read_bound_log(root, (log.name,), **options)

    def test_hwcap_mapping_and_native_read(self):
        reader = lambda entry: (1 << (8 if entry == 16 else 7)) | (1 << 61)
        with patch.object(diag.ctypes, 'CDLL', return_value=SimpleNamespace(getauxval=reader)):
            features = diag.read_features()
        self.assertEqual({name for name, present in features.items() if present}, {'atomics', 'flagm2'})
        self.assertEqual(set(features), diag.HWCAP_BITS.keys() | diag.HWCAP2_BITS.keys())
        if platform.machine() == 'aarch64':
            native = diag.read_features()
            self.assertTrue(native['fp'])
            self.assertTrue(native['asimd'])

    def test_failure_log_only_returns_fixed_markers(self):
        record = diag.log_observation(self.log)
        self.assertIs(record['sigill_text_observed'], True)
        self.assertEqual(record['last_stage_marker'], 'scf_started')
        self.assertEqual(record['backtrace_modules'], ['libxsmm', 'qs_scf'])
        self.assertNotIn(b'SECRET', shared.encoded(record))
        self.assertFalse(diag.log_observation(b'not a backtrace libxsmm')['backtrace_modules'])

    def test_three_ci_pins_and_new_fixed_request(self):
        policy = diag.POLICY
        base = shared.module('authorize_application_upgrade')
        ids = (12345, policy.source_ci, policy.native_ci)
        data = {}
        for run, sha, workflow, names in (
                (ids[0], self.config['control_sha'], policy.control_workflow, policy.control_jobs),
                (ids[1], policy.source_sha, base.APP_WORKFLOW, base.APP_JOB_NAMES),
                (ids[2], policy.source_sha, shared.NATIVE_WORKFLOW, shared.NATIVE_JOBS)):
            data[f'/actions/runs/{run}'] = {'id': run, 'head_sha': sha, 'head_branch': 'main',
                                           'event': 'push', 'path': workflow, 'status': 'completed', 'conclusion': 'success'}
            data[f'/actions/runs/{run}/jobs?filter=latest&per_page=100'] = {
                'total_count': len(names), 'jobs': [{'id': i+1, 'run_id': run, 'name': name, 'status': 'completed',
                                                    'conclusion': 'success'} for i, name in enumerate(sorted(names))]}
        base.api_get = lambda suffix, *_args, **_kwargs: data[suffix]
        base.control_checkout_matches = lambda mapped, **_: mapped['QUANTA_APPLICATION_CONTROL_SHA'] == self.config['control_sha']
        env = {'GITHUB_REPOSITORY': shared.REPOSITORY, 'GITHUB_REF': 'refs/heads/ops/oci', 'GITHUB_EVENT_NAME': 'push',
               'QUANTA_HOST_ISA_CONTROL_SHA': self.config['control_sha'], 'QUANTA_HOST_ISA_CONTROL_CI_RUN': '12345'}
        request = {'schema_version': 1, 'operation': policy.operation,
                   **{key: self.config[key] for key in ('source_sha', 'request_id')}}
        with tempfile.TemporaryDirectory() as tmp, patch.object(shared, 'module', return_value=base):
            path = Path(tmp) / 'request.json'
            path.write_bytes(shared.encoded(request))
            self.assertEqual(shared.authorize(env, path=path, policy=policy)['status'], 'authorized')
            for run, stage in zip(ids, ('control_ci', 'source_ci', 'native_ci')):
                job = data[f'/actions/runs/{run}/jobs?filter=latest&per_page=100']['jobs'][0]
                job['conclusion'] = 'failure'
                self.assertEqual(shared.authorize(env, path=path, policy=policy)['stage'], stage)
                job['conclusion'] = 'success'
            for change in ({'path': '/etc/quanta/app.env'}, {'operation': shared.OPERATION}, {'source_sha': shared.SOURCE_SHA}):
                path.write_bytes(shared.encoded(dict(request, **change)))
                self.assertEqual(shared.authorize(env, path=path, policy=policy)['stage'], 'request')

    def test_remote_and_sanitizer(self):
        calls = []
        def run(command):
            calls.append(command)
            if command == shared.SERVICE_COMMAND:
                return 'observed', b'active\nactive\n'
            self.assertEqual(command, shared.CONTAINER_COMMAND)
            return 'observed', b'a'*64+b' 123 sha256:'+b'd'*64+b' 2026-11-07T01:00:00.000Z true\n'

        lock = SimpleNamespace(parents=(SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0)),))
        info = SimpleNamespace(st_mode=stat.S_IFREG|0o600, st_uid=0, st_nlink=1)
        bits = {name: True for name in diag.HWCAP_BITS.keys() | diag.HWCAP2_BITS.keys()}
        with patch.object(shared, 'LOCK', lock), patch.object(shared.os, 'geteuid', return_value=0), \
                patch.object(shared.platform, 'machine', return_value='aarch64'), \
                patch.object(shared.os, 'open', return_value=123) as opened, patch.object(shared.os, 'fstat', return_value=info), \
                patch.object(shared.os, 'close'), patch.object(shared.fcntl, 'flock'), \
                patch.object(diag, 'read_features', return_value=bits), patch.object(diag, 'read_log', return_value=self.log):
            receipt = diag.remote(self.config, run=run)
        self.assertEqual(opened.call_args.args[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.assertEqual(set(calls), {shared.SERVICE_COMMAND, shared.CONTAINER_COMMAND})
        self.assertEqual(receipt['status'], 'success')
        self.assertEqual(diag.sanitize_report(shared.encoded(receipt)), receipt)
        for change in ({'private_environment_read': True}, {'failure_log': dict(receipt['failure_log'], raw='SECRET')},
                       {'arm64_elf_hwcaps': dict(bits, unlisted=True)}, {'failure_log': dict(receipt['failure_log'], sha256='0'*64)}):
            self.assertIsNone(diag.sanitize_report(shared.encoded(dict(receipt, **change))))

    def test_bootstrap_is_local_offline_and_fails_closed(self):
        command = shlex.split(shared.remote_command(diag.remote_source(), self.config, policy=diag.POLICY))
        self.assertEqual(command[:6], ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', '-c'])
        bad_config = self.config.copy()
        bad_config['source_sha'] = shared.SOURCE_SHA
        with self.assertRaises(ValueError):
            shared.remote_command(diag.remote_source(), bad_config, policy=diag.POLICY)
        # Send an invalid config directly to the hashed bootstrap. The control
        # rejects it before opening the lock or making any subprocess call.
        output = subprocess.run([sys.executable, *command[3:-1], 'e30='], capture_output=True, check=False)
        self.assertEqual(output.returncode, 2, output.stderr.decode())
        receipt = json.loads(output.stdout)
        self.assertEqual(receipt['stage'], 'config')
        self.assertEqual(receipt['operation'], diag.POLICY.operation)
        self.assertEqual(diag.sanitize_report(output.stdout), receipt)


if __name__ == '__main__':
    unittest.main()
