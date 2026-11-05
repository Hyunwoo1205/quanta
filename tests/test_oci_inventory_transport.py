"""Local subprocesses and synthetic credentials only; never an SSH connection."""
import base64
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/oci/probe_inventory.py'
spec = importlib.util.spec_from_file_location('quanta_test_inventory_transport', SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
HOST = '8.8.8.8'  # Valid syntax only; no test connects to it.
PIN = 'SHA256:' + base64.b64encode(bytes(range(32))).decode().rstrip('=')
KEY = '\n'.join([
    'PuTTY-User-Key-File-3: ssh-rsa', 'Encryption: none', 'Comment: synthetic-fixture',
    'Public-Lines: 1', 'cHVibGlj', 'Private-Lines: 1', 'cHJpdmF0ZQ==',
    'Private-MAC: ' + '0' * 64, '',
])


class InventoryTransportTests(unittest.TestCase):
    def test_exact_opt_in_prevents_loading_or_launching(self):
        with mock.patch.object(inventory, '_module', side_effect=AssertionError('must not load')):
            self.assertEqual(inventory.probe({})['status'], 'not_configured')

    def test_invalid_configuration_never_launches(self):
        def forbidden(*args):
            self.fail('must not launch')
        for field, value in [('QUANTA_OCI_HOST', '127.0.0.1'),
                             ('QUANTA_OCI_HOST_KEY', '*'), ('QUANTA_OCI_PPK', 'bad')]:
            env = self.config()
            env[field] = value
            with self.subTest(field=field):
                result = inventory.probe(env, runner=forbidden)
                self.assertEqual(result['status'], 'not_configured')
                self.assertFalse(result['authentication_attempted'])

    @staticmethod
    def config():
        return {'QUANTA_OCI_AUTH_CONFIRMED': 'true', 'QUANTA_OCI_HOST': HOST,
                'QUANTA_OCI_HOST_KEY': PIN, 'QUANTA_OCI_PPK': KEY,
                'GITHUB_TOKEN': 'never-pass-to-child', 'REMOTE_COMMAND': 'not an input'}

    def test_private_files_fixed_argv_minimal_environment_and_cleanup(self):
        paths, calls = [], []
        for status in ('success', 'failed', 'timeout', 'output_limit'):
            def runner(argv, environment, directory):
                calls.append(argv)
                key_path = Path(argv[argv.index('-i') + 1])
                paths.extend([key_path, Path(directory)])
                self.assertEqual(key_path.read_bytes(), KEY.encode())
                self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
                self.assertEqual(environment, {'HOME': directory, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
                self.assertEqual(argv[:-1], ['/usr/bin/plink', '-ssh', '-2', '-4', '-batch',
                    '-noagent', '-no-trivial-auth', '-a', '-x', '-T', '-noshare',
                    '-P', '22', '-l', 'ubuntu', '-i', str(key_path), '-hostkey', PIN, HOST])
                self.assertTrue(argv[-1].startswith('/usr/bin/python3 -I -B -c '))
                self.assertNotIn('not an input', argv[-1])
                return status, b'never publish raw output', True

            real_module = inventory._module
            sanitized = {'scope': 'host_inventory', 'status': 'success'}
            def module(name):
                return mock.Mock(sanitize_report=lambda raw: sanitized) if name == 'host_inventory' else real_module(name)
            with self.subTest(status=status), mock.patch.object(inventory, '_module', side_effect=module):
                result = inventory.probe(self.config(), runner=runner)
                self.assertEqual(result['status'], status)
                self.assertTrue(result['authentication_attempted'])
                self.assertNotIn(HOST, json.dumps(result))
                self.assertNotIn(PIN, json.dumps(result))
                self.assertNotIn('never publish', json.dumps(result))
            self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(len(calls), 4)

    def test_invalid_remote_output_is_never_exposed(self):
        result = inventory.probe(self.config(), runner=lambda *args: ('success', KEY.encode(), True))
        self.assertEqual(result['status'], 'invalid_output')
        self.assertNotIn(KEY, json.dumps(result))

    def capture(self, code, **options):
        with tempfile.TemporaryDirectory() as directory:
            return inventory._capture([sys.executable, '-I', '-c', code],
                                      {'PATH': '/usr/bin:/bin'}, directory, **options)

    def test_real_local_client_success_eof_and_stderr_discard(self):
        status, raw, started = self.capture('import sys; sys.stderr.write("hidden"); print("ok")')
        self.assertEqual((status, raw, started), ('success', b'ok\n', True))

    def test_real_local_nonzero_exit_is_failed(self):
        status, raw, started = self.capture('raise SystemExit(7)')
        self.assertEqual((status, raw, started), ('failed', b'', True))

    def test_real_local_output_is_bounded_and_child_terminated(self):
        status, raw, started = self.capture('import sys; sys.stdout.write("x" * 1000000)', limit=100)
        self.assertEqual((status, raw, started), ('output_limit', b'', True))

    def test_real_local_timeout_is_bounded(self):
        status, raw, started = self.capture('import time; time.sleep(10)', timeout=0.1)
        self.assertEqual((status, raw, started), ('timeout', b'', True))

    def test_nonexistent_client_is_not_an_authentication_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(inventory._capture(['/no/such/client'], {}, directory), ('failed', b'', False))


class InventoryWorkflowGateTests(unittest.TestCase):
    def test_actual_gate_rejects_invalid_requests_before_credentials(self):
        workflow = (ROOT / '.github/workflows/oci-host-inventory.yml').read_text()
        source = textwrap.dedent(workflow.split("python3 -I - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
        valid = {'schema_version': 1, 'operation': 'host-inventory',
                 'request_id': 'a45e68ce-2a91-467e-a1a1-9d23d61eb0ff'}
        cases = [(json.dumps(valid), 0), ('[]', 2), ('x' * 1025, 2), ('broken', 2),
                 (json.dumps({**valid, 'schema_version': True}), 2),
                 (json.dumps({**valid, 'operation': 'arbitrary-command'}), 2),
                 (json.dumps({**valid, 'request_id': 'unsafe output'}), 2),
                 (json.dumps({**valid, 'extra': 'secret-like fixture'}), 2),
                 (json.dumps(valid)[:-1] + ',"operation":"host-inventory"}', 2)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.github/oci/inventory-request.json'
            path.parent.mkdir(parents=True)
            for raw, expected in cases:
                with self.subTest(raw=raw[:30]):
                    path.write_text(raw)
                    result = subprocess.run([sys.executable, '-I', '-c', source], cwd=directory,
                        capture_output=True, text=True, timeout=3, check=False)
                    self.assertEqual(result.returncode, expected)
                    self.assertEqual(result.stderr, '')
                    self.assertNotIn('secret-like fixture', result.stdout)
                    self.assertEqual(json.loads(result.stdout)['status'], 'authorized' if expected == 0 else 'denied')


if __name__ == '__main__':
    unittest.main()
