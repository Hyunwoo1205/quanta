"""Encrypted backup export: fixed content, confidentiality, and failure boundaries."""
from __future__ import annotations

import base64
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load('quanta_export_helper_test', ROOT / 'deploy/oci/verify_backup.py')
sys.modules['quanta_fixed_backup'] = helper
operation = load('quanta_export_operation_test', ROOT / 'deploy/oci/export_recovery.py')
BOOT_ID = '11111111-2222-4333-8444-555555555555'
NONCE = '11223344556647788900aabbccddeeff'


def config():
    return {'source_sha': helper.SOURCE_SHA, 'public_origin': 'https://app.example.net', 'auth_mode': 'owner-token'}


def baseline(raw=b'private sqlite bytes'):
    return {'schema_version': 1, 'source_sha': helper.SOURCE_SHA, 'boot_id': BOOT_ID,
            'snapshot': '20261106T010203Z-' + NONCE, 'database_size': len(raw),
            'database_sha256': hashlib.sha256(raw).hexdigest(),
            'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}


class ExportTests(unittest.TestCase):
    def test_config_preserves_exact_existing_deployment_pin(self):
        self.assertEqual(operation.validate_config(config()), config())
        for value in ({**config(), 'source_sha': 'a' * 40}, {**config(), 'recipient': 'arbitrary'},
                      {**config(), 'auth_mode': 'access'}, {**config(), 'public_origin': 'http://app.example.net'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                operation.validate_config(value)

    def test_public_certificate_is_pinned_and_contains_no_private_key(self):
        cert = operation.EMBEDDED_RECIPIENT_CERT.encode('ascii')
        self.assertEqual(hashlib.sha256(cert).hexdigest(), operation.EXPECTED_CERT_SHA256)
        self.assertTrue(cert.startswith(b'-----BEGIN CERTIFICATE-----\n'))
        self.assertNotIn(b'PRIVATE KEY', cert)

    def test_baseline_validates_fixed_names_size_digest_age_and_current_boot(self):
        good = baseline()
        with patch.object(helper, '_read_root', return_value=json.dumps(good).encode()), \
                patch.object(Path, 'read_text', return_value=BOOT_ID + '\n'):
            self.assertEqual(operation._baseline(config()), good)
        cases = [{**good, 'snapshot': '../private'}, {**good, 'schema_version': True},
                 {**good, 'database_size': True}, {**good, 'database_size': 0},
                 {**good, 'database_size': operation.MAX_DATABASE_BYTES + 1},
                 {**good, 'database_sha256': 'PRIVATE'}, {**good, 'source_sha': 'a' * 40},
                 {**good, 'created_at': '2000-01-01T00:00:00Z'},
                 {**good, 'created_at': '2999-01-01T00:00:00Z'},
                 {**good, 'boot_id': 'different'}, {**good, 'extra': 'not accepted'}]
        for value in cases:
            with self.subTest(value=value), patch.object(helper, '_read_root', return_value=json.dumps(value).encode()), \
                    patch.object(Path, 'read_text', return_value=BOOT_ID + '\n'), self.assertRaises(Exception):
                operation._baseline(config())
        with patch.object(helper, '_read_root', return_value=json.dumps(good).encode()), \
                patch.object(Path, 'read_text', return_value='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n'), \
                self.assertRaises(helper.VerificationError):
            operation._baseline(config())

    def test_der_framing_rejects_text_truncation_indefinite_lengths_and_excess(self):
        valid = b'\x30\x81\x80' + b'x' * 128
        operation._check_der(valid)
        for raw in (b'private error', b'\x30\x80' + b'x' * 128, valid[:-1], valid + b'extra',
                    b'\x31\x81\x80' + b'x' * 128, b'\x30\x85' + b'x' * 130):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                operation._check_der(raw)

    def test_runner_destination_is_fixed_exclusive_private_and_rejects_symlinks(self):
        raw = b'\x30\x81\x80' + b'x' * 128
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            try:
                os.chdir(directory)
                value = operation.save_ciphertext(raw)
                target = Path('.cache/recovery-backup.cms')
                self.assertEqual(target.read_bytes(), raw)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                self.assertEqual(value['ciphertext_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertFalse(value['off_host_backup_verified'])
                with self.assertRaises(FileExistsError):
                    operation.save_ciphertext(raw)
                target.unlink()
                target.symlink_to('../protected')
                with self.assertRaises(FileExistsError):
                    operation.save_ciphertext(raw)
                target.unlink()
                Path('.cache').rmdir()
                Path('.cache').symlink_to(directory, target_is_directory=True)
                with self.assertRaises(ValueError):
                    operation.save_ciphertext(raw)
            finally:
                os.chdir(original)

    def test_reading_archive_source_preserves_exact_bytes_and_rejects_digest_mismatch(self):
        raw = b'\x00 sqlite private data \xff'
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'jobs.sqlite3'
            source.write_bytes(raw)
            with patch.object(helper, '_private_file', side_effect=lambda p, d, **kw: p.stat()):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode='w') as archive:
                    operation._add_snapshot_file(archive, source, 'backup/jobs.sqlite3', source.stat().st_dev,
                                                 len(raw), hashlib.sha256(raw).hexdigest())
                buffer.seek(0)
                with tarfile.open(fileobj=buffer) as archive:
                    self.assertEqual(archive.getnames(), ['backup/jobs.sqlite3'])
                    self.assertEqual(archive.extractfile('backup/jobs.sqlite3').read(), raw)
                with tarfile.open(fileobj=io.BytesIO(), mode='w') as archive, self.assertRaises(helper.VerificationError):
                    operation._add_snapshot_file(archive, source, 'backup/jobs.sqlite3', source.stat().st_dev,
                                                 len(raw), '0' * 64)

    def test_main_failure_never_writes_plaintext_or_error_output(self):
        argument = base64.b64encode(json.dumps(config(), sort_keys=True, separators=(',', ':')).encode()).decode()
        output = types.SimpleNamespace(buffer=io.BytesIO())
        with patch.object(sys, 'stdout', output), patch.object(operation, 'export_bytes', side_effect=Exception('PRIVATE')):
            self.assertEqual(operation.main([argument]), 2)
            self.assertEqual(output.buffer.getvalue(), b'')
        with patch.object(sys, 'stdout', output):
            self.assertEqual(operation.main([]), 2)
            self.assertEqual(output.buffer.getvalue(), b'')

    def test_actual_openssl_aead_roundtrip_contains_only_snapshot_and_rejects_tampering(self):
        # A fresh TEST recipient is generated here; no production private key is read.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, cert = root / 'test-key.pem', root / 'test-cert.pem'
            subprocess.run([operation.OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=Quanta-Test-Only', '-days', '1'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            raw_db, manifest = b'SQLite-test-confidential-content', b'{"only":"test manifest"}'
            snapshot = root / 'backups' / baseline(raw_db)['snapshot']
            snapshot.mkdir(parents=True)
            (snapshot / 'jobs.sqlite3').write_bytes(raw_db)
            (snapshot / 'manifest.json').write_bytes(manifest)
            original_tempdir = tempfile.TemporaryDirectory
            original_lstat = os.lstat
            with ExitStack() as stack:
                stack.enter_context(patch.object(operation.os, 'geteuid', return_value=0))
                stack.enter_context(patch.object(operation.os, 'lstat', side_effect=lambda p, **kw:
                    types.SimpleNamespace(st_mode=0o100755, st_uid=0) if str(p) == operation.OPENSSL
                    else types.SimpleNamespace(st_dev=original_lstat('/').st_dev) if Path(p) == root
                    else original_lstat(p, **kw)))
                stack.enter_context(patch.object(operation, '_lock', side_effect=lambda: os.open(root / 'lock', os.O_CREAT | os.O_RDWR, 0o600)))
                stack.enter_context(patch.object(operation, '_baseline', return_value=baseline(raw_db)))
                stack.enter_context(patch.object(helper, 'ROOT', root))
                stack.enter_context(patch.object(helper, 'BACKUPS', root / 'backups'))
                stack.enter_context(patch.object(helper, '_read_root', return_value=json.dumps(config()).encode()))
                stack.enter_context(patch.object(helper, '_root_parents'))
                stack.enter_context(patch.object(helper, '_private_dir'))
                stack.enter_context(patch.object(helper, '_private_file', side_effect=lambda p, d, **kw: p.stat()))
                stack.enter_context(patch.object(helper, '_hash', return_value=(len(raw_db), hashlib.sha256(raw_db).digest())))
                stack.enter_context(patch.object(operation, 'EMBEDDED_RECIPIENT_CERT', cert.read_text()))
                stack.enter_context(patch.object(operation, 'EXPECTED_CERT_SHA256', hashlib.sha256(cert.read_bytes()).hexdigest()))
                stack.enter_context(patch.object(operation.tempfile, 'TemporaryDirectory',
                    side_effect=lambda **kw: original_tempdir(prefix=kw['prefix'], dir=directory)))
                encrypted = operation.export_bytes(config())
            operation._check_der(encrypted)
            self.assertNotIn(raw_db, encrypted)
            self.assertIn(bytes.fromhex('060b2a864886f70d0109100117'), encrypted[:64])
            envelope, restored = root / 'export.cms', root / 'restored.tar'
            envelope.write_bytes(encrypted)
            result = subprocess.run([operation.OPENSSL, 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                     '-in', str(envelope), '-inkey', str(key), '-recip', str(cert), '-out', str(restored)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertEqual(result.returncode, 0)
            with tarfile.open(restored) as archive:
                self.assertEqual(archive.getnames(), ['backup/jobs.sqlite3', 'backup/manifest.json'])
                self.assertEqual(archive.extractfile('backup/jobs.sqlite3').read(), raw_db)
                self.assertEqual(archive.extractfile('backup/manifest.json').read(), manifest)
            tampered = bytearray(encrypted)
            tampered[-1] ^= 1
            envelope.write_bytes(tampered)
            result = subprocess.run([operation.OPENSSL, 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                     '-in', str(envelope), '-inkey', str(key), '-recip', str(cert), '-out', str(restored)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
