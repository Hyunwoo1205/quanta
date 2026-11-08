"""Check the bounded DB/WAL observer using disposable files only."""

from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'deploy/oci/remote_atomistic_a04_db_wal.py'
SPEC = importlib.util.spec_from_file_location('test_a04_db_wal_observer', SOURCE)
DIAGNOSTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTIC)


class DbWalObserverTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.database = Path(directory) / 'jobs.sqlite3'
        self.wal = self.database.with_name(self.database.name + '-wal')
        self.original = b'private test database bytes'
        self.database.write_bytes(self.original)
        self.database.chmod(0o600)

    def observe(self, sample_count, advance=None):
        with patch.object(DIAGNOSTIC.time, 'sleep', side_effect=advance):
            return DIAGNOSTIC.observe(self.database, owner=os.getuid(),
                                      sample_count=sample_count, interval=0.017)

    def test_stable_database_and_absent_wal_leave_no_private_fields(self):
        result = self.observe(3)
        self.assertEqual(result['attempted_samples'], 3)
        self.assertEqual(result['stable_pairs'], 3)
        self.assertEqual(result['unstable_samples'], 0)
        self.assertEqual(result['main_fingerprints'], 1)
        self.assertEqual(result['wal_fingerprints'], 1)
        self.assertEqual(result['wal_states'], {'absent': 3, 'empty': 0, 'nonempty': 0})
        self.assertEqual(result['wal_state_transitions'], 0)
        self.assertEqual(result['differences_from_first'],
                         {'unchanged': 3, 'main_only': 0, 'wal_only': 0, 'both': 0})
        self.assertEqual(result['last_matches_first'], {'main': True, 'wal': True})
        payload = json.dumps(result)
        self.assertNotIn(self.original.decode(), payload)
        self.assertNotIn(hashlib.sha256(self.original).hexdigest(), payload)
        self.assertNotIn(str(self.database), payload)
        self.assertFalse(self.wal.exists())

    def test_classifies_main_and_wal_differences_independently(self):
        def write_wal(data):
            self.wal.write_bytes(data)
            self.wal.chmod(0o600)

        steps = iter((
            lambda: write_wal(b''),
            lambda: write_wal(b'different WAL bytes'),
            lambda: self.database.write_bytes(b'new main bytes'),
            self.wal.unlink,
            lambda: self.database.write_bytes(self.original),
        ))
        result = self.observe(6, lambda _: next(steps)())
        self.assertEqual(result['stable_pairs'], 6)
        self.assertEqual(result['unstable_samples'], 0)
        self.assertEqual(result['main_fingerprints'], 2)
        self.assertEqual(result['wal_fingerprints'], 3)
        self.assertEqual(result['wal_states'], {'absent': 3, 'empty': 1, 'nonempty': 2})
        self.assertEqual(result['wal_state_transitions'], 3)
        self.assertEqual(result['differences_from_first'],
                         {'unchanged': 2, 'main_only': 1, 'wal_only': 2, 'both': 1})
        self.assertEqual(result['last_matches_first'], {'main': True, 'wal': True})

    def test_read_uses_noatime_and_never_writes_either_file(self):
        self.wal.write_bytes(b'WAL test bytes')
        self.wal.chmod(0o600)
        old_atime = 1_600_000_000_000_000_000
        for path in (self.database, self.wal):
            os.utime(path, ns=(old_atime, path.stat().st_mtime_ns))
        with patch.object(DIAGNOSTIC.os, 'open', wraps=os.open) as opened:
            result = self.observe(2)
        self.assertEqual(result['stable_pairs'], 2)
        file_opens = [call.args for call in opened.call_args_list
                      if Path(call.args[0]).name in {self.database.name, self.wal.name}]
        self.assertEqual({Path(args[0]).name for args in file_opens},
                         {self.database.name, self.wal.name})
        required = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME
        for _, flags, *_ in file_opens:
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertEqual(flags & required, required)
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC))
        for path in (self.database, self.wal):
            self.assertEqual(path.stat().st_atime_ns, old_atime)

    def test_streams_database_over_initial_64_mib_limit_once(self):
        size = 64 * 1024**2 + 1
        with self.database.open('r+b') as stream:
            stream.truncate(size)
        with patch.object(DIAGNOSTIC.os, 'read', wraps=os.read) as read:
            result = self.observe(3)
        self.assertEqual(result['stable_pairs'], 3)
        self.assertEqual(result['main_fingerprints'], 1)
        self.assertEqual(sum(call.args[1] for call in read.call_args_list), size)
        self.assertLessEqual(max(call.args[1] for call in read.call_args_list), 256 * 1024)

    def test_symbolic_links_are_rejected(self):
        target = self.database.with_name('unrelated-file')
        target.write_bytes(b'private contents')
        target.chmod(0o600)
        self.wal.symlink_to(target)
        with self.assertRaises(DIAGNOSTIC.DiagnosticError):
            self.observe(2)
        self.wal.unlink()
        self.database.unlink()
        self.database.symlink_to(target)
        with self.assertRaises(DIAGNOSTIC.DiagnosticError):
            self.observe(2)

    def test_rejects_group_readable_database_and_wal(self):
        self.wal.write_bytes(b'')
        self.wal.chmod(0o600)
        for path in (self.database, self.wal):
            with self.subTest(file=path.name):
                path.chmod(0o640)
                with self.assertRaisesRegex(DIAGNOSTIC.DiagnosticError, 'unsafe_file'):
                    self.observe(2)
                path.chmod(0o600)

    def test_excludes_an_in_place_change_during_hashing(self):
        read = os.read
        modified = False

        def read_then_modify(fd, size):
            nonlocal modified
            result = read(fd, size)
            if not modified:
                modified = True
                self.database.write_bytes(b'changed while reading')
            return result

        with patch.object(DIAGNOSTIC.os, 'read', side_effect=read_then_modify):
            result = self.observe(3)
        self.assertEqual(result['stable_pairs'], 2)
        self.assertEqual(result['unstable_samples'], 1)
        self.assertEqual(result['main_fingerprints'], 1)
        self.assertEqual(result['differences_from_first']['unchanged'], 2)

    def test_observes_a_disposable_sqlite_idle_wal_lifecycle(self):
        self.database.unlink()
        with closing(sqlite3.connect(self.database, isolation_level=None)) as writer:
            self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
            writer.execute('CREATE TABLE runs (status TEXT)')
        self.database.chmod(0o600)
        self.assertFalse(self.wal.exists())
        shm = self.database.with_name(self.database.name + '-shm')
        connect = sqlite3.connect

        def open_idle_writer():
            writer = connect(self.database, isolation_level=None)
            self.addCleanup(writer.close)
            writer.execute('BEGIN IMMEDIATE')
            self.assertIsNone(writer.execute("SELECT 1 FROM runs WHERE status='QUEUED'").fetchone())
            self.assertEqual(self.wal.stat().st_size, 0)
            return writer

        writer = None

        def advance(_):
            nonlocal writer
            if writer is None:
                self.assertFalse(self.wal.exists())
                self.assertFalse(shm.exists())
                writer = open_idle_writer()
            else:
                writer.commit()
                writer.close()

        with patch.object(sqlite3, 'connect', side_effect=AssertionError('observer opened SQLite')):
            result = self.observe(3, advance)
        self.assertEqual(result['stable_pairs'], 3)
        self.assertEqual(result['main_fingerprints'], 1)
        self.assertEqual(result['wal_states'], {'absent': 2, 'empty': 1, 'nonempty': 0})
        self.assertEqual(result['wal_state_transitions'], 2)
        self.assertEqual(result['differences_from_first']['wal_only'], 1)
        self.assertEqual(result['last_matches_first'], {'main': True, 'wal': True})
        self.assertFalse(self.wal.exists())
        self.assertFalse(shm.exists())

    def test_subprocess_report_rejects_private_fields_and_invalid_counters(self):
        observation = self.observe(DIAGNOSTIC.SAMPLE_COUNT)
        report = {'schema_version': 1, 'operation': DIAGNOSTIC.OPERATION,
                  'scope': DIAGNOSTIC.SCOPE, 'status': 'success',
                  'source_sha': 'a' * 40, 'control_sha': 'a' * 40,
                  'request_id': '00000000-0000-4000-8000-000000000001',
                  'observation': observation}

        def parse(value):
            return DIAGNOSTIC.sanitize_report(json.dumps(value).encode('ascii'))

        self.assertEqual(parse(report), report)
        self.assertIsNone(parse(dict(report, database_path=str(self.database))))
        for change in ({'database_sha256': hashlib.sha256(self.original).hexdigest()},
                       {'main_fingerprints': True}, {'stable_pairs': 1}):
            with self.subTest(change=change):
                self.assertIsNone(parse(dict(report, observation=dict(observation, **change))))
