"""Recovery audit boundaries; fixtures never contact Docker, SSH or production."""
import base64
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "oci" / "audit_recovery.py"
spec = importlib.util.spec_from_file_location("quanta_recovery_audit_test", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
IMAGE = "sha256:" + "a" * 64
APP_ID = "b" * 64
PEER_ID = "c" * 64
TOKEN = "d" * 64


def config():
    return {"source_sha": audit.SOURCE_SHA, "public_origin": "https://app.example.net", "auth_mode": "owner-token"}


def encoded(value=None):
    return base64.b64encode(json.dumps(config() if value is None else value, sort_keys=True, separators=(",", ":")).encode()).decode()


def complete():
    result = audit._initial_report()
    result.update(status="success", stage="complete", failure_reason="none")
    return result


def host_ready():
    result = complete()
    result.update(dict.fromkeys(audit.PREREQUISITES, True))
    result.update(host_reboot_prerequisites_met=True, backup_snapshots=1)
    return result


def row(ident, name, policy="always", running="true", image=IMAGE, paused="false", restarting="false", dead="false"):
    return f"{ident} /{name} {image} {running} {policy} {paused} {restarting} {dead}\n"


class AuditConfigurationTests(unittest.TestCase):
    def test_only_canonical_three_field_pinned_config_is_accepted(self):
        self.assertEqual(audit.validate_config(config()), config())
        self.assertEqual(audit._argument(encoded()), config())
        cases = [None, [], {}, {**config(), "source_sha": "f" * 40}, {**config(), "auth_mode": "access"},
                 {**config(), "token": TOKEN}]
        for origin in ("https://127.0.0.1", "http://app.example.net", "https://APP.example.net",
                       "https://app.example.net/", "https://app.example.net:443", "https://user@app.example.net",
                       "https://app.example.net?x", "https://app..example.net", "https://localhost",
                       "https://app.example.net\nPRIVATE", "https://app.example.123", None):
            cases.append({**config(), "public_origin": origin})
        for value in cases:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                audit.validate_config(value)
        for value in ("", "%%%", encoded() + "=", "A" * 4097,
                      base64.b64encode(json.dumps(config()).encode()).decode(),
                      base64.b64encode(b'{"source_sha":0,"source_sha":1}').decode()):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                audit._argument(value)

    def test_report_is_exact_and_only_bounded_numbers_booleans_and_enums(self):
        self.assertEqual(audit.validate_report(complete()), complete())
        self.assertEqual(audit.validate_report(host_ready()), host_ready())
        for field in audit.BOOLEANS:
            for value in (None, 1, "true", []):
                with self.subTest(field=field, value=repr(value)), self.assertRaises(ValueError):
                    audit.validate_report({**complete(), field: value})
        for field in audit.INTEGERS:
            for value in (-1, True, 1.0, audit.MAX_COUNT + 1, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    audit.validate_report({**complete(), field: value})
        for field in ("status", "stage", "failure_reason"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.validate_report({**complete(), field: []})

    def test_impossible_or_scope_inflating_claims_are_rejected(self):
        cases = [{**complete(), "token": TOKEN}, {**complete(), "status": "failed"},
                 {**complete(), "failure_reason": "inspection_failed"},
                 {**complete(), "server_modified": True}, {**complete(), "off_host_backup_verified": True},
                 {**complete(), "safe_to_reboot": True}, {**complete(), "running_peer_containers": 1},
                 {**complete(), "restartable_running_peers": 1}, {**complete(), "nonterminal_runs": 1},
                 {**complete(), "no_pending_runs": True}, {**complete(), "host_reboot_prerequisites_met": True},
                 {**host_ready(), "authenticated_ready": False}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit.validate_report(value)

    def test_remote_junk_secrets_duplicate_keys_and_nonfinite_are_not_returned(self):
        raw = json.dumps(complete()).encode()
        self.assertEqual(audit.sanitize_report(raw), complete())
        for value in (None, b"", b"\xff", b"x" * 8193, raw + b"PRIVATE", b'{"x":NaN}',
                      raw[:-1] + b',"status":"success"}', json.dumps({**complete(), "token": TOKEN}).encode()):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertIsNone(audit.sanitize_report(value))
                self.assertEqual(out.getvalue(), "")

    def test_configuration_failure_has_no_work_or_exception_text(self):
        with patch.object(audit, "_perform") as perform, contextlib.redirect_stdout(io.StringIO()) as out:
            result = audit.run({})
        perform.assert_not_called()
        self.assertEqual(result["failure_reason"], "invalid_configuration")
        self.assertEqual(out.getvalue(), "")
        with patch.object(audit, "_installation", side_effect=RuntimeError(TOKEN)):
            result = audit.run(config())
        self.assertEqual(result["stage"], "installation")
        self.assertEqual(result["failure_reason"], "inspection_failed")
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_main_has_one_sanitized_json_record_and_no_traceback(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(["invalid-private-input"]), 2)
        self.assertEqual(json.loads(output.getvalue()), audit._initial_report())


class AuditCollectorsTests(unittest.TestCase):
    @contextlib.contextmanager
    def effective_identity_fixture(self, *, entry_failure=False):
        state = {"uid": 0, "gid": 7}
        calls = []
        def uid(value):
            calls.append(("uid", value))
            if entry_failure and value == 10001:
                raise PermissionError("private error")
            state["uid"] = value
        def gid(value):
            calls.append(("gid", value))
            state["gid"] = value
        with patch.object(audit.os, "geteuid", side_effect=lambda: state["uid"]), \
                patch.object(audit.os, "getegid", side_effect=lambda: state["gid"]), \
                patch.object(audit.os, "seteuid", side_effect=uid), \
                patch.object(audit.os, "setegid", side_effect=gid):
            yield state, calls

    def test_sqlite_identity_drops_effective_ids_and_restores_after_success(self):
        with self.effective_identity_fixture() as (state, calls):
            with audit._database_identity():
                self.assertEqual(state, {"uid": 10001, "gid": 10001})
            self.assertEqual(state, {"uid": 0, "gid": 7})
        self.assertEqual(calls, [("gid", 10001), ("uid", 10001), ("uid", 0), ("gid", 7)])

    def test_sqlite_identity_restores_after_partial_entry_failure(self):
        with self.effective_identity_fixture(entry_failure=True) as (state, calls), self.assertRaises(PermissionError):
            with audit._database_identity():
                self.fail("must not enter body")
        self.assertEqual(state, {"uid": 0, "gid": 7})
        self.assertEqual(calls[-2:], [("uid", 0), ("gid", 7)])

    def test_actual_alarm_unwinds_sqlite_identity_and_restores_mask(self):
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        with self.effective_identity_fixture() as (state, calls), self.assertRaises(audit.AuditDeadline):
            with audit._deadline(0.02):
                with audit._database_identity():
                    time.sleep(2)
        self.assertEqual(state, {"uid": 0, "gid": 7})
        self.assertEqual(calls[-2:], [("uid", 0), ("gid", 7)])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), original_mask)

    def test_sqlite_connection_closes_as_store_user_before_sql_error_privilege_restore(self):
        connection = unittest.mock.Mock()
        observed = []
        with self.effective_identity_fixture() as (state, calls):
            def connect(*args, **kwargs):
                observed.append(("open", state.copy()))
                return connection
            def close():
                observed.append(("close", state.copy()))
            connection.execute.side_effect = sqlite3.OperationalError("private error")
            connection.close.side_effect = close
            with patch.object(audit, "_private", return_value=types.SimpleNamespace(st_dev=1, st_ino=1)), \
                    patch.object(audit, "_database_auxiliaries"), patch.object(audit.sqlite3, "connect", side_effect=connect), \
                    self.assertRaises(sqlite3.OperationalError):
                audit._database(audit._initial_report(), 1)
            self.assertEqual(state, {"uid": 0, "gid": 7})
        self.assertEqual(observed, [("open", {"uid": 10001, "gid": 10001}),
                                    ("close", {"uid": 10001, "gid": 10001})])

    def test_sqlite_auxiliaries_are_optional_but_existing_bad_metadata_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(audit, "DATA", Path(directory)), patch.object(audit, "_private") as private:
                audit._database_auxiliaries(1)
                private.assert_not_called()
                wal = Path(directory) / "jobs.sqlite3-wal"
                wal.write_bytes(b"live changing fixture")
                audit._database_auxiliaries(1)
                private.assert_called_once_with(wal, 1, maximum=audit.MAX_DATABASE_BYTES)
            with patch.object(audit, "DATA", Path(directory)), patch.object(audit, "_private", side_effect=audit.AuditError()), self.assertRaises(audit.AuditError):
                audit._database_auxiliaries(1)
            self.assertEqual(wal.read_bytes(), b"live changing fixture")

    def test_sqlite_auxiliary_disappearing_between_metadata_reads_is_normal(self):
        with tempfile.TemporaryDirectory() as directory:
            wal = Path(directory) / "jobs.sqlite3-wal"
            wal.write_bytes(b"transient SQLite helper")
            with patch.object(audit, "DATA", Path(directory)), \
                    patch.object(audit, "_private", side_effect=FileNotFoundError()) as private:
                audit._database_auxiliaries(1)
            private.assert_called_once_with(wal, 1, maximum=audit.MAX_DATABASE_BYTES)

    def test_real_capture_is_bounded_and_reaps_nonzero_timeout_and_output_limit(self):
        self.assertEqual(audit._capture([sys.executable, "-c", "print('ok')"]), b"ok\n")
        cases = [([sys.executable, "-c", "raise SystemExit(3)"], {}),
                 ([sys.executable, "-c", "print('x'*100)"], {"limit": 10}),
                 ([sys.executable, "-c", "import time;time.sleep(10)"], {"timeout": 0.03})]
        for command, args in cases:
            with self.subTest(command=command), self.assertRaises(audit.AuditError):
                audit._capture(command, **args)

    def test_deadline_restores_signal_state(self):
        handler = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(audit.AuditDeadline):
            with audit._deadline(0.02):
                time.sleep(2)
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_unit_properties_reject_duplicates_unknown_fields_and_missing_fields(self):
        with patch.object(audit, "_capture", return_value=b"UnitFileState=enabled\nActiveState=active\n"):
            self.assertEqual(audit._unit_properties("quanta-boot.service", ("ActiveState", "UnitFileState")),
                             {"ActiveState": "active", "UnitFileState": "enabled"})
        for raw in (b"ActiveState=active\n", b"ActiveState=active\nActiveState=active\n",
                    b"Private=value\nActiveState=active\n", b"ActiveState\nUnitFileState=enabled\n"):
            with patch.object(audit, "_capture", return_value=raw), self.assertRaises(audit.AuditError):
                audit._unit_properties("quanta-boot.service", ("ActiveState", "UnitFileState"))

    def test_unit_resolution_and_hashes_cannot_be_replaced_by_dropins(self):
        content = b"trusted unit"
        with patch.object(audit, "TRUSTED", {"runtime": "ignored", "quanta-boot.service": hashlib.sha256(content).hexdigest()}), \
                patch.object(audit, "_read_root", return_value=content), \
                patch.object(audit, "_unit_properties", return_value={"FragmentPath": "/etc/systemd/system/quanta-boot.service", "DropInPaths": ""}):
            audit._verify_units()
        with patch.object(audit, "TRUSTED", {"runtime": "ignored", "quanta-boot.service": hashlib.sha256(content).hexdigest()}), \
                patch.object(audit, "_read_root", return_value=content), \
                patch.object(audit, "_unit_properties", return_value={"FragmentPath": "/etc/systemd/system/quanta-boot.service", "DropInPaths": "/private/override"}), \
                self.assertRaises(audit.AuditError):
            audit._verify_units()

    def test_service_collection_preserves_active_timer_and_reports_backup_history(self):
        def properties(unit, names):
            if "UnitFileState" in names:
                return {"ActiveState": "active", "UnitFileState": "enabled"}
            if "LoadState" in names:
                return {"ActiveState": "inactive", "LoadState": "loaded" if unit.endswith("-boot.service") else "not-found"}
            return {"Result": "success", "ExecMainStatus": "0", "ExecMainStartTimestampMonotonic": "100"}
        result = audit._initial_report()
        with patch.object(audit, "_unit_properties", side_effect=properties):
            audit._services(result)
        self.assertTrue(result["backup_timer_active"])
        self.assertTrue(result["backup_services_idle"])
        self.assertTrue(result["latest_backup_service_succeeded"])
        self.assertFalse(result["server_modified"])

    def test_active_backup_vetoes_idle_without_stopping_it(self):
        def properties(unit, names):
            if "UnitFileState" in names:
                return {"ActiveState": "active", "UnitFileState": "enabled"}
            if "LoadState" in names:
                return {"ActiveState": "active", "LoadState": "loaded"}
            return {"Result": "success", "ExecMainStatus": "0", "ExecMainStartTimestampMonotonic": "0"}
        result = audit._initial_report()
        with patch.object(audit, "_unit_properties", side_effect=properties):
            audit._services(result)
        self.assertFalse(result["backup_services_idle"])
        self.assertFalse(result["latest_backup_service_succeeded"])

    def test_peer_restart_policies_are_checked_without_public_identity(self):
        for policy, expected in (("always", True), ("unless-stopped", True), ("no", False), ("on-failure", False)):
            result = audit._initial_report()
            raw = row(APP_ID, "quanta", "no") + row(PEER_ID, "other-private-name", policy)
            with patch.object(audit, "_capture", side_effect=[(APP_ID + "\n" + PEER_ID + "\n").encode(), raw.encode()]) as capture:
                audit._containers(IMAGE, result)
            self.assertTrue(result["single_app_container"])
            self.assertEqual(result["peer_restart_policies_safe"], expected)
            self.assertEqual(result["running_peer_containers"], 1)
            self.assertNotIn("other-private-name", json.dumps(result))
            self.assertNotIn(".Config", str(capture.call_args_list))

    def test_stopped_peer_does_not_need_to_be_started_and_paused_peer_vetoes(self):
        for running, paused, expected in (("false", "false", True), ("true", "true", False)):
            result = audit._initial_report()
            raw = row(APP_ID, "quanta", "no") + row(PEER_ID, "peer", "always", running, paused=paused)
            with patch.object(audit, "_capture", side_effect=[(APP_ID + "\n" + PEER_ID + "\n").encode(), raw.encode()]):
                audit._containers(IMAGE, result)
            self.assertEqual(result["peer_restart_policies_safe"], expected)

    def test_invalid_duplicate_or_unknown_container_facts_fail_closed(self):
        cases = [(b"\n", b""), ((APP_ID + "\n").encode(), b"private-error"),
                 ((APP_ID + "\n" + APP_ID + "\n").encode(), b""),
                 ((APP_ID + "\n").encode(), row(PEER_ID, "quanta", "no").encode()),
                 ((APP_ID + "\n").encode(), row(APP_ID, "quanta", "unknown").encode())]
        for ids, facts in cases:
            with self.subTest(ids=ids), patch.object(audit, "_capture", side_effect=[ids, facts]), self.assertRaises(audit.AuditError):
                audit._containers(IMAGE, audit._initial_report())

    def test_backup_container_marks_backup_busy(self):
        result = audit._initial_report()
        result["backup_services_idle"] = True
        raw = row(APP_ID, "quanta", "no") + row(PEER_ID, "quanta-backup", "no")
        with patch.object(audit, "_capture", side_effect=[(APP_ID + "\n" + PEER_ID + "\n").encode(), raw.encode()]):
            audit._containers(IMAGE, result)
        self.assertFalse(result["backup_services_idle"])
        self.assertEqual(result["peer_containers"], 0)

    def test_kernel_lock_is_bound_to_device_inode_and_exclusive_flock(self):
        lock = types.SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=123)
        for raw, expected in ((b"1: FLOCK ADVISORY WRITE 42 08:01:123 0 EOF\n", True),
                              (b"1: FLOCK  ADVISORY  WRITE 42 08:01:123 0 EOF\n", True),
                              (b"1:\tFLOCK\tADVISORY\tWRITE\t42\t08:01:123\t0\tEOF\n", True),
                              (b"1: POSIX ADVISORY WRITE 42 08:01:123 0 EOF\n", False),
                              (b"1: FLOCK ADVISORY WRITE 42 08:01:124 0 EOF\n", False),
                              (b"1: FLOCK ADVISORY WRITE 42 08:01:123 0 EOF\n2: FLOCK ADVISORY WRITE 43 08:01:123 0 EOF\n", False)):
            result = audit._initial_report()
            with patch.object(audit, "_private", return_value=lock), patch.object(audit, "_read_root", return_value=raw):
                audit._worker(result, lock.st_dev)
            self.assertEqual(result["worker_exclusivity_verified"], expected)

    def test_native_flock_fixture_is_observed_in_actual_proc_locks(self):
        with tempfile.TemporaryFile() as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock = os.fstat(stream.fileno())
            result = audit._initial_report()
            # This container maps procfs/root owners to nonzero IDs. Only the
            # host-ownership gate is bypassed; bytes come from the real kernel.
            with patch.object(audit, "_private", return_value=lock), \
                    patch.object(audit, "_read_root", side_effect=lambda path, **kwargs: path.read_bytes()):
                audit._worker(result, lock.st_dev)
            self.assertTrue(result["worker_exclusivity_verified"])
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            result = audit._initial_report()
            with patch.object(audit, "_private", return_value=lock), \
                    patch.object(audit, "_read_root", side_effect=lambda path, **kwargs: path.read_bytes()):
                audit._worker(result, lock.st_dev)
            self.assertFalse(result["worker_exclusivity_verified"])

    def test_actual_readonly_sqlite_inventory_includes_pending_work_and_changes_no_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jobs.sqlite3"
            db = sqlite3.connect(path)
            for table in ("experiments", "revisions", "runs", "idempotency", "events", "artifacts"):
                db.execute("CREATE TABLE " + table + " (status TEXT)")
            db.executemany("INSERT INTO runs VALUES(?)", [("SUCCEEDED",), ("CANCELLED",), ("QUEUED",)])
            db.execute("INSERT INTO experiments VALUES('private')")
            db.commit()
            db.close()
            before = path.read_bytes()
            result = audit._initial_report()
            with patch.object(audit, "DATA", Path(directory)), patch.object(audit, "_private", side_effect=lambda p, device: p.stat()), \
                    patch.object(audit, "_database_identity", side_effect=contextlib.nullcontext):
                audit._database(result, path.stat().st_dev)
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(result["database_checked"])
            self.assertEqual(result["experiments"], 1)
            self.assertEqual(result["runs"], 3)
            self.assertEqual(result["nonterminal_runs"], 1)
            self.assertFalse(result["no_pending_runs"])
            self.assertEqual(set(Path(directory).iterdir()), {path})

    def test_unknown_run_status_or_missing_schema_is_not_an_empty_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jobs.sqlite3"
            db = sqlite3.connect(path)
            for table in ("experiments", "revisions", "runs", "idempotency", "events", "artifacts"):
                db.execute("CREATE TABLE " + table + " (status TEXT)")
            db.execute("INSERT INTO runs VALUES('UNKNOWN')")
            db.commit()
            db.close()
            result = audit._initial_report()
            with patch.object(audit, "DATA", Path(directory)), patch.object(audit, "_private", side_effect=lambda p, device: p.stat()), \
                    patch.object(audit, "_database_identity", side_effect=contextlib.nullcontext), self.assertRaises(audit.AuditError):
                audit._database(result, path.stat().st_dev)
            self.assertFalse(result["database_checked"])
            self.assertFalse(result["no_pending_runs"])

    def test_native_clean_wal_read_creates_auxiliaries_as_connection_owner(self):
        # Native SQLite regression: mode=ro is not a promise of no helper files.
        # Run the real UID drop when root; ordinary CI uses the fixture owner's
        # UID while the separate identity tests exercise every transition.
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "store"
            store.mkdir(mode=0o700)
            path = store / "jobs.sqlite3"
            db = sqlite3.connect(path)
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
            for table in ("experiments", "revisions", "runs", "idempotency", "events", "artifacts"):
                db.execute("CREATE TABLE " + table + " (status TEXT)")
            db.commit()
            db.close()
            path.chmod(0o600)
            self.assertFalse(Path(str(path) + "-wal").exists())
            self.assertFalse(Path(str(path) + "-shm").exists())
            root = os.geteuid() == 0
            if root:
                Path(directory).chmod(0o755)
                os.chown(store, 10001, 10001)
                os.chown(path, 10001, 10001)
            expected_owner = (path.stat().st_uid, path.stat().st_gid)
            before = path.read_bytes()
            observed = []
            native_connect = sqlite3.connect
            class TrackingConnection(sqlite3.Connection):
                def close(self):
                    for suffix in ("-wal", "-shm"):
                        info = Path(str(path) + suffix).stat()
                        observed.append((info.st_uid, info.st_gid))
                    super().close()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(audit, "DATA", store))
                stack.enter_context(patch.object(audit.sqlite3, "connect", side_effect=lambda *args, **kwargs:
                    native_connect(*args, **kwargs, factory=TrackingConnection)))
                if not root:
                    stack.enter_context(patch.object(audit, "_private", side_effect=lambda p, device, **kwargs: p.stat()))
                    stack.enter_context(patch.object(audit, "_database_identity", side_effect=contextlib.nullcontext))
                result = audit._initial_report()
                audit._database(result, path.stat().st_dev)
            self.assertEqual(observed, [expected_owner, expected_owner])
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(result["database_checked"])

    def test_private_storage_checks_owner_mode_device_and_link_count(self):
        metadata = dict(st_mode=stat.S_IFREG | 0o600, st_uid=10001, st_gid=10001, st_dev=1, st_nlink=1, st_size=20)
        for change in ({"st_uid": 0}, {"st_gid": 0}, {"st_mode": stat.S_IFREG | 0o644}, {"st_dev": 2}, {"st_nlink": 2}, {"st_size": audit.MAX_DATABASE_BYTES + 1}):
            with patch.object(audit, "_no_links"), patch.object(audit.os, "lstat", return_value=types.SimpleNamespace(**{**metadata, **change})), self.assertRaises(audit.AuditError):
                audit._private(Path("/fixed/db"), 1)

    def test_snapshot_inventory_reads_only_fixed_children_and_reports_age(self):
        with tempfile.TemporaryDirectory() as directory:
            stamp = "20261106T010203Z"
            snapshot = Path(directory) / (stamp + "-" + uuid.uuid4().hex)
            snapshot.mkdir()
            (snapshot / "jobs.sqlite3").write_bytes(b"private fixture")
            (snapshot / "manifest.json").write_text("{}")
            (Path(directory) / "unrelated-file").write_text("not a snapshot")
            now = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp() + 60
            result = audit._initial_report()
            with patch.object(audit, "BACKUPS", Path(directory)), patch.object(audit, "_private") as private, \
                    patch.object(audit.time, "time", return_value=now), \
                    patch.object(audit.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * 1024**3)):
                audit._backups(result, 1)
            self.assertTrue(result["latest_snapshot_present"])
            self.assertTrue(result["sufficient_disk_space"])
            self.assertEqual(result["backup_snapshots"], 1)
            self.assertEqual(result["latest_snapshot_age_seconds"], 60)
            self.assertEqual([call.args[0] for call in private.call_args_list],
                             [snapshot, snapshot / "jobs.sqlite3", snapshot / "manifest.json"])

    def test_no_snapshot_or_low_space_never_becomes_reboot_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            result = audit._initial_report()
            with patch.object(audit, "BACKUPS", Path(directory)), \
                    patch.object(audit.shutil, "disk_usage", return_value=types.SimpleNamespace(free=1024)):
                audit._backups(result, 1)
            self.assertFalse(result["latest_snapshot_present"])
            self.assertFalse(result["sufficient_disk_space"])
            self.assertEqual(result["backup_snapshots"], 0)

    def test_root_file_rejects_public_token_permissions_and_never_opens_it(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1)
        with patch.object(audit, "_root_parents"), patch.object(audit.os, "lstat", return_value=info), \
                patch.object(audit.os, "open") as opened, self.assertRaises(audit.AuditError):
            audit._read_root(Path("/fixed/app.env"), private=True)
        opened.assert_not_called()

    def test_completed_collection_never_claims_external_backup_or_reboot_safety(self):
        result = audit._initial_report()
        def install(config, report):
            report.update(source_verified=True, storage_verified=True, boot_id_valid=True)
            return IMAGE, 1, TOKEN
        def collector(report, *args):
            report.update(dict.fromkeys(audit.PREREQUISITES, True))
        with patch.object(audit, "_installation", side_effect=install), patch.object(audit, "_services", side_effect=collector), \
                patch.object(audit, "_ready", return_value=True), patch.object(audit, "_containers"), \
                patch.object(audit, "_worker"), patch.object(audit, "_database"), patch.object(audit, "_backups"):
            audit._perform(config(), result)
        self.assertTrue(result["host_reboot_prerequisites_met"])
        self.assertFalse(result["safe_to_reboot"])
        self.assertFalse(result["off_host_backup_verified"])
        self.assertFalse(result["server_modified"])
        self.assertEqual(result["status"], "success")


if __name__ == "__main__":
    unittest.main()
