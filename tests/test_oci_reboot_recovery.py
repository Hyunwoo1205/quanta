"""Guarded reboot tests: local files/SQLite and fake service managers only."""
from __future__ import annotations

import base64
import contextlib
import http.server
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
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy/oci" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("quanta_fixed_backup", "verify_backup.py")
audit = load("quanta_fixed_audit", "audit_recovery.py")
with patch.dict(sys.modules, {"quanta_fixed_backup": helper, "quanta_fixed_audit": audit}):
    operation = load("quanta_reboot_test", "reboot_recovery.py")

OLD_BOOT = "47f25d5d-7e2d-4556-90ec-058e736e2b83"
NEW_BOOT = "f5052a3c-b8d2-466b-af38-2b975b5b360a"
TOKEN = "c" * 64
SNAPSHOT = Path("/srv/quanta/backups/20261106T010203Z-1c1205b707954369af8ea9ad2c9ba5ca")


def config():
    return {"source_sha": operation.SOURCE_SHA, "public_origin": "https://app.example.net", "auth_mode": "owner-token"}


def semantics():
    return {"schema_sha256": "a" * 64,
            "tables": {table: {"rows": index + 1, "sha256": "b" * 64} for index, table in enumerate(operation.TABLES)},
            "nonterminal_runs": 0}


def backup():
    return {"schema_version": 1, "source_sha": operation.SOURCE_SHA, "boot_id": OLD_BOOT,
            "snapshot": SNAPSHOT.name, "database_size": 100, "database_sha256": "d" * 64,
            "created_at": "2026-11-06T01:02:03Z"}


def peers():
    return {"c" * 64: {"name": "/synthetic-peer", "image": "sha256:" + "d" * 64,
            "running": True, "restart": {"Name": "always", "MaximumRetryCount": 0}, "configuration_sha256": "e" * 64}}


def baseline():
    return {"schema_version": 1, "source_sha": operation.SOURCE_SHA, "created_at": "2026-11-06T01:02:03Z",
            "operation_id": "929df7a2-c026-4b3e-8ff2-ea416c2d2550", "old_boot_id": OLD_BOOT,
            "backup": backup(), "database": semantics(), "peers": peers(),
            "settings": {path: "f" * 64 for path in operation.SETTINGS},
            "external_copy_verification": "separate_operator_check_not_attested_by_server"}


@contextlib.contextmanager
def fake_operation():
    with contextlib.ExitStack() as stack:
        mocks = {}
        values = {"_operation_lock": contextlib.nullcontext(), "_interruptions": contextlib.nullcontext(),
                  "_baseline_absent": None, "_backup_baseline": (backup(), SNAPSHOT, 1),
                  "_semantic_database": semantics(), "_peer_state": peers(),
                  "_settings": baseline()["settings"], "_absent_transients": None,
                  "_transient": None, "_stop_transient": None, "_service_state": None,
                  "_idle_backups": None, "_timer_enabled": None,
                  "_idle_database": None, "_publish_baseline": None, "_boot_id": OLD_BOOT,
                  "_restore_services": None, "_read_reboot_baseline": baseline()}
        for name, value in values.items():
            mocks[name] = stack.enter_context(patch.object(operation, name, return_value=value))
        mocks["audit_run"] = stack.enter_context(patch.object(audit, "run", return_value={
            "status": "success", "host_reboot_prerequisites_met": True,
            "worker_exclusivity_verified": True, "no_pending_runs": True,
            "source_verified": True, "app_active": True, "https_active": True,
            "backup_timer_active": True, "backup_timer_enabled": True}))
        mocks["_reboot_audit"] = stack.enter_context(patch.object(operation, "_reboot_audit", return_value=(
            mocks["audit_run"].return_value, 1, TOKEN)))
        env = ("QUANTA_PUBLIC_ORIGIN=https://app.example.net\nQUANTA_AUTH_MODE=owner-token\nQUANTA_OWNER_TOKEN=" + TOKEN + "\n").encode()
        mocks["_read_root"] = stack.enter_context(patch.object(helper, "_read_root", return_value=env))
        mocks["_quiet"] = stack.enter_context(patch.object(helper, "_quiet"))
        stack.enter_context(patch.object(helper, "_deadline", side_effect=lambda seconds: contextlib.nullcontext()))
        yield mocks


def report_success(action):
    with fake_operation() as mocks:
        if action == "verify-reboot":
            mocks["_boot_id"].return_value = NEW_BOOT
        return operation.run(config(), action)


@contextlib.contextmanager
def fake_root_identity(fail_enter=None):
    state = {"uid": 0, "gid": 0}
    events = []
    def set_uid(value):
        events.append(("uid", value))
        if fail_enter == "uid" and value == 10001:
            raise OSError("test entering effective UID failed")
        state["uid"] = value
    def set_gid(value):
        events.append(("gid", value))
        if fail_enter == "gid" and value == 10001:
            raise OSError("test entering effective GID failed")
        state["gid"] = value
    with patch.object(operation.os, "getuid", return_value=0), \
            patch.object(operation.os, "geteuid", side_effect=lambda: state["uid"]), \
            patch.object(operation.os, "getegid", side_effect=lambda: state["gid"]), \
            patch.object(operation.os, "seteuid", side_effect=set_uid), \
            patch.object(operation.os, "setegid", side_effect=set_gid):
        yield state, events


class RebootRecoveryTests(unittest.TestCase):
    def test_request_schedules_only_after_barrier_stopped_app_and_quiescent_live_capture(self):
        with fake_operation() as mocks:
            events = []
            for name in ("_transient", "_idle_database", "_publish_baseline"):
                mocks[name].side_effect = lambda *a, _name=name, **kw: events.append((_name, a))
            mocks["_quiet"].side_effect = lambda command, **kw: events.append(("quiet", command))
            result = operation.run(config(), "reboot-recovery")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["reboot_scheduled"])
        self.assertFalse(result["boot_changed"])
        self.assertFalse(result["off_host_backup_verified_by_server"])
        self.assertFalse(result["new_calculation_verified"])
        self.assertTrue(result["quiescent_live_baseline_verified"])
        self.assertFalse(result["backup_baseline_verified"])
        self.assertFalse(result["snapshot_semantics_matched"])
        self.assertFalse(result["backup_policy_console_verified"])
        self.assertEqual(result["baseline_schema_version"], 2)
        mocks["_backup_baseline"].assert_not_called()
        self.assertEqual(events[0], ("_transient", (operation.RESUME_UNIT, 180, ["/usr/bin/systemctl", "start", operation.APP, operation.HTTPS, operation.TIMER])))
        self.assertEqual(events[1], ("quiet", ["/usr/bin/systemctl", "stop", operation.HTTPS]))
        self.assertEqual(events[2], ("_idle_database", (1,)))
        self.assertEqual(events[3], ("quiet", ["/usr/bin/systemctl", "stop", operation.TIMER]))
        self.assertEqual(events[4], ("quiet", ["/usr/bin/systemctl", "stop", operation.APP]))
        self.assertEqual(events[-1], ("_transient", (operation.REBOOT_UNIT, 10, ["/usr/bin/systemctl", "reboot"])))
        mocks["_restore_services"].assert_not_called()
        mocks["_stop_transient"].assert_not_called()
        self.assertEqual(result["artifacts"], semantics()["tables"]["artifacts"]["rows"])
        self.assertEqual(operation.sanitize_report(json.dumps(result).encode()), result)

    def test_configuration_and_unknown_action_never_acquire_lock(self):
        for value, action in (({}, "reboot-recovery"), (config(), "arbitrary"), ({**config(), "command": "true"}, "verify-reboot")):
            with fake_operation() as mocks:
                result = operation.run(value, action)
            self.assertEqual(result["failure_reason"], "invalid_configuration")
            mocks["_operation_lock"].assert_not_called()

    def test_existing_reboot_claim_or_unsafe_audit_never_stop_services(self):
        for field in ("_baseline_absent", "_reboot_audit"):
            with self.subTest(field=field), fake_operation() as mocks:
                mocks[field].side_effect = operation.RebootError()
                result = operation.run(config())
            self.assertEqual(result["failure_reason"], "preflight_refused")
            mocks["_quiet"].assert_not_called()
            mocks["_transient"].assert_not_called()

    def test_https_stop_failure_prevents_app_stop_and_recovers_services(self):
        with fake_operation() as mocks:
            mocks["_quiet"].side_effect = operation.RebootError()
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "admission_barrier_failed")
        self.assertEqual(mocks["_quiet"].call_args_list[0].args[0], ["/usr/bin/systemctl", "stop", operation.HTTPS])
        self.assertEqual(mocks["_quiet"].call_count, 1)
        mocks["_idle_database"].assert_not_called()
        mocks["_publish_baseline"].assert_not_called()
        mocks["_restore_services"].assert_called_once_with(config(), TOKEN)
        self.assertTrue(result["fallback_recovery_verified"])

    def test_request_accepted_before_https_stop_is_detected_before_app_stop(self):
        with fake_operation() as mocks:
            mocks["_idle_database"].side_effect = operation.RebootError()
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "admission_barrier_failed")
        self.assertTrue(result["admission_paused"])
        self.assertFalse(result["application_stopped"])
        self.assertEqual(mocks["_quiet"].call_count, 1)
        mocks["_restore_services"].assert_called_once()
        mocks["_publish_baseline"].assert_not_called()

    def test_application_stop_failure_recovers_and_does_not_publish_baseline(self):
        with fake_operation() as mocks:
            mocks["_quiet"].side_effect = [None, None, operation.RebootError()]
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "application_stop_failed")
        mocks["_restore_services"].assert_called_once()
        mocks["_publish_baseline"].assert_not_called()

    def test_changed_quiescent_live_or_settings_prevents_reboot_and_restores(self):
        for field in ("_semantic_database", "_settings", "_boot_id"):
            with self.subTest(field=field), fake_operation() as mocks:
                if field == "_semantic_database":
                    changed = semantics(); changed["tables"]["artifacts"]["sha256"] = "e" * 64
                    mocks[field].side_effect = [semantics(), changed]
                elif field == "_settings":
                    mocks[field].side_effect = [baseline()["settings"], {}]
                else:
                    mocks[field].side_effect = [OLD_BOOT, NEW_BOOT]
                result = operation.run(config())
            self.assertEqual(result["failure_reason"], "live_baseline_failed")
            self.assertFalse(result["reboot_scheduled"])
            mocks["_publish_baseline"].assert_not_called()
            mocks["_restore_services"].assert_called_once()

    def test_schedule_failure_keeps_private_claim_prevents_duplicate_and_recovers(self):
        with fake_operation() as mocks:
            mocks["_transient"].side_effect = [None, operation.RebootError()]
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "scheduling_failed")
        self.assertTrue(result["private_baseline_saved"])
        self.assertFalse(result["reboot_scheduled"])
        self.assertEqual([call.args[0] for call in mocks["_stop_transient"].call_args_list], [operation.REBOOT_UNIT, operation.RESUME_UNIT])
        mocks["_restore_services"].assert_called_once()

    def test_failed_immediate_restore_preserves_failsafe_and_reports_failure(self):
        with fake_operation() as mocks:
            mocks["_idle_database"].side_effect = operation.RebootError()
            mocks["_restore_services"].side_effect = RuntimeError("PRIVATE")
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "fallback_recovery_failed")
        self.assertFalse(result["fallback_recovery_verified"])
        self.assertFalse(result["services_restored"])
        mocks["_stop_transient"].assert_not_called()
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_verify_requires_an_actual_new_boot_and_never_schedules_services(self):
        with fake_operation() as mocks:
            result = operation.run(config(), "verify-reboot")
        self.assertEqual(result["failure_reason"], "boot_not_changed_or_invalid_baseline")
        mocks["audit_run"].assert_not_called()
        mocks["_quiet"].assert_not_called()
        mocks["_transient"].assert_not_called()

    def test_verify_passes_only_with_data_settings_peers_and_worker_preserved(self):
        with fake_operation() as mocks:
            mocks["_boot_id"].return_value = NEW_BOOT
            result = operation.run(config(), "verify-reboot")
        self.assertEqual(result["status"], "success")
        for field in ("boot_changed", "services_restored", "database_preserved", "peer_containers_preserved", "settings_preserved", "worker_exclusivity_verified"):
            self.assertTrue(result[field])
        self.assertFalse(result["reboot_scheduled"])
        self.assertFalse(result["new_calculation_verified"])
        mocks["_quiet"].assert_not_called()
        mocks["_restore_services"].assert_not_called()
        self.assertEqual(operation.sanitize_report(json.dumps(result).encode()), result)

    def test_verify_refuses_changed_data_peer_or_settings_without_repairing(self):
        for field, reason in (("_semantic_database", "database_changed"), ("_peer_state", "peer_containers_changed"), ("_settings", "settings_changed")):
            with self.subTest(field=field), fake_operation() as mocks:
                mocks["_boot_id"].return_value = NEW_BOOT
                if field == "_semantic_database":
                    changed = semantics(); changed["tables"]["runs"]["rows"] += 1
                    mocks[field].return_value = changed
                else:
                    mocks[field].return_value = {}
                result = operation.run(config(), "verify-reboot")
            self.assertEqual(result["failure_reason"], reason)
            mocks["_quiet"].assert_not_called()
            mocks["_transient"].assert_not_called()

    def test_reports_are_exact_typed_and_cannot_inflate_reboot_request_scope(self):
        request = report_success("reboot-recovery")
        verify = report_success("verify-reboot")
        for original, field in ((request, "boot_changed"), (request, "database_preserved"), (verify, "reboot_scheduled"), (verify, "application_stopped"), (request, "new_calculation_verified"), (verify, "off_host_backup_verified_by_server")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.validate_report({**original, field: True})
        for field in operation.BOOLEANS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.validate_report({**request, field: 1})
        for field in operation.COUNTS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.validate_report({**request, field: True})
        for raw in (b"", b"\xff", b"x" * 8193, json.dumps({**request, "token": TOKEN}).encode(),
                    json.dumps(request).encode()[:-1] + b',"status":"success"}'):
            self.assertIsNone(operation.sanitize_report(raw))

    def test_typed_hash_encoding_distinguishes_types_boundaries_and_blob_content(self):
        values = [None, 1, 1.0, "1", b"1", "", b"", 0.0, -0.0]
        self.assertEqual(len({operation._typed(value) for value in values}), len(values))
        for value in (True, float("nan"), float("inf"), [], {}):
            with self.assertRaises(operation.RebootError):
                operation._typed(value)
        with patch.object(operation, "MAX_VALUE_BYTES", 2), self.assertRaises(operation.RebootError):
            operation._typed(b"abc")

    def make_database(self, path, *, reverse=False):
        with sqlite3.connect(path) as db:
            for name in operation.TABLES:
                db.execute("CREATE TABLE " + name + "(value)") if name != "runs" else db.execute("CREATE TABLE runs(value,status)")
            rows = [(1,), ("1",), (b"artifact-one",), (None,)]
            for name in operation.TABLES:
                if name == "runs":
                    db.executemany("INSERT INTO runs VALUES (?,?)", [("run-one", "SUCCEEDED"), ("run-two", "CANCELLED")])
                else:
                    db.executemany("INSERT INTO " + name + " VALUES (?)", list(reversed(rows)) if reverse else rows)

    def test_real_sqlite_semantics_ignore_layout_and_row_order_but_include_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / "a.sqlite3", Path(directory) / "b.sqlite3"
            self.make_database(a); self.make_database(b, reverse=True)
            with patch.object(helper, "_private_file", side_effect=lambda p, device: p.stat()):
                original = operation._semantic_database(a, a.stat().st_dev)
                self.assertEqual(original, operation._semantic_database(b, b.stat().st_dev))
                with sqlite3.connect(b) as db:
                    db.execute("VACUUM")
                self.assertEqual(original, operation._semantic_database(b, b.stat().st_dev))
                with sqlite3.connect(b) as db:
                    db.execute("UPDATE artifacts SET value=? WHERE typeof(value)='blob'", (b"artifact-two",))
                changed = operation._semantic_database(b, b.stat().st_dev)
                self.assertNotEqual(original["tables"]["artifacts"]["sha256"], changed["tables"]["artifacts"]["sha256"])
                self.assertEqual(original["tables"]["artifacts"]["rows"], changed["tables"]["artifacts"]["rows"])

    def test_real_sqlite_nonterminal_rows_unknown_status_schema_and_limits_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db.sqlite3"
            self.make_database(path)
            with patch.object(helper, "_private_file", side_effect=lambda p, device: p.stat()):
                with sqlite3.connect(path) as db:
                    db.execute("UPDATE runs SET status='QUEUED'")
                value = operation._semantic_database(path, path.stat().st_dev)
                with self.assertRaises(operation.RebootError):
                    operation._validate_semantics(value)
                with sqlite3.connect(path) as db:
                    db.execute("UPDATE runs SET status='UNRECOGNIZED'")
                with self.assertRaises(operation.RebootError):
                    operation._semantic_database(path, path.stat().st_dev)
                with sqlite3.connect(path) as db:
                    db.execute("UPDATE runs SET status='SUCCEEDED'")
                    db.execute("CREATE TABLE unexpected(value)")
                with self.assertRaises(operation.RebootError):
                    operation._semantic_database(path, path.stat().st_dev)

    def test_backup_baseline_is_fresh_same_boot_exact_and_hash_verified(self):
        base = backup()
        with patch.object(helper, "_read_root", return_value=json.dumps(base).encode()), \
                patch.object(operation, "_boot_id", return_value=OLD_BOOT), patch.object(operation, "_recent"), \
                patch.object(operation.os, "lstat", return_value=types.SimpleNamespace(st_dev=1)), \
                patch.object(helper, "_private_dir"), patch.object(helper, "_children"), patch.object(helper, "_private_file"), \
                patch.object(helper, "_hash", return_value=(100, bytes.fromhex("d" * 64))):
            self.assertEqual(operation._backup_baseline(), (base, SNAPSHOT, 1))
        for changes in ({"boot_id": NEW_BOOT}, {"database_size": True}, {"source_sha": "a" * 40},
                        {"snapshot": "../escape"}, {"extra": "private"}):
            with patch.object(helper, "_read_root", return_value=json.dumps({**base, **changes}).encode()), \
                    patch.object(operation, "_boot_id", return_value=OLD_BOOT), self.assertRaises(operation.RebootError):
                operation._backup_baseline()

    def test_recency_rejects_future_and_older_than_twenty_four_hours(self):
        with patch.object(operation.time, "time", return_value=100000):
            for value in (None, "PRIVATE", "1970-01-01T00:00:00Z", "2099-01-01T00:00:00Z"):
                with self.subTest(value=value), self.assertRaises((operation.RebootError, ValueError)):
                    operation._recent(value)

    def test_reboot_baseline_real_no_replace_and_private_single_link(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recovery-reboot.json"
            with patch.object(operation, "REBOOT_BASELINE", path), patch.object(helper, "_root_parents"), \
                    patch.object(helper, "_read_root", side_effect=lambda p, **kw: p.read_bytes()):
                operation._publish_baseline(baseline())
                original = path.read_bytes()
                self.assertEqual(json.loads(original), baseline())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
                with self.assertRaises(operation.RebootError):
                    operation._publish_baseline({**baseline(), "operation_id": "other"})
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_reboot_baseline_symlink_never_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "baseline"; target = root / "target"
            target.write_bytes(b"original"); path.symlink_to(target)
            with patch.object(operation, "REBOOT_BASELINE", path), patch.object(helper, "_root_parents"), self.assertRaises(operation.RebootError):
                operation._publish_baseline(baseline())
            self.assertEqual(target.read_bytes(), b"original")

    def test_fixed_transient_unit_and_command_have_no_arbitrary_request_input(self):
        with patch.object(helper, "_quiet") as quiet, patch.object(audit, "_unit_properties", return_value={"LoadState": "loaded", "ActiveState": "active"}):
            operation._transient(operation.REBOOT_UNIT, 10, ["/usr/bin/systemctl", "reboot"])
        command = quiet.call_args.args[0]
        self.assertEqual(command[:4], ["/usr/bin/systemd-run", "--quiet", "--collect", "--unit=quanta-recovery-reboot"])
        self.assertIn("--on-active=10s", command)
        self.assertEqual(command[-2:], ["/usr/bin/systemctl", "reboot"])
        with patch.object(audit, "_unit_properties", return_value={"LoadState": "loaded"}), self.assertRaises(operation.RebootError):
            operation._absent_transients()

    def test_transient_cleanup_accepts_collected_service_and_verifies_timer_cancellation(self):
        values = [{"LoadState": "loaded", "ActiveState": "active"},
                  {"LoadState": "not-found", "ActiveState": "inactive"},
                  {"LoadState": "not-found", "ActiveState": "inactive"}]
        with patch.object(audit, "_unit_properties", side_effect=values) as query, patch.object(helper, "_quiet") as quiet:
            operation._stop_transient(operation.RESUME_UNIT)
        quiet.assert_called_once_with(["/usr/bin/systemctl", "stop", operation.RESUME_UNIT + ".timer"], timeout=10)
        self.assertEqual([call.args[0] for call in query.call_args_list], [operation.RESUME_UNIT + ".timer", operation.RESUME_UNIT + ".timer", operation.RESUME_UNIT + ".service"])

    def test_transient_stop_failure_is_tolerated_only_when_inactive_is_observed(self):
        for final, valid in (({"LoadState": "not-found", "ActiveState": "inactive"}, True),
                             ({"LoadState": "loaded", "ActiveState": "active"}, False)):
            values = [{"LoadState": "loaded", "ActiveState": "active"}, final,
                      {"LoadState": "not-found", "ActiveState": "inactive"}]
            with patch.object(audit, "_unit_properties", side_effect=values), \
                    patch.object(helper, "_quiet", side_effect=helper.VerificationError()):
                if valid:
                    operation._stop_transient(operation.RESUME_UNIT)
                else:
                    with self.assertRaises(operation.RebootError):
                        operation._stop_transient(operation.RESUME_UNIT)

    def test_compare_collects_safe_generation_difference_without_stopping_or_locking(self):
        changed = semantics(); changed["tables"]["runs"]["rows"] += 1
        with fake_operation() as mocks, patch.object(audit, "_unit_properties", return_value={"LoadState": "not-found", "ActiveState": "inactive"}):
            mocks["_semantic_database"].side_effect = [semantics(), changed]
            result = operation.run(config(), "compare-recovery")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["action"], "compare-recovery")
        self.assertFalse(result["all_tables_match"])
        self.assertFalse(result["runs_matches"])
        self.assertEqual(result["live_runs_rows"], result["snapshot_runs_rows"] + 1)
        self.assertFalse(result["server_modified"])
        mocks["_backup_baseline"].assert_called_once_with(require_current_boot=False)
        mocks["_operation_lock"].assert_not_called()
        mocks["_quiet"].assert_not_called()
        mocks["_publish_baseline"].assert_not_called()
        self.assertEqual(operation.sanitize_report(json.dumps(result).encode()), result)

    def test_compare_database_read_failure_exposes_stage_but_not_private_exception(self):
        with fake_operation() as mocks:
            mocks["_semantic_database"].side_effect = [semantics(), RuntimeError("PRIVATE TOKEN")]
            result = operation.run(config(), "compare-recovery")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stage"], "live_database")
        self.assertTrue(result["snapshot_checked"])
        self.assertFalse(result["live_checked"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        mocks["_quiet"].assert_not_called()

    def test_compare_report_rejects_unknown_values_and_any_modification_claim(self):
        with fake_operation(), patch.object(audit, "_unit_properties", return_value={"LoadState": "not-found", "ActiveState": "inactive"}):
            valid = operation.run(config(), "compare-recovery")
        self.assertTrue(valid["all_tables_match"])
        for changed in ({**valid, "server_modified": True}, {**valid, "private_path": "/private"},
                        {**valid, "runs_matches": 1}, {**valid, "live_runs_rows": True},
                        {**valid, "runs_matches": False}, {**valid, "snapshot_checked": False}):
            with self.assertRaises(ValueError):
                operation.validate_report(changed)

    def test_failed_reboot_comparison_records_fixed_detail_separately_from_cleanup(self):
        changed = semantics(); changed["tables"]["revisions"]["rows"] += 1
        with fake_operation() as mocks:
            mocks["_semantic_database"].side_effect = [semantics(), changed]
            result = operation.run(config())
        self.assertEqual(result["comparison_detail"], "table_mismatch")
        self.assertEqual(result["cleanup_detail"], "complete")
        self.assertTrue(result["fallback_recovery_verified"])
        with self.assertRaises(ValueError):
            operation.validate_report({**result, "comparison_detail": "PRIVATE"})

    def test_reboot_host_checks_do_not_inventory_or_require_any_sqlite_snapshot(self):
        def installation(config, report):
            report.update(source_verified=True, storage_verified=True, boot_id_valid=True)
            return "sha256:" + "a" * 64, 1, TOKEN
        def services(report):
            for field in ("app_active", "app_enabled", "https_active", "https_enabled", "docker_active", "docker_enabled",
                          "backup_timer_active", "backup_timer_enabled", "backup_services_idle"):
                report[field] = True
        def containers(image, report):
            report.update(single_app_container=True, peer_restart_policies_safe=True)
        def worker(report, device):
            report["worker_exclusivity_verified"] = True
        def database(report, device):
            report.update(database_checked=True, no_pending_runs=True)
        with patch.object(audit, "_installation", side_effect=installation), patch.object(audit, "_services", side_effect=services), \
                patch.object(audit, "_ready", return_value=True), patch.object(audit, "_containers", side_effect=containers), \
                patch.object(audit, "_worker", side_effect=worker), patch.object(audit, "_database", side_effect=database), \
                patch.object(helper.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * 1024**3)), \
                patch.object(audit, "_backups", side_effect=AssertionError("snapshot inventory is not a reboot gate")) as snapshots, \
                patch.object(audit, "run", side_effect=AssertionError("full audit includes snapshot inventory")):
            report, device, token = operation._reboot_audit(config())
        self.assertFalse(report["latest_snapshot_present"])
        self.assertTrue(report["sufficient_disk_space"])
        self.assertEqual((device, token), (1, TOKEN))
        snapshots.assert_not_called()

    def test_new_policy_does_not_remove_other_required_host_checks(self):
        for missing in ("worker_exclusivity_verified", "backup_services_idle", "peer_restart_policies_safe", "sufficient_disk_space"):
            def installation(config, report):
                report.update({field: True for field in audit.PREREQUISITES if field != "latest_snapshot_present"})
                report[missing] = False
                return "sha256:" + "a" * 64, 1, TOKEN
            with self.subTest(missing=missing), patch.object(audit, "_installation", side_effect=installation), \
                    patch.object(audit, "_services"), patch.object(audit, "_ready", return_value=True), \
                    patch.object(audit, "_containers"), patch.object(audit, "_worker"), patch.object(audit, "_database"), \
                    patch.object(helper.shutil, "disk_usage", return_value=types.SimpleNamespace(free=0 if missing == "sufficient_disk_space" else 2 * 1024**3)), \
                    self.assertRaises(operation.RebootError):
                operation._reboot_audit(config())

    def test_version_two_baseline_keeps_core_identity_and_marks_policy_as_user_report(self):
        current = baseline()
        current.pop("backup"); current.pop("external_copy_verification")
        current.update(schema_version=2, database_basis=operation.DATABASE_BASIS,
                       backup_policy_basis=operation.BACKUP_POLICY_BASIS, backup_policy_console_verified=False)
        for value in (baseline(), current):
            with patch.object(helper, "_read_root", return_value=json.dumps(value).encode()), patch.object(operation, "_recent"):
                self.assertEqual(operation._read_reboot_baseline(), value)
        for changes in ({"backup_policy_console_verified": True}, {"database_basis": "old_snapshot"},
                        {"backup_policy_basis": "verified_by_agent"}, {"schema_version": 3}):
            with patch.object(helper, "_read_root", return_value=json.dumps({**current, **changes}).encode()), \
                    patch.object(operation, "_recent"), self.assertRaises(operation.RebootError):
                operation._read_reboot_baseline()

    def test_new_policy_reports_cannot_claim_snapshot_or_console_verification(self):
        valid = report_success("reboot-recovery")
        for field in ("snapshot_semantics_matched", "backup_baseline_verified", "backup_policy_console_verified"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.validate_report({**valid, field: True})
        for changes in ({"quiescent_live_baseline_verified": False}, {"baseline_schema_version": 1},
                        {"prerequisite_basis": "legacy_full_backup_audit"}):
            with self.assertRaises(ValueError):
                operation.validate_report({**valid, **changes})

    def test_reader_identity_drops_effective_gid_then_uid_and_restores_both(self):
        with fake_root_identity() as (state, events):
            with operation._store_reader_identity():
                self.assertEqual(state, {"uid": 10001, "gid": 10001})
                self.assertEqual(operation.os.getuid(), 0)
            self.assertEqual(state, {"uid": 0, "gid": 0})
        self.assertEqual(events, [("gid", 10001), ("uid", 10001), ("uid", 0), ("gid", 0)])

    def test_partial_identity_entry_failures_restore_original_effective_ids(self):
        for failed in ("uid", "gid"):
            with self.subTest(failed=failed), fake_root_identity(failed) as (state, events):
                with self.assertRaises(OSError):
                    with operation._store_reader_identity():
                        self.fail("partial entry was accepted")
                self.assertEqual(state, {"uid": 0, "gid": 0})
                self.assertEqual(events[-2:], [("uid", 0), ("gid", 0)])

    def test_identity_transition_masks_restore_original_mask_after_partial_failure(self):
        original = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        with fake_root_identity("uid"):
            with self.assertRaises(OSError):
                with operation._store_reader_identity():
                    pass
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), original)

    def test_pending_hangup_during_identity_entry_restores_root_before_propagation(self):
        original_handler = signal.getsignal(signal.SIGHUP)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        def interrupted(signum, frame):
            raise operation.RebootError()
        signal.signal(signal.SIGHUP, interrupted)
        try:
            with fake_root_identity() as (state, events):
                original_setuid = operation.os.seteuid.side_effect
                def setuid_with_signal(value):
                    original_setuid(value)
                    if value == 10001:
                        os.kill(os.getpid(), signal.SIGHUP)
                operation.os.seteuid.side_effect = setuid_with_signal
                with self.assertRaises(operation.RebootError):
                    with operation._store_reader_identity():
                        self.fail("pending hangup should propagate before SQL work")
                self.assertEqual(state, {"uid": 0, "gid": 0})
        finally:
            signal.signal(signal.SIGHUP, original_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

    def test_pending_deadline_during_restore_propagates_only_after_gid_and_uid_restore(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        observed = []
        def deadline(signum, frame):
            observed.append(dict(state))
            raise helper.VerificationError()
        signal.signal(signal.SIGALRM, deadline)
        try:
            with fake_root_identity() as (state, events):
                original_setuid = operation.os.seteuid.side_effect
                def setuid_with_signal(value):
                    original_setuid(value)
                    if value == 0:
                        os.kill(os.getpid(), signal.SIGALRM)
                operation.os.seteuid.side_effect = setuid_with_signal
                with self.assertRaises(helper.VerificationError):
                    with operation._store_reader_identity():
                        self.assertEqual(state["uid"], 10001)
                self.assertEqual(state, {"uid": 0, "gid": 0})
                self.assertEqual(observed, [{"uid": 0, "gid": 0}])
        finally:
            signal.signal(signal.SIGALRM, original_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

    def test_reader_refuses_effective_root_without_real_root_restore_guarantee(self):
        with patch.object(operation.os, "geteuid", return_value=0), patch.object(operation.os, "getegid", return_value=0), \
                patch.object(operation.os, "getuid", return_value=1000), patch.object(operation.os, "seteuid") as uid, \
                patch.object(operation.os, "setegid") as gid, self.assertRaises(operation.RebootError):
            with operation._store_reader_identity():
                pass
        uid.assert_not_called(); gid.assert_not_called()

    def test_sql_exception_restores_root_before_final_metadata_checks(self):
        path = Path("/synthetic/jobs.sqlite3")
        with fake_root_identity() as (state, events):
            metadata_ids = []
            def metadata(path, device):
                metadata_ids.append((state["uid"], state["gid"]))
                return types.SimpleNamespace(st_dev=1, st_ino=2)
            def read(path):
                self.assertEqual(state, {"uid": 10001, "gid": 10001})
                raise sqlite3.OperationalError("PRIVATE SQLITE DETAIL")
            with patch.object(helper, "_private_file", side_effect=metadata), \
                    patch.object(operation, "_check_auxiliary_files"), patch.object(operation, "_read_semantics", side_effect=read), \
                    self.assertRaises(sqlite3.OperationalError):
                operation._semantic_database(path, 1)
            self.assertEqual(state, {"uid": 0, "gid": 0})
            self.assertEqual(metadata_ids, [(0, 0), (0, 0)])

    def test_deadline_during_sql_read_restores_effective_root(self):
        import time
        with fake_root_identity() as (state, events):
            with patch.object(helper, "_private_file", return_value=types.SimpleNamespace(st_dev=1, st_ino=2)), \
                    patch.object(operation, "_check_auxiliary_files"), \
                    patch.object(operation, "_read_semantics", side_effect=lambda path: time.sleep(0.2)), \
                    self.assertRaises(helper.VerificationError):
                with helper._deadline(0.02):
                    operation._semantic_database(Path("/synthetic/jobs.sqlite3"), 1)
            self.assertEqual(state, {"uid": 0, "gid": 0})

    def test_unexpected_auxiliary_ownership_is_refused_without_repair_or_sql_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jobs.sqlite3"; path.write_bytes(b"untouched database")
            wal = path.with_name(path.name + "-wal"); wal.write_bytes(b"unmodified WAL recovery bytes")
            def metadata(item, device):
                if item == wal:
                    raise helper.VerificationError()
                return path.stat()
            with patch.object(helper, "_private_file", side_effect=metadata), \
                    patch.object(operation.sqlite3, "connect") as connect, \
                    patch.object(operation.os, "chown") as chown, patch.object(operation.os, "chmod") as chmod, \
                    self.assertRaises(operation.AuxiliaryFileError):
                operation._semantic_database(path, path.stat().st_dev)
            connect.assert_not_called(); chown.assert_not_called(); chmod.assert_not_called()
            self.assertEqual(path.read_bytes(), b"untouched database")
            self.assertEqual(wal.read_bytes(), b"unmodified WAL recovery bytes")

    def test_actual_wal_reader_includes_committed_wal_and_aux_files_keep_reader_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jobs.sqlite3"
            self.make_database(path)
            writer = sqlite3.connect(path)
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("INSERT INTO artifacts VALUES (?)", (b"committed-only-in-WAL",))
            writer.commit()
            try:
                with patch.object(helper, "_private_file", side_effect=lambda p, device: p.stat()):
                    value = operation._semantic_database(path, path.stat().st_dev)
                self.assertEqual(value["tables"]["artifacts"]["rows"], 5)
                for suffix in ("-wal", "-shm"):
                    info = path.with_name(path.name + suffix).stat()
                    self.assertEqual((info.st_uid, info.st_gid), (os.geteuid(), os.getegid()))
            finally:
                writer.close()

    def test_auxiliary_refusal_uses_fixed_diagnostic_instead_of_raw_metadata(self):
        with fake_operation() as mocks:
            mocks["_semantic_database"].side_effect = operation.AuxiliaryFileError("PRIVATE")
            result = operation.run(config(), "compare-recovery")
        self.assertEqual(result["failure_reason"], "auxiliary_metadata_refused")
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertIsNotNone(operation.sanitize_report(json.dumps(result).encode()))

    def test_real_live_generation_can_exceed_old_snapshot_but_postboot_remains_exact(self):
        real_semantic = operation._semantic_database
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"; data.mkdir()
            live = data / "jobs.sqlite3"
            old = Path(directory) / "older-snapshot.sqlite3"
            self.make_database(live); self.make_database(old)
            with sqlite3.connect(live) as db:
                db.execute("INSERT INTO experiments VALUES (?)", ("new user experiment",))
                db.execute("INSERT INTO revisions VALUES (?)", ("new user revision",))
                db.execute("INSERT INTO runs VALUES (?,?)", ("new-user-run", "SUCCEEDED"))
                db.execute("INSERT INTO artifacts VALUES (?)", (b"new user artifact",))
            with fake_operation() as mocks, patch.object(helper, "DATA", data), \
                    patch.object(helper, "_private_file", side_effect=lambda path, device: path.stat()):
                mocks["_backup_baseline"].side_effect = AssertionError("old backup must not be a reboot prerequisite")
                mocks["_semantic_database"].side_effect = real_semantic
                result = operation.run(config(), "reboot-recovery")
                self.assertEqual(result["status"], "success")
                saved = mocks["_publish_baseline"].call_args.args[0]
                self.assertEqual(saved["schema_version"], 2)
                self.assertNotIn("backup", saved)
                self.assertFalse(saved["backup_policy_console_verified"])
                self.assertEqual(saved["database"]["tables"]["runs"]["rows"], 3)
                self.assertEqual(saved["database"]["tables"]["experiments"]["rows"], 5)
                self.assertTrue(all(call.args[0] == live for call in mocks["_semantic_database"].call_args_list))
                mocks["_read_reboot_baseline"].return_value = saved
                mocks["_boot_id"].return_value = NEW_BOOT
                verified = operation.run(config(), "verify-reboot")
                self.assertEqual(verified["status"], "success")
                self.assertTrue(verified["database_preserved"])
                self.assertEqual(verified["baseline_schema_version"], 2)
                with sqlite3.connect(live) as db:
                    db.execute("UPDATE artifacts SET value=? WHERE typeof(value)='blob'", (b"unexpected changed bytes",))
                changed = operation.run(config(), "verify-reboot")
                self.assertEqual(changed["failure_reason"], "database_changed")
                mocks["_backup_baseline"].assert_not_called()

    def test_idle_database_requires_no_pending_runs(self):
        def pending(report, device):
            report.update(database_checked=True, no_pending_runs=False)
        with patch.object(audit, "_database", side_effect=pending), self.assertRaises(operation.RebootError):
            operation._idle_database(1)

    def test_backup_racing_timer_pause_is_not_interrupted_by_app_stop_or_reboot(self):
        with fake_operation() as mocks:
            mocks["_idle_backups"].side_effect = operation.RebootError()
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "admission_barrier_failed")
        self.assertTrue(result["backup_timer_paused"])
        self.assertFalse(result["application_stopped"])
        self.assertEqual([call.args[0] for call in mocks["_quiet"].call_args_list], [
            ["/usr/bin/systemctl", "stop", operation.HTTPS], ["/usr/bin/systemctl", "stop", operation.TIMER]])
        mocks["_restore_services"].assert_called_once()
        mocks["_publish_baseline"].assert_not_called()

    def test_backup_idle_rejects_active_activating_or_unknown_services(self):
        for state in ("active", "activating", "deactivating", "unknown"):
            with patch.object(audit, "_unit_properties", return_value={"LoadState": "loaded", "ActiveState": state}), self.assertRaises(operation.RebootError):
                operation._idle_backups()
        for value in ({"LoadState": "loaded", "ActiveState": "inactive"},
                      {"LoadState": "not-found", "ActiveState": "inactive"}):
            with patch.object(audit, "_unit_properties", return_value=value):
                operation._idle_backups()

    def test_restore_services_checks_both_active_and_authenticated_readiness(self):
        with patch.object(helper, "_quiet") as quiet, patch.object(operation, "_service_state") as state, \
                patch.object(operation, "_timer_enabled") as enabled, patch.object(operation, "_wait_ready") as ready:
            operation._restore_services(config(), TOKEN)
        quiet.assert_called_once_with(["/usr/bin/systemctl", "start", operation.APP, operation.HTTPS, operation.TIMER], timeout=90)
        self.assertEqual([call.args for call in state.call_args_list], [(operation.APP, "active"), (operation.HTTPS, "active"), (operation.TIMER, "active")])
        enabled.assert_called_once_with()
        ready.assert_called_once_with(config(), TOKEN)

    def test_real_http_warmup_requires_authenticated_ready_before_canceling_fallback(self):
        calls = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.path, self.headers.get("Authorization"), self.headers.get("Host")))
                ready = len(calls) >= 3
                self.send_response(200 if ready else 503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ready"}' if ready else b'{"status":"starting"}')
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = helper.http.client.HTTPConnection
        try:
            with patch.object(helper.http.client, "HTTPConnection", side_effect=lambda host, port, timeout: connection("127.0.0.1", server.server_port, timeout=timeout)), \
                    patch.object(helper, "_quiet"), patch.object(operation, "_service_state"), patch.object(operation, "_timer_enabled"):
                operation._restore_services(config(), TOKEN)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(item == ("/health/ready", "Bearer " + TOKEN, "app.example.net") for item in calls))

    def test_readiness_failure_has_a_fixed_deadline(self):
        with patch.object(operation, "READINESS_TIMEOUT", 0.02), \
                patch.object(helper, "_ready", side_effect=ConnectionRefusedError()), self.assertRaises(operation.RebootError):
            operation._wait_ready(config(), TOKEN)

    def test_signal_handler_restored_after_interruption(self):
        original = signal.getsignal(signal.SIGHUP)
        with self.assertRaises(operation.RebootError):
            with operation._interruptions():
                os.kill(os.getpid(), signal.SIGHUP)
        self.assertIs(signal.getsignal(signal.SIGHUP), original)

    def test_main_requires_fixed_second_action_and_emits_only_public_report(self):
        encoded = base64.b64encode(json.dumps(config(), sort_keys=True, separators=(",", ":")).encode()).decode()
        for args in ([], [encoded], [encoded, "shell"], ["%%%", "verify-reboot"]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(operation.main(args), 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "failed")
        with fake_operation(), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(operation.main([encoded, "reboot-recovery"]), 0)
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["action"], "reboot-recovery")


if __name__ == "__main__":
    unittest.main()
