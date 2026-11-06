"""Recovery backup tests use synthetic credentials and no OCI/network access."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("quanta_fixed_backup", ROOT / "deploy/oci/verify_backup.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
# The controller gives the operation this same fixed, reviewed helper namespace.
with patch.dict(sys.modules, {"quanta_fixed_backup": helper}):
    SPEC = importlib.util.spec_from_file_location("quanta_recovery_backup_test", ROOT / "deploy/oci/recovery_backup.py")
    operation = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(operation)

TOKEN = "b" * 64
IMAGE = "sha256:" + "a" * 64
BOOT = "2db9768f-4509-4204-926c-e0b9334c6052"
SNAPSHOT = Path("/srv/quanta/backups/20261106T040506Z-1c1205b707954369af8ea9ad2c9ba5ca")
SCRATCH = Path("/srv/quanta/restore-verification-1c1205b707954369af8ea9ad2c9ba5ca")


def config():
    return {"source_sha": operation.SOURCE_SHA, "public_origin": "https://app.example.net", "auth_mode": "owner-token"}


def success(action="prepare-recovery"):
    return {"scope": "recovery_backup_preparation", "action": action, "status": "success", "stage": "complete",
            "failure_reason": "none", **dict.fromkeys(operation.REQUIRED_SUCCESS, True),
            "off_host_backup_verified": False, "operating_system_rebooted": False,
            "previous_baseline_archived": action == "refresh-recovery", "baseline_refreshed": action == "refresh-recovery"}


def previous():
    return {"raw": b"old-private-baseline", "identity": (1, 2, 3, 4), "value": {"boot_id": BOOT}}


@contextlib.contextmanager
def fake_operation():
    with contextlib.ExitStack() as stack:
        mocks = {}
        values = {
            "_preflight": (IMAGE, 1, TOKEN, ("production-identity",), ("active", "enabled"), BOOT),
            "_operation_lock": contextlib.nullcontext(), "_services_idle": None,
            "_timer_state": ("active", "enabled"), "_boot_id": BOOT,
            "_publish_baseline": None,
            "_read_previous_baseline": previous(), "_archive_previous": Path("/etc/quanta/recovery-backup-archive-test.json"),
            "_replace_baseline": None,
        }
        for name, value in values.items():
            mocks[name] = stack.enter_context(patch.object(operation, name, return_value=value))
        values = {
            "_entries": {"earlier": ("unchanged",)}, "_quiet": None, "_names_absent": None,
            "_fresh_backup": SNAPSHOT, "_container": None, "_hash": (20, bytes.fromhex("d" * 64)),
            "_scratch": SCRATCH, "_private_dir": None, "_children": None,
            "_check_production": None,
        }
        for name, value in values.items():
            mocks[name] = stack.enter_context(patch.object(helper, name, return_value=value))
        stack.enter_context(patch.object(helper, "_deadline", side_effect=lambda seconds: contextlib.nullcontext()))
        stack.enter_context(patch.object(helper.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * 1024**3)))
        yield mocks


class RecoveryBackupTests(unittest.TestCase):
    def test_config_retains_deployed_source_and_rejects_extra_remote_inputs(self):
        self.assertEqual(operation.validate_config(config()), config())
        for value in ({**config(), "source_sha": "a" * 40}, {**config(), "path": "/private"},
                      {**config(), "auth_mode": "access"}, {**config(), "public_origin": "http://app.example.net"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                operation.validate_config(value)
        with patch.object(operation, "_operation_lock") as lock:
            result = operation.run({})
        self.assertEqual(result["failure_reason"], "configuration_invalid")
        lock.assert_not_called()

    def test_exact_report_rejects_sensitive_fields_wrong_types_and_scope_inflation(self):
        self.assertEqual(operation.sanitize_report(json.dumps(success()).encode()), success())
        cases = [{**success(), "token": TOKEN}, {**success(), "off_host_backup_verified": True},
                 {**success(), "operating_system_rebooted": True}, {**success(), "status": "failed"},
                 {**success(), "stage": "restore"}, {**success(), "failure_reason": "private-error"}]
        for field in operation.BOOLEAN_FIELDS:
            cases.extend({**success(), field: item} for item in (1, "true", None))
        for value in cases:
            with self.subTest(keys=list(value)), self.assertRaises(ValueError):
                operation.validate_report(value)

    def test_report_rejects_unordered_success_facts(self):
        for field in operation.BOOLEAN_FIELDS[1:4]:
            value = {**operation._initial_report(), field: True}
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.validate_report(value)
        with self.assertRaises(ValueError):
            operation.validate_report({**operation._initial_report(), "baseline_saved": True})

    def test_parser_discards_duplicates_nonfinite_trailing_text_and_unbounded_output(self):
        raw = json.dumps(success()).encode()
        for value in (b"", b"\xff", b"x" * 8193, raw + b"private", raw[:-1] + b',"status":"success"}',
                      b'{"status":NaN}', json.dumps({**success(), "path": "/private"}).encode()):
            with self.subTest(length=len(value)), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertIsNone(operation.sanitize_report(value))
                self.assertEqual(out.getvalue(), "")

    def test_success_starts_same_systemd_backup_service_without_timer_mutations(self):
        with fake_operation() as mocks:
            result = operation.run(config())
        self.assertEqual(result, success())
        mocks["_quiet"].assert_called_once_with(["/usr/bin/systemctl", "start", "quanta-backup-boot.service"], timeout=200)
        mocks["_fresh_backup"].assert_called_once_with({"earlier": ("unchanged",)}, 1)
        calls = mocks["_container"].call_args_list
        self.assertEqual(calls[0].args[-1], ["verify-backup", "/backup"])
        self.assertEqual(calls[1].args[-1], ["restore-store", "/backup", "--output", "/restore/store"])
        self.assertEqual(calls[1].kwargs, {"scratch": SCRATCH})
        mocks["_publish_baseline"].assert_called_once_with(SNAPSHOT, (20, bytes.fromhex("d" * 64)), BOOT)
        self.assertFalse(result["off_host_backup_verified"])
        self.assertFalse(result["operating_system_rebooted"])

    def test_busy_operation_does_not_run_preflight_or_backup(self):
        with fake_operation() as mocks:
            mocks["_operation_lock"].side_effect = helper.VerificationError()
            result = operation.run(config())
        self.assertEqual(result["stage"], "lock")
        self.assertEqual(result["failure_reason"], "operation_busy_or_unsafe")
        mocks["_preflight"].assert_not_called()
        mocks["_quiet"].assert_not_called()

    def test_preflight_failure_does_not_start_backup(self):
        with fake_operation() as mocks:
            mocks["_preflight"].side_effect = RuntimeError("PRIVATE VALUE")
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "preflight_refused")
        self.assertNotIn("PRIVATE", json.dumps(result))
        mocks["_quiet"].assert_not_called()

    def test_backup_failure_still_observes_timer_and_production_without_changing_them(self):
        with fake_operation() as mocks:
            mocks["_quiet"].side_effect = helper.VerificationError()
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "backup_failed")
        self.assertTrue(result["production_preserved"])
        self.assertTrue(result["timer_state_preserved"])
        self.assertFalse(result["backup_created"])
        mocks["_container"].assert_not_called()
        mocks["_publish_baseline"].assert_not_called()

    def test_verifier_failure_never_restores_or_publishes_baseline(self):
        with fake_operation() as mocks:
            mocks["_container"].side_effect = helper.VerificationError()
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "snapshot_verification_failed")
        self.assertTrue(result["backup_created"])
        self.assertFalse(result["backup_verified"])
        self.assertTrue(result["timer_state_preserved"])
        mocks["_scratch"].assert_not_called()
        mocks["_publish_baseline"].assert_not_called()

    def test_restored_bytes_must_match_snapshot(self):
        with fake_operation() as mocks:
            mocks["_hash"].side_effect = [(20, b"snapshot"), (20, b"different")]
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "restore_failed")
        self.assertFalse(result["restore_verified"])
        mocks["_publish_baseline"].assert_not_called()

    def test_timer_change_or_reboot_before_baseline_is_not_accepted(self):
        for field in ("_timer_state", "_boot_id"):
            with self.subTest(field=field), fake_operation() as mocks:
                mocks[field].return_value = ("inactive", "enabled") if field == "_timer_state" else "other-boot"
                result = operation.run(config())
                self.assertEqual(result["failure_reason"], "production_or_timer_changed")
                mocks["_publish_baseline"].assert_not_called()

    def test_post_baseline_production_failure_keeps_failure_evidence(self):
        with fake_operation() as mocks:
            mocks["_check_production"].side_effect = [None, helper.VerificationError()]
            result = operation.run(config())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_reason"], "production_or_timer_changed")
        self.assertTrue(result["baseline_saved"])
        self.assertFalse(result["production_preserved"])
        self.assertIsNotNone(operation.sanitize_report(json.dumps(result).encode()))

    def test_baseline_failure_leaves_operation_failed_and_does_not_echo_error(self):
        with fake_operation() as mocks:
            mocks["_publish_baseline"].side_effect = RuntimeError("PRIVATE METADATA")
            result = operation.run(config())
        self.assertEqual(result["failure_reason"], "baseline_failed")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_timer_state_accepts_only_exact_active_enabled_fields(self):
        good = b"UnitFileState=enabled\nActiveState=active\n"
        with patch.object(helper, "_capture", return_value=good):
            self.assertEqual(operation._timer_state(), ("active", "enabled"))
        for raw in (None, good + b"Other=private\n", good.replace(b"active", b"inactive"),
                    good.replace(b"enabled", b"disabled"), b"ActiveState=active\nActiveState=active\n"):
            with self.subTest(raw=raw), patch.object(helper, "_capture", return_value=raw), self.assertRaises(helper.VerificationError):
                operation._timer_state()

    def test_only_services_not_timer_are_checked_for_inactivity(self):
        for code, valid in ((3, True), (4, True), (0, False), (1, False)):
            with patch.object(operation.subprocess, "run", return_value=types.SimpleNamespace(returncode=code)) as run:
                if valid:
                    operation._services_idle()
                    self.assertEqual(run.call_count, 2)
                else:
                    with self.assertRaises(helper.VerificationError):
                        operation._services_idle()
                self.assertTrue(all(".timer" not in " ".join(call.args[0]) for call in run.call_args_list))
                self.assertTrue(all(call.args[0][1:3] == ["is-active", "--quiet"] for call in run.call_args_list))

    def test_boot_id_is_private_canonical_and_bounded(self):
        with patch.object(helper, "_read_root", return_value=(BOOT + "\n").encode()) as read:
            self.assertEqual(operation._boot_id(), BOOT)
        read.assert_called_once_with(operation.BOOT_ID, limit=64)
        for raw in ((BOOT.upper() + "\n").encode(), BOOT.encode(), b"private", b"\xff", (BOOT + "\n\n").encode()):
            with patch.object(helper, "_read_root", return_value=raw), self.assertRaises(helper.VerificationError):
                operation._boot_id()

    def test_real_baseline_publication_is_private_atomic_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "recovery-backup.json"
            with patch.object(operation, "BASELINE", baseline), patch.object(helper, "_root_parents"), \
                    patch.object(helper, "_read_root", side_effect=lambda path, **kw: path.read_bytes()):
                operation._publish_baseline(SNAPSHOT, (20, bytes.fromhex("d" * 64)), BOOT)
                original = baseline.read_bytes()
                value = json.loads(original)
                self.assertEqual(set(value), {"schema_version", "source_sha", "boot_id", "snapshot",
                                             "database_size", "database_sha256", "created_at"})
                self.assertEqual(value["boot_id"], BOOT)
                self.assertEqual(value["snapshot"], SNAPSHOT.name)
                self.assertEqual(value["database_sha256"], "d" * 64)
                self.assertEqual(stat.S_IMODE(baseline.stat().st_mode), 0o600)
                self.assertEqual(baseline.stat().st_nlink, 1)
                self.assertEqual(list(Path(directory).iterdir()), [baseline])
                with self.assertRaises(helper.VerificationError):
                    operation._publish_baseline(SNAPSHOT, (21, bytes.fromhex("a" * 64)), BOOT)
                self.assertEqual(baseline.read_bytes(), original)

    def test_baseline_existing_symlink_and_directory_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline"
            with patch.object(operation, "BASELINE", baseline), patch.object(helper, "_root_parents"):
                baseline.symlink_to(root / "missing-target")
                with self.assertRaises(helper.VerificationError):
                    operation._baseline_absent()
                baseline.unlink()
                baseline.mkdir()
                with self.assertRaises(helper.VerificationError):
                    operation._baseline_absent()

    def test_baseline_race_never_overwrites_winner_and_cleans_own_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline"
            real_link = operation.os.link
            def collision(source, target, **kwargs):
                baseline.write_bytes(b"winner")
                return real_link(source, target, **kwargs)
            with patch.object(operation, "BASELINE", baseline), patch.object(helper, "_root_parents"), \
                    patch.object(operation.os, "link", side_effect=collision), self.assertRaises(FileExistsError):
                operation._publish_baseline(SNAPSHOT, (20, bytes.fromhex("d" * 64)), BOOT)
            self.assertEqual(baseline.read_bytes(), b"winner")
            self.assertEqual(list(Path(directory).iterdir()), [baseline])

    def test_real_operation_flock_excludes_second_request_and_releases_after_exception(self):
        original_fstat = os.fstat
        def root_metadata(fd):
            info = original_fstat(fd)
            return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                                         st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino)
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lock"
            with patch.object(operation, "LOCK", lock), patch.object(helper, "_root_parents"), \
                    patch.object(operation.os, "fstat", side_effect=root_metadata):
                with self.assertRaises(RuntimeError):
                    with operation._operation_lock():
                        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
                        with self.assertRaises(helper.VerificationError):
                            with operation._operation_lock():
                                self.fail("second request entered")
                        raise RuntimeError("test release")
                with operation._operation_lock():
                    pass

    def test_lock_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"untouched")
            link = root / "lock"
            link.symlink_to(target)
            with patch.object(operation, "LOCK", link), patch.object(helper, "_root_parents"), self.assertRaises(OSError):
                with operation._operation_lock():
                    self.fail("symlink lock entered")
            self.assertEqual(target.read_bytes(), b"untouched")

    def test_main_emits_only_public_report_and_uses_canonical_argument(self):
        encoded = base64.b64encode(json.dumps(config(), sort_keys=True, separators=(",", ":")).encode()).decode()
        with fake_operation(), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(operation.main([encoded]), 0)
        self.assertEqual(json.loads(output.getvalue()), success())
        self.assertNotIn(TOKEN, output.getvalue())
        for args in ([], ["%%%"], [encoded, "extra"]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(operation.main(args), 2)
            self.assertEqual(json.loads(output.getvalue()), operation._initial_report())

    def test_explicit_refresh_archives_known_old_marker_then_replaces_only_current_marker(self):
        with fake_operation() as mocks:
            result = operation.run(config(), "refresh-recovery")
        self.assertEqual(result, success("refresh-recovery"))
        mocks["_read_previous_baseline"].assert_called_once_with()
        mocks["_preflight"].assert_called_once_with(config(), previous=previous())
        mocks["_archive_previous"].assert_called_once_with(previous())
        mocks["_replace_baseline"].assert_called_once_with(SNAPSHOT, (20, bytes.fromhex("d" * 64)), BOOT,
            previous(), Path("/etc/quanta/recovery-backup-archive-test.json"))
        mocks["_publish_baseline"].assert_not_called()
        self.assertEqual(operation.sanitize_report(json.dumps(result).encode()), result)

    def test_refresh_refuses_invalid_old_marker_before_starting_backup(self):
        with fake_operation() as mocks:
            mocks["_read_previous_baseline"].side_effect = helper.VerificationError()
            result = operation.run(config(), "refresh-recovery")
        self.assertEqual(result["failure_reason"], "refresh_preflight_refused")
        mocks["_preflight"].assert_not_called()
        mocks["_quiet"].assert_not_called()
        mocks["_archive_previous"].assert_not_called()

    def test_refresh_archive_failure_never_replaces_current_marker(self):
        with fake_operation() as mocks:
            mocks["_archive_previous"].side_effect = helper.VerificationError()
            result = operation.run(config(), "refresh-recovery")
        self.assertEqual(result["failure_reason"], "archive_failed")
        self.assertTrue(result["production_preserved"])
        self.assertTrue(result["timer_state_preserved"])
        self.assertFalse(result["baseline_refreshed"])
        mocks["_replace_baseline"].assert_not_called()

    def test_refresh_replace_failure_reports_preserved_archive_and_no_refresh_success(self):
        with fake_operation() as mocks:
            mocks["_replace_baseline"].side_effect = helper.VerificationError()
            result = operation.run(config(), "refresh-recovery")
        self.assertEqual(result["failure_reason"], "baseline_failed")
        self.assertTrue(result["previous_baseline_archived"])
        self.assertFalse(result["baseline_refreshed"])
        self.assertIsNotNone(operation.sanitize_report(json.dumps(result).encode()))

    def test_prepare_reports_cannot_claim_refresh_and_refresh_success_requires_archive(self):
        cases = [{**success(), "previous_baseline_archived": True},
                 {**success(), "baseline_refreshed": True},
                 {**success("refresh-recovery"), "previous_baseline_archived": False},
                 {**success("refresh-recovery"), "baseline_refreshed": False},
                 {**success(), "action": "arbitrary-command"}]
        for value in cases:
            with self.assertRaises(ValueError):
                operation.validate_report(value)

    def test_real_refresh_keeps_old_bytes_in_private_single_link_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "recovery-backup.json"
            old = b'{"old":"immutable original bytes"}\n'
            baseline.write_bytes(old); baseline.chmod(0o600)
            prior = {"raw": old, "identity": operation._identity(baseline), "value": {"boot_id": BOOT}}
            with patch.object(operation, "BASELINE", baseline), patch.object(operation, "REBOOT_BASELINE", Path(directory) / "reboot.json"), \
                    patch.object(helper, "_root_parents"), patch.object(helper, "_read_root", side_effect=lambda p, **kw: p.read_bytes()):
                archive = operation._archive_previous(prior)
                operation._replace_baseline(SNAPSHOT, (20, bytes.fromhex("d" * 64)), BOOT, prior, archive)
            self.assertEqual(archive.read_bytes(), old)
            self.assertNotEqual(baseline.read_bytes(), old)
            self.assertEqual(json.loads(baseline.read_bytes())["snapshot"], SNAPSHOT.name)
            for path in (archive, baseline):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(set(Path(directory).iterdir()), {archive, baseline})

    def test_refresh_does_not_replace_concurrently_changed_known_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "recovery-backup.json"
            baseline.write_bytes(b"known-old-marker"); baseline.chmod(0o600)
            prior = {"raw": baseline.read_bytes(), "identity": operation._identity(baseline), "value": {"boot_id": BOOT}}
            with patch.object(operation, "BASELINE", baseline), patch.object(operation, "REBOOT_BASELINE", Path(directory) / "reboot.json"), \
                    patch.object(helper, "_root_parents"), patch.object(helper, "_read_root", side_effect=lambda p, **kw: p.read_bytes()):
                archive = operation._archive_previous(prior)
                baseline.write_bytes(b"concurrent-new-marker")
                with self.assertRaises(helper.VerificationError):
                    operation._replace_baseline(SNAPSHOT, (20, bytes.fromhex("d" * 64)), BOOT, prior, archive)
            self.assertEqual(baseline.read_bytes(), b"concurrent-new-marker")
            self.assertEqual(archive.read_bytes(), b"known-old-marker")
            self.assertEqual(set(Path(directory).iterdir()), {archive, baseline})

    def test_refresh_refuses_any_existing_reboot_claim_and_does_not_touch_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            claim = Path(directory) / "reboot.json"
            claim.write_bytes(b"existing claim")
            with patch.object(operation, "REBOOT_BASELINE", claim), patch.object(helper, "_root_parents"), \
                    self.assertRaises(helper.VerificationError):
                operation._reboot_baseline_absent()
            self.assertEqual(claim.read_bytes(), b"existing claim")

    def test_refresh_archive_collision_never_overwrites_any_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "recovery-backup.json"
            baseline.write_bytes(b"old marker"); baseline.chmod(0o600)
            prior = {"raw": baseline.read_bytes(), "identity": operation._identity(baseline), "value": {"boot_id": BOOT}}
            archive = Path(directory) / ("recovery-backup-archive-" + "a" * 32 + ".json")
            archive.write_bytes(b"existing archive")
            with patch.object(operation, "BASELINE", baseline), patch.object(operation, "REBOOT_BASELINE", Path(directory) / "reboot.json"), \
                    patch.object(helper, "_root_parents"), patch.object(helper, "_read_root", side_effect=lambda p, **kw: p.read_bytes()), \
                    patch.object(operation.uuid, "uuid4", return_value=types.SimpleNamespace(hex="a" * 32)), self.assertRaises(FileExistsError):
                operation._archive_previous(prior)
            self.assertEqual(archive.read_bytes(), b"existing archive")
            self.assertEqual(baseline.read_bytes(), b"old marker")

    def test_refresh_reader_requires_exact_root_marker_same_boot_source_and_snapshot_hash(self):
        value = {"schema_version": 1, "source_sha": operation.SOURCE_SHA, "boot_id": BOOT,
                 "snapshot": SNAPSHOT.name, "database_size": 20, "database_sha256": "d" * 64,
                 "created_at": "2026-11-06T04:05:06Z"}
        raw = json.dumps(value).encode()
        with patch.object(operation, "_reboot_baseline_absent"), patch.object(operation, "_identity", return_value=(1, 2, 3, 4)), \
                patch.object(helper, "_read_root", return_value=raw), patch.object(operation, "_boot_id", return_value=BOOT), \
                patch.object(operation.time, "time", return_value=2_000_000_000), \
                patch.object(operation.os, "lstat", return_value=types.SimpleNamespace(st_dev=1)), \
                patch.object(helper, "_private_dir"), patch.object(helper, "_children"), patch.object(helper, "_private_file"), \
                patch.object(helper, "_hash", return_value=(20, bytes.fromhex("d" * 64))):
            previous_value = operation._read_previous_baseline()
            self.assertEqual(previous_value, {"raw": raw, "identity": (1, 2, 3, 4), "value": value})
        for change in ({"source_sha": "a" * 40}, {"boot_id": "wrong"}, {"database_size": True},
                       {"snapshot": "../escape"}, {"extra": "private"}):
            with patch.object(operation, "_reboot_baseline_absent"), patch.object(operation, "_identity", return_value=(1, 2, 3, 4)), \
                    patch.object(helper, "_read_root", return_value=json.dumps({**value, **change}).encode()), \
                    patch.object(operation, "_boot_id", return_value=BOOT), self.assertRaises(helper.VerificationError):
                operation._read_previous_baseline()

    def test_refresh_main_requires_explicit_fixed_literal(self):
        encoded = base64.b64encode(json.dumps(config(), sort_keys=True, separators=(",", ":")).encode()).decode()
        with fake_operation(), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(operation.main([encoded, "refresh-recovery"]), 0)
        self.assertEqual(json.loads(output.getvalue()), success("refresh-recovery"))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(operation.main([encoded, "refresh-arbitrary"]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
