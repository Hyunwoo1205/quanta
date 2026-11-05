"""Backup-operation boundaries with synthetic data; no OCI/Docker/network/keys."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/verify_backup.py"
spec = importlib.util.spec_from_file_location("quanta_verify_backup", SCRIPT)
operation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operation)
IMAGE = "sha256:" + "a" * 64
TOKEN = "b" * 64
NONCE = "12345678123442348123123456789abc"
SNAPSHOT_NAME = "20261106T010203Z-" + NONCE
SNAPSHOT = operation.BACKUPS / SNAPSHOT_NAME
SCRATCH = operation.ROOT / ("restore-verification-" + NONCE)


def config():
    return {"source_sha": operation.SOURCE_SHA, "public_origin": "https://app.example.net", "auth_mode": "owner-token"}


def encoded(value=None):
    return base64.b64encode(json.dumps(config() if value is None else value,
                                     sort_keys=True, separators=(",", ":")).encode()).decode()


def success():
    return {"scope": "backup_verification", "status": "success", "stage": "complete",
            **dict.fromkeys(operation.BOOLEAN_FIELDS, True)}


def info(**changes):
    values = {"st_mode": stat.S_IFREG | 0o600, "st_uid": 10001, "st_gid": 10001,
              "st_dev": 1, "st_ino": 10, "st_nlink": 1, "st_size": 20, "st_mtime_ns": 100}
    values.update(changes)
    return types.SimpleNamespace(**values)


@contextlib.contextmanager
def pipeline():
    with contextlib.ExitStack() as stack:
        values = {"_preflight": (IMAGE, 1, TOKEN, ("private-identity",)), "_entries": {},
                  "_quiet": None, "_names_absent": None, "_fresh_backup": SNAPSHOT,
                  "_container": None, "_hash": (20, b"private-hash"), "_scratch": SCRATCH,
                  "_private_dir": None, "_children": None, "_check_production": None, "_verify_units": None}
        mocks = {name: stack.enter_context(patch.object(operation, name, return_value=value))
                 for name, value in values.items()}
        stack.enter_context(patch.object(operation, "_deadline", side_effect=lambda seconds: contextlib.nullcontext()))
        stack.enter_context(patch.object(operation.uuid, "uuid4", return_value=types.SimpleNamespace(hex=NONCE)))
        stack.enter_context(patch.object(operation.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * 1024**3)))
        yield mocks


class BackupOperationTests(unittest.TestCase):
    def test_config_and_argument_are_exact_fixed_source_and_canonical_json(self):
        self.assertEqual(operation.validate_config(config()), config())
        self.assertEqual(operation._argument(encoded()), config())
        cases = [{**config(), "source_sha": "a" * 40}, {**config(), "auth_mode": "access"},
                 {**config(), "token": TOKEN}, {}, [], None]
        for origin in ("http://app.example.net", "https://APP.example.net", "https://127.0.0.1",
                       "https://[::1]", "https://app.example.net/", "https://app.example.net:443",
                       "https://user@app.example.net", "https://app.example.net?x", "https://app.example.net#x",
                       "https://app.example.net.", "https://localhost", "https://app..example.net",
                       "https://app.example.net\nPRIVATE", None):
            cases.append({**config(), "public_origin": origin})
        for value in cases:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                operation.validate_config(value)
        for value in ("", "%%%", encoded() + "=", "A" * 4097,
                      base64.b64encode(json.dumps(config()).encode()).decode()):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                operation._argument(value)
        with patch.object(operation, "_preflight") as preflight:
            self.assertEqual(operation.run({})["stage"], "configuration")
        preflight.assert_not_called()

    def test_report_is_boolean_only_exact_and_rejects_unordered_claims(self):
        self.assertEqual(operation.parse_output(json.dumps(success()).encode()), success())
        for field in operation.BOOLEAN_FIELDS:
            for value in (None, 1, "true", []):
                with self.subTest(field=field, kind=type(value).__name__), self.assertRaises(ValueError):
                    operation.validate_report({**success(), field: value})
        cases = [{**success(), "private_path": "/private"}, {**success(), "status": []},
                 {**success(), "stage": "private-error"}, {**success(), "status": "failed"},
                 {**success(), "backup_verified": False}]
        for value in cases:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                operation.validate_report(value)
        for field in operation.BOOLEAN_FIELDS[1:]:
            value = {**operation._initial_report(), field: True}
            with self.subTest(field=field), self.assertRaises(ValueError):
                operation.validate_report(value)

    def test_remote_junk_duplicates_and_exceptions_are_never_echoed(self):
        valid = json.dumps(success()).encode()
        for raw in (b"", b"\xff", b" " * 8193, valid + b"private", b'{"status":NaN}',
                    valid[:-1] + b',"status":"failed"}', json.dumps({**success(), "token": TOKEN}).encode()):
            with self.subTest(length=len(raw)), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertIsNone(operation.sanitize_report(raw))
                self.assertEqual(out.getvalue(), "")

    def test_absolute_deadline_interrupts_blocked_work_and_restores_signal_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(operation.VerificationError):
            with operation._deadline(0.02):
                time.sleep(2)
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_trusted_hashes_match_source_runtime_and_boot_units(self):
        for name, expected in operation.TRUSTED.items():
            filename = "runtime.py" if name == "runtime" else name
            self.assertEqual(hashlib.sha256((SCRIPT.parent / filename).read_bytes()).hexdigest(), expected)

    def test_unit_resolution_requires_trusted_fragment_and_no_applied_dropins(self):
        unit = "quanta-backup-boot.timer"
        path = operation.SYSTEMD / unit
        content = b"trusted timer"
        expected = hashlib.sha256(content).hexdigest()
        clean = ("DropInPaths=\nFragmentPath=" + str(path) + "\n").encode()
        with patch.object(operation, "TRUSTED", {"runtime": "ignored", unit: expected}), \
                patch.object(operation, "_read_root", return_value=content), \
                patch.object(operation, "_capture", return_value=clean) as capture:
            operation._verify_units()
        capture.assert_called_once_with(["/usr/bin/systemctl", "show", "--all", "--no-pager",
                                         "--property=FragmentPath,DropInPaths", unit])
        for raw in (None, clean.replace(b"DropInPaths=", b"DropInPaths=/etc/systemd/system/service.d/override.conf"),
                    clean.replace(str(path).encode(), b"/run/systemd/transient/other.timer"),
                    clean + b"DropInPaths=\n", b"private error"):
            with patch.object(operation, "TRUSTED", {"runtime": "ignored", unit: expected}), \
                    patch.object(operation, "_read_root", return_value=content), \
                    patch.object(operation, "_capture", return_value=raw), self.assertRaises(operation.VerificationError):
                operation._verify_units()

    def test_root_reader_rejects_symlinks_nonprivate_modes_wrong_owner_and_hardlinks(self):
        for metadata in (info(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
                         info(st_uid=1000), info(st_uid=0, st_mode=stat.S_IFREG | 0o644), info(st_uid=0, st_nlink=2)):
            with patch.object(operation, "_root_parents"), patch.object(operation.os, "lstat", return_value=metadata), \
                    patch.object(operation.os, "open") as opened, self.assertRaises(operation.VerificationError):
                operation._read_root(Path("/fixed/private"), private=True)
            opened.assert_not_called()

    def test_private_storage_requires_expected_uid_gid_mode_device_and_single_link(self):
        with patch.object(operation, "_no_links"), patch.object(operation.os, "lstat", return_value=info()):
            self.assertEqual(operation._private_file(Path("/fixed/db"), 1).st_ino, 10)
        for changes in ({"st_uid": 0}, {"st_gid": 0}, {"st_mode": stat.S_IFREG | 0o644},
                        {"st_mode": stat.S_IFLNK | 0o600}, {"st_nlink": 2}, {"st_dev": 2},
                        {"st_size": operation.MAX_DATABASE_BYTES + 1}):
            with self.subTest(changes=changes), patch.object(operation, "_no_links"), \
                    patch.object(operation.os, "lstat", return_value=info(**changes)), self.assertRaises(operation.VerificationError):
                operation._private_file(Path("/fixed/db"), 1)
        with patch.object(operation, "_no_links"), \
                patch.object(operation.os, "lstat", return_value=info(st_mode=stat.S_IFDIR | 0o700)):
            self.assertEqual(operation._private_dir(Path("/fixed/directory"), 1).st_ino, 10)

    def test_backup_timer_must_be_inactive_and_fixed_container_names_absent(self):
        for code, valid in ((3, True), (4, True), (0, False), (1, False)):
            with patch.object(operation.subprocess, "run", return_value=types.SimpleNamespace(returncode=code)) as run:
                if valid:
                    operation._inactive_backups()
                else:
                    with self.assertRaises(operation.VerificationError):
                        operation._inactive_backups()
            self.assertEqual(run.call_args.args[0][-4:], ["quanta-backup.service", "quanta-backup-boot.service",
                                                         "quanta-backup.timer", "quanta-backup-boot.timer"])
        for raw in (None, b"quanta-backup\n", b"quanta-operations-check\n", b"private error"):
            with patch.object(operation, "_capture", return_value=raw), self.assertRaises(operation.VerificationError):
                operation._names_absent()
        with patch.object(operation, "_capture", return_value=b"") as capture:
            operation._names_absent()
        self.assertEqual(capture.call_args.args[0][:3], operation.DOCKER)
        self.assertIn("--all", capture.call_args.args[0])

    def test_fresh_snapshot_is_exactly_one_and_old_entries_are_preserved(self):
        old = (1, 1, stat.S_IFDIR | 0o700, 10001, 10001, 100)
        before = {"old-private-name": old}
        new = {**before, SNAPSHOT_NAME: old}
        with patch.object(operation, "_entries", return_value=new), patch.object(operation, "_private_dir"), \
                patch.object(operation, "_children") as children, patch.object(operation, "_private_file"):
            self.assertEqual(operation._fresh_backup(before, 1), SNAPSHOT)
        children.assert_called_once_with(SNAPSHOT, {"jobs.sqlite3", "manifest.json"})
        cases = [before, {SNAPSHOT_NAME: old}, {**new, "second": old},
                 {**new, "old-private-name": (2, *old[1:])},
                 {**before, "../escape": old}, {**before, "20269999T010203Z-" + NONCE: old},
                 {**before, "20261106T010203Z-" + "a" * 32: old}]
        for after in cases:
            with self.subTest(count=len(after)), patch.object(operation, "_entries", return_value=after), \
                    self.assertRaises((operation.VerificationError, ValueError)):
                operation._fresh_backup(before, 1)

    def test_snapshot_enumeration_is_bounded_and_does_not_follow_entries(self):
        entry = MagicMock()
        entry.name = "private-name"
        entry.stat.return_value = info()
        manager = MagicMock()
        manager.__enter__.return_value = iter([entry])
        with patch.object(operation.os, "scandir", return_value=manager):
            self.assertIn("private-name", operation._entries())
        entry.stat.assert_called_once_with(follow_symlinks=False)
        manager.__enter__.return_value = iter([entry, entry])
        with patch.object(operation.os, "scandir", return_value=manager), patch.object(operation, "MAX_ENTRIES", 1), \
                self.assertRaises(operation.VerificationError):
            operation._entries()

    def test_restore_container_can_only_mount_snapshot_readonly_and_own_scratch(self):
        for arguments, scratch in ((["verify-backup", "/backup"], None),
                                   (["restore-store", "/backup", "--output", "/restore/store"], SCRATCH)):
            with patch.object(operation, "_names_absent") as names, patch.object(operation, "_quiet") as quiet:
                operation._container(IMAGE, NONCE, SNAPSHOT, arguments, scratch=scratch)
            self.assertEqual(names.call_count, 2)
            command = quiet.call_args.args[0]
            mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
            expected = ["type=bind,source=" + str(SNAPSHOT) + ",target=/backup,readonly"]
            if scratch is not None:
                expected.append("type=bind,source=" + str(SCRATCH) + ",target=/restore")
            self.assertEqual(mounts, expected)
            self.assertFalse(any(str(operation.DATA) in mount for mount in mounts))
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertEqual(command[command.index("--user") + 1], "10001:10001")
            self.assertEqual(command[command.index("--memory") + 1], "2g")
            self.assertIn("--read-only", command)
            self.assertIn("--pull=never", command)
            self.assertNotIn("--env-file", command)
            self.assertEqual(command[-len(arguments):], arguments)
            self.assertEqual(quiet.call_args.kwargs["timeout"], 90)

    def test_timeout_cleanup_only_stops_exact_labeled_image_and_never_backup_or_app(self):
        with patch.object(operation, "_names_absent"), \
                patch.object(operation, "_quiet", side_effect=operation.VerificationError()), \
                patch.object(operation, "_stop_owned") as cleanup:
            with self.assertRaises(operation.VerificationError):
                operation._container(IMAGE, NONCE, SNAPSHOT, ["verify-backup", "/backup"])
        cleanup.assert_called_once_with(IMAGE, NONCE)
        for raw, count in (((NONCE + " " + IMAGE + "\n").encode(), 1),
                           (("wrong-label " + IMAGE + "\n").encode(), 0), (None, 0)):
            with patch.object(operation, "_capture", return_value=raw), patch.object(operation, "_quiet") as quiet:
                operation._stop_owned(IMAGE, NONCE)
            self.assertEqual(quiet.call_count, count)
            if count:
                self.assertEqual(quiet.call_args.args[0], operation.DOCKER + ["stop", "--time", "5", operation.NAME])

    def test_real_synthetic_database_hash_is_independent_and_refuses_symlink_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jobs.sqlite3"
            content = b"synthetic snapshot bytes\x00\xff"
            path.write_bytes(content)
            with patch.object(operation, "_private_file", side_effect=lambda file, device: file.stat()):
                self.assertEqual(operation._hash(path, path.stat().st_dev), (len(content), hashlib.sha256(content).digest()))
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with patch.object(operation, "_private_file", return_value=path.stat()), self.assertRaises(OSError):
                operation._hash(alias, path.stat().st_dev)

    def test_scratch_creation_is_new_private_nonrecursive_and_owned_by_app_uid(self):
        with patch.object(operation, "_root_parents"), patch.object(operation.os, "mkdir") as mkdir, \
                patch.object(operation.os, "chown") as chown, patch.object(operation.os, "chmod") as chmod, \
                patch.object(operation, "_private_dir"):
            self.assertEqual(operation._scratch(1, NONCE), SCRATCH)
        mkdir.assert_called_once_with(SCRATCH, 0o700)
        chown.assert_called_once_with(SCRATCH, 10001, 10001, follow_symlinks=False)
        chmod.assert_called_once_with(SCRATCH, 0o700, follow_symlinks=False)
        with patch.object(operation, "_root_parents"), patch.object(operation.os, "mkdir", side_effect=FileExistsError), \
                patch.object(operation.os, "chown") as chown, self.assertRaises(FileExistsError):
            operation._scratch(1, NONCE)
        chown.assert_not_called()

    def test_production_identity_requires_same_container_image_starttime_and_live_files(self):
        raw = ("c" * 64 + " " + IMAGE + " true 2026-11-06T01:02:03.123456789Z\n").encode()
        with patch.object(operation, "_capture", return_value=raw), \
                patch.object(operation, "_private_dir", return_value=info()), \
                patch.object(operation, "_private_file", return_value=info()):
            identity = operation._production_identity(IMAGE, 1)
        with patch.object(operation, "_production_identity", return_value=identity), \
                patch.object(operation, "_quiet"), patch.object(operation, "_ready"):
            operation._check_production(config(), TOKEN, IMAGE, 1, identity)
        for changed in (("different-container",), ("different-start-time",)):
            with patch.object(operation, "_production_identity", return_value=changed), \
                    patch.object(operation, "_quiet") as quiet, self.assertRaises(operation.VerificationError):
                operation._check_production(config(), TOKEN, IMAGE, 1, identity)
            quiet.assert_not_called()

    def test_pipeline_creates_checks_and_restores_before_enabling_only_required_units(self):
        with pipeline() as mocks:
            report = operation.run(config())
        self.assertEqual(report, success())
        commands = [call.args[0] for call in mocks["_quiet"].call_args_list]
        self.assertEqual(commands[0], ["/usr/bin/python3", "-I", "-B", str(operation.RUNTIME), "backup", "--storage-mode", "boot"])
        self.assertEqual(mocks["_quiet"].call_args_list[0].kwargs["timeout"], 180)
        self.assertIn(["/usr/bin/systemctl", "enable", "quanta-boot.service"], commands)
        self.assertIn(["/usr/bin/systemctl", "enable", "--now", "quanta-backup-boot.timer"], commands)
        self.assertFalse(any("restart" in command or "stop" in command or "prune" in command for command in commands))
        self.assertEqual(mocks["_container"].call_args_list[0].args[-1], ["verify-backup", "/backup"])
        self.assertEqual(mocks["_container"].call_args_list[1].args[-1], ["restore-store", "/backup", "--output", "/restore/store"])
        self.assertEqual(mocks["_container"].call_args_list[1].kwargs["scratch"], SCRATCH)
        self.assertEqual(mocks["_check_production"].call_count, 2)
        self.assertNotIn(TOKEN, json.dumps(report))
        self.assertNotIn(SNAPSHOT_NAME, json.dumps(report))
        self.assertNotIn(NONCE, json.dumps(report))

    def test_failed_stages_cannot_enable_timer_or_claim_later_success(self):
        for helper, stage in (("_preflight", "preflight"), ("_fresh_backup", "backup"),
                              ("_container", "verify"), ("_scratch", "restore"), ("_check_production", "production_check")):
            with self.subTest(stage=stage), pipeline() as mocks:
                mocks[helper].side_effect = RuntimeError("private-error-" + TOKEN)
                report = operation.run(config())
            self.assertEqual(report["stage"], stage)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["app_enabled"])
            self.assertFalse(report["backup_timer_enabled"])
            self.assertFalse(any("enable" in call.args[0] for call in mocks["_quiet"].call_args_list))
            self.assertNotIn(TOKEN, json.dumps(report))
            self.assertEqual(operation.validate_report(report), report)
        with pipeline() as mocks:
            mocks["_hash"].side_effect = [(20, b"source"), (20, b"different-restored")]
            report = operation.run(config())
        self.assertEqual(report["stage"], "restore")
        self.assertFalse(report["restore_verified"])
        self.assertFalse(report["backup_timer_enabled"])

    def test_restore_failure_or_runtime_timeout_preserves_artifacts_without_cleanup_of_others(self):
        with pipeline() as mocks:
            mocks["_quiet"].side_effect = operation.VerificationError()
            report = operation.run(config())
        self.assertEqual(report["stage"], "backup")
        mocks["_container"].assert_not_called()
        mocks["_scratch"].assert_not_called()
        self.assertEqual(mocks["_quiet"].call_count, 1)

    def test_private_authenticated_readiness_uses_loopback_and_bounded_body(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b'{"status":"ready"}'
        with patch.object(operation.http.client, "HTTPConnection", return_value=connection) as create:
            operation._ready(config(), TOKEN)
        create.assert_called_once_with("127.0.0.1", 8765, timeout=2)
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Host"], "app.example.net")
        self.assertEqual(headers["Origin"], config()["public_origin"])
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        connection.getresponse.return_value.read.assert_called_once_with(1025)
        connection.close.assert_called_once_with()

    def test_subprocess_environment_fixes_runtime_docker_socket_and_hides_all_output(self):
        with patch.dict(os.environ, {"DOCKER_CONTEXT": "private", "QUANTA_OWNER_TOKEN": TOKEN, "HTTP_PROXY": "private"}), \
                patch.object(operation.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            operation._quiet(["/fixed/client"], timeout=180)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn(TOKEN, str(environment))
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertFalse(run.call_args.kwargs["shell"])
        with patch.object(operation.subprocess, "run", side_effect=subprocess.TimeoutExpired("private", 1)), \
                self.assertRaises(operation.VerificationError):
            operation._quiet(["/fixed/client"])

    def test_capture_limits_local_synthetic_child_output_and_runtime(self):
        cases = [("import sys;sys.stderr.write('private');print('ok')", {}, b"ok\n"),
                 ("raise SystemExit(3)", {}, None),
                 ("import sys;sys.stdout.write('x'*100000)", {"limit": 10}, None),
                 ("import time;time.sleep(2)", {"timeout": 0.02}, None)]
        for source, options, expected in cases:
            with self.subTest(source=source), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(operation._capture([sys.executable, "-I", "-c", source], **options), expected)
                self.assertEqual(out.getvalue(), "")

    def test_cli_only_emits_validated_fixed_facts(self):
        with patch.object(operation, "run", return_value=success()), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(operation.main([encoded()]), 0)
        self.assertEqual(operation.sanitize_report(out.getvalue().encode()), success())
        with patch.object(operation, "run") as run, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(operation.main(["private-invalid"]), 2)
        run.assert_not_called()
        self.assertNotIn("private-invalid", out.getvalue())


if __name__ == "__main__":
    unittest.main()
