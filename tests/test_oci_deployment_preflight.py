"""Fixed-source and malicious-output tests; no OCI, SSH, keys or host probes."""
import contextlib
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import mock_open, patch


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/deployment_preflight.py"
spec = importlib.util.spec_from_file_location("quanta_deployment_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def fixture(*, ready=True):
    result = {"scope": "deployment_preflight", "status": "success",
              **dict.fromkeys(preflight.READY_FIELDS, ready),
              **dict.fromkeys(preflight.CONFLICT_FIELDS, not ready),
              "ready_for_initial_deployment": ready}
    return result


def table(*rows, ipv6=False):
    remote = b"remote_address" if ipv6 else b"rem_address"
    return (b"  sl local_address " + remote
            + b" st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + b"".join(rows))


def row(address, port, *, remote_port=0, state="0A"):
    ip = ipaddress.ip_address(address)
    packed = ip.packed
    native = b"".join(f"{int.from_bytes(packed[index:index + 4], sys.byteorder):08X}".encode()
                       for index in range(0, len(packed), 4))
    return (b"0: " + native + f":{port:04X} ".encode() + b"0" * len(native)
            + f":{remote_port:04X} {state} 00000000:00000000 00:00000000 00000000 0 0 1\n".encode())


def root_reply(**changes):
    filesystem = {"target": "/", "uuid": "12345678-1234-1234-1234-123456789abc",
                  "fstype": "ext4", "options": "rw,relatime", "fsroot": "/"}
    filesystem.update(changes)
    return json.dumps({"filesystems": [filesystem]}).encode()


class DeploymentPreflightTests(unittest.TestCase):
    def test_contract_round_trip_is_exact_and_copied(self):
        for original in (fixture(), fixture(ready=False)):
            report = preflight.parse_output(json.dumps(original).encode())
            self.assertEqual(report, original)
            self.assertIsNot(report, original)
            self.assertEqual(preflight.sanitize_report(json.dumps(original).encode()), original)
            self.assertLess(len(json.dumps(report).encode()), preflight.MAX_OUTPUT_BYTES)

    def test_contract_rejects_wrong_types_unknown_fields_and_inconsistent_ready(self):
        for field in preflight.BOOLEAN_FIELDS:
            for value in (None, 0, 1, "true", [], {}):
                with self.subTest(field=field, kind=type(value).__name__):
                    report = {**fixture(), field: value}
                    with self.assertRaisesRegex(ValueError, "^invalid preflight report$"):
                        preflight.validate_report(report)
        cases = [[], {}, {**fixture(), "hostname": "private"},
                 {**fixture(), "scope": "deployment_preflight\nprivate"},
                 {**fixture(), "status": "failed"},
                 {key: value for key, value in fixture().items() if key != "paths_inspected"},
                 {**fixture(), "ready_for_initial_deployment": False},
                 {**fixture(ready=False), "ready_for_initial_deployment": True}]
        for report in cases:
            with self.subTest(kind=type(report).__name__), self.assertRaises(ValueError):
                preflight.validate_report(report)

    def test_contract_rejects_positive_facts_without_completed_inspection(self):
        for inspected, fields in (("tcp_tables_inspected", preflight.PORT_FIELDS),
                                  ("docker_names_inspected", preflight.DOCKER_FIELDS),
                                  ("paths_inspected", preflight.PATH_FIELDS),
                                  ("root_filesystem_inspected", preflight.ROOT_FIELDS)):
            for field in fields:
                report = {**fixture(ready=False), field: True}
                with self.subTest(inspected=inspected, field=field), self.assertRaises(ValueError):
                    preflight.validate_report(report)
        for field in preflight.CONFLICT_FIELDS:
            report = {**fixture(), field: True}
            with self.subTest(field=field), self.assertRaises(ValueError):
                preflight.validate_report(report)

    def test_raw_output_is_bounded_and_never_echoed_on_invalid_json(self):
        valid = json.dumps(fixture()).encode()
        cases = [b"", b"\xff", b"[1]", b"null", valid + b"private error", b" " * 4097,
                 valid[:-1] + b',"scope":"private"}',
                 valid.replace(b'"paths_inspected": true', b'"paths_inspected": NaN'),
                 valid.replace(b'"paths_inspected": true', b'"paths_inspected": Infinity')]
        for raw in cases:
            with self.subTest(length=len(raw)), contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaisesRegex(ValueError, "^invalid preflight report$"):
                    preflight.parse_output(raw)
                self.assertIsNone(preflight.sanitize_report(raw))
                self.assertEqual(out.getvalue(), "")
        self.assertIsNone(preflight.sanitize_report(valid.decode()))

    def test_port_tables_are_bounded_and_empty_tables_are_available(self):
        opened = mock_open()
        opened.return_value.read.side_effect = [table(), table(ipv6=True)]
        with patch("builtins.open", opened):
            report = preflight._port_facts()
        self.assertEqual(report, {"tcp_tables_inspected": True,
                                 **dict.fromkeys(preflight.PORT_FIELDS, True)})
        self.assertEqual([call.args for call in opened.call_args_list],
                         [("/proc/net/tcp", "rb"), ("/proc/net/tcp6", "rb")])
        self.assertEqual([call.args for call in opened.return_value.read.call_args_list],
                         [(preflight.MAX_TCP_BYTES + 1,), (preflight.MAX_TCP_BYTES + 1,)])

    def test_any_local_80_or_443_socket_blocks_but_remote_ports_do_not(self):
        data = table(row("127.0.0.1", 80, state="01"),
                     row("192.0.2.10", 443, state="06"), row("127.0.0.1", 40000, remote_port=8765))
        with patch("builtins.open", side_effect=[io.BytesIO(data), io.BytesIO(table(ipv6=True))]):
            report = preflight._port_facts()
        self.assertTrue(report["tcp_tables_inspected"])
        self.assertFalse(report["tcp_80_available"])
        self.assertFalse(report["tcp_443_available"])
        self.assertTrue(report["loopback_8765_available"])

    def test_loopback_ipv4_ipv6_wildcard_and_mapped_sockets_block_8765(self):
        for address in ("127.0.0.1", "127.9.8.7", "0.0.0.0", "::1", "::",
                        "::ffff:127.0.0.1", "::ffff:0.0.0.0"):
            ipv6 = ":" in address
            tables = [table(), table(ipv6=True)]
            tables[int(ipv6)] = table(row(address, 8765), ipv6=ipv6)
            with self.subTest(address=address), \
                    patch("builtins.open", side_effect=[io.BytesIO(value) for value in tables]):
                report = preflight._port_facts()
            self.assertTrue(report["tcp_tables_inspected"])
            self.assertFalse(report["loopback_8765_available"])
        with patch("builtins.open", side_effect=[io.BytesIO(table(row("192.0.2.2", 8765))),
                                                io.BytesIO(table(row("2001:db8::1", 8765), ipv6=True))]):
            self.assertTrue(preflight._port_facts()["loopback_8765_available"])

    def test_unreadable_incomplete_malformed_or_oversized_table_fails_closed(self):
        valid_row = row("127.0.0.1", 80)
        cases = [b"", table()[:-1], b"private error\n", table(b"\n"),
                 table(valid_row.replace(b":0050", b":ZZZZ", 1)),
                 table(valid_row.replace(b"0100007F", b"0100007", 1)),
                 table(valid_row.replace(b" 0A ", b" bad ", 1)),
                 table(valid_row.replace(b"0:", b"x:", 1)),
                 b"x" * (preflight.MAX_TCP_BYTES + 1),
                 table(*(valid_row for _ in range(preflight.MAX_TCP_ROWS + 1)))]
        for raw in cases:
            with self.subTest(length=len(raw)), patch("builtins.open", mock_open(read_data=raw)):
                self.assertEqual(preflight._port_facts(), {"tcp_tables_inspected": False,
                                                          **dict.fromkeys(preflight.PORT_FIELDS, False)})
        for error in (FileNotFoundError("private"), PermissionError("private")):
            with patch("builtins.open", side_effect=error):
                self.assertFalse(preflight._port_facts()["tcp_tables_inspected"])
        with patch("builtins.open", side_effect=[io.BytesIO(table()), PermissionError("private")]):
            self.assertFalse(any(preflight._port_facts().values()))

    def test_sudo_probe_is_fixed_noninteractive_and_suppresses_all_output(self):
        for code, expected in ((0, True), (1, False)):
            with patch.object(preflight.subprocess, "run", return_value=types.SimpleNamespace(returncode=code)) as run:
                self.assertIs(preflight._sudo_ready(), expected)
            run.assert_called_once_with(["/usr/bin/sudo", "-n", "true"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": preflight.BINPATH, "LC_ALL": "C"}, cwd="/", timeout=2, check=False)
        with patch.object(preflight.subprocess, "run", side_effect=subprocess.TimeoutExpired("private", 2)):
            self.assertFalse(preflight._sudo_ready())

    def test_docker_checks_all_containers_only_fixed_names_and_local_socket(self):
        for privileged in (False, True):
            with self.subTest(privileged=privileged), \
                    patch.object(preflight.shutil, "which", return_value="/usr/bin/docker"), \
                    patch.object(preflight, "_bounded_output", return_value=b"quanta-backup\n") as capture:
                report = preflight._docker_facts(privileged)
            prefix = ["/usr/bin/sudo", "-n"] if privileged else []
            capture.assert_called_once_with(prefix + ["/usr/bin/docker", "--host",
                "unix:///var/run/docker.sock", "container", "ls", "--all", "--filter",
                "name=^/(quanta|quanta-backup)$", "--format", "{{.Names}}"], limit=128)
            self.assertEqual(report, {"docker_names_inspected": True,
                "docker_quanta_name_absent": True, "docker_quanta_backup_name_absent": False})
        for raw, absent in ((b"", (True, True)), (b"quanta\n", (False, True)),
                            (b"quanta\nquanta-backup\n", (False, False)),
                            (b"quanta-backup\nquanta\n", (False, False))):
            with patch.object(preflight.shutil, "which", return_value="/usr/bin/docker"), \
                    patch.object(preflight, "_bounded_output", return_value=raw):
                report = preflight._docker_facts(True)
            self.assertTrue(report["docker_names_inspected"])
            self.assertEqual(tuple(report[field] for field in preflight.DOCKER_FIELDS), absent)

    def test_docker_errors_truncation_and_unexpected_names_never_mean_absent(self):
        for raw in (None, b"\n", b"quanta", b"quanta\nquanta\n", b"other-private-name\n",
                    b"/quanta\n", b"quanta\nprivate error", b"quanta\r\n", b"\xff"):
            with self.subTest(raw_length=0 if raw is None else len(raw)), \
                    patch.object(preflight.shutil, "which", return_value="/usr/bin/docker"), \
                    patch.object(preflight, "_bounded_output", return_value=raw):
                self.assertFalse(any(preflight._docker_facts(True).values()))
        with patch.object(preflight.shutil, "which", return_value=None), \
                patch.object(preflight, "_bounded_output") as capture:
            self.assertFalse(any(preflight._docker_facts(True).values()))
            capture.assert_not_called()

    def test_paths_distinguish_absence_existing_dangling_symlink_and_unknown(self):
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        for final, expected in ((FileNotFoundError(), (True, True)),
                                (PermissionError("private"), (False, False)),
                                (types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0), (False, True)),
                                (directory, (False, True))):
            def inspect(path):
                if path == "/srv/quanta":
                    if isinstance(final, Exception):
                        raise final
                    return final
                return directory
            with self.subTest(kind=type(final).__name__), patch.object(preflight.os, "lstat", side_effect=inspect):
                self.assertEqual(preflight._path_absent("/srv/quanta"), expected)
        for parent in (types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
                       types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                       types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000)):
            with patch.object(preflight.os, "lstat", side_effect=lambda path: parent if path == "/srv" else directory):
                self.assertEqual(preflight._path_absent("/srv/quanta"), (False, False))

    def test_expected_merged_usr_alias_is_accepted_but_other_aliases_rejected(self):
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        link = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        def inspect(path):
            if path.endswith("quanta.service"):
                raise FileNotFoundError
            return link if path == "/lib" else directory
        for target, expected in (("usr/lib", (True, True)), ("/usr/lib", (True, True)),
                                  ("/private", (False, False))):
            with self.subTest(target=target), patch.object(preflight.os, "lstat", side_effect=inspect), \
                    patch.object(preflight.os, "readlink", return_value=target):
                self.assertEqual(preflight._path_absent("/lib/systemd/system/quanta.service"), expected)

    def test_unit_paths_include_stopped_unit_files_dropins_and_all_six_names(self):
        with patch.object(preflight, "_path_absent", return_value=(True, True)) as inspect:
            report = preflight._path_facts()
        self.assertTrue(report["paths_inspected"])
        self.assertTrue(all(report[field] for field in preflight.PATH_FIELDS))
        self.assertFalse(any(report[field] for field in preflight.CONFLICT_FIELDS))
        requested = {call.args[0] for call in inspect.call_args_list}
        self.assertIn("/srv/quanta", requested)
        self.assertIn("/etc/quanta", requested)
        for unit in preflight.UNITS:
            for directory in preflight.UNIT_DIRECTORIES:
                self.assertIn(directory + "/" + unit, requested)
                self.assertIn(directory + "/" + unit + ".d", requested)
        for conflicting in ("/srv/quanta", "/etc/quanta",
                            "/run/systemd/transient/quanta.service",
                            "/usr/lib/systemd/system/quanta-backup-boot.service.d"):
            with self.subTest(path=conflicting), patch.object(preflight, "_path_absent",
                    side_effect=lambda path: (path != conflicting, True)):
                report = preflight._path_facts()
            self.assertTrue(report["paths_inspected"])
            self.assertFalse(all(report[field] for field in preflight.PATH_FIELDS))
        with patch.object(preflight, "_path_absent", side_effect=lambda path: (True, path != "/etc/quanta")):
            report = preflight._path_facts()
        self.assertFalse(report["paths_inspected"])
        self.assertFalse(any(report[field] for field in preflight.PATH_FIELDS))
        self.assertTrue(all(report[field] for field in preflight.CONFLICT_FIELDS))

    def test_root_filesystem_probe_is_fixed_and_never_exposes_uuid_device_or_options(self):
        with patch.object(preflight, "_bounded_output", return_value=root_reply()) as capture:
            report = preflight._root_facts()
        capture.assert_called_once_with(["/usr/bin/findmnt", "--json", "--target", "/", "--output",
                                         "TARGET,UUID,FSTYPE,OPTIONS,FSROOT"])
        self.assertTrue(all(report.values()))
        self.assertNotIn("12345678", json.dumps(report))
        self.assertEqual(set(report), {"root_filesystem_inspected", *preflight.ROOT_FIELDS})
        for changes, false_field in (({"fstype": "btrfs"}, "root_filesystem_type_supported"),
                                     ({"uuid": None}, "root_filesystem_uuid_available"),
                                     ({"uuid": "private-label"}, "root_filesystem_uuid_available"),
                                     ({"uuid": "12345678123412341234123456789abc"}, "root_filesystem_uuid_available"),
                                     ({"options": "rw,ro"}, "root_filesystem_writable"),
                                     ({"options": "ro"}, "root_filesystem_writable"),
                                     ({"target": "/other"}, "root_filesystem_is_root"),
                                     ({"fsroot": "/subvolume"}, "root_filesystem_is_root")):
            with self.subTest(field=false_field), \
                    patch.object(preflight, "_bounded_output", return_value=root_reply(**changes)):
                report = preflight._root_facts()
            self.assertTrue(report["root_filesystem_inspected"])
            self.assertFalse(report[false_field])

    def test_root_filesystem_malformed_or_ambiguous_reply_fails_closed(self):
        valid = json.loads(root_reply())
        duplicate = root_reply().replace(b'"fstype": "ext4"', b'"fstype":"ext4","fstype":"xfs"')
        cases = [None, b"private error", b"\xff", b"[]", b"{}", duplicate,
                 json.dumps({"filesystems": []}).encode(),
                 json.dumps({"filesystems": valid["filesystems"] * 2}).encode(),
                 json.dumps({**valid, "device": "private"}).encode(), root_reply(uuid=True),
                 root_reply(target=None), root_reply(options=[]), root_reply(fstype={})]
        for raw in cases:
            with self.subTest(length=0 if raw is None else len(raw)), \
                    patch.object(preflight, "_bounded_output", return_value=raw):
                self.assertFalse(any(preflight._root_facts().values()))

    def test_collect_is_boolean_only_and_readiness_requires_every_prerequisite(self):
        original = fixture()
        port = {field: original[field] for field in ("tcp_tables_inspected", *preflight.PORT_FIELDS)}
        docker = {field: original[field] for field in ("docker_names_inspected", *preflight.DOCKER_FIELDS)}
        paths = {field: original[field] for field in ("paths_inspected", *preflight.PATH_FIELDS, *preflight.CONFLICT_FIELDS)}
        root = {field: original[field] for field in ("root_filesystem_inspected", *preflight.ROOT_FIELDS)}
        for sudo in (True, False):
            with patch.object(preflight, "_sudo_ready", return_value=sudo), \
                    patch.object(preflight, "_port_facts", return_value=port), \
                    patch.object(preflight, "_docker_facts", return_value=docker) as docker_probe, \
                    patch.object(preflight, "_path_facts", return_value=paths), \
                    patch.object(preflight, "_root_facts", return_value=root):
                report = preflight.collect()
            self.assertEqual(preflight.validate_report(report), report)
            self.assertIs(report["ready_for_initial_deployment"], sudo)
            docker_probe.assert_called_once_with(sudo)

    def test_bounded_client_local_eof_failure_limit_timeout_and_hidden_stderr(self):
        cases = [("import sys; sys.stderr.write('private'); print('ok')", {}, b"ok\n"),
                 ("raise SystemExit(7)", {}, None),
                 ("import sys; sys.stdout.write('x'*1000000)", {"limit": 10}, None),
                 ("import time; time.sleep(5)", {"timeout": 0.05}, None)]
        for code, options, expected in cases:
            with self.subTest(code=code), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(preflight._bounded_output([sys.executable, "-I", "-c", code], **options), expected)
                self.assertEqual(out.getvalue(), "")
        with patch.object(preflight.subprocess, "Popen", side_effect=OSError("private spawn error")) as spawn:
            self.assertIsNone(preflight._bounded_output(["/fixed/client"]))
        spawn.assert_called_once_with(["/fixed/client"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False,
            env={"PATH": preflight.BINPATH, "LC_ALL": "C"}, cwd="/")

    def test_cli_never_prints_exceptions_or_unvalidated_data(self):
        for value in (RuntimeError("private error"), {**fixture(), "uuid": "private"}):
            with self.subTest(kind=type(value).__name__), contextlib.redirect_stdout(io.StringIO()) as out, \
                    patch.object(preflight, "collect", side_effect=value if isinstance(value, Exception) else None,
                                 return_value=value):
                self.assertEqual(preflight.main(), 2)
            self.assertEqual(json.loads(out.getvalue()), {"scope": "deployment_preflight", "status": "failed"})
        with patch.object(preflight, "collect", return_value=fixture()), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(preflight.main(), 0)
        self.assertEqual(preflight.parse_output(out.getvalue().encode()), fixture())


if __name__ == "__main__":
    unittest.main()
