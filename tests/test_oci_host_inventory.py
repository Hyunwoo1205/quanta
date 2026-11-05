"""Mocked host facts and malicious output fixtures; no OCI or SSH access."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import types
import unittest
from unittest.mock import patch, mock_open


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/host_inventory.py"
spec = importlib.util.spec_from_file_location("quanta_host_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def fixture():
    return {
        "scope": "host_inventory", "status": "success", "os_id": "ubuntu",
        "os_version": "26.04", "architecture": "aarch64", "logical_cpus": 2,
        "memory_total_gib": 11.5, "root_filesystem_total_gib": 190,
        "root_filesystem_free_gib": 182,
        **{field: False for field in inventory.BOOLEAN_FIELDS},
        "quanta_units_active": {unit: False for unit in inventory.UNITS},
    }


class HostInventoryTests(unittest.TestCase):
    def test_valid_round_trip_and_copy(self):
        original = fixture()
        report = inventory.parse_output(json.dumps(original).encode())
        self.assertEqual(report, original)
        report["quanta_units_active"][inventory.UNITS[0]] = True
        self.assertFalse(original["quanta_units_active"][inventory.UNITS[0]])
        self.assertEqual(inventory.sanitize_report(json.dumps(original).encode()), original)
        self.assertIsNone(inventory.sanitize_report(b'{"scope":"host_inventory","status":"failed"}'))

    def test_report_rejects_unapproved_types_ranges_and_strings(self):
        mutations = [
            ("scope", "host_inventory\nprivate"), ("status", "failed"),
            ("os_id", "ubuntu\x1b[2J"), ("os_id", []),
            ("os_version", "26.04\nhost-secret"), ("os_version", "26.04.1.2"),
            ("os_version", 26.04), ("architecture", "aarch64/private"),
            ("architecture", {}), ("logical_cpus", True), ("logical_cpus", 0),
            ("logical_cpus", 4097), ("logical_cpus", 2.0),
            ("memory_total_gib", float("nan")), ("memory_total_gib", float("inf")),
            ("memory_total_gib", -1), ("memory_total_gib", 65537),
            ("root_filesystem_total_gib", 1048577),
            ("root_filesystem_free_gib", 191), ("root_filesystem_free_gib", True),
        ]
        mutations += [(field, "true") for field in inventory.BOOLEAN_FIELDS]
        for field, value in mutations:
            with self.subTest(field=field, value=repr(value)):
                data = fixture()
                data[field] = value
                with self.assertRaises((ValueError, TypeError)):
                    inventory.validate_report(data)
        for data in [[], {}, {**fixture(), "hostname": "private"},
                     {key: value for key, value in fixture().items() if key != "os_id"}]:
            with self.subTest(data_type=type(data).__name__):
                with self.assertRaises(ValueError):
                    inventory.validate_report(data)

    def test_nested_units_are_exact_and_boolean(self):
        for units in [{}, {**fixture()["quanta_units_active"], "other.service": False},
                      {**fixture()["quanta_units_active"], inventory.UNITS[0]: 0}, []]:
            data = fixture()
            data["quanta_units_active"] = units
            with self.assertRaises(ValueError):
                inventory.parse_output(json.dumps(data).encode())
        data = fixture()
        for field in (*inventory.BOOLEAN_FIELDS, *inventory.NUMBER_FIELDS, "logical_cpus"):
            data[field] = None
        data["quanta_units_active"] = {unit: None for unit in inventory.UNITS}
        self.assertEqual(inventory.parse_output(json.dumps(data).encode()), data)

    def test_raw_output_rejects_duplicates_nonfinite_junk_and_size(self):
        valid = json.dumps(fixture()).encode()
        cases = [b"", b"\xff", b"[1]", valid + b"\nprivate text", b" " * 8193,
                 valid[:-1] + b', "os_id":"debian"}',
                 valid.replace(b'"memory_total_gib": 11.5', b'"memory_total_gib": NaN'),
                 valid.replace(b'"memory_total_gib": 11.5', b'"memory_total_gib": Infinity'),
                 valid.replace(b'"quanta.service": false', b'"quanta.service":false,"quanta.service":true')]
        for raw in cases:
            with self.subTest(raw_length=len(raw)):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), self.assertRaises(ValueError) as error:
                    inventory.parse_output(raw)
                self.assertEqual(str(error.exception), "invalid inventory report")
                self.assertEqual(out.getvalue(), "")
                self.assertIsNone(inventory.sanitize_report(raw))

    def test_memory_read_is_bounded_and_converted(self):
        handle = mock_open(read_data="MemTotal:       12582912 kB\nPrivate: ignored\n")
        with patch("builtins.open", handle):
            self.assertEqual(inventory._memory_gib(), 12)
        handle.assert_called_once_with("/proc/meminfo", encoding="ascii")
        handle().read.assert_called_once_with(65536)

    def test_path_facts_distinguish_absent_unknown_symlink_and_directory(self):
        for error, expected in [(FileNotFoundError(), False), (PermissionError(), None)]:
            with patch.object(inventory.os, "lstat", side_effect=error), \
                    patch.object(inventory.os, "stat", side_effect=PermissionError()):
                report = inventory._path_facts()
            self.assertIs(report["srv_quanta_exists"], expected)
            self.assertIsNone(report["srv_quanta_same_device_as_root"])
        root = types.SimpleNamespace(st_dev=11)
        for mode, device, directory, same in [(stat.S_IFDIR | 0o755, 11, True, True),
                                             (stat.S_IFDIR | 0o777, 12, True, False),
                                             (stat.S_IFLNK | 0o777, 11, False, None)]:
            info = types.SimpleNamespace(st_mode=mode, st_uid=0, st_dev=device)
            with patch.object(inventory.os, "lstat", return_value=info), \
                    patch.object(inventory.os, "stat", return_value=root):
                report = inventory._path_facts()
            self.assertIs(report["srv_quanta_is_directory"], directory)
            self.assertIs(report["srv_quanta_same_device_as_root"], same)
            self.assertIs(report["srv_quanta_is_symlink"], not directory)

    def test_systemctl_uses_only_fixed_quiet_read_request(self):
        with patch.object(inventory.shutil, "which", return_value="/usr/bin/systemctl"), \
                patch.object(inventory.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertTrue(inventory._unit_active(inventory.UNITS[0]))
        run.assert_called_once_with(
            ["/usr/bin/systemctl", "is-active", "--quiet", inventory.UNITS[0]],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": inventory.BINPATH, "LC_ALL": "C"}, cwd="/", timeout=2, check=False)
        with patch.object(inventory.shutil, "which", return_value=None), \
                patch.object(inventory.subprocess, "run") as run:
            self.assertIsNone(inventory._unit_active(inventory.UNITS[0]))
            run.assert_not_called()

    def test_collect_with_host_calls_mocked_exposes_only_contract(self):
        disk = types.SimpleNamespace(total=200 * 2**30, free=180 * 2**30)
        facts = {field: None for field in inventory.BOOLEAN_FIELDS if field.startswith("srv_")}
        with patch.object(inventory.platform, "freedesktop_os_release", return_value={
                "ID": "ubuntu", "VERSION_ID": "26.04", "PRETTY_NAME": "private hostname"}), \
                patch.object(inventory.platform, "machine", return_value="aarch64"), \
                patch.object(inventory.os, "cpu_count", return_value=2), \
                patch.object(inventory.shutil, "disk_usage", return_value=disk), \
                patch.object(inventory, "_memory_gib", return_value=12), \
                patch.object(inventory, "_available", return_value=True) as available, \
                patch.object(inventory.importlib.util, "find_spec", return_value=object()), \
                patch.object(inventory, "_path_facts", return_value=facts), \
                patch.object(inventory, "_unit_active", return_value=False) as unit:
            report = inventory.collect()
        self.assertEqual(inventory.validate_report(report), report)
        self.assertEqual(report["root_filesystem_total_gib"], 200)
        self.assertEqual({call.args[0] for call in available.call_args_list}, {"docker", "git", "systemctl"})
        self.assertEqual([call.args[0] for call in unit.call_args_list], list(inventory.UNITS))
        self.assertNotIn("private hostname", json.dumps(report))

    def test_cli_omits_exception_and_never_prints_unvalidated_report(self):
        for value in [RuntimeError("private secret"), {**fixture(), "hostname": "private secret"}]:
            with self.subTest(kind=type(value).__name__):
                out = io.StringIO()
                with patch.object(inventory, "collect", side_effect=value if isinstance(value, Exception) else None,
                                  return_value=value), contextlib.redirect_stdout(out):
                    self.assertEqual(inventory.main(), 2)
                self.assertEqual(json.loads(out.getvalue()), {"scope": "host_inventory", "status": "failed"})


if __name__ == "__main__":
    unittest.main()
