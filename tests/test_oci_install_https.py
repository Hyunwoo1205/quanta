"""Installer safety and fixed-command tests; no OCI, downloads or services."""
import base64
from contextlib import nullcontext, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import MagicMock, Mock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("quanta_install_https", ROOT / "deploy/oci/install_https.py")
https = importlib.util.module_from_spec(spec)
spec.loader.exec_module(https)
TEMPLATE = (ROOT / "deploy/oci/Caddyfile.example").read_bytes()
TOKEN = "ab" * 32


def config(**changes):
    result = {"public_origin": "https://app.example.net", "source_sha": https.SOURCE_SHA,
              "auth_mode": "owner-token"}
    result.update(changes)
    return result


def app_env(**changes):
    result = {"QUANTA_PUBLIC_ORIGIN": config()["public_origin"],
              "QUANTA_AUTH_MODE": "owner-token", "QUANTA_OWNER_TOKEN": TOKEN}
    result.update(changes)
    return "".join(f"{key}={value}\n" for key, value in result.items()).encode()


def metadata(mode=stat.S_IFREG | 0o600, uid=0):
    return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_ino=3, st_dev=4)


def archive(binary=None, *, kind=tarfile.REGTYPE):
    binary = binary or (b"\x7fELF\x02\x01" + b"\0" * 12 + b"\xb7\x00" + b"\0" * 44)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as stream:
        member = tarfile.TarInfo("caddy")
        member.type = kind
        member.size = len(binary) if kind == tarfile.REGTYPE else 0
        member.linkname = "/private/other" if kind != tarfile.REGTYPE else ""
        stream.addfile(member, io.BytesIO(binary) if member.size else None)
    return output.getvalue(), binary


def fixture(status="success"):
    result = {"scope": "https_install", "status": status,
              "state": "issued" if status == "success" else "awaiting_network",
              "failure_stage": "none", **dict.fromkeys(https.BOOLEAN_FIELDS, True)}
    result["host_firewall_changed"] = False
    result["tls_issued"] = status == "success"
    if status == "failed":
        result = https._report()
    return result


class ConfigAndReportTests(unittest.TestCase):
    def test_exact_pinned_configuration_and_round_trip(self):
        original = config()
        self.assertEqual(https.validate_config(original), original)
        self.assertIsNot(https.validate_config(original), original)
        encoded = base64.b64encode(json.dumps(original, sort_keys=True, separators=(",", ":")).encode()).decode()
        self.assertEqual(https._config_argument(encoded), original)

    def test_configuration_rejects_extra_secret_alternate_source_and_non_dns_origin(self):
        invalid = [None, [], {}, config(source_sha="0" * 40), config(auth_mode="access"),
                   {**config(), "token": TOKEN}, config(public_origin=None)]
        invalid += [config(public_origin=value) for value in (
            "http://app.example.net", "https://app.example.net/", "https://APP.example.net",
            "https://app.example.net:443", "https://app.example.net:8443", "https://127.0.0.1",
            "https://[::1]", "https://app.example.net?secret", "https://user@app.example.net",
            "https://app.example.net#private", "https://app.localhost", "https://app.invalid",
            "https://app.local", "https://app.internal", "https://*.example.net",
            "https://app.example.net\nQUANTA_OWNER_TOKEN=" + TOKEN)]
        for value in invalid:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                https.validate_config(value)

    def test_configuration_argument_is_bounded_and_rejects_duplicate_keys(self):
        for argument in ("", "!", "a" * 4097, base64.b64encode(b"{}" * 1025).decode(),
                         base64.b64encode(b'{"public_origin":"x","public_origin":"y"}').decode()):
            with self.subTest(length=len(argument)), self.assertRaises(ValueError):
                https._config_argument(argument)

    def test_reports_allow_only_fixed_progress_and_distinguish_awaiting_network(self):
        for status in ("success", "awaiting_network", "failed"):
            value = fixture(status)
            raw = json.dumps(value).encode()
            self.assertEqual(https.sanitize_report(raw), value)
            self.assertLess(len(raw), https.MAX_OUTPUT_BYTES)
        invalid = [b"", b"x" * 8193, b"null", b"\xff", b'{"status":NaN}']
        invalid += [json.dumps(value).encode() for value in (
            {**fixture(), "hostname": "private"}, {**fixture(), "host_firewall_changed": True},
            {**fixture(), "tls_issued": False}, {**fixture("awaiting_network"), "tls_issued": True},
            {**fixture("failed"), "failure_stage": "none"},
            {**fixture("failed"), "source_verified": False, "app_ready": True})]
        for raw in invalid:
            self.assertIsNone(https.sanitize_report(raw))
        for field in https.BOOLEAN_FIELDS:
            self.assertIsNone(https.sanitize_report(json.dumps({**fixture(), field: 1}).encode()))

    def test_main_never_prints_configuration_secret_or_exception(self):
        argument = base64.b64encode(json.dumps(config()).encode()).decode()
        with patch.object(https, "install", side_effect=RuntimeError("private " + TOKEN)), redirect_stdout(io.StringIO()) as output:
            code = https.main([argument])
        self.assertEqual(code, 2)
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn("app.example.net", output.getvalue())
        self.assertEqual(https.sanitize_report(output.getvalue().encode()), https._report())
        for status in ("success", "awaiting_network"):
            with patch.object(https, "install", return_value=fixture(status)), redirect_stdout(io.StringIO()):
                self.assertEqual(https.main([argument]), 0 if status == "success" else 2)


class FilesystemAndConflictTests(unittest.TestCase):
    def test_root_reads_require_regular_private_files_and_nofollow(self):
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.fileno.return_value = 7
        stream.read.return_value = b"{}"
        with patch.object(https, "_safe_parents"), patch.object(Path, "lstat", return_value=metadata()), \
                patch.object(os, "open", return_value=7) as opened, patch.object(os, "fdopen", return_value=stream), \
                patch.object(os, "fstat", return_value=metadata()):
            self.assertEqual(https._read_root_file(https.APP_ENV, private=True), b"{}")
        self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        for info in (metadata(stat.S_IFLNK | 0o600), metadata(stat.S_IFREG | 0o640),
                     metadata(stat.S_IFREG | 0o660), metadata(uid=1000)):
            with patch.object(https, "_safe_parents"), patch.object(Path, "lstat", return_value=info), \
                    patch.object(os, "open") as opened, self.assertRaises(ValueError):
                https._read_root_file(https.APP_ENV, private=True)
            opened.assert_not_called()

    def test_unsafe_real_ancestors_refuse_before_file_open(self):
        for info in (metadata(stat.S_IFDIR | 0o777), metadata(stat.S_IFDIR | 0o755, uid=1000),
                     metadata(stat.S_IFLNK | 0o777)):
            with patch.object(Path, "lstat", return_value=info), self.assertRaises(ValueError):
                https._safe_parents(https.APP_ENV)

    def test_new_file_creation_is_exclusive_nofollow_and_preserves_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(https, "_safe_parents"):
            path = Path(temporary) / "new"
            https._write_new(path, b"own", 0o600)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                https._write_new(path, b"other", 0o755)
            self.assertEqual(path.read_bytes(), b"own")
            link = Path(temporary) / "link"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                https._write_new(link, b"other", 0o755)
            self.assertEqual(path.read_bytes(), b"own")

    def test_preflight_checks_shared_receipt_fixed_template_and_existing_web_services(self):
        with patch.object(os, "geteuid", return_value=0), \
                patch.object(os, "uname", return_value=types.SimpleNamespace(machine="aarch64")), \
                patch.object(https, "_secure_directory"), patch.object(https, "_absent") as absent, \
                patch.object(https, "_ports_free") as ports, \
                patch.object(https, "_read_root_file", side_effect=[json.dumps(config()).encode(), TEMPLATE]):
            self.assertEqual(https._preflight(config()), TEMPLATE)
        inspected = {str(call.args[0]) for call in absent.call_args_list}
        for name in ("/etc/caddy", "/etc/nginx", "/etc/apache2", "/etc/httpd",
                     "/var/lib/quanta-caddy", "/var/lib/private/quanta-caddy",
                     "/etc/systemd/system/caddy.service", "/etc/systemd/system/quanta-https.service.d"):
            self.assertIn(name, inspected)
        ports.assert_called_once_with()
        self.assertEqual(hashlib.sha256(TEMPLATE).hexdigest(), https.TEMPLATE_SHA256)

    def test_conflict_refusal_never_downloads_writes_stops_or_disables(self):
        with patch.object(https, "_preflight", side_effect=ValueError("existing service")), \
                patch.object(https, "_download_binary") as download, patch.object(https, "_write_new") as write, \
                patch.object(https, "_run") as run:
            result = https.install(config())
        self.assertEqual(result["failure_stage"], "preflight")
        self.assertEqual(result["status"], "failed")
        download.assert_not_called()
        write.assert_not_called()
        run.assert_not_called()

    def test_ports_fail_closed_on_any_local_web_socket_and_bad_tables(self):
        ipv4 = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        ipv6 = b"sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        row = b"0: 0100007F:0050 00000000:0000 0A 0 0 0 0 0 0\n"
        with patch("builtins.open", side_effect=[io.BytesIO(ipv4), io.BytesIO(ipv6)]):
            https._ports_free()
        for first in (ipv4 + row, b"", b"private output\n", ipv4[:-1], b"x" * 1_048_577):
            with patch("builtins.open", return_value=io.BytesIO(first)), self.assertRaises(ValueError):
                https._ports_free()


class ReleaseAndUnitTests(unittest.TestCase):
    def test_release_is_exact_pinned_arm64_and_hash_checked_before_tar(self):
        raw, binary = archive()
        response = io.BytesIO(raw)
        with patch.object(https, "_deadline", return_value=nullcontext()), \
                patch.object(https, "CADDY_SHA256", hashlib.sha256(raw).hexdigest()), \
                patch.object(https, "build_opener") as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(https._download_binary(), binary)
        self.assertEqual(opener.return_value.open.call_args.args, (https.CADDY_URL,))
        self.assertIn("v2.11.9/caddy_2.11.9_linux_arm64.tar.gz", https.CADDY_URL)
        self.assertEqual(https.CADDY_SHA256, "5e377cff994fc9362a6fcf695c53f226cfca3a3ef85bd3a3687cf252d6310165")
        with patch.object(https, "_deadline", return_value=nullcontext()), \
                patch.object(https, "build_opener") as opener, patch.object(tarfile, "open") as unpack:
            opener.return_value.open.return_value = io.BytesIO(raw)
            with self.assertRaises(ValueError):
                https._download_binary()
        unpack.assert_not_called()

    def test_archive_size_links_and_wrong_elf_are_refused(self):
        for raw in (archive(kind=tarfile.SYMTYPE)[0], archive(kind=tarfile.LNKTYPE)[0],
                    archive(binary=b"x" * 64)[0]):
            with patch.object(https, "_deadline", return_value=nullcontext()), \
                    patch.object(https, "CADDY_SHA256", hashlib.sha256(raw).hexdigest()), \
                    patch.object(https, "build_opener") as opener, self.assertRaises(ValueError):
                opener.return_value.open.return_value = io.BytesIO(raw)
                https._download_binary()
        with patch.object(https, "_deadline", return_value=nullcontext()), \
                patch.object(https, "MAX_ARCHIVE", 10), patch.object(https, "build_opener") as opener, \
                patch.object(tarfile, "open") as unpack, self.assertRaises(ValueError):
            opener.return_value.open.return_value = io.BytesIO(b"x" * 11)
            https._download_binary()
        unpack.assert_not_called()

    def test_absolute_download_deadline_is_installed_and_restored(self):
        with patch.object(https.signal, "signal", return_value="previous") as signal, \
                patch.object(https.signal, "setitimer", return_value=(0.0, 0.0)) as timer:
            with https._deadline(45):
                with self.assertRaises(ValueError):
                    signal.call_args.args[1](None, None)
        self.assertEqual(timer.call_args_list[0].args, (https.signal.ITIMER_REAL, 45))
        self.assertEqual(timer.call_args_list[-1].args, (https.signal.ITIMER_REAL, 0.0, 0.0))
        self.assertEqual(signal.call_args_list[-1].args, (https.signal.SIGALRM, "previous"))

    def test_unit_uses_dynamic_credentials_private_state_and_only_bind_capability(self):
        unit = https.UNIT_TEXT
        for line in ("DynamicUser=yes", "StateDirectory=quanta-caddy", "StateDirectoryMode=0700",
                     "LoadCredential=Caddyfile:/etc/quanta/Caddyfile", "EnvironmentFile=/etc/quanta/https.env",
                     "ExecStart=/usr/local/lib/quanta/caddy run --config %d/Caddyfile --adapter caddyfile",
                     "AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
                     "ProtectSystem=strict", "ProtectHome=yes", "NoNewPrivileges=yes", "PrivateTmp=yes",
                     "Requires=quanta-boot.service", "ReadWritePaths=/var/lib/quanta-caddy"):
            self.assertIn(line + "\n", unit)
        for forbidden in ("app.env", "QUANTA_OWNER_TOKEN", "User=root", "CAP_SYS_ADMIN", "ExecReload=", "sudo"):
            self.assertNotIn(forbidden, unit)

    def test_fixed_commands_discard_output_and_inherit_no_caller_secrets(self):
        with patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            https._run([https.SYSTEMCTL, "daemon-reload"])
        options = run.call_args.kwargs
        self.assertIs(options["stdout"], subprocess.DEVNULL)
        self.assertIs(options["stderr"], subprocess.DEVNULL)
        self.assertFalse(options["shell"])
        self.assertEqual(options["env"], {"PATH": https.BINPATH, "LC_ALL": "C"})


class ReadinessAndInstallationTests(unittest.TestCase):
    def test_authenticated_app_probe_uses_only_loopback_and_private_env(self):
        with patch.object(https, "_read_root_file", return_value=app_env()) as read, \
                patch.object(https, "HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"status":"ready"}'
            https._app_ready(config())
        read.assert_called_once_with(https.APP_ENV, private=True)
        connection.assert_called_once_with("127.0.0.1", 8765, timeout=3)
        headers = connection.return_value.request.call_args.kwargs["headers"]
        self.assertEqual(headers, {"Host": "app.example.net", "Origin": config()["public_origin"],
                                  "Authorization": "Bearer " + TOKEN})
        connection.return_value.close.assert_called_once_with()

    def test_invalid_app_environment_never_opens_a_connection(self):
        for raw in (app_env(QUANTA_AUTH_MODE="access"), app_env(QUANTA_OWNER_TOKEN="A" * 64),
                    app_env(QUANTA_PUBLIC_ORIGIN="https://other.example.net"),
                    app_env() + b"QUANTA_OWNER_TOKEN=private\n", app_env() + b"OTHER=private\n"):
            with patch.object(https, "_read_root_file", return_value=raw), \
                    patch.object(https, "HTTPConnection") as connection, self.assertRaises(ValueError):
                https._app_ready(config())
            connection.assert_not_called()

    def test_tls_probe_retains_system_ca_and_public_sni_on_loopback_without_token(self):
        with patch.object(https.ssl, "create_default_context") as context, \
                patch.object(https.socket, "create_connection") as socket, \
                patch.object(https, "HTTPResponse") as response:
            response.return_value.status = 200
            response.return_value.read.return_value = b'{"mode":"bearer","authenticated":false,"authentication":"owner_token"}'
            self.assertTrue(https._tls_ready("app.example.net"))
        context.assert_called_once_with()
        socket.assert_called_once_with(("127.0.0.1", 443), timeout=2)
        self.assertEqual(context.return_value.wrap_socket.call_args.kwargs, {"server_hostname": "app.example.net"})
        sent = context.return_value.wrap_socket.return_value.__enter__.return_value.sendall.call_args.args[0]
        self.assertIn(b"Host: app.example.net\r\n", sent)
        self.assertNotIn(TOKEN.encode(), sent)
        self.assertNotIn(b"Authorization", sent)

    def orchestration(self, *, active=True, issued=True, failure=None):
        stack = []
        names = {
            "_preflight": {"return_value": TEMPLATE}, "_app_ready": {},
            "_download_binary": {"return_value": b"verified fixture"}, "_write_new": {},
            "_run": {}, "_unit_active": {"return_value": active},
            "_tls_ready": {"return_value": issued},
        }
        for name, options in names.items():
            if failure == name:
                options = {"side_effect": RuntimeError("private " + TOKEN)}
            item = patch.object(https, name, **options)
            stack.append((item, item.start()))
        directory = patch.object(https.tempfile, "TemporaryDirectory")
        directory_mock = directory.start()
        directory_mock.return_value.__enter__.return_value = "/private/temporary"
        timeout = patch.object(https, "TLS_WAIT_SECONDS", 40 if issued else 0)
        timeout.start()
        try:
            result = https.install(config())
            mocks = {name: pair[1] for name, pair in zip(names, stack)}
            return result, mocks
        finally:
            timeout.stop()
            directory.stop()
            for item, _ in reversed(stack):
                item.stop()

    def test_success_wires_only_new_fixed_files_and_validates_before_final_write(self):
        result, mocks = self.orchestration()
        self.assertEqual(result, fixture())
        self.assertEqual(mocks["_preflight"].call_count, 2)
        self.assertEqual(mocks["_app_ready"].call_count, 2)
        writes = mocks["_write_new"].call_args_list
        self.assertEqual([(str(call.args[0]), call.args[2]) for call in writes[-4:]], [
            (str(https.BINARY), 0o755), (str(https.CADDYFILE), 0o600),
            (str(https.HTTPS_ENV), 0o600), (str(https.UNIT), 0o644)])
        self.assertEqual(writes[-2].args[1], b"QUANTA_PUBLIC_HOST=app.example.net\n")
        self.assertIn(b"\tadmin off\n", writes[-3].args[1])
        self.assertNotIn(b"admin 127.0.0.1:2019", writes[-3].args[1])
        for call in writes:
            self.assertNotIn(TOKEN.encode(), call.args[1])
        calls = mocks["_run"].call_args_list
        self.assertIn("--validate", calls[0].args[0])
        environment = calls[0].kwargs["environment"]
        self.assertEqual(set(environment), {"PATH", "LC_ALL", "QUANTA_PUBLIC_HOST", "XDG_DATA_HOME", "XDG_CONFIG_HOME"})
        self.assertEqual([call.args[0] for call in calls[1:]], [
            [https.SYSTEMCTL, "daemon-reload"], [https.SYSTEMCTL, "enable", "quanta-https.service"],
            [https.SYSTEMCTL, "start", "--no-block", "quanta-https.service"]])

    def test_network_wait_is_distinct_from_certificate_success_and_service_failure(self):
        result, _ = self.orchestration(issued=False)
        self.assertEqual(result, fixture("awaiting_network"))
        result, _ = self.orchestration(active=False, issued=False)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_stage"], "service")
        self.assertTrue(result["configured"])
        self.assertFalse(result["tls_issued"])

    def test_failed_release_or_stage_does_not_restart_other_services_or_publish_success(self):
        for failure, stage in (("_download_binary", "download"), ("_write_new", "install"), ("_run", "install")):
            result, mocks = self.orchestration(failure=failure)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_stage"], stage)
            self.assertFalse(result["configured"])
            self.assertFalse(result["service_active"])
            for call in mocks["_run"].call_args_list:
                self.assertNotIn("stop", call.args[0])
                self.assertNotIn("disable", call.args[0])


if __name__ == "__main__":
    unittest.main()
