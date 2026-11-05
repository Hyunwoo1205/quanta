"""Initial-installer boundary tests; no OCI, Docker, sudo, network or key use."""
import base64
import contextlib
import gzip
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
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import mock_open, patch


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/install_app.py"
spec = importlib.util.spec_from_file_location("quanta_install_app", SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
IMAGE = "sha256:" + "a" * 64
IDENTIFIER = "12345678-1234-1234-1234-123456789abc"
TOKEN = "b" * 64


def config():
    return {"source_sha": installer.SOURCE_SHA, "public_origin": "https://app.example.net",
            "auth_mode": "owner-token"}


def encoded(value=None):
    return base64.b64encode(json.dumps(config() if value is None else value,
                                     sort_keys=True, separators=(",", ":")).encode()).decode()


def archive_bytes(entries=None):
    buffer = io.BytesIO()
    prefix = "quanta-" + installer.SOURCE_SHA
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo(prefix)
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, content, kind in entries or [("src/app.py", b"print('safe')\n", tarfile.REGTYPE)]:
            item = tarfile.TarInfo(name if name.startswith("/") else prefix + "/" + name)
            item.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                item.linkname = "../../outside"
            item.size = len(content) if kind == tarfile.REGTYPE else 0
            archive.addfile(item, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return gzip.compress(buffer.getvalue())


def root_reply(**changes):
    filesystem = {"target": "/", "uuid": IDENTIFIER, "fstype": "ext4",
                  "options": "rw,relatime", "fsroot": "/"}
    filesystem.update(changes)
    return json.dumps({"filesystems": [filesystem]}).encode()


@contextlib.contextmanager
def mocked_pipeline():
    with contextlib.ExitStack() as stack:
        patches = {
            "_preflight": IDENTIFIER, "_stage_source": None, "_build_image": IMAGE,
            "_smoke": None, "_install_layout": TOKEN, "_quiet": None,
            "_readiness": None, "_write_new": None, "_unit_paths_free": True,
            "_ports_free": True, "_docker_conflicts_absent": True,
        }
        mocks = {name: stack.enter_context(patch.object(installer, name, return_value=value))
                 for name, value in patches.items()}
        stack.enter_context(patch.object(installer, "_deadline", side_effect=lambda seconds: contextlib.nullcontext()))
        yield mocks


class InitialAppInstallerTests(unittest.TestCase):
    def test_config_is_fixed_canonical_owner_token_and_strict_https_dns(self):
        self.assertEqual(installer.validate_config(config()), config())
        self.assertEqual(installer.decode_config(encoded()), config())
        bad_origins = [None, 1, "http://app.example.net", "https://APP.example.net", "https://127.0.0.1",
                       "https://[::1]", "https://app.example.net/", "https://app.example.net:443",
                       "https://user@app.example.net", "https://app.example.net?x", "https://app.example.net#x",
                       "https://app.example.net.", "https://localhost", "https://app..example.net",
                       "https://-app.example.net", "https://app_.example.net", "https://app.example.net\nPRIVATE",
                       "https://" + "a" * 64 + ".example.net", "https://한글.example.net", "https://app.123"]
        cases = [{**config(), "public_origin": origin} for origin in bad_origins]
        cases += [{**config(), "source_sha": "a" * 40}, {**config(), "auth_mode": "access"},
                  {**config(), "token": "private"}, {}, [], None]
        for value in cases:
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(ValueError, "^invalid installation configuration$"):
                installer.validate_config(value)
        raw = json.dumps(config()).encode()
        duplicate = json.dumps(config(), sort_keys=True, separators=(",", ":"))[:-1] + ',"auth_mode":"owner-token"}'
        for value in ("", "%%%", encoded() + "=", base64.b64encode(raw).decode(),
                      base64.b64encode(duplicate.encode()).decode(), "A" * 4097):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                installer.decode_config(value)

    def test_invalid_config_cannot_reach_host_operations(self):
        with patch.object(installer, "_preflight") as preflight:
            report = installer.run({**config(), "auth_mode": "access"})
        preflight.assert_not_called()
        self.assertEqual(report, {"scope": "app_installation", "status": "invalid_config", "stage": "configuration"})

    def test_reports_have_only_fixed_stage_status_and_reject_remote_junk(self):
        valid = {"scope": "app_installation", "status": "success", "stage": "complete"}
        self.assertEqual(installer.parse_output(json.dumps(valid).encode()), valid)
        cases = [b"", b"\xff", b" " * 8193, json.dumps({**valid, "token": TOKEN}).encode(),
                 json.dumps({**valid, "stage": "private-error"}).encode(),
                 json.dumps({**valid, "status": "failed"}).encode(),
                 json.dumps({**valid, "stage": "build"}).encode(),
                 json.dumps(valid).encode() + b"private", b'{"status":NaN}',
                 b'{"scope":"app_installation","scope":"private","status":"success","stage":"complete"}']
        for raw in cases:
            with self.subTest(length=len(raw)), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertIsNone(installer.sanitize_report(raw))
                self.assertEqual(output.getvalue(), "")

    def test_real_local_signal_deadline_interrupts_blocking_work_and_restores_handler(self):
        original = signal.getsignal(signal.SIGALRM)
        started = time.monotonic()
        with self.assertRaises(installer.InstallError):
            with installer._deadline(0.02):
                time.sleep(2)
        self.assertLess(time.monotonic() - started, 1)
        self.assertIs(signal.getsignal(signal.SIGALRM), original)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_resource_floor_and_bounded_meminfo(self):
        for available, disk, cpus, expected in ((6 * 1048576, 10 * 1024**3, 2, True),
                                                (6 * 1048576 - 1, 10 * 1024**3, 2, False),
                                                (7 * 1048576, 10 * 1024**3 - 1, 2, False),
                                                (7 * 1048576, 11 * 1024**3, 1, False)):
            opened = mock_open(read_data=f"MemAvailable: {available} kB\n".encode())
            with self.subTest(available=available, disk=disk, cpus=cpus), \
                    patch("builtins.open", opened), patch.object(installer.shutil, "disk_usage", return_value=types.SimpleNamespace(free=disk)), \
                    patch.object(installer.os, "cpu_count", return_value=cpus):
                self.assertIs(installer._resources_ready(), expected)
            opened.return_value.read.assert_called_once_with(65537)
        with patch("builtins.open", mock_open(read_data=b"x" * 65537)):
            self.assertFalse(installer._resources_ready())

    def test_socket_probe_only_binds_fixed_endpoints_and_closes_without_listening(self):
        endpoint = types.SimpleNamespace(bind=lambda value: None, setsockopt=lambda *value: None)
        manager = unittest.mock.MagicMock()
        manager.__enter__.return_value = endpoint
        with patch.object(installer.socket, "socket", return_value=manager) as create:
            self.assertTrue(installer._ports_free())
        self.assertEqual(create.call_count, 6)
        self.assertEqual(manager.__exit__.call_count, 6)
        with patch.object(installer.socket, "socket", side_effect=OSError("private")):
            self.assertFalse(installer._ports_free())

    def test_published_docker_ports_include_dnat_and_ranges_without_exposing_addresses(self):
        safe = [b"", b"\n", b"25565/tcp\n", b"0.0.0.0:25565->25565/tcp, [::]:25565->25565/tcp\n",
                b"127.0.0.1:9000-9010->8000-8010/tcp\n", b"53/udp, 9000-9002/tcp\n"]
        unsafe = [None, b"private error", b"0.0.0.0:80->8080/tcp\n", b"[::]:443->443/tcp\n",
                  b"127.0.0.1:8765->80/tcp\n", b"0.0.0.0:79-81->79-81/tcp\n",
                  b"0.0.0.0:400-450->400-450/udp\n", b"0.0.0.0:9000-8000->90/tcp\n",
                  b"99999/tcp\n", b"bad-host:9000->80/tcp\n", b"0.0.0.0:0->80/tcp\n", b"x" * 8193]
        for raw in safe:
            with self.subTest(length=len(raw)):
                self.assertTrue(installer._published_ports_safe(raw))
        for raw in unsafe:
            with self.subTest(length=0 if raw is None else len(raw)):
                self.assertFalse(installer._published_ports_safe(raw))
        with patch.object(installer, "_capture", side_effect=[b"", b"0.0.0.0:80->80/tcp\n"]) as capture:
            self.assertFalse(installer._docker_conflicts_absent())
        self.assertIn("--all", capture.call_args_list[0].args[0])
        self.assertEqual(capture.call_args_list[1].args[0], installer.DOCKER_PREFIX + ["ps", "--format", "{{.Ports}}"])
        self.assertEqual(capture.call_args_list[0].args[0][:3], installer.DOCKER_PREFIX)

    def test_preflight_refuses_wrong_privilege_architecture_and_existing_paths(self):
        for user, architecture in ((1000, "aarch64"), (0, "x86_64")):
            with patch.object(installer.os, "geteuid", return_value=user), \
                    patch.object(installer.platform, "machine", return_value=architecture), \
                    patch.object(installer, "_resources_ready", return_value=True), \
                    patch.object(installer, "_quiet") as quiet:
                with self.assertRaises(installer.InstallError) as error:
                    installer._preflight()
            self.assertEqual(error.exception.status, "not_ready")
            quiet.assert_not_called()
        with patch.object(installer.os, "geteuid", return_value=0), \
                patch.object(installer.platform, "machine", return_value="aarch64"), \
                patch.object(installer, "_resources_ready", return_value=True), \
                patch.object(installer, "_quiet"), patch.object(installer, "_absent", return_value=False):
            with self.assertRaises(installer.InstallError) as error:
                installer._preflight()
        self.assertEqual(error.exception.status, "conflict")

    def test_root_filesystem_is_private_single_writable_supported_and_canonical(self):
        with patch.object(installer, "_capture", return_value=root_reply()) as capture:
            self.assertEqual(installer._root_filesystem(), IDENTIFIER)
        capture.assert_called_once_with(["/usr/bin/findmnt", "--json", "--target", "/", "--output",
                                        "TARGET,UUID,FSTYPE,OPTIONS,FSROOT"], limit=4096)
        replies = [None, b"private error", b"[]", b'{"filesystems":[]}', root_reply(fstype="btrfs"),
                   root_reply(target="/other"), root_reply(fsroot="/subvolume"), root_reply(options="rw,ro"),
                   root_reply(uuid=IDENTIFIER.replace("-", "")), root_reply(uuid=None)]
        for raw in replies:
            with self.subTest(length=0 if raw is None else len(raw)), patch.object(installer, "_capture", return_value=raw):
                with self.assertRaises(installer.InstallError) as error:
                    installer._root_filesystem()
            self.assertEqual(error.exception.status, "not_ready")

    def test_absence_never_follows_untrusted_ancestors_or_dangling_symlinks(self):
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        link = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        for final, expected in ((FileNotFoundError(), True), (link, False), (directory, False)):
            def inspect(path):
                if str(path) == "/srv/quanta":
                    if isinstance(final, Exception):
                        raise final
                    return final
                return directory
            with patch.object(installer.os, "lstat", side_effect=inspect):
                self.assertIs(installer._absent("/srv/quanta"), expected)
        for parent in (link, types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                       types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000)):
            with patch.object(installer.os, "lstat", side_effect=lambda path: parent if str(path) == "/srv" else directory):
                with self.assertRaises(installer.InstallError):
                    installer._absent("/srv/quanta")

    def test_exclusive_real_file_creation_does_not_overwrite_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, "_check_parents"), \
                patch.object(installer.os, "fchown"):
            path = Path(directory) / "app.env"
            installer._write_new(path, b"private-initial-value")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for destination in (path, Path(directory) / "alias"):
                if destination != path:
                    destination.symlink_to(path)
                with self.assertRaises(installer.InstallError) as error:
                    installer._write_new(destination, b"replacement")
                self.assertEqual(error.exception.status, "conflict")
            self.assertEqual(path.read_bytes(), b"private-initial-value")

    def test_valid_archive_is_inspected_before_any_host_directory_creation(self):
        compressed = archive_bytes()
        archive, members = installer._archive_members(compressed, time.monotonic() + 10)
        try:
            self.assertEqual([parts for parts, _ in members], [(), ("src", "app.py")])
            self.assertEqual(archive.extractfile(members[1][1]).read(), b"print('safe')\n")
        finally:
            archive.close()
        with patch.object(installer, "_download", return_value=archive_bytes([("../escape", b"x", tarfile.REGTYPE)])), \
                patch.object(installer, "_new_dir") as create:
            with self.assertRaises(installer.InstallError):
                installer._stage_source()
        create.assert_not_called()

    def test_archive_rejects_traversal_links_devices_duplicates_and_parent_files(self):
        cases = [[(name, b"x", tarfile.REGTYPE)] for name in ("../escape", "src/../escape", "src/./file", "src//file", "/absolute", "src\\file")]
        cases += [[("link", b"", kind)] for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE)]
        cases += [[("same", b"x", tarfile.REGTYPE), ("same", b"y", tarfile.REGTYPE)],
                  [("parent", b"x", tarfile.REGTYPE), ("parent/child", b"y", tarfile.REGTYPE)],
                  [("src/" + "x" * 513, b"x", tarfile.REGTYPE)]]
        for entries in cases:
            with self.subTest(names=[item[0] for item in entries]):
                with self.assertRaises(installer.InstallError):
                    installer._archive_members(archive_bytes(entries), time.monotonic() + 10)

    def test_archive_caps_compression_metadata_member_count_file_size_and_deadline(self):
        compressed = archive_bytes()
        for raw in (b"", compressed[:-5], compressed + gzip.compress(b"extra")):
            with self.subTest(length=len(raw)), self.assertRaises((installer.InstallError, tarfile.TarError)):
                installer._archive_members(raw, time.monotonic() + 10)
        with patch.object(installer, "MAX_EXPANDED", 1024):
            with self.assertRaises(installer.InstallError):
                installer._archive_members(gzip.compress(b"x" * 4096), time.monotonic() + 10)
        with patch.object(installer, "MAX_DOWNLOAD", 10):
            with self.assertRaises(installer.InstallError):
                installer._archive_members(compressed, time.monotonic() + 10)
        with patch.object(installer, "MAX_MEMBERS", 2):
            with self.assertRaises(installer.InstallError):
                installer._archive_members(archive_bytes([("a", b"x", tarfile.REGTYPE), ("b", b"y", tarfile.REGTYPE)]), time.monotonic() + 10)
        with patch.object(installer, "MAX_FILE", 1):
            with self.assertRaises(installer.InstallError):
                installer._archive_members(archive_bytes([("large", b"xx", tarfile.REGTYPE)]), time.monotonic() + 10)
        with self.assertRaises(installer.InstallError):
            installer._archive_members(compressed, time.monotonic() - 1)

    def test_download_is_fixed_no_proxy_no_redirect_bounded_and_hides_private_errors(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.status, response.headers = 200, {}
        response.geturl.return_value = installer.ARCHIVE_URL
        response.read.side_effect = [b"gzip-data", b""]
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(installer.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(installer._download(time.monotonic() + 10), b"gzip-data")
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], installer._NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, installer.ARCHIVE_URL)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
        with self.assertRaises(installer.InstallError):
            installer._NoRedirect().redirect_request(None, None, 302, "private", {}, "https://other.example.net/")
        response.read.side_effect = None
        response.headers = {"Content-Length": str(installer.MAX_DOWNLOAD + 1)}
        with patch.object(installer.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(installer.InstallError):
                installer._download(time.monotonic() + 10)

    def test_artifact_hashes_match_the_fixed_repository_runtime_and_units(self):
        repository = SCRIPT.parents[2]
        for name, expected in installer.TRUSTED_FILES.items():
            self.assertEqual(hashlib.sha256((repository / name).read_bytes()).hexdigest(), expected)

    def test_build_limits_are_explicit_legacy_and_image_must_be_immutable_arm(self):
        with patch.object(installer, "_resources_ready", return_value=True), \
                patch.object(installer, "_quiet") as quiet, \
                patch.object(installer, "_capture", return_value=(IMAGE + " arm64 linux\n").encode()):
            self.assertEqual(installer._build_image(), IMAGE)
        command = quiet.call_args.args[0]
        self.assertEqual(command[:3], installer.DOCKER_PREFIX)
        for name, value in (("--memory", "2g"), ("--memory-swap", "2g"), ("--cpu-period", "100000"),
                            ("--cpu-quota", "200000"), ("--cpuset-cpus", "0,1"), ("--platform", "linux/arm64")):
            self.assertEqual(command[command.index(name) + 1], value)
        self.assertTrue(quiet.call_args.kwargs["build"])
        self.assertEqual(quiet.call_args.kwargs["timeout"], installer.BUILD_TIMEOUT)
        self.assertEqual(installer._environment(build=True)["DOCKER_BUILDKIT"], "0")
        for raw in (None, (IMAGE + " amd64 linux\n").encode(), b"private-error", b"latest arm64 linux\n"):
            with patch.object(installer, "_resources_ready", return_value=True), patch.object(installer, "_quiet"), \
                    patch.object(installer, "_capture", return_value=raw), self.assertRaises(installer.InstallError):
                installer._build_image()

    def test_smoke_checks_contract_and_actual_energy_in_hardened_isolated_containers(self):
        with patch.object(installer, "_quiet") as quiet:
            installer._smoke(IMAGE)
        self.assertEqual(quiet.call_count, 2)
        commands = [call.args[0] for call in quiet.call_args_list]
        self.assertEqual(commands[0][-1], "check-contracts")
        self.assertEqual(commands[1][-4:], ["evaluate", "/app/examples/pair_energy_forces.json", "--format", "text"])
        for command in commands:
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertEqual(command[command.index("--user") + 1], "10001:10001")
            self.assertIn("--read-only", command)
            self.assertIn("--pull=never", command)
            self.assertNotIn("--env-file", command)
            self.assertIn(IMAGE, command)
        with patch.object(installer, "_quiet", side_effect=installer.InstallError()), \
                patch.object(installer, "_stop_owned_smoke") as cleanup:
            with self.assertRaises(installer.InstallError):
                installer._smoke(IMAGE)
        cleanup.assert_called_once_with(IMAGE)

    def test_smoke_cleanup_refuses_another_container_even_with_same_name(self):
        for raw, expected in (((installer.SOURCE_SHA + " " + IMAGE + "\n").encode(), 1),
                              (b"other-source " + IMAGE.encode() + b"\n", 0), (None, 0)):
            with patch.object(installer, "_capture", return_value=raw), patch.object(installer, "_quiet") as quiet:
                installer._stop_owned_smoke(IMAGE)
            self.assertEqual(quiet.call_count, expected)
            if expected:
                self.assertEqual(quiet.call_args.args[0], installer.DOCKER_PREFIX + ["stop", "--time", "5", installer.SMOKE_NAME])

    def test_layout_generates_token_privately_outside_source_and_never_enables_timer(self):
        with patch.object(installer, "_absent", return_value=True), patch.object(installer, "_unit_paths_free", return_value=True), \
                patch.object(installer, "_new_dir") as create, patch.object(installer, "_write_new") as write, \
                patch.object(installer, "_artifact", return_value=b"trusted"), \
                patch.object(installer.secrets, "token_hex", return_value=TOKEN) as generate:
            self.assertEqual(installer._install_layout(config(), IDENTIFIER, IMAGE), TOKEN)
        generate.assert_called_once_with(32)
        writes = {call.args[0]: (call.args[1], call.args[2:] or (0o600,)) for call in write.call_args_list}
        self.assertIn(("QUANTA_OWNER_TOKEN=" + TOKEN).encode(), writes[installer.ETC / "app.env"][0])
        self.assertEqual(writes[installer.ETC / "app.env"][1], (0o600,))
        self.assertFalse(any(installer.SOURCE in path.parents for path in writes))
        self.assertEqual(json.loads(writes[installer.ETC / "deployment.json"][0]),
                         {"storage_mode": "boot", "filesystem_uuid": IDENTIFIER, "image": IMAGE})
        for name in ("data", "backups"):
            self.assertIn(unittest.mock.call(installer.ROOT / name, 0o700, uid=10001, gid=10001), create.call_args_list)

    def test_pipeline_defers_layout_until_smoke_and_rechecks_before_only_app_start(self):
        with mocked_pipeline() as mocks:
            report = installer.run(config())
        self.assertEqual(report, {"scope": "app_installation", "status": "success", "stage": "complete"})
        mocks["_smoke"].assert_called_once_with(IMAGE)
        mocks["_install_layout"].assert_called_once_with(config(), IDENTIFIER, IMAGE)
        mocks["_unit_paths_free"].assert_called_once_with(installed=True)
        commands = [call.args[0] for call in mocks["_quiet"].call_args_list]
        self.assertEqual(commands[-2:], [["/usr/bin/systemctl", "daemon-reload"],
                                         ["/usr/bin/systemctl", "start", "quanta-boot.service"]])
        self.assertFalse(any("enable" in command or "prune" in command for command in commands))
        final_manifest = mocks["_write_new"].call_args
        self.assertEqual(final_manifest.args[0], installer.ETC / "installed.json")
        self.assertEqual(json.loads(final_manifest.args[1]), config())
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_pipeline_failure_never_progresses_or_publishes_secrets(self):
        stages = [("_preflight", "preflight"), ("_stage_source", "source"), ("_build_image", "build"),
                  ("_smoke", "smoke"), ("_install_layout", "layout"), ("_readiness", "readiness")]
        for name, stage in stages:
            with self.subTest(stage=stage), mocked_pipeline() as mocks:
                mocks[name].side_effect = RuntimeError("private-token-" + TOKEN)
                report = installer.run(config())
            self.assertEqual(report, {"scope": "app_installation", "status": "failed", "stage": stage})
            self.assertNotIn(TOKEN, json.dumps(report))
            mocks["_write_new"].assert_not_called()
            if stage in {"preflight", "source", "build", "smoke"}:
                mocks["_install_layout"].assert_not_called()
        with mocked_pipeline() as mocks:
            mocks["_ports_free"].return_value = False
            report = installer.run(config())
        self.assertEqual(report["stage"], "app_start")
        self.assertEqual(report["status"], "conflict")
        self.assertEqual(mocks["_quiet"].call_count, 1)

    def test_readiness_checks_unauthorized_auth_and_read_only_example_validation(self):
        example = {"id": "pair_energy_forces", "schema_version": "0.2.0", "definition": {"unit_system": "SI"}}
        responses = [(401, {}), (200, {"status": "ready"}), (200, {"examples": [example]}), (200, {"valid": True})]
        with patch.object(installer, "_http", side_effect=responses) as request:
            installer._readiness(config(), TOKEN)
        self.assertIsNone(request.call_args_list[0].args[1])
        self.assertEqual(request.call_args_list[-1].args[2], "/v1/validate")
        self.assertEqual(json.loads(request.call_args_list[-1].kwargs["body"]),
                         {"schema_version": "0.2.0", "definition": {"unit_system": "SI"}})
        self.assertFalse(any("experiments" in call.args[2] or "runs" in call.args[2] for call in request.call_args_list))

    def test_http_is_fixed_loopback_with_host_origin_auth_and_bounded_body(self):
        connection = unittest.mock.MagicMock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b'{"status":"ready"}'
        with patch.object(installer.http.client, "HTTPConnection", return_value=connection) as create:
            self.assertEqual(installer._http(config(), TOKEN, "/health/ready"), (200, {"status": "ready"}))
        create.assert_called_once_with("127.0.0.1", 8765, timeout=2)
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Host"], "app.example.net")
        self.assertEqual(headers["Origin"], config()["public_origin"])
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        connection.getresponse.return_value.read.assert_called_once_with(65537)
        connection.close.assert_called_once_with()

    def test_subprocesses_inherit_no_secrets_and_suppress_all_build_output(self):
        with patch.dict(os.environ, {"QUANTA_OWNER_TOKEN": TOKEN, "HTTP_PROXY": "private", "DOCKER_HOST": "private"}), \
                patch.object(installer.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            installer._quiet(["/fixed/client"], timeout=5, build=True)
        self.assertEqual(run.call_args.kwargs["env"], installer._environment(build=True))
        self.assertNotIn(TOKEN, str(run.call_args.kwargs["env"]))
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertFalse(run.call_args.kwargs["shell"])
        for failure in (subprocess.TimeoutExpired("private", 1), OSError("private")):
            with patch.object(installer.subprocess, "run", side_effect=failure), self.assertRaises(installer.InstallError):
                installer._quiet(["/fixed/client"])

    def test_capture_local_child_eof_limit_timeout_and_hidden_stderr(self):
        cases = [("import sys;sys.stderr.write('private');print('ok')", {}, b"ok\n"),
                 ("raise SystemExit(3)", {}, None),
                 ("import sys;sys.stdout.write('x'*100000)", {"limit": 10}, None),
                 ("import time;time.sleep(2)", {"timeout": 0.02}, None)]
        for source, options, expected in cases:
            with self.subTest(source=source), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(installer._capture([sys.executable, "-I", "-c", source], **options), expected)
                self.assertEqual(output.getvalue(), "")

    def test_cli_only_emits_sanitized_status_stage(self):
        with patch.object(installer, "run", return_value={"scope": "app_installation", "status": "success", "stage": "complete"}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(installer.main([encoded()]), 0)
        self.assertEqual(installer.sanitize_report(output.getvalue().encode())["status"], "success")
        with contextlib.redirect_stdout(io.StringIO()) as output, patch.object(installer, "run") as run:
            self.assertEqual(installer.main(["private-invalid"]), 2)
        run.assert_not_called()
        self.assertNotIn("private-invalid", output.getvalue())


if __name__ == "__main__":
    unittest.main()
