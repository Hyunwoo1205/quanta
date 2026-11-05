"""Mocked fixed IPv4 web-rule control; no firewall, OCI, root-path or network calls."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/oci/configure_web_firewall.py"
spec = importlib.util.spec_from_file_location("quanta_test_web_firewall", SCRIPT)
firewall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)
PRIVATE = "untrusted-private-fixture"


def config():
    return {"source_sha": firewall.SOURCE_SHA, "auth_mode": "owner-token",
            "public_origin": "https://quanta.example.com"}


def success(*, ufw=False, tls=False):
    result = firewall._report()
    result.update(status="success", failure_stage="none", scope_verified=True,
                  rules_inspected=True, ufw_active=ufw, rule_mutation_attempted=True,
                  rules_applied=True, persistence_configured=True,
                  persistence_service_active=not ufw, https_service_active=True, tls_issued=tls)
    return result


class ConfigurationAndReportTests(unittest.TestCase):
    def test_configuration_requires_exact_source_auth_and_https_dns_origin(self):
        value = config()
        self.assertEqual(firewall.validate_config(value), value)
        self.assertIsNot(firewall.validate_config(value), value)
        cases = [None, [], {**value, "extra": PRIVATE}, {**value, "source_sha": "0" * 40},
                 {**value, "auth_mode": "owner_token"}]
        for origin in ["http://quanta.example.com", "https://quanta.example.com:443", "https://quanta.example.com/",
                       "https://user@quanta.example.com", "https://quanta.example.com?secret=x",
                       "https://quanta.example.com#fragment", "https://127.0.0.1", "https://[::1]",
                       "https://localhost", "https://x.local", "https://x.internal", "https://x.invalid",
                       "https://QUANTA.example.com", "https://bad_host.example.com", "https://x.example.com\n"]:
            cases.append({**value, "public_origin": origin})
        for changed in cases:
            with self.subTest(value=repr(changed)[:90]), self.assertRaises((ValueError, TypeError)):
                firewall.validate_config(changed)

    def test_encoded_config_is_bounded_strict_and_never_accepts_duplicate_keys(self):
        raw = json.dumps(config()).encode()
        self.assertEqual(firewall._decode(base64.b64encode(raw).decode()), config())
        duplicate = raw[:-1] + b',"auth_mode":"owner-token"}'
        for argument in [None, "", "!bad!", "a" * 4097,
                         base64.b64encode(b" " * 2049).decode(),
                         base64.b64encode(duplicate).decode(),
                         base64.b64encode(raw.replace(b'"owner-token"', b'NaN')).decode()]:
            with self.subTest(type=type(argument).__name__), self.assertRaises((ValueError, TypeError, UnicodeError)):
                firewall._decode(argument)

    def test_success_can_record_tls_pending_but_never_claim_cloud_or_ipv6_change(self):
        for ufw in (False, True):
            value = success(ufw=ufw, tls=False)
            self.assertEqual(firewall.validate_report(value), value)
            self.assertEqual(firewall.sanitize_report(json.dumps(value).encode()), value)
        for field, value in [("cloud_ingress_changed", True), ("ipv6_changed", True),
                             ("rules_applied", False), ("scope_verified", False),
                             ("persistence_configured", False), ("https_service_active", False),
                             ("persistence_service_active", False), ("failure_stage", "https")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                firewall.validate_report({**success(), field: value})

    def test_raw_reports_reject_duplicates_nonfinite_extra_strings_and_oversize(self):
        raw = json.dumps(success()).encode()
        for changed in [None, "not-bytes", b"", b"\xff", b"[]", raw + b"junk", b" " * 8193,
                        raw[:-1] + b',"tls_issued":false}',
                        raw.replace(b'"tls_issued": false', b'"tls_issued": NaN'),
                        json.dumps({**success(), "private": PRIVATE}).encode(),
                        json.dumps({**success(), "scope": PRIVATE}).encode(),
                        json.dumps({**success(), "rules_applied": 1}).encode()]:
            with self.subTest(raw_type=type(changed).__name__):
                self.assertIsNone(firewall.sanitize_report(changed))
        for data in [{**firewall._report(), "tls_issued": True},
                     {**firewall._report(), "rules_applied": True},
                     {**firewall._report(), "persistence_service_active": True},
                     {**firewall._report(), "rule_mutation_attempted": True},
                     {**firewall._report(), "rules_inspected": True}]:
            self.assertIsNone(firewall.sanitize_report(json.dumps(data).encode()))


class IPv4RuleTests(unittest.TestCase):
    def test_only_owned_tcp80_443_check_or_front_insert_commands_are_constructed(self):
        for port in (80, 443):
            for operation in ("-C", "-I"):
                command = firewall._iptables(operation, port)
                self.assertEqual(command, ["/usr/sbin/iptables", "-w", "5", "-t", "filter", operation,
                    "INPUT", *(["1"] if operation == "-I" else []), "-p", "tcp", "--dport", str(port),
                    "-m", "comment", "--comment", "quanta-web-v1-" + str(port), "-j", "ACCEPT"])
        for operation in ("-F", "-D", "-A", "--flush", None):
            with self.assertRaises(ValueError):
                firewall._iptables(operation, 80)
        for port in (22, 8765, "80", None):
            with self.assertRaises(ValueError):
                firewall._rule(port)

    def test_input_parser_reads_only_filter_input_and_rejects_unknown_shape(self):
        raw = b'-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT\n'
        with mock.patch.object(firewall, "_command", return_value=(0, raw)) as command:
            rules = firewall._inspect_input()
        command.assert_called_once_with([firewall.IPTABLES, "-w", "5", "-t", "filter", "-S", "INPUT"], timeout=10)
        self.assertEqual(rules[0], ["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])
        for raw in [b"", b"-P FORWARD DROP\n", b"-P INPUT REJECT\n", b"-P INPUT ACCEPT\n-A OUTPUT -j ACCEPT\n",
                    b"-P INPUT ACCEPT\nprivate\n", b"-P INPUT ACCEPT\n-A INPUT \"unterminated\n", b"\xff"]:
            with self.subTest(raw=raw), mock.patch.object(firewall, "_command", return_value=(0, raw)), self.assertRaises(ValueError):
                firewall._inspect_input()

    def test_front_rule_detection_stops_at_existing_foreign_rules(self):
        web80 = ["-A", "INPUT", *firewall._rule(80)]
        web443 = ["-A", "INPUT", *firewall._rule(443)]
        foreign = ["-A", "INPUT", "-j", "REJECT"]
        self.assertEqual(firewall._front_ports([web80, web443, foreign]), {80, 443})
        self.assertEqual(firewall._front_ports([web80, foreign, web443]), {80})
        self.assertEqual(firewall._front_ports([foreign, web80, web443]), set())
        with_tcp_module = ["-A", "INPUT", "-p", "tcp", "-m", "tcp", *firewall._rule(80)[2:]]
        self.assertEqual(firewall._front_ports([with_tcp_module]), {80})

    def test_iptables_inserts_missing_or_ineffective_late_owned_rules_without_deleting_others(self):
        foreign = ["-A", "INPUT", "-j", "REJECT"]
        for already_exists in (0, 1):
            rules = [foreign, ["-A", "INPUT", *firewall._rule(80)]]
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if "-I" in argv:
                    port = int(argv[argv.index("--dport") + 1])
                    rules.insert(0, ["-A", "INPUT", *firewall._rule(port)])
                return (already_exists if "-C" in argv and len(calls) <= 3 else 0), b""
            with self.subTest(existing=already_exists), mock.patch.object(firewall, "_trusted_command"), \
                    mock.patch.object(firewall, "_inspect_input", side_effect=lambda: [r[:] for r in rules]), \
                    mock.patch.object(firewall, "_command", side_effect=command):
                firewall._apply_iptables()
            self.assertEqual([argv[argv.index("--dport") + 1] for argv in calls if "-I" in argv], ["80", "443"])
            self.assertIn(foreign, rules)
            self.assertTrue(all("-C" in argv or "-I" in argv for argv in calls))
            self.assertTrue(all(argv[argv.index("-t") + 1] == "filter" for argv in calls))

    def test_correct_front_rules_are_only_checked(self):
        rules = [["-A", "INPUT", *firewall._rule(port)] for port in (80, 443)]
        with mock.patch.object(firewall, "_trusted_command"), mock.patch.object(firewall, "_inspect_input", return_value=rules), \
                mock.patch.object(firewall, "_command", return_value=(0, b"")) as command:
            firewall._apply_iptables()
        self.assertEqual(command.call_count, 4)
        self.assertTrue(all("-C" in call.args[0] for call in command.call_args_list))

    def test_ufw_uses_explicit_ipv4_prepend_only_and_never_enables_or_flushes(self):
        with mock.patch.object(firewall, "_command", return_value=(0, b"")) as command, \
                mock.patch.object(firewall, "_ufw_active", return_value=True):
            firewall._apply_ufw()
        self.assertEqual(command.call_count, 2)
        for port, call in zip((80, 443), command.call_args_list):
            self.assertEqual(call.args[0], [firewall.UFW, "prepend", "allow", "in", "proto", "tcp",
                "from", "0.0.0.0/0", "to", "0.0.0.0/0", "port", str(port), "comment", "quanta-web-v1-" + str(port)])
            self.assertEqual(call.kwargs, {"timeout": 15})
        with mock.patch.object(firewall, "_command", return_value=(0, b"")), \
                mock.patch.object(firewall, "_ufw_active", return_value=False), self.assertRaises(ValueError):
            firewall._apply_ufw()

    def test_active_alternative_manager_or_unknown_ufw_status_fail_closed(self):
        for manager in ("firewalld.service", "nftables.service"):
            with mock.patch.object(firewall, "_active", side_effect=lambda unit: unit == manager), \
                    mock.patch.object(firewall, "_command") as command, self.assertRaises(ValueError):
                firewall._ufw_active()
            command.assert_not_called()
        for raw, expected in [(b"Status: active\nprivate details", True), (b"Status: inactive\n", False)]:
            with mock.patch.object(firewall, "_active", return_value=False), mock.patch.object(Path, "lstat"), \
                    mock.patch.object(firewall, "_trusted_command"), mock.patch.object(firewall, "_command", return_value=(0, raw)):
                self.assertEqual(firewall._ufw_active(), expected)
        with mock.patch.object(firewall, "_active", return_value=False), mock.patch.object(Path, "lstat"), \
                mock.patch.object(firewall, "_trusted_command"), mock.patch.object(firewall, "_command", return_value=(0, PRIVATE.encode())), \
                self.assertRaises(ValueError):
            firewall._ufw_active()


class FixedScopeAndLifecycleTests(unittest.TestCase):
    @contextlib.contextmanager
    def scoped_host(self):
        spec = importlib.util.spec_from_file_location("quanta_test_https_unit_fixture", ROOT / "deploy/oci/install_https.py")
        https = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(https)
        template = (ROOT / "deploy/oci/Caddyfile.example").read_bytes()
        self.assertEqual(hashlib.sha256(https.UNIT_TEXT.encode()).hexdigest(), firewall.HTTPS_UNIT_SHA256)
        self.assertEqual(hashlib.sha256(template).hexdigest(), firewall.TEMPLATE_SHA256)
        files = {firewall.MARKER: json.dumps(config()).encode(), firewall.HTTPS_UNIT: https.UNIT_TEXT.encode(),
                 firewall.TEMPLATE: template, firewall.CADDYFILE: template.replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n"),
                 firewall.HTTPS_ENV: b"QUANTA_PUBLIC_HOST=quanta.example.com\n"}
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = b"\xb7\x00"
        with contextlib.ExitStack() as stack:
            calls = {}
            calls["read"] = stack.enter_context(mock.patch.object(firewall, "_read", side_effect=lambda path, **kwargs: files[path]))
            calls["absent"] = stack.enter_context(mock.patch.object(firewall, "_absent"))
            calls["active"] = stack.enter_context(mock.patch.object(firewall, "_active", return_value=True))
            calls["command"] = stack.enter_context(mock.patch.object(firewall, "_command", side_effect=[(0, (str(firewall.HTTPS_UNIT) + "\n").encode()), (0, b"\n")]))
            stack.enter_context(mock.patch.object(firewall.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(firewall, "_parents"))
            stack.enter_context(mock.patch.object(firewall, "_trusted_command"))
            stack.enter_context(mock.patch.object(Path, "lstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_size=1024)))
            stack.enter_context(mock.patch.object(firewall.os, "open", return_value=9))
            stack.enter_context(mock.patch.object(firewall.os, "fdopen", return_value=io.BytesIO(header)))
            yield calls, files

    @contextlib.contextmanager
    def configured(self, *, ufw=False, tls=False):
        with contextlib.ExitStack() as stack:
            names = {"_scope": None, "_own_paths_absent": None, "_ufw_active": ufw,
                     "_trusted_command": None, "_inspect_input": [], "_carried_source": SCRIPT.read_bytes(),
                     "_write_new": None, "_command": (0, b""), "_effective_unit": None, "_active": True,
                     "_apply_iptables": None, "_apply_ufw": None, "_wait_tls": tls}
            mocks = {name: stack.enter_context(mock.patch.object(firewall, name, return_value=value)) for name, value in names.items()}
            yield mocks

    def test_initial_iptables_configuration_creates_only_own_persistence_and_restarts_only_https(self):
        with self.configured() as calls:
            result = firewall.configure(config())
        self.assertEqual(result, success())
        calls["_scope"].assert_called_once_with(config(), require_active=True)
        calls["_own_paths_absent"].assert_called_once_with()
        calls["_effective_unit"].assert_called_once_with("quanta-web-firewall.service", firewall.UNIT)
        self.assertEqual(calls["_write_new"].call_args_list, [
            mock.call(firewall.HELPER, SCRIPT.read_bytes(), 0o755),
            mock.call(firewall.UNIT, firewall.UNIT_TEXT.encode("ascii"), 0o644)])
        commands = [call.args[0] for call in calls["_command"].call_args_list]
        self.assertEqual(commands, [[firewall.SYSTEMCTL, "daemon-reload"],
            [firewall.SYSTEMCTL, "enable", "quanta-web-firewall.service"],
            [firewall.SYSTEMCTL, "start", "quanta-web-firewall.service"],
            [firewall.SYSTEMCTL, "restart", "quanta-https.service"]])
        calls["_wait_tls"].assert_called_once_with("quanta.example.com")

    def test_effective_persistence_conflict_stops_before_enable_start_or_rule_mutation(self):
        with self.configured() as calls:
            calls["_effective_unit"].side_effect = firewall.FirewallError(PRIVATE)
            result = firewall.configure(config())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_stage"], "persistence")
        self.assertFalse(result["persistence_configured"])
        self.assertFalse(result["rule_mutation_attempted"])
        self.assertFalse(result["rules_applied"])
        self.assertEqual(calls["_command"].call_args_list,
                         [mock.call([firewall.SYSTEMCTL, "daemon-reload"], limit=4096)])
        calls["_apply_iptables"].assert_not_called()
        calls["_apply_ufw"].assert_not_called()
        calls["_wait_tls"].assert_not_called()
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_effective_unit_refuses_wrong_fragment_or_any_cached_global_dropin(self):
        expected = (str(firewall.UNIT) + "\n").encode()
        for fragment, dropins in [(expected, b""), (expected, b"\n")]:
            with mock.patch.object(firewall, "_command", side_effect=[(0, fragment), (0, dropins)]) as command:
                firewall._effective_unit("quanta-web-firewall.service", firewall.UNIT)
            self.assertEqual(command.call_args_list, [
                mock.call([firewall.SYSTEMCTL, "show", "--property=FragmentPath", "--value", "quanta-web-firewall.service"], timeout=3, limit=4096),
                mock.call([firewall.SYSTEMCTL, "show", "--property=DropInPaths", "--value", "quanta-web-firewall.service"], timeout=3, limit=4096)])
        for fragment, dropins in [(b"/run/systemd/generator/quanta-web-firewall.service\n", b"\n"),
                                  (expected, b"/run/systemd/system/service.d/private.conf\n"),
                                  (expected, b" \n"), (expected.rstrip(), b"\n")]:
            with self.subTest(fragment=fragment, dropins=dropins), \
                    mock.patch.object(firewall, "_command", side_effect=[(0, fragment), (0, dropins)]), self.assertRaises(ValueError):
                firewall._effective_unit("quanta-web-firewall.service", firewall.UNIT)

    def test_existing_ufw_persistence_is_used_without_new_helper_or_unit(self):
        with self.configured(ufw=True, tls=True) as calls:
            result = firewall.configure(config())
        self.assertEqual(result, success(ufw=True, tls=True))
        calls["_apply_ufw"].assert_called_once_with()
        calls["_apply_iptables"].assert_not_called()
        calls["_write_new"].assert_not_called()
        calls["_carried_source"].assert_not_called()
        self.assertEqual([call.args[0] for call in calls["_command"].call_args_list],
                         [[firewall.SYSTEMCTL, "restart", "quanta-https.service"]])

    def test_scope_and_collision_denial_precede_any_rule_or_file_mutation(self):
        for failing in ("_scope", "_own_paths_absent", "_ufw_active", "_inspect_input", "_carried_source"):
            with self.subTest(failing=failing), self.configured() as calls:
                calls[failing].side_effect = firewall.FirewallError(PRIVATE)
                result = firewall.configure(config())
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["rule_mutation_attempted"])
                calls["_write_new"].assert_not_called()
                calls["_apply_iptables"].assert_not_called()
                calls["_apply_ufw"].assert_not_called()
                calls["_command"].assert_not_called()
                self.assertNotIn(PRIVATE, json.dumps(result))

    def test_invalid_config_does_not_inspect_host_and_inactive_https_never_claims_success(self):
        with self.configured() as calls:
            result = firewall.configure({**config(), "auth_mode": "other"})
            self.assertEqual(result["failure_stage"], "config")
            calls["_scope"].assert_not_called()
        with self.configured(ufw=True) as calls:
            calls["_active"].return_value = False
            result = firewall.configure(config())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_stage"], "https")
            self.assertTrue(result["rules_applied"])
            self.assertFalse(result["https_service_active"])
            calls["_wait_tls"].assert_not_called()

    def test_missing_scope_or_bad_trusted_receipt_stops_before_any_command(self):
        with mock.patch.object(firewall.os, "geteuid", return_value=1000), mock.patch.object(firewall, "_read") as read:
            with self.assertRaises(ValueError):
                firewall._scope(config(), require_active=True)
            read.assert_not_called()
        with mock.patch.object(firewall.os, "geteuid", return_value=0), \
                mock.patch.object(firewall, "_read", return_value=json.dumps({**config(), "source_sha": "0" * 40}).encode()), \
                mock.patch.object(firewall, "_trusted_command") as command, self.assertRaises(ValueError):
            firewall._scope(config(), require_active=True)
        command.assert_not_called()

    def test_fixed_scope_checks_all_unit_fragments_dropins_and_effective_unit(self):
        with self.scoped_host() as (calls, _):
            firewall._scope(config(), require_active=True)
        expected = []
        for directory in firewall.UNIT_DIRECTORIES:
            fragment = Path(directory) / "quanta-https.service"
            if fragment != firewall.HTTPS_UNIT:
                expected.append(mock.call(fragment))
            expected.append(mock.call(Path(directory) / "quanta-https.service.d"))
        self.assertEqual(calls["absent"].call_args_list, expected)
        calls["active"].assert_called_once_with("quanta-https.service")
        self.assertEqual(calls["command"].call_args_list, [
            mock.call([firewall.SYSTEMCTL, "show", "--property=FragmentPath", "--value", "quanta-https.service"], timeout=3, limit=4096),
            mock.call([firewall.SYSTEMCTL, "show", "--property=DropInPaths", "--value", "quanta-https.service"], timeout=3, limit=4096)])
        calls["read"].assert_any_call(firewall.MARKER, private=True)
        calls["read"].assert_any_call(firewall.HTTPS_UNIT, mode=0o644)
        calls["read"].assert_any_call(firewall.CADDYFILE, private=True)
        calls["read"].assert_any_call(firewall.HTTPS_ENV, private=True)

    def test_dropin_conflict_or_effective_unit_mismatch_blocks_scope(self):
        for path in [Path("/etc/systemd/system/quanta-https.service.d"), Path("/run/systemd/transient/quanta-https.service")]:
            with self.subTest(path=str(path)), self.scoped_host() as (calls, _):
                def absent(candidate):
                    if candidate == path:
                        raise firewall.FirewallError(PRIVATE)
                calls["absent"].side_effect = absent
                with self.assertRaises(ValueError):
                    firewall._scope(config(), require_active=True)
                calls["command"].assert_not_called()
        for fragment, dropins in [(b"/run/systemd/generator/quanta-https.service\n", b"\n"),
                                  ((str(firewall.HTTPS_UNIT) + "\n").encode(), b"/etc/systemd/system/service.d/global.conf\n")]:
            with self.scoped_host() as (calls, _):
                calls["command"].side_effect = [(0, fragment), (0, dropins)]
                with self.assertRaises(ValueError):
                    firewall._scope(config(), require_active=True)
                calls["active"].assert_not_called()

    def test_wrong_receipt_template_caddy_or_environment_never_reaches_system_commands(self):
        for path in (firewall.MARKER, firewall.HTTPS_UNIT, firewall.TEMPLATE, firewall.CADDYFILE, firewall.HTTPS_ENV):
            with self.subTest(path=str(path)), self.scoped_host() as (calls, files):
                files[path] = json.dumps({**config(), "source_sha": "0" * 40}).encode() if path == firewall.MARKER else PRIVATE.encode()
                with self.assertRaises(ValueError):
                    firewall._scope(config(), require_active=True)
                calls["command"].assert_not_called()

    def test_boot_restore_revalidates_fixed_scope_without_https_active_or_restart(self):
        def read(path, **kwargs):
            if path == firewall.MARKER:
                self.assertEqual(kwargs, {"private": True})
                return json.dumps(config()).encode()
            if path == firewall.UNIT:
                self.assertEqual(kwargs, {"mode": 0o644})
                return firewall.UNIT_TEXT.encode()
            self.assertEqual(path, firewall.HELPER)
            self.assertEqual(kwargs, {"mode": 0o755, "limit": 65_536})
            return SCRIPT.read_bytes()
        with mock.patch.object(firewall, "_read", side_effect=read), mock.patch.object(firewall, "_scope") as scope, \
                mock.patch.object(firewall, "_effective_unit") as effective, \
                mock.patch.object(firewall, "_ufw_active", return_value=False), \
                mock.patch.object(firewall, "_apply_iptables") as apply, mock.patch.object(firewall, "_command") as command:
            firewall.restore()
        scope.assert_called_once_with(config(), require_active=False)
        effective.assert_called_once_with("quanta-web-firewall.service", firewall.UNIT)
        apply.assert_called_once_with()
        command.assert_not_called()
        with mock.patch.object(firewall, "_read", side_effect=read), mock.patch.object(firewall, "_scope"), \
                mock.patch.object(firewall, "_effective_unit"), \
                mock.patch.object(firewall, "_ufw_active", return_value=True), mock.patch.object(firewall, "_apply_iptables") as apply:
            with self.assertRaises(ValueError):
                firewall.restore()
        apply.assert_not_called()

    def test_carried_source_is_compiled_but_not_executed_and_cannot_be_arbitrary_argv(self):
        source = SCRIPT.read_text()
        with mock.patch.object(firewall.sys, "orig_argv", ["python3", "-I", "-B", "-c", source, "opaque-config"]):
            self.assertEqual(firewall._carried_source(), source.encode())
        for argv in [[], ["python3", "-c"], ["python3", "-c", source, "-c", source],
                     ["python3", "-c", "print('short')"], ["python3", "-c", "x" * 65537]]:
            with mock.patch.object(firewall.sys, "orig_argv", argv), self.assertRaises(ValueError):
                firewall._carried_source()

    def test_main_restore_is_silent_and_failure_output_contains_only_fixed_report(self):
        for error, expected in [(None, 0), (OSError(PRIVATE), 2)]:
            out = io.StringIO()
            with mock.patch.object(firewall, "restore", side_effect=error), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                self.assertEqual(firewall.main(["--restore"]), expected)
            self.assertEqual(out.getvalue(), "")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            self.assertEqual(firewall.main([PRIVATE, PRIVATE]), 2)
        self.assertEqual(json.loads(out.getvalue()), firewall._report())
        self.assertNotIn(PRIVATE, out.getvalue())

    def test_tls_probe_uses_system_ca_loopback_and_validated_hostname_without_credentials(self):
        response = mock.Mock(status=200)
        response.read.return_value = json.dumps({"mode": "bearer", "authenticated": False, "authentication": "owner_token"}).encode()
        secured, raw, context = mock.Mock(), mock.Mock(), mock.Mock()
        context.wrap_socket.return_value = mock.MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = secured
        connection = mock.MagicMock()
        connection.__enter__.return_value = raw
        with mock.patch.object(firewall.ssl, "create_default_context", return_value=context) as create, \
                mock.patch.object(firewall.socket, "create_connection", return_value=connection) as connect, \
                mock.patch.object(firewall, "HTTPResponse", return_value=response):
            self.assertTrue(firewall._tls_ready("quanta.example.com"))
        create.assert_called_once_with()
        connect.assert_called_once_with(("127.0.0.1", 443), timeout=2)
        context.wrap_socket.assert_called_once_with(raw, server_hostname="quanta.example.com")
        response.read.assert_called_once_with(1025)
        secured.sendall.assert_called_once_with(b"GET /ui/auth HTTP/1.1\r\nHost: quanta.example.com\r\nConnection: close\r\n\r\n")

    def test_command_capture_is_private_minimal_environment_and_output_bounded(self):
        process = mock.Mock()
        process.stdout.fileno.return_value = 7
        process.poll.return_value = 0
        process.wait.return_value = 0
        selector = mock.MagicMock()
        selector.__enter__.return_value.select.return_value = [(object(), 1)]
        with mock.patch.object(firewall.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(firewall.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(firewall.os, "read", side_effect=[b"ok", b""]):
            self.assertEqual(firewall._command(["/fixed/command"]), (0, b"ok"))
        popen.assert_called_once_with(["/fixed/command"], stdin=firewall.subprocess.DEVNULL,
            stdout=firewall.subprocess.PIPE, stderr=firewall.subprocess.DEVNULL, shell=False, cwd="/",
            env={"PATH": firewall.BINPATH, "LC_ALL": "C"})
        process.stdout.close.assert_called_once_with()
        process.poll.return_value = None
        process.kill.reset_mock()
        with mock.patch.object(firewall.subprocess, "Popen", return_value=process), \
                mock.patch.object(firewall.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(firewall.os, "read", return_value=PRIVATE.encode()), self.assertRaises(ValueError):
            firewall._command(["/fixed/command"], limit=2)
        process.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
