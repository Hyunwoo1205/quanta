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


def manager_facts(manager):
    return {"manager": manager, "ufw_active": manager == "ufw",
            "nftables_active": manager == "nftables", "firewalld_active": manager == "firewalld"}


def success(*, ufw=False, tls=False, manager=None):
    manager = manager or ("ufw" if ufw else "iptables")
    result = firewall._report()
    result.update(status="success", failure_stage="none", failure_reason="none", scope_verified=True,
                  rules_inspected=True, **manager_facts(manager), rule_mutation_attempted=True,
                  rules_applied=True, persistence_configured=True,
                  persistence_service_active=manager in {"iptables", "nftables"}, https_service_active=True, tls_issued=tls)
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

    def test_failure_reason_is_required_fixed_and_consistent_with_status(self):
        self.assertEqual(firewall._report()["failure_reason"], "invalid_config")
        self.assertIn("none", firewall.REASONS)
        for reason in (PRIVATE, None, True, 1, [], {}, "", "none\n"):
            with self.subTest(reason=repr(reason)):
                self.assertIsNone(firewall.sanitize_report(json.dumps({**firewall._report(), "failure_reason": reason}).encode()))
        for value in [{**firewall._report(), "failure_reason": "none"},
                      {**success(), "failure_reason": "invalid_config"},
                      {key: value for key, value in firewall._report().items() if key != "failure_reason"}]:
            self.assertIsNone(firewall.sanitize_report(json.dumps(value).encode()))

    def test_manager_and_active_flags_are_required_and_consistent(self):
        for manager in ("iptables", "ufw", "nftables", "firewalld"):
            self.assertEqual(firewall.validate_report(success(manager=manager)), success(manager=manager))
        for changed in ({"manager": "unknown"}, {"manager": "ambiguous"}, {"manager": PRIVATE},
                        {"manager": "nftables"}, {"nftables_active": True}, {"firewalld_active": True},
                        {"manager": "firewalld", "firewalld_active": 1}):
            self.assertIsNone(firewall.sanitize_report(json.dumps({**success(), **changed}).encode()))

    def test_failure_classifier_uses_fixed_literals_without_formatting_unknown_errors(self):
        class Unprintable:
            def __str__(self):
                raise AssertionError("private error must not be formatted")
        class ForeignFirewallError(firewall.FirewallError):
            pass
        for message, expected in [("another firewall manager is active", "other_firewall_active"),
                                  ("unsafe fixed path", "unsafe_path"),
                                  ("untrusted system directory alias", "untrusted_system_alias"),
                                  ("application receipt differs", "receipt_mismatch"),
                                  ("effective fixed service differs", "effective_service_mismatch")]:
            self.assertEqual(firewall._failure_reason(firewall.FirewallError(message)), expected)
        for error in [firewall.FirewallError(PRIVATE), firewall.FirewallError(),
                      firewall.FirewallError("unsafe fixed path", PRIVATE),
                      firewall.FirewallError(Unprintable()), RuntimeError(Unprintable()),
                      ForeignFirewallError("unsafe fixed path"), RuntimeError("unsafe fixed path")]:
            self.assertEqual(firewall._failure_reason(error), "operation_failed")
        for error, expected in [(FileNotFoundError(PRIVATE), "system_path_missing"),
                                (PermissionError(PRIVATE), "permission_denied"),
                                (firewall.subprocess.TimeoutExpired(PRIVATE, 2), "command_timeout")]:
            self.assertEqual(firewall._failure_reason(error), expected)


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

    def test_unknown_ufw_status_fails_closed(self):
        for raw, expected in [(b"Status: active\nprivate details", True), (b"Status: inactive\n", False)]:
            with mock.patch.object(firewall, "_active", return_value=False), mock.patch.object(Path, "lstat"), \
                    mock.patch.object(firewall, "_trusted_command"), mock.patch.object(firewall, "_command", return_value=(0, raw)):
                self.assertEqual(firewall._ufw_active(), expected)
        with mock.patch.object(firewall, "_active", return_value=False), mock.patch.object(Path, "lstat"), \
                mock.patch.object(firewall, "_trusted_command"), mock.patch.object(firewall, "_command", return_value=(0, PRIVATE.encode())), \
                self.assertRaises(ValueError):
            firewall._ufw_active()


class NativeManagerTests(unittest.TestCase):
    def test_manager_detection_records_all_active_facts_and_never_chooses_an_overlap(self):
        for active in (set(), {"ufw"}, {"nftables"}, {"firewalld"},
                       {"ufw", "nftables"}, {"nftables", "firewalld"}, {"ufw", "nftables", "firewalld"}):
            with self.subTest(active=sorted(active)), \
                    mock.patch.object(firewall, "_active", side_effect=lambda unit: unit.removesuffix(".service") in active), \
                    mock.patch.object(firewall, "_ufw_active", return_value="ufw" in active):
                facts = firewall._detect_manager()
            expected = "ambiguous" if len(active) > 1 else next(iter(active), "iptables")
            self.assertEqual(facts, {"manager": expected, **{name + "_active": name in active for name in ("ufw", "nftables", "firewalld")}})

    def test_firewalld_default_zone_is_bounded_and_strict_before_any_mutation(self):
        with mock.patch.object(firewall, "_native_command") as trust, \
                mock.patch.object(firewall, "_command", return_value=(0, b"public\n")) as command:
            self.assertEqual(firewall._firewalld_zone(), "public")
        trust.assert_called_once_with(firewall.FIREWALL_CMD)
        command.assert_called_once_with([firewall.FIREWALL_CMD, "--get-default-zone"], timeout=5, limit=128)
        for raw in (b"", b"public", b"public\nother\n", b"--help\n", b"bad zone\n", b"a;private\n", b"x" * 33 + b"\n", b"\xff\n"):
            with self.subTest(raw=raw), mock.patch.object(firewall, "_native_command"), \
                    mock.patch.object(firewall, "_command", return_value=(0, raw)), self.assertRaises(ValueError):
                firewall._firewalld_zone()
        for zone in (None, "", "--help", "public\n", "public;private"):
            with mock.patch.object(firewall, "_command") as command, self.assertRaises(ValueError):
                firewall._apply_firewalld(zone)
            command.assert_not_called()

    def test_firewalld_adds_and_verifies_only_ipv4_rich_rules_runtime_and_permanent_without_reload(self):
        with mock.patch.object(firewall, "_command", side_effect=[(1, b""), (0, b""), (0, b"")] * 4) as command:
            firewall._apply_firewalld("public")
        expected = []
        for port in (80, 443):
            rule = f'rule family="ipv4" priority="-100" port port="{port}" protocol="tcp" accept'
            self.assertEqual(firewall._rich_rule(port), rule)
            for permanent in (False, True):
                prefix = [firewall.FIREWALL_CMD, "--zone=public", *(["--permanent"] if permanent else [])]
                query = prefix + ["--query-rich-rule=" + rule]
                expected.extend([mock.call(query, allowed=(0, 1), timeout=10, limit=4096),
                                 mock.call(prefix + ["--add-rich-rule=" + rule], allowed=(0, 11), timeout=10, limit=4096),
                                 mock.call(query, timeout=10, limit=4096)])
        self.assertEqual(command.call_args_list, expected)
        for port in (22, "80", None):
            with self.assertRaises(ValueError):
                firewall._rich_rule(port)

    def test_existing_firewalld_rules_are_only_queried_and_failed_verification_stops(self):
        with mock.patch.object(firewall, "_command", return_value=(0, b"")) as command:
            firewall._apply_firewalld("public")
        self.assertEqual(command.call_count, 8)
        self.assertTrue(all(call.args[0][-1].startswith("--query-rich-rule=") for call in command.call_args_list))
        with mock.patch.object(firewall, "_command", side_effect=[(1, b""), (0, b""), firewall.FirewallError(PRIVATE)]) as command:
            with self.assertRaises(ValueError):
                firewall._apply_firewalld("public")
        self.assertEqual(command.call_count, 3)


class NativeNftablesTests(unittest.TestCase):
    @staticmethod
    def own_rule(family="inet", table="filter", chain="input"):
        return {"family": family, "table": table, "chain": chain, "handle": 100,
                "comment": "quanta-web-v1", "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}},
                    {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [80, 443]}}},
                    {"accept": None}]}

    @staticmethod
    def entries(family="inet", table="filter", chain="input", *, rules=None, **changed):
        definition = {"family": family, "table": table, "name": chain, "type": "filter",
                      "hook": "input", "prio": 0, "policy": "drop", **changed}
        return [{"table": {"family": family, "name": table}}, {"chain": definition},
                *({"rule": rule} for rule in (rules or []))]

    @staticmethod
    def raw(entries):
        return json.dumps({"nftables": entries}).encode()

    def test_nft_inspection_is_fixed_bounded_json_and_selects_all_ipv4_input_chains(self):
        entries = self.entries() + self.entries("ip", "host", "inbound") + self.entries("ip6", "v6", "input6")
        with mock.patch.object(firewall, "_native_command") as trust, \
                mock.patch.object(firewall, "_command", return_value=(0, self.raw(entries))) as command:
            selected = firewall._inspect_nft()
        self.assertEqual(set(selected), {("inet", "filter", "input"), ("ip", "host", "inbound")})
        trust.assert_called_once_with(firewall.NFT)
        command.assert_called_once_with([firewall.NFT, "--json", "--numeric", "list", "ruleset"], timeout=10, limit=1_048_576)

    def test_nft_parser_refuses_unsupported_or_ambiguous_input_scopes(self):
        cases = [[], self.entries("ip6"), self.entries("bridge"), self.entries(type="nat"),
                 self.entries(policy="reject"), self.entries(prio=True), self.entries(prio=2 ** 31),
                 self.entries(table="unsafe-table"), self.entries(chain="input;private"),
                 self.entries(table="DOCKER"), self.entries(table="nat"), self.entries(table="NAT"), self.entries(flags=["offload"]),
                 self.entries() + [self.entries()[1]],
                 sum((self.entries(table="filter" + str(i)) for i in range(9)), [])]
        flagged_table = self.entries()
        flagged_table[0]["table"]["flags"] = ["owner"]
        cases.append(flagged_table)
        for entries in cases:
            with self.subTest(entries=repr(entries)[:160]), self.assertRaises(ValueError):
                firewall._parse_nft(self.raw(entries))
        for raw in (None, b"", b"x" * 1_048_577, b"[]", b'{"nftables":[],"nftables":[]}', b"\xff"):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises((ValueError, TypeError)):
                firewall._parse_nft(raw)

    def test_owned_nft_rule_requires_exact_ipv4_tcp_web_semantics(self):
        self.assertTrue(firewall._nft_owned(self.own_rule()))
        valid = self.own_rule()
        valid["expr"].pop(1)
        self.assertTrue(firewall._nft_owned(valid))
        for mutate in (lambda rule: rule.update(comment="foreign"),
                       lambda rule: rule.update(extra=PRIVATE),
                       lambda rule: rule["expr"][0]["match"].update(right="ipv6"),
                       lambda rule: rule["expr"][1]["match"].update(right="udp"),
                       lambda rule: rule["expr"][2]["match"].update(right={"set": [22, 443]}),
                       lambda rule: rule["expr"][2]["match"].update(right={"set": [80, "443"]}),
                       lambda rule: rule["expr"].__setitem__(-1, {"drop": None})):
            rule = self.own_rule()
            mutate(rule)
            self.assertFalse(firewall._nft_owned(rule))

    def test_nft_set_membership_normalization_does_not_relax_scalar_protocol_matches(self):
        for family in ("ip", "inet"):
            rule = self.own_rule(family)
            rule["expr"][2]["match"]["op"] = "in"
            self.assertTrue(firewall._nft_owned(rule))
            for index in (0, 1):
                changed = self.own_rule(family)
                changed["expr"][index]["match"]["op"] = "in"
                self.assertFalse(firewall._nft_owned(changed))
            for right in (80, {"range": [80, 443]}, {"set": [80, 443, 8765]}, {"set": [80, "443"]}):
                changed = self.own_rule(family)
                changed["expr"][2]["match"].update(op="in", right=right)
                self.assertFalse(firewall._nft_owned(changed))

    def test_nft_implicit_ipv4_is_accepted_only_for_the_ip_family(self):
        for family in ("ip", "inet", "ip6", "bridge", None):
            for include_tcp_meta in (True, False):
                rule = self.own_rule(family)
                rule["expr"].pop(0)
                if not include_tcp_meta:
                    rule["expr"].pop(0)
                rule["expr"][-2]["match"]["op"] = "in"
                self.assertEqual(firewall._nft_owned(rule), family == "ip")
            explicit = self.own_rule(family)
            self.assertEqual(firewall._nft_owned(explicit), family in {"ip", "inet"})

    def test_nft_inserts_ipv4_web_rule_at_each_chain_head_without_deleting_foreign_rules(self):
        foreign = {"family": "inet", "table": "filter", "chain": "input", "expr": [{"reject": None}]}
        before_entries = self.entries(rules=[foreign, self.own_rule()]) + self.entries("ip", "host", "inbound")
        after_entries = self.entries(rules=[self.own_rule(), foreign, self.own_rule()]) + self.entries(
            "ip", "host", "inbound", rules=[self.own_rule("ip", "host", "inbound")])
        before, after = firewall._parse_nft(self.raw(before_entries)), firewall._parse_nft(self.raw(after_entries))
        with mock.patch.object(firewall, "_inspect_nft", side_effect=[before, after]), \
                mock.patch.object(firewall, "_command", return_value=(0, b"")) as command:
            firewall._apply_nft()
        expected = []
        for family, table, chain in (("inet", "filter", "input"), ("ip", "host", "inbound")):
            ipv4 = ["meta", "nfproto", "ipv4"] if family == "inet" else []
            expected.append(mock.call([firewall.NFT, "insert", "rule", family, table, chain,
                *ipv4, "meta", "l4proto", "tcp", "tcp", "dport", "{", "80", ",", "443", "}",
                "accept", "comment", '"quanta-web-v1"'], timeout=10, limit=4096))
        self.assertEqual(command.call_args_list, expected)
        self.assertIn(foreign, after[("inet", "filter", "input")]["rules"])

    def test_nft_family_specific_argv_omits_nfproto_only_for_intrinsic_ipv4(self):
        for family in ("ip", "inet"):
            before = firewall._parse_nft(self.raw(self.entries(family)))
            owned = self.own_rule(family)
            if family == "ip":
                owned["expr"].pop(0)
            after = firewall._parse_nft(self.raw(self.entries(family, rules=[owned])))
            with mock.patch.object(firewall, "_inspect_nft", side_effect=[before, after]), \
                    mock.patch.object(firewall, "_command", return_value=(0, b"")) as command:
                firewall._apply_nft()
            argv = command.call_args.args[0]
            self.assertEqual(argv[:6], [firewall.NFT, "insert", "rule", family, "filter", "input"])
            self.assertEqual("nfproto" in argv, family == "inet")
            self.assertIn(["meta", "l4proto", "tcp", "tcp", "dport"],
                          [argv[index:index + 5] for index in range(len(argv) - 4)])
            self.assertIn(["{", "80", ",", "443", "}"],
                          [argv[index:index + 5] for index in range(len(argv) - 4)])

    def test_nft_exact_owned_rule_already_first_is_idempotent(self):
        selected = firewall._parse_nft(self.raw(self.entries(rules=[self.own_rule()])))
        with mock.patch.object(firewall, "_inspect_nft", side_effect=[selected, selected]) as inspect, \
                mock.patch.object(firewall, "_command") as command:
            firewall._apply_nft()
        self.assertEqual(inspect.call_count, 2)
        command.assert_not_called()

    def test_nft_post_write_requires_same_scope_definition_and_owned_rule_first(self):
        before = firewall._parse_nft(self.raw(self.entries()))
        changed_definition = firewall._parse_nft(self.raw(self.entries(policy="accept", rules=[self.own_rule()])))
        cases = [before, changed_definition, firewall._parse_nft(self.raw(self.entries("ip", "other", "input")))]
        for after in cases:
            with mock.patch.object(firewall, "_inspect_nft", side_effect=[before, after]), \
                    mock.patch.object(firewall, "_command", return_value=(0, b"")), self.assertRaises(ValueError):
                firewall._apply_nft()


class FixedParentSafetyTests(unittest.TestCase):
    @contextlib.contextmanager
    def metadata(self, entries=None, *, link="bin"):
        entries = entries or {}
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with mock.patch.object(Path, "lstat", autospec=True,
                               side_effect=lambda path: entries.get(path, directory)) as lstat, \
                mock.patch.object(firewall.os, "readlink", return_value=link) as readlink:
            yield lstat, readlink

    def test_exact_root_owned_usr_sbin_alias_targets_are_permitted(self):
        alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        for target in ("bin", "/usr/bin"):
            with self.subTest(target=target), self.metadata({Path("/usr/sbin"): alias}, link=target) as (lstat, readlink):
                firewall._parents(Path("/usr/sbin/iptables"))
            readlink.assert_called_once_with(Path("/usr/sbin"))
            self.assertIn(mock.call(Path("/usr/bin")), lstat.call_args_list)

    def test_known_root_owned_lib_alias_remains_permitted(self):
        alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        for target in ("usr/lib", "/usr/lib"):
            with self.subTest(target=target), self.metadata({Path("/lib"): alias}, link=target) as (_, readlink):
                firewall._parents(Path("/lib/systemd/system/quanta-https.service"))
            readlink.assert_called_once_with(Path("/lib"))

    def test_noncanonical_or_unrelated_alias_targets_are_rejected(self):
        alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        for target in ("../bin", "../usr/bin", "bin/", "/usr/bin/", "/bin", "/tmp/bin", "usr/bin", "./bin"):
            with self.subTest(target=target), self.metadata({Path("/usr/sbin"): alias}, link=target), self.assertRaises(ValueError):
                firewall._parents(Path("/usr/sbin/iptables"))

    def test_usr_sbin_alias_owner_and_real_target_are_both_trusted(self):
        root_alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        untrusted_alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=1000)
        targets = [types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
                   types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                   types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0),
                   types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
                   types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)]
        with self.metadata({Path("/usr/sbin"): untrusted_alias}), self.assertRaises(ValueError):
            firewall._parents(Path("/usr/sbin/iptables"))
        for target in targets:
            with self.subTest(mode=target.st_mode, owner=target.st_uid), \
                    self.metadata({Path("/usr/sbin"): root_alias, Path("/usr/bin"): target}), self.assertRaises(ValueError):
                firewall._parents(Path("/usr/sbin/iptables"))

    def test_project_and_other_system_symlinks_are_still_rejected(self):
        alias = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        for path, parent in [(firewall.MARKER, Path("/etc/quanta")),
                             (firewall.CADDY, Path("/usr/local/lib/quanta")),
                             (firewall.TEMPLATE, Path("/srv/quanta/source")),
                             (Path("/usr/local/sbin/tool"), Path("/usr/local/sbin")),
                             (Path("/usr/bin/systemctl"), Path("/usr/bin"))]:
            with self.subTest(parent=str(parent)), self.metadata({parent: alias}), self.assertRaises(ValueError):
                firewall._parents(path)


class FixedScopeAndLifecycleTests(unittest.TestCase):
    @staticmethod
    def acme_files(files, email="operator@example.com"):
        files[firewall.CADDYFILE] = files[firewall.CADDYFILE].replace(
            b"\tadmin off\n", b"\tadmin off\n\temail {$QUANTA_ACME_EMAIL}\n"
            b"\tacme_ca https://acme.zerossl.com/v2/DV90\n")
        files[firewall.HTTPS_ENV] += ("QUANTA_ACME_EMAIL=" + email + "\n").encode("ascii")
        receipt = {"schema": 1, **config(), "issuer": "zerossl_acme",
                   "email_sha256": hashlib.sha256(email.encode("ascii")).hexdigest()}
        files[firewall.ACME_RECEIPT] = json.dumps(receipt).encode()
        return receipt

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
    def configured(self, *, ufw=False, tls=False, manager=None):
        manager = manager or ("ufw" if ufw else "iptables")
        with contextlib.ExitStack() as stack:
            names = {"_scope": None, "_own_paths_absent": None, "_ufw_active": ufw,
                     "_detect_manager": manager_facts(manager), "_firewalld_zone": "public", "_inspect_nft": {},
                     "_trusted_command": None, "_inspect_input": [], "_carried_source": SCRIPT.read_bytes(),
                     "_write_new": None, "_command": (0, b""), "_effective_unit": None, "_active": True,
                     "_apply_iptables": None, "_apply_ufw": None, "_apply_nft": None, "_apply_firewalld": None, "_wait_tls": tls}
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

    def test_native_firewalld_uses_only_its_runtime_and_permanent_persistence(self):
        with self.configured(manager="firewalld") as calls:
            result = firewall.configure(config())
        self.assertEqual(result, success(manager="firewalld"))
        calls["_firewalld_zone"].assert_called_once_with()
        calls["_apply_firewalld"].assert_called_once_with("public")
        for name in ("_write_new", "_carried_source", "_apply_iptables", "_apply_ufw", "_apply_nft"):
            calls[name].assert_not_called()
        self.assertEqual([call.args[0] for call in calls["_command"].call_args_list],
                         [[firewall.SYSTEMCTL, "restart", "quanta-https.service"]])

    def test_native_nftables_inspects_before_writing_own_boot_persistence_and_dispatches_only_nft(self):
        with self.configured(manager="nftables") as calls:
            result = firewall.configure(config())
        self.assertEqual(result, success(manager="nftables"))
        calls["_inspect_nft"].assert_called_once_with()
        calls["_apply_nft"].assert_called_once_with()
        calls["_apply_iptables"].assert_not_called()
        calls["_apply_ufw"].assert_not_called()
        calls["_apply_firewalld"].assert_not_called()
        self.assertEqual(calls["_write_new"].call_args_list, [
            mock.call(firewall.HELPER, SCRIPT.read_bytes(), 0o755),
            mock.call(firewall.UNIT, firewall.UNIT_TEXT.encode("ascii"), 0o644)])
        self.assertIn("nftables.service", firewall.UNIT_TEXT.split("After=", 1)[1].splitlines()[0])
        with self.configured(manager="nftables") as calls:
            calls["_inspect_nft"].side_effect = firewall.FirewallError("unsupported nftables input scope")
            result = firewall.configure(config())
        self.assertEqual(result["failure_reason"], "nft_scope_unsupported")
        calls["_write_new"].assert_not_called()
        calls["_command"].assert_not_called()

    def test_overlapping_managers_are_reported_and_refused_before_any_write(self):
        facts = {"manager": "ambiguous", "ufw_active": False, "nftables_active": True, "firewalld_active": True}
        with self.configured() as calls:
            calls["_detect_manager"].return_value = facts
            result = firewall.configure(config())
        self.assertEqual(result["failure_reason"], "manager_overlap")
        self.assertEqual({key: result[key] for key in facts}, facts)
        self.assertFalse(result["rule_mutation_attempted"])
        for name in ("_write_new", "_command", "_inspect_input", "_inspect_nft", "_firewalld_zone",
                     "_apply_iptables", "_apply_nft", "_apply_ufw", "_apply_firewalld"):
            calls[name].assert_not_called()

    def test_failed_later_manager_inspection_retains_native_manager_already_observed(self):
        detect = firewall._detect_manager
        for known in ("firewalld", "nftables"):
            with self.subTest(known=known), self.configured() as calls:
                calls["_detect_manager"].side_effect = detect
                calls["_active"].side_effect = lambda unit: unit == known + ".service"
                calls["_ufw_active"].side_effect = FileNotFoundError(PRIVATE)
                result = firewall.configure(config())
                self.assertEqual(result["manager"], known)
                self.assertTrue(result[known + "_active"])
                self.assertEqual(result["failure_reason"], "system_path_missing")
                self.assertFalse(result["rule_mutation_attempted"])
                calls["_write_new"].assert_not_called()
                calls["_command"].assert_not_called()
                self.assertNotIn(PRIVATE, json.dumps(result))

    def test_missing_native_cli_is_reported_before_any_write(self):
        with self.configured(manager="firewalld") as calls:
            calls["_firewalld_zone"].side_effect = firewall.FirewallError("required manager command is missing")
            result = firewall.configure(config())
        self.assertEqual(result["manager"], "firewalld")
        self.assertEqual(result["failure_reason"], "manager_cli_missing")
        self.assertFalse(result["rule_mutation_attempted"])
        calls["_write_new"].assert_not_called()
        calls["_command"].assert_not_called()
        calls["_apply_firewalld"].assert_not_called()

    def test_scope_and_collision_denial_precede_any_rule_or_file_mutation(self):
        for failing in ("_scope", "_own_paths_absent", "_detect_manager", "_inspect_input", "_carried_source"):
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

    def test_preflight_and_manager_failures_have_fixed_reasons_before_any_write(self):
        for failing, message, expected in [("_scope", "unsafe fixed path", "unsafe_path"),
                                           ("_scope", "untrusted system directory alias", "untrusted_system_alias"),
                                           ("_detect_manager", "another firewall manager is active", "other_firewall_active")]:
            with self.subTest(failing=failing, reason=expected), self.configured() as calls:
                calls[failing].side_effect = firewall.FirewallError(message)
                result = firewall.configure(config())
                self.assertEqual(result["failure_reason"], expected)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["rule_mutation_attempted"])
                calls["_write_new"].assert_not_called()
                calls["_command"].assert_not_called()
                calls["_apply_iptables"].assert_not_called()
                calls["_apply_ufw"].assert_not_called()

    def test_unknown_private_failure_is_generic_and_main_never_prints_it(self):
        class PrivateFailure(Exception):
            def __str__(self):
                raise AssertionError("private error must not be formatted")
        for error in [firewall.FirewallError(PRIVATE), PrivateFailure(PRIVATE)]:
            with self.configured() as calls:
                calls["_scope"].side_effect = error
                result = firewall.configure(config())
                self.assertEqual(result["failure_reason"], "operation_failed")
                calls["_write_new"].assert_not_called()
                self.assertNotIn(PRIVATE, json.dumps(result))
            out = io.StringIO()
            with mock.patch.object(firewall, "configure", side_effect=error), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                self.assertEqual(firewall.main([base64.b64encode(json.dumps(config()).encode()).decode()]), 2)
            self.assertEqual(json.loads(out.getvalue()), {**firewall._report(), "failure_reason": "operation_failed"})
            self.assertNotIn(PRIVATE, out.getvalue())

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
        expected.append(mock.call(firewall.ACME_RECEIPT))
        self.assertEqual(calls["absent"].call_args_list, expected)
        calls["active"].assert_called_once_with("quanta-https.service")
        self.assertEqual(calls["command"].call_args_list, [
            mock.call([firewall.SYSTEMCTL, "show", "--property=FragmentPath", "--value", "quanta-https.service"], timeout=3, limit=4096),
            mock.call([firewall.SYSTEMCTL, "show", "--property=DropInPaths", "--value", "quanta-https.service"], timeout=3, limit=4096)])
        calls["read"].assert_any_call(firewall.MARKER, private=True)
        calls["read"].assert_any_call(firewall.HTTPS_UNIT, mode=0o644)
        calls["read"].assert_any_call(firewall.CADDYFILE, private=True)
        calls["read"].assert_any_call(firewall.HTTPS_ENV, private=True)

    def test_acme_variant_requires_exact_config_environment_and_protected_hashed_receipt(self):
        with self.scoped_host() as (calls, files):
            receipt = self.acme_files(files)
            firewall._scope(config(), require_active=True)
        self.assertEqual(set(receipt), {"schema", "source_sha", "public_origin", "auth_mode", "issuer", "email_sha256"})
        self.assertNotIn("operator@example.com", json.dumps(receipt))
        calls["read"].assert_any_call(firewall.ACME_RECEIPT, private=True)
        self.assertNotIn(mock.call(firewall.ACME_RECEIPT), calls["absent"].call_args_list)
        calls["active"].assert_called_once_with("quanta-https.service")

    def test_acme_receipt_schema_identity_hash_and_presence_are_required_before_commands(self):
        for changed in ({"schema": True}, {"schema": 2}, {"source_sha": "0" * 40},
                        {"public_origin": "https://other.example.com"}, {"auth_mode": "access"},
                        {"issuer": "unknown"}, {"email_sha256": "0" * 64}, {"email": "operator@example.com"}):
            with self.subTest(fields=sorted(changed)), self.scoped_host() as (calls, files):
                receipt = self.acme_files(files)
                files[firewall.ACME_RECEIPT] = json.dumps({**receipt, **changed}).encode()
                with self.assertRaises(ValueError):
                    firewall._scope(config(), require_active=True)
                calls["command"].assert_not_called()
        with self.scoped_host() as (calls, files):
            self.acme_files(files)
            def read(path, **kwargs):
                if path == firewall.ACME_RECEIPT:
                    raise FileNotFoundError(PRIVATE)
                return files[path]
            calls["read"].side_effect = read
            with self.assertRaises(FileNotFoundError):
                firewall._scope(config(), require_active=True)
            calls["command"].assert_not_called()

    def test_acme_unknown_configuration_or_email_environment_injection_is_refused(self):
        for altered in ("unknown_caddy", "unknown_ca", "email_without_variant", "wrong_host", "non_ascii",
                        "crlf", "extra_assignment", "shell_expression", "double_dot", "missing_newline"):
            with self.subTest(altered=altered), self.scoped_host() as (calls, files):
                self.acme_files(files)
                if altered == "unknown_caddy":
                    files[firewall.CADDYFILE] += b"\n# unknown\n"
                elif altered == "unknown_ca":
                    files[firewall.CADDYFILE] = files[firewall.CADDYFILE].replace(b"acme.zerossl.com", b"other.example.com")
                elif altered == "email_without_variant":
                    files[firewall.CADDYFILE] = files[firewall.TEMPLATE].replace(b"\tadmin 127.0.0.1:2019\n", b"\tadmin off\n")
                elif altered == "wrong_host":
                    files[firewall.HTTPS_ENV] = files[firewall.HTTPS_ENV].replace(b"quanta.example.com", b"other.example.com")
                else:
                    email = {"non_ascii": b"person@ex\xffample.com", "crlf": b"operator@example.com\r\nEVIL=1",
                             "extra_assignment": b"operator@example.com\nEVIL=1", "shell_expression": b"$(private)@example.com",
                             "double_dot": b"operator..one@example.com", "missing_newline": b"operator@example.com"}[altered]
                    files[firewall.HTTPS_ENV] = b"QUANTA_PUBLIC_HOST=quanta.example.com\nQUANTA_ACME_EMAIL=" + email
                    if altered != "missing_newline":
                        files[firewall.HTTPS_ENV] += b"\n"
                with self.assertRaises((ValueError, UnicodeError)):
                    firewall._scope(config(), require_active=True)
                calls["command"].assert_not_called()

    def test_legacy_https_requires_absent_acme_receipt_and_receipt_reads_require_root0600(self):
        with self.scoped_host() as (calls, _):
            def absent(path):
                if path == firewall.ACME_RECEIPT:
                    raise firewall.FirewallError("fixed path already exists")
            calls["absent"].side_effect = absent
            with self.assertRaises(ValueError):
                firewall._scope(config(), require_active=True)
            calls["command"].assert_not_called()
        for mode, owner in ((stat.S_IFREG | 0o644, 0), (stat.S_IFREG | 0o640, 0),
                            (stat.S_IFREG | 0o600, 1000), (stat.S_IFLNK | 0o600, 0), (stat.S_IFDIR | 0o600, 0)):
            info = types.SimpleNamespace(st_mode=mode, st_uid=owner)
            with self.subTest(mode=mode, owner=owner), mock.patch.object(firewall, "_parents"), \
                    mock.patch.object(Path, "lstat", return_value=info), mock.patch.object(firewall.os, "open") as opened:
                with self.assertRaises(ValueError):
                    firewall._read(firewall.ACME_RECEIPT, private=True)
                opened.assert_not_called()

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
        for manager in ("iptables", "nftables", "ufw", "firewalld", "ambiguous"):
            with self.subTest(manager=manager), contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(firewall, "_read", side_effect=read))
                scope = stack.enter_context(mock.patch.object(firewall, "_scope"))
                effective = stack.enter_context(mock.patch.object(firewall, "_effective_unit"))
                stack.enter_context(mock.patch.object(firewall, "_detect_manager", return_value=manager_facts(manager)))
                stack.enter_context(mock.patch.object(firewall, "_firewalld_zone", return_value="public"))
                command = stack.enter_context(mock.patch.object(firewall, "_command"))
                applies = {name: stack.enter_context(mock.patch.object(firewall, name))
                           for name in ("_apply_iptables", "_apply_nft", "_apply_ufw", "_apply_firewalld")}
                if manager == "ambiguous":
                    with self.assertRaises(ValueError):
                        firewall.restore()
                else:
                    firewall.restore()
                scope.assert_called_once_with(config(), require_active=False)
                effective.assert_called_once_with("quanta-web-firewall.service", firewall.UNIT)
                selected = "_apply_nft" if manager == "nftables" else "_apply_" + manager
                for name, apply in applies.items():
                    if name == selected:
                        apply.assert_called_once_with(*(["public"] if manager == "firewalld" else []))
                    else:
                        apply.assert_not_called()
                command.assert_not_called()

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


class CommandSymlinkChainTests(unittest.TestCase):
    @contextlib.contextmanager
    def chain(self, *, unsafe_intermediate=False):
        directory = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        link = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        executable = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        targets = {Path("/usr/sbin"): "bin",
                   Path("/usr/sbin/iptables"): "/etc/alternatives/iptables",
                   Path("/etc/alternatives/iptables"): "/usr/sbin/iptables-nft",
                   Path("/usr/sbin/iptables-nft"): "xtables-nft-multi"}
        entries = {path: link for path in targets}
        entries[Path("/usr/sbin/xtables-nft-multi")] = executable
        if unsafe_intermediate:
            entries[Path("/etc/alternatives")] = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)
        with mock.patch.object(Path, "lstat", autospec=True,
                               side_effect=lambda path: entries.get(path, directory)) as lstat, \
                mock.patch.object(firewall.os, "readlink", side_effect=lambda path: targets[path]) as readlink:
            yield lstat, readlink

    def test_standard_root_owned_iptables_alternatives_chain_is_supported(self):
        with self.chain() as (lstat, readlink):
            firewall._trusted_command("/usr/sbin/iptables")
        self.assertIn(mock.call(Path("/etc/alternatives")), lstat.call_args_list)
        self.assertIn(mock.call(Path("/usr/sbin/xtables-nft-multi")), lstat.call_args_list)
        self.assertIn(mock.call(Path("/etc/alternatives/iptables")), readlink.call_args_list)

    def test_untrusted_intermediate_directory_cannot_hide_behind_root_final_executable(self):
        with self.chain(unsafe_intermediate=True) as (lstat, readlink), self.assertRaises(ValueError):
            firewall._trusted_command("/usr/sbin/iptables")
        self.assertIn(mock.call(Path("/etc/alternatives")), lstat.call_args_list)
        self.assertNotIn(mock.call(Path("/etc/alternatives/iptables")), readlink.call_args_list)


if __name__ == "__main__":
    unittest.main()
