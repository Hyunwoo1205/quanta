#!/usr/bin/env python3
"""Verify real nft CLI/JSON behavior only in a separate, initially empty netns.

Caller: sudo -n unshare --net python3 -I deploy/oci/verify_nft_namespace.py
No host, application, web or SSH configuration is read. Only the three fixed
fixture tables may be created or removed, after the root/network-namespace guard.
CLI grammar follows https://netfilter.org/projects/nftables/manpage.html .
"""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sys


WORK_SECONDS = 95
CLEANUP_SECONDS = 20
MAX_NFT_BYTES = 1_048_576
TABLES = (("inet", "quanta_nscheck_inet"), ("ip", "quanta_nscheck_ip"), ("ip6", "quanta_nscheck_ip6"))
INPUTS = frozenset((family, table, "input") for family, table in TABLES[:2])
_NAMESPACE = re.compile(r"net:\[[0-9]+\]\Z")
_FLAGS = ("namespace_guard_passed", "initial_ruleset_empty", "fixture_created", "input_chains_selected",
          "inet_ipv4_head_verified", "ip_ipv4_head_verified", "only_web_ports_opened",
          "original_rules_unchanged", "ipv6_unchanged", "forward_unchanged", "idempotence_verified", "cleanup_complete")


class VerificationFailed(ValueError):
    pass


def _report():
    return {"scope": "nft_namespace_verification", "status": "refused", "phase": "namespace_guard",
            **dict.fromkeys(_FLAGS, False), "apply_diagnostics": None}


def _namespace_guard(expected=None):
    if os.geteuid() != 0:
        raise VerificationFailed
    current = os.readlink("/proc/self/ns/net")
    initial = os.readlink("/proc/1/ns/net")
    if (not _NAMESPACE.fullmatch(current) or not _NAMESPACE.fullmatch(initial)
            or current == initial or (expected is not None and current != expected)):
        raise VerificationFailed
    return current


@contextmanager
def _deadline(seconds):
    def expired(*args):
        raise TimeoutError

    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] or previous_timer[1]:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def _backend():
    path = Path(__file__).with_name("configure_web_firewall.py")
    spec = importlib.util.spec_from_file_location("quanta_namespace_nft_backend", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.NFT != "/usr/sbin/nft" or not all(callable(getattr(module, name, None)) for name in (
            "_trusted_command", "_command", "_inspect_nft", "_apply_nft", "_nft_owned")):
        raise VerificationFailed
    return module


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise VerificationFailed
        value[key] = item
    return value


def _nonfinite(value):
    raise VerificationFailed


def _snapshot(backend, *, timeout=10):
    _, raw = backend._command([backend.NFT, "--json", "--numeric", "list", "ruleset"],
                              timeout=timeout, limit=MAX_NFT_BYTES)
    if type(raw) is not bytes or len(raw) > MAX_NFT_BYTES:
        raise VerificationFailed
    data = json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)
    if type(data) is not dict or set(data) != {"nftables"} or type(data["nftables"]) is not list:
        raise VerificationFailed
    entries = []
    for entry in data["nftables"]:
        if type(entry) is not dict or len(entry) != 1:
            raise VerificationFailed
        kind = next(iter(entry))
        if kind == "metainfo":
            continue
        if kind not in {"table", "chain", "rule"} or type(entry[kind]) is not dict:
            raise VerificationFailed
        entries.append(entry)
    return entries


def _mutate(backend, namespace, arguments, *, allowed=(0,)):
    _namespace_guard(namespace)
    return backend._command([backend.NFT, *arguments], allowed=allowed, timeout=10, limit=4096)


def _fixtures(backend, namespace):
    for family, table in TABLES:
        _mutate(backend, namespace, ["create", "table", family, table])
    for family, table, chain, hook in (
            ("inet", TABLES[0][1], "input", "input"), ("ip", TABLES[1][1], "input", "input"),
            ("inet", TABLES[0][1], "forward", "forward"), ("ip6", TABLES[2][1], "forward", "forward")):
        _mutate(backend, namespace, ["create", "chain", family, table, chain,
            "{", "type", "filter", "hook", hook, "priority", "0", ";", "policy", "drop", ";", "}"])
    for family, table in TABLES[:2]:
        _mutate(backend, namespace, ["add", "rule", family, table, "input", "tcp", "dport", "8080",
                                    "counter", "accept", "comment", '"quanta-nscheck-other-port"'])
        if family == "inet":
            _mutate(backend, namespace, ["add", "rule", family, table, "input", "meta", "nfproto", "ipv6",
                "tcp", "dport", "8081", "counter", "accept", "comment", '"quanta-nscheck-inet-ip6"'])
        _mutate(backend, namespace, ["add", "rule", family, table, "input", "counter", "drop",
                                    "comment", '"quanta-nscheck-terminal"'])
    for family, table in (TABLES[0], TABLES[2]):
        _mutate(backend, namespace, ["add", "rule", family, table, "forward", "tcp", "dport", "8082",
                                    "counter", "drop", "comment", '"quanta-nscheck-forward"'])


def _head_is_ipv4_web(rule):
    """Independently inspect the generated JSON rather than trust its comment."""
    if (type(rule) is not dict or rule.get("comment") != "quanta-web-v1"
            or rule.get("family") not in {"ip", "inet"} or type(rule.get("expr")) is not list
            or not rule["expr"] or rule["expr"][-1] != {"accept": None}):
        return False
    counts = {"nfproto": 0, "l4proto": 0, "ports": 0}
    for expression in rule["expr"][:-1]:
        if type(expression) is not dict or set(expression) != {"match"}:
            return False
        match = expression["match"]
        if type(match) is not dict or set(match) != {"op", "left", "right"} or match["op"] not in {"==", "in"}:
            return False
        left, right = match["left"], match["right"]
        if left == {"meta": {"key": "nfproto"}} and right in ("ipv4", 2):
            counts["nfproto"] += 1
        elif left == {"meta": {"key": "l4proto"}} and right in ("tcp", 6):
            counts["l4proto"] += 1
        elif left == {"payload": {"protocol": "tcp", "field": "dport"}}:
            if (type(right) is not dict or set(right) != {"set"} or type(right["set"]) is not list
                    or len(right["set"]) != 2 or any(type(port) is not int for port in right["set"])
                    or set(right["set"]) != {80, 443}):
                return False
            counts["ports"] += 1
        else:
            return False
    return (counts["ports"] == 1 and counts["l4proto"] <= 1 and counts["nfproto"] <= 1
            and (rule["family"] == "ip" or counts["nfproto"] == 1))


def _rules(entries, key):
    family, table, chain = key
    return [entry["rule"] for entry in entries if "rule" in entry and
            (entry["rule"].get("family"), entry["rule"].get("table"), entry["rule"].get("chain")) == (family, table, chain)]


def _ipv6_entries(entries):
    return [entry for entry in entries if next(iter(entry.values())).get("family") == "ip6"
            or entry.get("rule", {}).get("comment") == "quanta-nscheck-inet-ip6"]


def _forward_entries(entries):
    return [entry for entry in entries if entry.get("chain", {}).get("hook") == "forward"
            or entry.get("rule", {}).get("chain") == "forward"]


def _apply_with_trace(backend, trace):
    original = backend._command

    def tracked(command, **kwargs):
        kind = "other"
        if command == [backend.NFT, "--json", "--numeric", "list", "ruleset"]:
            kind = "query"
        elif (type(command) is list and command[:3] == [backend.NFT, "insert", "rule"]
                and tuple(command[3:6]) in INPUTS):
            kind = "insert"
            trace["last_insert_family"] = command[3]
        trace["last_command"] = kind
        trace[kind + "_commands"] = min(16, trace[kind + "_commands"] + 1)
        try:
            return original(command, **kwargs)
        except Exception:
            trace["last_command_failed"] = True
            raise

    backend._command = tracked
    try:
        backend._apply_nft()
    finally:
        backend._command = original


def _safe_value(value):
    known_numbers = {2, 6, 10, 17, 80, 443, 8080, 8081, 8082}
    known_strings = {"ip", "ip6", "ipv4", "ipv6", "tcp", "udp"}
    return ((type(value) is int and value in known_numbers)
            or (type(value) is str and value in known_strings))


def _describe_expression(expression):
    description = {"kind": "other"}
    if type(expression) is not dict or len(expression) != 1:
        return description
    for verdict in ("accept", "drop", "counter"):
        if verdict in expression:
            return {"kind": verdict}
    match = expression.get("match")
    if type(match) is not dict:
        return description
    left, right, operator = match.get("left"), match.get("right"), match.get("op")
    description["kind"] = "other_match"
    for kind, expected in (("meta_nfproto", {"meta": {"key": "nfproto"}}),
                           ("meta_l4proto", {"meta": {"key": "l4proto"}}),
                           ("tcp_dport", {"payload": {"protocol": "tcp", "field": "dport"}}),
                           ("ip_protocol", {"payload": {"protocol": "ip", "field": "protocol"}})):
        if left == expected:
            description["kind"] = kind
            break
    description["operator"] = operator if type(operator) is str and operator in {"==", "in", "!=", "not in"} else "other"
    if type(right) is dict and set(right) in ({"set"}, {"range"}):
        form = next(iter(right))
        values = right[form]
    elif type(right) is list:
        form, values = "list", right
    else:
        form, values = "scalar", [right]
    safe = type(values) is list and len(values) <= 4 and all(_safe_value(value) for value in values)
    description.update(value_form=form, values=values if safe else [], unknown_value=not safe)
    return description


def _describe_head(backend, rules):
    description = {"present": bool(rules), "owned_comment": False, "backend_owned": False,
                   "independent_owned": False, "expression_count": 0, "truncated": False, "expressions": []}
    if not rules:
        return description
    rule = rules[0]
    description["owned_comment"] = rule.get("comment") == "quanta-web-v1"
    try:
        description["backend_owned"] = bool(backend._nft_owned(rule))
        description["independent_owned"] = bool(_head_is_ipv4_web(rule))
    except Exception:
        pass
    expressions = rule.get("expr")
    if type(expressions) is list:
        description["expression_count"] = min(256, len(expressions))
        description["truncated"] = len(expressions) > 16
        description["expressions"] = [_describe_expression(expression) for expression in expressions[:16]]
    return description


def _apply_diagnostics(backend, namespace, error, trace):
    labels = {"fixed command failed": "command_failed", "fixed command timed out": "command_timeout",
              "fixed command output exceeded limit": "command_output_limit",
              "nftables web rule verification failed": "rule_verification",
              "invalid nftables ruleset": "ruleset_schema", "unsupported nftables input scope": "input_scope",
              "required manager command is missing": "missing_command", "untrusted fixed command": "untrusted_command"}
    failure = "operation_timeout" if isinstance(error, TimeoutError) else labels.get(str(error), "unclassified")
    description = {"failure_kind": failure, **trace, "snapshot_available": False, "inet_head": None, "ip_head": None}
    if isinstance(error, TimeoutError):
        return description
    try:
        _namespace_guard(namespace)
        entries = _snapshot(backend, timeout=3)
        description["snapshot_available"] = True
        for key in sorted(INPUTS):
            description[key[0] + "_head"] = _describe_head(backend, _rules(entries, key))
    except Exception:
        pass
    return description


def _fixture_shape(entries):
    tables = [entry["table"] for entry in entries if "table" in entry]
    chains = [entry["chain"] for entry in entries if "chain" in entry]
    rules = [entry["rule"] for entry in entries if "rule" in entry]
    expected_chains = INPUTS | {("inet", TABLES[0][1], "forward"), ("ip6", TABLES[2][1], "forward")}
    if (len(tables) != 3 or {(item.get("family"), item.get("name")) for item in tables} != set(TABLES)
            or len(chains) != 4 or {(item.get("family"), item.get("table"), item.get("name")) for item in chains} != expected_chains
            or len(rules) != 7):
        return False
    if any(item.get("type") != "filter" or item.get("hook") != item.get("name")
           or type(item.get("prio")) is not int or item["prio"] != 0 or item.get("policy") != "drop"
           for item in chains):
        return False
    expected_comments = {
        "quanta-nscheck-other-port": (2, 8080), "quanta-nscheck-inet-ip6": (1, 8081),
        "quanta-nscheck-terminal": (2, None), "quanta-nscheck-forward": (2, 8082),
    }
    if {rule.get("comment") for rule in rules} != set(expected_comments):
        return False
    locations = {"quanta-nscheck-other-port": INPUTS, "quanta-nscheck-terminal": INPUTS,
                 "quanta-nscheck-inet-ip6": {("inet", TABLES[0][1], "input")},
                 "quanta-nscheck-forward": expected_chains - INPUTS}
    for comment, (count, port) in expected_comments.items():
        matching = [rule for rule in rules if rule.get("comment") == comment]
        if (len(matching) != count or {(item.get("family"), item.get("table"), item.get("chain"))
                                      for item in matching} != locations[comment]):
            return False
        for rule in matching:
            expressions = rule.get("expr")
            if (type(expressions) is not list or not expressions
                    or not any(type(item) is dict and set(item) == {"counter"} for item in expressions)):
                return False
            verdict = "drop" if comment in {"quanta-nscheck-terminal", "quanta-nscheck-forward"} else "accept"
            if expressions[-1] != {verdict: None}:
                return False
            if port is not None and not any(type(item) is dict and type(item.get("match")) is dict
                    and item["match"].get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}
                    and type(item["match"].get("right")) is int and item["match"]["right"] == port
                    for item in expressions):
                return False
            if comment == "quanta-nscheck-inet-ip6" and not any(type(item) is dict and type(item.get("match")) is dict
                    and item["match"].get("left") == {"meta": {"key": "nfproto"}}
                    and item["match"].get("right") in ("ipv6", 10) for item in expressions):
                return False
    return True


def _cleanup(backend, namespace):
    for family, table in reversed(TABLES):
        # The initially empty, still-guarded namespace establishes ownership even
        # if a timed-out create completed before its subprocess was terminated.
        _mutate(backend, namespace, ["delete", "table", family, table], allowed=(0, 1))
    _namespace_guard(namespace)
    if _snapshot(backend):
        raise VerificationFailed


def verify():
    result = _report()
    backend, namespace, cleanup_allowed = None, None, False
    trace = {"query_commands": 0, "insert_commands": 0, "other_commands": 0,
             "last_command": "none", "last_insert_family": None, "last_command_failed": False}
    try:
        namespace = _namespace_guard()
        result.update(status="failed", namespace_guard_passed=True)
        with _deadline(WORK_SECONDS):
            result["phase"] = "module_load"
            backend = _backend()
            backend._trusted_command(backend.NFT)
            result["phase"] = "initial_ruleset"
            if _snapshot(backend):
                raise VerificationFailed
            result["initial_ruleset_empty"] = True
            cleanup_allowed = True
            result["phase"] = "fixture_create"
            _fixtures(backend, namespace)
            result["fixture_created"] = True
            result["phase"] = "fixture_inspect"
            baseline = _snapshot(backend)
            selected = backend._inspect_nft()
            if not _fixture_shape(baseline) or set(selected) != INPUTS or any(not _rules(baseline, key) for key in INPUTS):
                raise VerificationFailed
            result["input_chains_selected"] = True
            result["phase"] = "apply"
            _namespace_guard(namespace)
            _apply_with_trace(backend, trace)
            after = _snapshot(backend)
            result["phase"] = "head_rules"
            for key in INPUTS:
                rules = _rules(after, key)
                if not rules or not _head_is_ipv4_web(rules[0]) or not backend._nft_owned(rules[0]):
                    raise VerificationFailed
                result[key[0] + "_ipv4_head_verified"] = True
            owned = [entry for entry in after if entry.get("rule", {}).get("comment") == "quanta-web-v1"]
            if len(owned) != 2 or any(not _head_is_ipv4_web(entry["rule"]) for entry in owned):
                raise VerificationFailed
            without_owned = [entry for entry in after if entry not in owned]
            result["only_web_ports_opened"] = True
            result["phase"] = "preservation"
            result["original_rules_unchanged"] = without_owned == baseline
            result["ipv6_unchanged"] = _ipv6_entries(after) == _ipv6_entries(baseline)
            result["forward_unchanged"] = _forward_entries(after) == _forward_entries(baseline)
            if not all(result[key] for key in ("original_rules_unchanged", "ipv6_unchanged", "forward_unchanged")):
                raise VerificationFailed
            result["phase"] = "idempotence"
            _namespace_guard(namespace)
            _apply_with_trace(backend, trace)
            result["idempotence_verified"] = _snapshot(backend) == after
            if not result["idempotence_verified"]:
                raise VerificationFailed
            result.update(status="success", phase="complete")
    except TimeoutError as error:
        result["status"] = "timeout"
        if result["phase"] in {"apply", "head_rules", "idempotence"} and cleanup_allowed:
            result["apply_diagnostics"] = _apply_diagnostics(backend, namespace, error, trace)
    except Exception as error:
        if result["phase"] in {"apply", "head_rules", "idempotence"} and cleanup_allowed:
            result["apply_diagnostics"] = _apply_diagnostics(backend, namespace, error, trace)
    finally:
        if cleanup_allowed:
            try:
                with _deadline(CLEANUP_SECONDS):
                    _cleanup(backend, namespace)
                result["cleanup_complete"] = True
            except Exception:
                result.update(status="failed", phase="cleanup")
    return result


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        result = verify() if not arguments else _report()
    except Exception:
        result = _report()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "success" and all(result[key] for key in _FLAGS) else 2


if __name__ == "__main__":
    raise SystemExit(main())
