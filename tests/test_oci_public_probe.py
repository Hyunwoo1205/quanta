"""Mocked public HTTPS observations and local processes; no external requests."""
from __future__ import annotations

import contextlib
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import signal
import socket
import ssl
import sys
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/oci/probe_public.py"
spec = importlib.util.spec_from_file_location("quanta_public_probe", SCRIPT)
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)

ORIGIN = "https://quanta.example.com"
HOST = "8.8.8.8"
CONFIG = (ORIGIN, "quanta.example.com", HOST)
ENV = {"QUANTA_PUBLIC_ORIGIN": ORIGIN, "QUANTA_AUTH_MODE": "owner-token", "QUANTA_OCI_HOST": HOST}
MARKER = "private-address-or-secret-must-not-appear"


def addresses(ipv6=False):
    result = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (HOST, 443))]
    if ipv6:
        result.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2606:4700:4700::1111", 443, 0, 0)))
    return result


def resolver(*args, **kwargs):
    return addresses()


class Response:
    def __init__(self, url, status=200, body=b"", media="application/json", location=None, headers=()):
        self.url, self.status, self.body = url, status, body
        self.headers = Message()
        self.headers.add_header("Content-Type", media)
        if location is not None:
            self.headers.add_header("Location", location)
        for name, value in headers:
            self.headers.add_header(name, value)
        self.read_sizes, self.closed = [], False

    def geturl(self):
        return self.url

    def read(self, size):
        self.read_sizes.append(size)
        return self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class Opener:
    def __init__(self, responses=None, clock=None):
        self.responses = successful_responses() if responses is None else responses
        self.calls, self.clock = [], clock

    def open(self, request, *, timeout):
        self.calls.append((request, timeout))
        if self.clock is not None:
            self.clock[0] += 9.9
        response = self.responses[len(self.calls) - 1]
        if isinstance(response, Exception):
            raise response
        return response


def successful_responses():
    return [Response("http://quanta.example.com/", status=308, location=ORIGIN + "/"),
            Response(ORIGIN + "/", media="text/html; charset=utf-8", body=b"<!doctype html><title>Quanta fixture</title>"),
            Response(ORIGIN + "/ui/auth", body=b'{"mode":"bearer","authenticated":false,"authentication":"owner_token"}'),
            Response(ORIGIN + "/v1/capabilities", status=401, body=b'{"errors":[]}'),
            Response(ORIGIN + "/v1/capabilities", status=401, body=b'{"errors":[]}')]


def successful_report():
    return public._run_probe(CONFIG, opener=Opener(), resolver=resolver)


class PublicProbeTests(unittest.TestCase):
    def test_valid_config_is_explicit_and_no_other_environment_value_is_read(self):
        class Restricted(dict):
            def get(self, key, default=None):
                if key not in public.CONFIG_KEYS:
                    raise AssertionError("Read outside public configuration")
                return super().get(key, default)

        self.assertEqual(public._configuration(Restricted(ENV)), CONFIG)

    def test_invalid_config_refuses_before_starting_a_process_or_network(self):
        cases = [{}, {**ENV, "QUANTA_AUTH_MODE": "access"}, {**ENV, "QUANTA_AUTH_MODE": ""}]
        cases += [{**ENV, "QUANTA_PUBLIC_ORIGIN": origin} for origin in (
            None, "", "http://quanta.example.com", "https://QUANTA.example.com", "https://localhost",
            "https://dev.localhost", "https://127.0.0.1", "https://quanta.example.com/", "https://quanta.example.com?",
            "https://quanta.example.com:443", "https://quanta.example.com:8443", "https://user@quanta.example.com",
            "https://quanta.example.com#", "https://quanta.example.com/path", "https://[::1]",
        )]
        cases += [{**ENV, "QUANTA_OCI_HOST": host} for host in (
            None, "", "127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "192.0.2.1",
            "008.8.8.8", "8.8.8.8:22", "example.com", "::1",
        )]
        for environment in cases:
            with self.subTest(environment=environment), patch.object(public, "_capture") as capture:
                report = public.probe(environment)
                self.assertEqual((report["status"], report["phase"]), ("not_configured", "configuration"))
                capture.assert_not_called()

    def test_success_reports_only_fixed_fields_and_never_owner_or_browser_claims(self):
        opener = Opener()
        report = public._run_probe(CONFIG, opener=opener, resolver=resolver)
        self.assertEqual((report["status"], report["phase"]), ("success", "complete"))
        self.assertIs(report["dns_a_matches_expected"], True)
        self.assertIs(report["dns_aaaa_present"], False)
        for field in public._CLAIMS:
            self.assertIs(report[field], False)
        raw = json.dumps(report).encode()
        self.assertEqual(public.sanitize_report(raw), report)
        self.assertNotIn(ORIGIN.encode(), raw)
        self.assertNotIn(HOST.encode(), raw)
        self.assertEqual(len(opener.calls), 5)
        for request, timeout in opener.calls:
            self.assertEqual(request.method, "GET")
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 10)
        self.assertEqual(opener.calls[-1][0].get_header("Authorization"), public.WRONG_AUTHORIZATION)
        self.assertTrue(all(request.get_header("Authorization") is None for request, _ in opener.calls[:-1]))
        self.assertNotRegex(public.WRONG_AUTHORIZATION, r"Bearer [0-9a-f]{64}\Z")
        for response in opener.responses:
            self.assertTrue(response.closed)
            self.assertLessEqual(response.read_sizes[0], public.MAX_SHELL + 1)

    def test_tls_uses_normal_hostname_and_certificate_verification(self):
        with patch.object(public, "build_opener", return_value=Opener()) as build:
            report = public._run_probe(CONFIG, resolver=resolver)
        self.assertEqual(report["status"], "success")
        redirect, https = build.call_args.args
        self.assertIsInstance(redirect, public._NoRedirect)
        self.assertTrue(https._context.check_hostname)
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(redirect.redirect_request(None, None, 302, "", {}, "https://attacker.example/"))

    def test_dns_only_reports_match_and_aaaa_presence(self):
        def resolved(*args, **kwargs):
            self.assertEqual(args, ("quanta.example.com", 443))
            self.assertEqual(kwargs, {"family": socket.AF_UNSPEC, "type": socket.SOCK_STREAM, "proto": socket.IPPROTO_TCP})
            return addresses(ipv6=True)

        report = public._run_probe(CONFIG, opener=Opener(), resolver=resolved)
        self.assertEqual(report["status"], "success")
        self.assertIs(report["dns_aaaa_present"], True)
        self.assertNotIn("2606:", json.dumps(report))

    def test_wrong_mixed_private_or_empty_dns_stops_before_http(self):
        cases = [[], addresses() * 129,
                 [(socket.AF_INET, 1, 6, "", ("1.1.1.1", 443))],
                 addresses() + [(socket.AF_INET, 1, 6, "", ("1.1.1.1", 443))],
                 addresses() + [(socket.AF_INET6, 1, 6, "", ("::1", 443, 0, 0))],
                 [(socket.AF_INET, 1, 6, "", ("::1", 443))]]
        for records in cases:
            with self.subTest(record_count=len(records)):
                opener = Opener()
                report = public._run_probe(CONFIG, opener=opener, resolver=lambda *args, **kw: records)
                self.assertEqual((report["status"], report["phase"]), ("failed", "dns"))
                self.assertEqual(opener.calls, [])

    def test_http_redirect_must_target_the_exact_https_origin_and_root(self):
        for location in (None, "https://attacker.example/", ORIGIN + ":443/", ORIGIN + ":8443/",
                         "http://quanta.example.com/", "/", "//quanta.example.com/", ORIGIN + "/login",
                         ORIGIN + "/?token=" + MARKER, ORIGIN + "/#fragment"):
            with self.subTest(location=location):
                opener = Opener([Response("http://quanta.example.com/", 308, location=location)])
                report = public._run_probe(CONFIG, opener=opener, resolver=resolver)
                self.assertEqual((report["status"], report["phase"]), ("failed", "http_redirect"))
                self.assertIs(report["http_redirect_matches_origin"], False)
                self.assertEqual(len(opener.calls), 1)
                self.assertNotIn(MARKER, json.dumps(report))
        for code in public._REDIRECTS:
            responses = successful_responses()
            responses[0].status = code
            self.assertEqual(public._run_probe(CONFIG, opener=Opener(responses), resolver=resolver)["status"], "success")

    def test_https_redirects_and_automatic_following_are_not_accepted(self):
        for changed_url, code in ((ORIGIN + "/", 302), ("https://attacker.example/", 200), (ORIGIN + ":8443/", 200)):
            responses = successful_responses()
            responses[1].url, responses[1].status = changed_url, code
            opener = Opener(responses)
            report = public._run_probe(CONFIG, opener=opener, resolver=resolver)
            self.assertEqual((report["status"], report["phase"]), ("failed", "https_shell"))
            self.assertEqual(len(opener.calls), 2)

    def test_discovery_is_an_exact_typed_unauthenticated_owner_mode(self):
        bodies = [b'{}', b'{"mode":"access","authenticated":false}',
                  b'{"mode":"bearer","authenticated":0,"authentication":"owner_token"}',
                  b'{"mode":"bearer","authenticated":true,"authentication":"owner_token"}',
                  b'{"mode":"bearer","authenticated":false,"authentication":"owner_token","principal":"private"}',
                  b'{"mode":"bearer","authenticated":false,"authenticated":false,"authentication":"owner_token"}',
                  b'{"mode":"bearer","authenticated":NaN,"authentication":"owner_token"}', b'\xff']
        for body in bodies:
            with self.subTest(body_length=len(body)):
                responses = successful_responses()
                responses[2].body = body
                opener = Opener(responses)
                report = public._run_probe(CONFIG, opener=opener, resolver=resolver)
                self.assertEqual((report["status"], report["phase"]), ("failed", "auth_discovery"))
                self.assertIsNot(report["owner_token_mode"], True)
                self.assertEqual(len(opener.calls), 3)

    def test_private_api_checks_both_missing_and_known_invalid_credentials(self):
        for index, phase in ((3, "anonymous_api"), (4, "wrong_token_api")):
            for status, media in ((200, "application/json"), (302, "application/json"), (401, "text/html")):
                with self.subTest(index=index, status=status, media=media):
                    responses = successful_responses()
                    responses[index].status = status
                    responses[index].headers.replace_header("Content-Type", media)
                    report = public._run_probe(CONFIG, opener=Opener(responses), resolver=resolver)
                    self.assertEqual((report["status"], report["phase"]), ("failed", phase))
                    self.assertIs(report[phase + "_denied"], False)

    def test_urllib_http_errors_are_bounded_responses_not_raw_errors(self):
        responses = successful_responses()
        for index in (3, 4):
            value = responses[index]
            responses[index] = HTTPError(value.url, 401, MARKER, value.headers, io.BytesIO(value.body))
        report = public._run_probe(CONFIG, opener=Opener(responses), resolver=resolver)
        self.assertEqual(report["status"], "success")
        self.assertNotIn(MARKER, json.dumps(report))

    def test_body_caps_and_ambiguous_or_compressed_headers_fail_closed(self):
        cases = [Response(ORIGIN + "/", body=b"x" * (public.MAX_SHELL + 1), media="text/html"),
                 Response(ORIGIN + "/", headers=[("Content-Length", str(public.MAX_SHELL + 1))]),
                 Response(ORIGIN + "/", headers=[("Content-Length", "-1")]),
                 Response(ORIGIN + "/", body=b"abc", headers=[("Content-Length", "2")]),
                 Response(ORIGIN + "/", headers=[("Content-Length", "0"), ("Content-Length", "0")]),
                 Response(ORIGIN + "/", headers=[("Content-Type", "text/html")]),
                 Response(ORIGIN + "/", headers=[("Location", ORIGIN), ("Location", ORIGIN)]),
                 Response(ORIGIN + "/", headers=[("Content-Encoding", "gzip")])]
        for response in cases:
            with self.subTest(headers=str(response.headers)):
                responses = successful_responses()
                responses[1] = response
                report = public._run_probe(CONFIG, opener=Opener(responses), resolver=resolver)
                self.assertEqual((report["status"], report["phase"]), ("failed", "https_shell"))
                self.assertTrue(response.closed)

    def test_dns_tls_and_timeout_errors_never_publish_exception_details(self):
        for error in (OSError(MARKER), TimeoutError(MARKER)):
            with self.subTest(error_type=type(error).__name__):
                def failed(*args, **kwargs):
                    raise error

                report = public._run_probe(CONFIG, opener=Opener(), resolver=failed)
                self.assertEqual(report["status"], "timeout" if isinstance(error, TimeoutError) else "failed")
                self.assertNotIn(MARKER, json.dumps(report))
        for error in (ssl.SSLCertVerificationError(MARKER), URLError(MARKER), TimeoutError(MARKER)):
            responses = successful_responses()
            responses[1] = error
            report = public._run_probe(CONFIG, opener=Opener(responses), resolver=resolver)
            self.assertEqual(report["phase"], "https_shell")
            self.assertNotIn(MARKER, json.dumps(report))

    def test_overall_deadline_stops_before_additional_requests(self):
        current = [0.0]
        opener = Opener(clock=current)
        report = public._run_probe(CONFIG, opener=opener, resolver=resolver, clock=lambda: current[0])
        self.assertEqual((report["status"], report["phase"]), ("timeout", "wrong_token_api"))
        self.assertEqual(len(opener.calls), 4)

    def test_per_step_alarm_interrupts_a_slow_operation_and_restores_handler(self):
        before = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(TimeoutError), public._bounded_step(0.02):
            time.sleep(2)
        self.assertIs(signal.getsignal(signal.SIGALRM), before)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_parent_passes_only_public_config_not_owner_or_ssh_secrets(self):
        observed = []

        def run(command, environment):
            observed.append((command, environment))
            return "completed", json.dumps(successful_report()).encode()

        environment = {**ENV, "QUANTA_OWNER_TOKEN": MARKER, "QUANTA_OCI_PPK": MARKER,
                       "QUANTA_OCI_HOST_KEY": MARKER, "HTTPS_PROXY": MARKER, "PYTHONPATH": MARKER}
        report = public.probe(environment, runner=run)
        self.assertEqual(report["status"], "success")
        command, child_environment = observed[0]
        self.assertEqual(command, [sys.executable, "-I", "-B", str(SCRIPT), "--worker"])
        self.assertEqual(child_environment, {**ENV, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.assertNotIn(MARKER, json.dumps(child_environment))

    def test_parent_sanitizes_bounded_child_output_and_failure_labels(self):
        for status, raw, expected in (("timeout", MARKER.encode(), "timeout"),
                                      ("output_limit", b"", "output_limit"),
                                      (MARKER, b"", "failed"),
                                      ("completed", MARKER.encode(), "invalid_output")):
            report = public.probe(ENV, runner=lambda *args: (status, raw))
            self.assertEqual((report["status"], report["phase"]), (expected, "worker"))
            self.assertNotIn(MARKER, json.dumps(report))
        with patch.object(public, "_capture", side_effect=OSError(MARKER)):
            self.assertEqual(public.probe(ENV)["status"], "failed")

    def test_report_parser_rejects_extra_strings_wrong_types_and_false_claims(self):
        original = successful_report()
        changes = [{"hostname": MARKER}, {"status": MARKER}, {"phase": MARKER},
                   {"dns_a_matches_expected": 1}, {"https_shell_status": True}, {"https_shell_status": 999},
                   {"dns_aaaa_present": None}, {"anonymous_api_status": 200}, {"owner_authentication_verified": True},
                   {"compute_verified": True}, {"browser_verified": True}, {"valid_owner_credential_used": True}]
        for changed in changes:
            with self.subTest(changed=changed):
                self.assertIsNone(public.sanitize_report(json.dumps({**original, **changed}).encode()))
        raw = json.dumps(original).encode()
        for changed in (b"", b"\xff", b"[]", raw + MARKER.encode(), b" " * 4097,
                        raw[:-1] + b',"status":"success"}', raw.replace(b'"https_shell_status": 200', b'"https_shell_status": NaN')):
            self.assertIsNone(public.sanitize_report(changed))

    def test_local_process_capture_bounds_stdout_time_and_stderr(self):
        cases = [("print('safe')", {}, ("completed", b"safe\n")),
                 ("import sys;sys.stderr.write('" + MARKER + "');raise SystemExit(7)", {}, ("failed", b"")),
                 ("print('x'*100000)", {"limit": 10}, ("output_limit", b"")),
                 ("import time;time.sleep(5)", {"timeout": 0.05}, ("timeout", b""))]
        for source, options, expected in cases:
            with self.subTest(options=options), contextlib.redirect_stdout(io.StringIO()) as output:
                observed = public._capture([sys.executable, "-I", "-c", source], {}, **options)
                self.assertEqual(observed, expected)
                self.assertEqual(output.getvalue(), "")
        with patch.object(public.subprocess, "Popen", side_effect=OSError(MARKER)):
            self.assertEqual(public._capture(["/missing"], {}), ("failed", b""))

    def test_cli_prints_only_sanitized_json_and_never_exception_details(self):
        with patch.object(public, "probe", return_value=successful_report()), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public.main([], ENV), 0)
        self.assertIsNotNone(public.sanitize_report(output.getvalue().encode()))
        with patch.object(public, "probe", side_effect=OSError(MARKER)), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public.main([], ENV), 2)
        self.assertNotIn(MARKER, output.getvalue())
        with patch.object(public, "_run_probe") as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public.main(["--worker"], {}), 2)
            run.assert_not_called()
        with patch.object(public, "probe") as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public.main(["--url=" + MARKER], ENV), 2)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
