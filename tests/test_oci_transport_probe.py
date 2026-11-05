"""Bounded, credential-free transport evidence; no real OCI connection."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/oci/probe_transport.py"
spec = importlib.util.spec_from_file_location("quanta_oci_transport_probe", SCRIPT)
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
HOST = "8.8.8.8"  # Valid input only: connectors below never contact this address.


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeouts = []
        self.read_sizes = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, amount):
        self.read_sizes.append(amount)
        item = self.chunks.pop(0) if self.chunks else b""
        if isinstance(item, Exception):
            raise item
        if len(item) > amount:
            self.chunks.insert(0, item[amount:])
            return item[:amount]
        return item

    def send(self, *args):
        pytest.fail("transport probe must not send any bytes")

    sendall = send


def run_fake(chunks, *, clock=lambda: 100):
    stream = FakeSocket(chunks)
    calls = []

    def connect(address, *, timeout):
        calls.append((address, timeout))
        return stream

    report = transport.probe(HOST, connector=connect, clock=clock)
    assert calls == [((HOST, 22), 8)]
    assert stream.closed
    assert all(0 < value <= 5 for value in stream.timeouts)
    assert all(0 < value <= 256 for value in stream.read_sizes)
    assert report["scope"] == "tcp_ssh_banner"
    assert report["authentication_attempted"] is False
    assert report["server_modified"] is False
    return report, stream


@pytest.mark.parametrize("host", [
    None, "", " ", HOST + " ", " " + HOST, "008.8.8.8", "8.8.8", "134744072",
    "0x08080808", "example.com", "https://8.8.8.8", "8.8.8.8:22", "8.8.8.8/32",
    "ubuntu@8.8.8.8", "8.8.8.8\n", "8.8.8.8;id", "$(id)", "::1", "::ffff:8.8.8.8",
    "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
    "172.16.0.1", "192.168.1.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
])
def test_missing_noncanonical_or_nonglobal_host_never_opens_socket(host):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid configuration must not open a socket")

    assert transport.probe(host, connector=forbidden) == {
        "scope": "tcp_ssh_banner", "status": "no_config",
        "authentication_attempted": False, "server_modified": False,
    }


@pytest.mark.parametrize("banner", [
    b"SSH-2.0-OpenSSH_10.0p2 Ubuntu-example\r\n",
    b"SSH-1.99-compatible\r\n", b"SSH-2.0-example\n",
])
def test_partial_reads_and_prebanner_lines_identify_only_supported_ssh(banner):
    report, stream = run_fake([b"notice\r", b"\n", *[bytes([c]) for c in banner]])
    assert report["status"] == "reachable"
    assert sum(stream.read_sizes) > len(banner)


@pytest.mark.parametrize("chunks", [
    [], [b"SSH-2.0-incomplete"], [b"HTTP/1.1 200 OK\r\n"],
    [b"SSH-1.5-obsolete\r\n"], [b"SSH-2.0-\r\n"],
    [b"SSH-2.0-example\x00\r\n"], [b"SSH-2.0-example\tcomment\r\n"],
    [b"SSH-2.0-" + b"x" * 246 + b"\r\n"],
])
def test_eof_other_protocol_or_invalid_identification_is_not_ssh(chunks):
    report, _ = run_fake(chunks)
    assert report["status"] == "not_ssh"


def test_byte_limit_stops_before_later_ssh_banner_without_a_retry():
    report, stream = run_fake([b"x" * 1024, b"\nSSH-2.0-too-late\r\n"])
    assert report["status"] == "not_ssh"
    assert stream.read_sizes == [256, 256, 256, 256]
    assert stream.chunks == [b"\nSSH-2.0-too-late\r\n"]


def test_banner_ending_at_total_byte_limit_is_accepted():
    banner = b"SSH-2.0-limit\r\n"
    report, _ = run_fake([b"x" * (1024 - len(banner) - 1) + b"\n" + banner])
    assert report["status"] == "reachable"


def test_partial_reads_share_one_deadline_instead_of_resetting_timeout():
    times = iter([100, 100, 101, 101, 103, 103, 105])
    report, stream = run_fake([b"S", b"S", b"H"], clock=lambda: next(times))
    assert report["status"] == "unreachable"
    assert stream.timeouts == [5, 4, 2]
    assert len(stream.read_sizes) == 3


def test_expired_deadline_does_not_start_another_read():
    times = iter([100, 105])
    report, stream = run_fake([b"SSH-2.0-never-read\r\n"], clock=lambda: next(times))
    assert report["status"] == "unreachable"
    assert stream.read_sizes == []


@pytest.mark.parametrize("error", [TimeoutError(HOST), OSError(HOST + " private detail")])
def test_connection_errors_are_sanitized_and_never_retried(error, capsys):
    calls = []

    def connect(address, *, timeout):
        calls.append((address, timeout))
        raise error

    report = transport.probe(HOST, connector=connect)
    assert report["status"] == "unreachable"
    assert calls == [((HOST, 22), 8)]
    assert HOST not in json.dumps(report)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("error", [TimeoutError(HOST), OSError(HOST)])
def test_read_errors_close_socket_and_expose_no_server_details(error):
    report, _ = run_fake([b"SSH-", error])
    assert report["status"] == "unreachable"
    assert HOST not in json.dumps(report)


@pytest.mark.parametrize("status,exit_code", [("reachable", 0), ("unreachable", 2),
                                             ("no_config", 2), ("not_ssh", 2)])
def test_cli_outputs_only_sanitized_json(monkeypatch, capsys, status, exit_code):
    monkeypatch.setenv("QUANTA_OCI_HOST", HOST)
    monkeypatch.setattr(transport, "probe", lambda host: transport._report(status))
    assert transport.main() == exit_code
    captured = capsys.readouterr()
    assert json.loads(captured.out) == transport._report(status)
    assert captured.err == ""
    assert HOST not in captured.out


def test_cli_unexpected_failure_also_omits_exception_text(monkeypatch, capsys):
    def fail(host):
        raise RuntimeError(HOST + " secret banner")

    monkeypatch.setenv("QUANTA_OCI_HOST", HOST)
    monkeypatch.setattr(transport, "probe", fail)
    assert transport.main() == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == transport._report("unreachable")
    assert captured.err == ""
    assert HOST not in captured.out


def test_real_cli_without_configuration_exits_two_and_ignores_key_paths(tmp_path):
    # These deliberately invalid key locations are not inputs to this probe.
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=tmp_path,
                            env={"QUANTA_OCI_PRIVATE_KEY": "/must/not/be/read.ppk"},
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 2
    assert json.loads(result.stdout) == transport._report("no_config")
    assert result.stderr == ""


def test_real_local_server_observes_connection_without_any_client_bytes():
    """Local TCP I/O proves the seam's lifecycle, not OCI reachability."""
    observations = []
    failures = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        local_address = listener.getsockname()

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(3)
                    peer.sendall(b"SSH-2.0-local-fixture\r\n")
                    observations.append(peer.recv(1))
            except Exception as exc:
                failures.append(type(exc).__name__)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        calls = []

        def local_connect(address, *, timeout):
            calls.append((address, timeout))
            return socket.create_connection(local_address, timeout=timeout)

        report = transport.probe(HOST, connector=local_connect)
        worker.join(timeout=4)
        assert not worker.is_alive()
    assert failures == []
    assert observations == [b""]
    assert calls == [((HOST, 22), 8)]
    assert report == transport._report("reachable")
