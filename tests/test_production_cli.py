"""Operational entry point fixes worker count and refuses incomplete configuration."""
from pathlib import Path

import pytest
import uvicorn

from quanta.cli import main


def configured(monkeypatch):
    for name, value in {"QUANTA_PUBLIC_ORIGIN": "https://quanta.example.com",
                        "QUANTA_ACCESS_TEAM_DOMAIN": "quanta.cloudflareaccess.com",
                        "QUANTA_ACCESS_AUDIENCE": "test-audience",
                        "QUANTA_ALLOWED_EMAIL": "owner@example.com"}.items():
        monkeypatch.setenv(name, value)


def test_missing_origin_configuration_refuses_before_creating_store(tmp_path, monkeypatch, capsys):
    for name in ("QUANTA_PUBLIC_ORIGIN", "QUANTA_ACCESS_TEAM_DOMAIN", "QUANTA_ACCESS_AUDIENCE", "QUANTA_ALLOWED_EMAIL"):
        monkeypatch.delenv(name, raising=False)
    store = tmp_path / "absent"
    assert main(["serve-production", "--store", str(store)]) == 2
    assert not store.exists()
    assert "HTTPS origin" in capsys.readouterr().err


def test_entry_point_keeps_single_loopback_process_despite_environment(tmp_path, monkeypatch):
    configured(monkeypatch)
    monkeypatch.setenv("WEB_CONCURRENCY", "12")
    monkeypatch.setenv("UVICORN_HOST", "0.0.0.0")
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append((app, kwargs)))
    assert main(["serve-production", "--store", str(tmp_path / "service"), "--port", "9876"]) == 0
    app, options = calls[0]
    assert app.config.owner == "local"
    assert options["host"] == "127.0.0.1" and options["port"] == 9876
    assert options["workers"] == 1 and options["reload"] is False
    assert options["proxy_headers"] is False and options["forwarded_allow_ips"] == ""
    assert options["lifespan"] == "on" and options["access_log"] is False
    assert options["limit_concurrency"] == 32


@pytest.mark.parametrize("port", ["-1", "65536"])
def test_invalid_port_refuses_before_store_creation(tmp_path, monkeypatch, port):
    configured(monkeypatch)
    store = tmp_path / "absent"
    assert main(["serve-production", "--store", str(store), "--port", port]) == 2
    assert not store.exists()
