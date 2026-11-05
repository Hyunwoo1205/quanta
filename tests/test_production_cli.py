"""Operational entry point fixes worker count and refuses incomplete configuration."""
from pathlib import Path

import pytest
from quanta.production_server import ProductionServer

from quanta.cli import main


def configured(monkeypatch):
    monkeypatch.delenv("QUANTA_AUTH_MODE", raising=False)
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
    monkeypatch.setattr(ProductionServer, "run", lambda server: (calls.append(server), setattr(server, "started", True)))
    assert main(["serve-production", "--store", str(tmp_path / "service"), "--port", "9876"]) == 0
    app, options = calls[0].quanta_app, vars(calls[0].config)
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


def test_explicit_owner_token_keeps_single_private_production_process(tmp_path, monkeypatch):
    from quanta.owner_token import OwnerTokenConfig
    configured(monkeypatch)
    monkeypatch.setenv("QUANTA_AUTH_MODE", "owner-token")
    monkeypatch.setenv("QUANTA_OWNER_TOKEN", "0123456789abcdef" * 4)
    # This mode does not require a Cloudflare account or silently use one.
    for name in ("QUANTA_ACCESS_TEAM_DOMAIN", "QUANTA_ACCESS_AUDIENCE", "QUANTA_ALLOWED_EMAIL"):
        monkeypatch.delenv(name)
    monkeypatch.setenv("WEB_CONCURRENCY", "12")
    monkeypatch.setenv("UVICORN_HOST", "0.0.0.0")
    calls = []
    monkeypatch.setattr(ProductionServer, "run", lambda server: (calls.append(server), setattr(server, "started", True)))
    assert main(["serve-production", "--store", str(tmp_path / "service")]) == 0
    app, options = calls[0].quanta_app, vars(calls[0].config)
    assert isinstance(app.config, OwnerTokenConfig) and app.config.owner == "local"
    assert options["host"] == "127.0.0.1" and options["workers"] == 1
    assert options["reload"] is False and options["proxy_headers"] is False
    assert options["forwarded_allow_ips"] == "" and options["access_log"] is False


@pytest.mark.parametrize("mode,token,origin", [
    ("", "a" * 64, "https://quanta.example.com"),
    ("bearer", "a" * 64, "https://quanta.example.com"),
    ("owner-token", None, "https://quanta.example.com"),
    ("owner-token", "do-not-print-this-secret", "https://quanta.example.com"),
    ("owner-token", "A" * 64, "https://quanta.example.com"),
    ("owner-token", "a" * 64, "http://quanta.example.com"),
    ("owner-token", "a" * 64, ""),
])
def test_invalid_auth_mode_or_owner_token_refuses_before_store_creation(tmp_path, monkeypatch, capsys, mode, token, origin):
    configured(monkeypatch)
    monkeypatch.setenv("QUANTA_AUTH_MODE", mode)
    monkeypatch.setenv("QUANTA_PUBLIC_ORIGIN", origin)
    if token is None:
        monkeypatch.delenv("QUANTA_OWNER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("QUANTA_OWNER_TOKEN", token)
    store = tmp_path / "absent"
    assert main(["serve-production", "--store", str(store)]) == 2
    assert not store.exists()
    error = capsys.readouterr().err
    assert token is None or token not in error


def test_owner_token_environment_never_enables_fallback_from_access(tmp_path, monkeypatch):
    configured(monkeypatch)
    monkeypatch.setenv("QUANTA_OWNER_TOKEN", "a" * 64)
    monkeypatch.delenv("QUANTA_ACCESS_AUDIENCE")
    store = tmp_path / "absent"
    assert main(["serve-production", "--store", str(store)]) == 2
    assert not store.exists()
