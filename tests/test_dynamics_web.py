"""New web resources and actual dynamics HTTP/storage boundary.

These tests provide numerical/backend evidence, not browser or production proof.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
from importlib import resources, util
import json
from pathlib import Path

import pytest

from quanta.owner_token import OwnerTokenConfig
from quanta.production import create_app
from quanta.service import ExecutionService

ROOT = Path(__file__).resolve().parents[1]
SPEC = util.spec_from_file_location("quanta_verify_dynamics_web", ROOT / "scripts/verify_dynamics_web.py")
VERIFY = util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def test_actual_web_examples_and_sparse_dynamics_http_child_artifacts_reopen(tmp_path):
    fixture_path = tmp_path / "actual-result.json"
    cases = VERIFY.measure(tmp_path / "store", fixture_path=fixture_path)
    assert [case["id"] for case in cases] == ["DWEB01", "DWEB02", "DWEB03", "DWEB04"]
    assert all(case["status"] == "passed" for case in cases), cases
    fixture = json.loads(fixture_path.read_text())
    raw = fixture["result_raw_utf8"].encode("utf-8")
    assert fixture["result_size_bytes"] == len(raw)
    assert fixture["result_raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert json.loads(raw) == fixture["result"]
    assert fixture["browser_verified"] is False and fixture["production_data"] is False
    assert [frame["step_index"] for frame in fixture["closed_form_reference"]] == [0, 3, 6, 8]
    assert [frame["time_s"] for frame in fixture["closed_form_reference"]] == [0, 0.375, 0.75, 1]
    assert fixture["result"]["physical_validation_status"] == "unvalidated"


class IdleWorker:
    healthy = False

    def start(self):
        self.healthy = True

    def stop(self):
        self.healthy = False


@asynccontextmanager
async def lifespan(app):
    incoming, outgoing = asyncio.Queue(), asyncio.Queue()
    task = asyncio.create_task(app({"type": "lifespan"}, incoming.get, outgoing.put))
    await incoming.put({"type": "lifespan.startup"})
    assert (await asyncio.wait_for(outgoing.get(), 5))["type"] == "lifespan.startup.complete"
    try:
        yield app
    finally:
        await incoming.put({"type": "lifespan.shutdown"})
        assert (await asyncio.wait_for(outgoing.get(), 5))["type"] == "lifespan.shutdown.complete"
        await asyncio.wait_for(task, 5)


async def anonymous_get(app, path):
    events = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(event):
        events.append(event)

    await app({"type": "http", "method": "GET", "scheme": "http", "path": path,
               "raw_path": path.encode(), "query_string": b"",
               "headers": [(b"host", b"quanta.example.com"), (b"content-length", b"0")]}, receive, send)
    return events[0]["status"], events[1]["body"], dict(events[0]["headers"])


@pytest.mark.parametrize("accounts", [False, True], ids=["owner", "account"])
@pytest.mark.parametrize("path,name,media", [
    (path, name, media) for path, (name, media) in VERIFY.ASSETS.items()
])
def test_production_anonymous_shell_can_load_exact_new_modules_but_not_private_api(tmp_path, accounts, path, name, media):
    async def scenario():
        service = ExecutionService(tmp_path / "store")
        config = OwnerTokenConfig("https://quanta.example.com", "0123456789abcdef" * 4)
        app = create_app(service, config, worker=IdleWorker(), account_store=None if accounts else False)
        async with lifespan(app):
            status, raw, headers = await anonymous_get(app, path)
            assert status == 200
            assert raw == resources.files("quanta").joinpath("web", name).read_bytes()
            assert headers[b"content-type"].decode().startswith(media)
            assert headers[b"x-content-type-options"] == b"nosniff"
            assert headers[b"cache-control"] == b"no-store"
            assert b"script-src 'self'" in headers[b"content-security-policy"]
            assert b"unsafe-inline" not in headers[b"content-security-policy"]
            assert (await anonymous_get(app, "/v1/capabilities"))[0] == 401
            assert (await anonymous_get(app, "/ui/examples"))[0] == 401
            assert (await anonymous_get(app, path + ".map"))[0] in {401, 404}
    asyncio.run(scenario())
