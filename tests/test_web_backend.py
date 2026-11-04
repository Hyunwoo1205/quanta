"""Same-origin application shell and owner-scoped durable run history."""
from __future__ import annotations

from copy import deepcopy
import http.client
from importlib import resources
import json
from pathlib import Path
import threading

import pytest

from quanta.job_store import ServiceError
from quanta.server import create_server
from quanta.service import ExecutionService

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "web-test-token-0123456789abcdef0123456789"


@pytest.fixture
def service(tmp_path):
    return ExecutionService(tmp_path / "web-store")


@pytest.fixture
def server(service):
    value = create_server(service, token=TOKEN, owner="alice", port=0)
    thread = threading.Thread(target=value.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield value
    finally:
        value.shutdown()
        thread.join(timeout=3)
        value.server_close()


def request(server, path, *, method="GET", body=None, authenticated=False, headers=None):
    merged = {"Authorization": "Bearer " + TOKEN} if authenticated else {}
    merged.update(headers or {})
    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
    try:
        connection.request(method, path, body=body, headers=merged)
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def revision(service, owner="alice", title="Browser experiment", experiment=None):
    source = json.loads((ROOT / "examples/pair_energy_forces.json").read_text())
    if experiment is None:
        _, experiment = service.request(owner, "POST", "/v1/experiments", {"title": title})
    _, result = service.request(owner, "POST", f"/v1/experiments/{experiment['experiment_id']}/revisions", {
        "schema_version": "0.2.0", "title": title, "definition": deepcopy(source["definition"]),
    })
    return experiment, result


def submit(service, value, key, owner="alice"):
    return service.request(owner, "POST", "/v1/runs", {"revision_id": value["revision_id"]},
                           idempotency_key=key)[1]


@pytest.mark.parametrize("path,name,media", [
    ("/", "index.html", "text/html"),
    ("/index.html", "index.html", "text/html"),
    ("/assets/app.js", "app.js", "text/javascript"),
    ("/assets/app.css", "app.css", "text/css"),
    ("/assets/view-model.mjs", "view-model.mjs", "text/javascript"),
    ("/ui/examples", "examples.json", "application/json"),
])
def test_application_resources_are_exact_public_package_bytes(server, path, name, media):
    status, raw, headers = request(server, path)
    assert status == 200
    assert headers["Content-Type"].startswith(media)
    assert raw == resources.files("quanta").joinpath("web", name).read_bytes()
    assert TOKEN.encode() not in raw
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert "Access-Control-Allow-Origin" not in headers


def test_head_shell_preserves_length_without_response_body(server):
    status, raw, headers = request(server, "/", method="HEAD")
    assert status == 200 and raw == b""
    assert int(headers["Content-Length"]) == len(resources.files("quanta").joinpath("web", "index.html").read_bytes())


def test_public_examples_have_no_private_identifiers_and_are_detached(server, service):
    status, raw, _ = request(server, "/ui/examples")
    examples = json.loads(raw)["examples"]
    assert status == 200 and len(examples) == 5
    assert len({example["id"] for example in examples}) == 5
    for example in examples:
        assert {"id", "title", "schema_version", "definition"} <= set(example)
        assert set(example) <= {"id", "title", "description", "schema_version", "definition"}
        assert example["schema_version"] == "0.2.0"
        report = service.request("alice", "POST", "/v1/validate", {
            "schema_version": example["schema_version"], "definition": example["definition"]})[1]
        assert report["valid"], (example["id"], report["errors"])
    assert service.request("alice", "GET", "/v1/experiments")[1]["items"] == []


@pytest.mark.parametrize("path", ["/v1/capabilities", "/v1/experiments", "/v1/runs"])
def test_public_shell_does_not_bypass_api_bearer_authentication(server, path):
    assert request(server, path)[0] == 401
    assert request(server, path, authenticated=True)[0] == 200


@pytest.mark.parametrize("path", [
    "/assets/../server.py", "/assets/%2e%2e/server.py", "/assets/../../requirements.lock.txt",
    "/assets/examples.json", "/ui/../service.py", "/index.html?file=server.py", "/assets/app.js.map",
])
def test_only_exact_resource_names_can_be_read(server, path):
    status, raw, _ = request(server, path, authenticated=True)
    assert status in {404, 422}
    assert b"Small authenticated loopback HTTP adapter" not in raw
    assert b"_WEB_RESOURCES" not in raw


@pytest.mark.parametrize("origin", ["https://foreign.invalid", "null", "http://127.0.0.1:1"])
def test_authenticated_cross_origin_requests_are_rejected_before_mutation(server, service, origin):
    status, _, _ = request(server, "/v1/experiments", method="POST", authenticated=True,
                            body=b'{"title":"Must not be created"}',
                            headers={"Origin": origin, "Content-Type": "application/json"})
    assert status == 403
    assert service.request("alice", "GET", "/v1/experiments")[1]["items"] == []


def test_matching_origin_and_loopback_host_are_accepted(server):
    origin = f"http://127.0.0.1:{server.server_port}"
    assert request(server, "/v1/capabilities", authenticated=True, headers={"Origin": origin})[0] == 200
    localhost = f"localhost:{server.server_port}"
    assert request(server, "/v1/capabilities", authenticated=True,
                   headers={"Origin": "http://" + localhost, "Host": localhost})[0] == 200


@pytest.mark.parametrize("host", ["foreign.invalid", "127.0.0.1:1", "localhost.evil.invalid"])
def test_dns_rebinding_host_is_rejected_even_for_public_shell(server, host):
    assert request(server, "/", headers={"Host": host})[0] == 400
    assert request(server, "/v1/capabilities", authenticated=True, headers={"Host": host})[0] == 400


def test_duplicate_origin_is_rejected(server):
    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
    try:
        connection.putrequest("GET", "/v1/capabilities")
        connection.putheader("Authorization", "Bearer " + TOKEN)
        origin = f"http://127.0.0.1:{server.server_port}"
        connection.putheader("Origin", origin)
        connection.putheader("Origin", origin)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 403
        response.read()
    finally:
        connection.close()


def test_history_is_newest_first_cursor_paginated_and_owner_scoped(service):
    experiment, first = revision(service)
    _, second = revision(service, experiment=experiment, title="Changed revision")
    runs = [submit(service, first if i % 2 == 0 else second, f"run-{i}") for i in range(4)]
    foreign_experiment, foreign_revision = revision(service, owner="bob")
    foreign_run = submit(service, foreign_revision, "foreign", owner="bob")
    status, page = service.request("alice", "GET", f"/v1/runs?experiment_id={experiment['experiment_id']}&limit=2")
    assert status == 200
    assert [row["run_id"] for row in page["items"]] == [run["run_id"] for run in reversed(runs[2:])]
    assert all(row["experiment_id"] == experiment["experiment_id"] for row in page["items"])
    assert all("plan" not in row and "report" not in row and "owner" not in row for row in page["items"])
    _, following = service.request("alice", "GET", f"/v1/runs?experiment_id={experiment['experiment_id']}&limit=2&cursor={page['next_cursor']}")
    assert [row["run_id"] for row in following["items"]] == [run["run_id"] for run in reversed(runs[:2])]
    assert following["next_cursor"] is None
    assert len(service.request("alice", "GET", "/v1/runs")[1]["items"]) == 4
    for query in (f"experiment_id={foreign_experiment['experiment_id']}", f"cursor={foreign_run['run_id']}"):
        with pytest.raises(ServiceError) as caught:
            service.request("alice", "GET", "/v1/runs?" + query)
        assert caught.value.status == 404


def test_history_cursor_cannot_cross_selected_experiments(service):
    experiment, first = revision(service)
    _, other = revision(service)
    original = submit(service, first, "original")
    different = submit(service, other, "different")
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "GET", f"/v1/runs?experiment_id={experiment['experiment_id']}&cursor={different['run_id']}")
    assert caught.value.status == 404
    assert service.request("alice", "GET", f"/v1/runs?experiment_id={experiment['experiment_id']}")[1]["items"][0]["run_id"] == original["run_id"]


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=x", "limit=2&limit=3", "unknown=x", "experiment_id=x&experiment_id=y"])
def test_history_query_is_strict(service, query):
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "GET", "/v1/runs?" + query)
    assert caught.value.status == 422
