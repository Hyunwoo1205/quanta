"""Independent service-boundary checks; no calculation is needed for these cases."""
from __future__ import annotations

from copy import deepcopy
import http.client
import json
from pathlib import Path
import threading
import uuid

import pytest

from quanta.job_store import ServiceError
from quanta.service import ExecutionService
from quanta.server import create_server


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path):
    return ExecutionService(tmp_path / "service")


def revision(service, *, owner="alice", title="Independent service test"):
    example = json.loads((ROOT / "examples" / "pair_energy_forces.json").read_text())
    status, experiment = service.request(owner, "POST", "/v1/experiments", {"title": title})
    assert status == 201
    experiment_id = experiment["experiment_id"]
    status, value = service.request(owner, "POST", f"/v1/experiments/{experiment_id}/revisions", {
        "schema_version": example["schema_version"], "title": title, "definition": example["definition"],
    })
    assert status == 201
    return experiment, value


def submit(service, value, *, owner="alice", key="independent-key"):
    status, run = service.request(owner, "POST", "/v1/runs", {"revision_id": value["revision_id"]},
                                  idempotency_key=key)
    assert status == 202
    return run


def test_service_assigns_ids_and_preserves_immutable_revision(service):
    experiment, value = revision(service)
    assert uuid.UUID(experiment["experiment_id"]).version == 4
    assert uuid.UUID(value["revision_id"]).version == 4
    assert value["experiment_id"] == experiment["experiment_id"]
    saved = deepcopy(value)
    value["definition"]["system"]["particles"][1]["position_m"][0] = 9.0
    status, reloaded = service.request("alice", "GET", f"/v1/revisions/{value['revision_id']}")
    assert status == 200
    assert reloaded == saved
    # Returning a record does not confer an update endpoint on immutable revisions.
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "PUT", f"/v1/revisions/{value['revision_id']}", saved)
    assert caught.value.status in {404, 405}


@pytest.mark.parametrize("route", [
    "experiment", "revision", "run", "cancel", "replay", "manifest",
])
def test_all_existing_resource_routes_hide_foreign_ids(service, route):
    experiment, value = revision(service)
    run = submit(service, value)
    method, path = {
        "experiment": ("GET", f"/v1/experiments/{experiment['experiment_id']}"),
        "revision": ("GET", f"/v1/revisions/{value['revision_id']}"),
        "run": ("GET", f"/v1/runs/{run['run_id']}"),
        "cancel": ("POST", f"/v1/runs/{run['run_id']}/cancel"),
        "replay": ("POST", f"/v1/runs/{run['run_id']}/replay"),
        "manifest": ("GET", f"/v1/runs/{run['run_id']}/artifacts"),
    }[route]
    with pytest.raises(ServiceError) as caught:
        service.request("bob", method, path, idempotency_key="foreign-replay")
    assert caught.value.status == 404


def test_submission_cannot_reference_foreign_revision(service):
    _, value = revision(service)
    with pytest.raises(ServiceError) as caught:
        service.request("bob", "POST", "/v1/runs", {"revision_id": value["revision_id"]},
                        idempotency_key="foreign-revision")
    assert caught.value.status == 404


def test_same_key_same_body_survives_terminal_cancellation(service):
    _, value = revision(service)
    original = submit(service, value)
    status, cancelled = service.request("alice", "POST", f"/v1/runs/{original['run_id']}/cancel")
    assert status in {200, 202}
    assert cancelled["execution_status"] == "CANCELLED"
    duplicate = submit(service, value)
    assert duplicate["run_id"] == original["run_id"]
    status, final = service.request("alice", "GET", f"/v1/runs/{original['run_id']}")
    assert status == 200
    assert final["execution_status"] == "CANCELLED"


def test_key_body_conflict_is_409_without_creating_second_run(service):
    _, first = revision(service, title="First immutable input")
    _, second = revision(service, title="Second immutable input")
    original = submit(service, first)
    with pytest.raises(ServiceError) as caught:
        submit(service, second)
    assert caught.value.status == 409
    assert caught.value.code == "IDEMPOTENCY_CONFLICT"
    assert submit(service, first)["run_id"] == original["run_id"]


def test_idempotency_precedes_full_queue_admission(service):
    _, value = revision(service)
    runs = [submit(service, value, key=f"capacity-{index}") for index in range(10)]
    assert len({run["run_id"] for run in runs}) == 10
    assert submit(service, value, key="capacity-0")["run_id"] == runs[0]["run_id"]
    with pytest.raises(ServiceError) as caught:
        submit(service, value, key="capacity-overflow")
    assert caught.value.code == "RESOURCE_LIMIT"
    for run in runs:
        assert service.request("alice", "GET", f"/v1/runs/{run['run_id']}")[1]["execution_status"] == "QUEUED"


def test_same_key_is_scoped_to_authenticated_owner(service):
    _, first = revision(service, owner="alice")
    _, second = revision(service, owner="bob")
    alice = submit(service, first, owner="alice")
    bob = submit(service, second, owner="bob")
    assert alice["run_id"] != bob["run_id"]


@pytest.mark.parametrize("body", [{"title": "ok", "owner": "bob"}, {"title": ""},
                                  {"title": "x" * 201}, {"title": 42}, [], None])
def test_create_experiment_rejects_noncontract_body(service, body):
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "POST", "/v1/experiments", body)
    assert caught.value.status == 422


def test_validation_has_no_experiment_or_run_side_effect(service):
    example = json.loads((ROOT / "examples" / "pair_energy_forces.json").read_text())
    status, report = service.request("alice", "POST", "/v1/validate", {
        "schema_version": example["schema_version"], "definition": example["definition"],
    })
    assert status == 200 and report["valid"]
    status, listing = service.request("alice", "GET", "/v1/experiments")
    assert status == 200
    assert listing["items"] == []


def test_missing_replay_source_is_not_found(service):
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "POST", f"/v1/runs/{uuid.uuid4()}/replay", idempotency_key="missing")
    assert caught.value.status == 404


def test_experiment_pagination_is_stable_and_owner_scoped(service):
    ids = []
    for title in ("one", "two", "three"):
        status, experiment = service.request("alice", "POST", "/v1/experiments", {"title": title})
        assert status == 201
        ids.append(experiment["experiment_id"])
    _, foreign = service.request("bob", "POST", "/v1/experiments", {"title": "private"})
    status, page = service.request("alice", "GET", "/v1/experiments?limit=2")
    assert status == 200
    assert [item["experiment_id"] for item in page["items"]] == ids[:2]
    status, following = service.request("alice", "GET", f"/v1/experiments?limit=2&cursor={page['next_cursor']}")
    assert status == 200
    assert [item["experiment_id"] for item in following["items"]] == ids[2:]
    assert following["next_cursor"] is None
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "GET", f"/v1/experiments?cursor={foreign['experiment_id']}")
    assert caught.value.status == 404


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=x", "limit=2&limit=3",
                                    "unknown=1", "&".join(f"x{i}=1" for i in range(9))])
def test_invalid_pagination_returns_a_client_error(service, query):
    with pytest.raises(ServiceError) as caught:
        service.request("alice", "GET", f"/v1/experiments?{query}")
    assert caught.value.status == 422


@pytest.fixture
def http_server(service):
    server = create_server(service, token="test-service-token-0123456789abcdef01234567", owner="alice", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def http_request(server, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection(*server.server_address, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


@pytest.mark.parametrize("path", ["/v1/capabilities", "/v1/experiments", "/unknown"])
@pytest.mark.parametrize("authorization", [None, "Bearer incorrect", "Basic test-service-token-0123456789abcdef01234567"])
def test_http_authentication_precedes_route_resolution(http_server, path, authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    status, _, _ = http_request(http_server, "GET", path, headers=headers)
    assert status == 401


def test_http_capabilities_and_unknown_route(http_server):
    headers = {"Authorization": "Bearer test-service-token-0123456789abcdef01234567"}
    status, raw, response_headers = http_request(http_server, "GET", "/v1/capabilities", headers=headers)
    assert status == 200
    assert "application/json" in response_headers["Content-Type"]
    assert isinstance(json.loads(raw), dict)
    status, _, _ = http_request(http_server, "GET", "/unknown", headers=headers)
    assert status == 404


@pytest.mark.parametrize("raw", [b"{", b'[]', b'{"title":"a","title":"b"}',
                                b'{"title":NaN}', b'{"title":"\xff"}'])
def test_http_malformed_json_is_a_structured_client_error(http_server, raw):
    status, response, headers = http_request(http_server, "POST", "/v1/experiments", body=raw, headers={
        "Authorization": "Bearer test-service-token-0123456789abcdef01234567", "Content-Type": "application/json",
    })
    assert status == 422
    assert "application/json" in headers["Content-Type"]
    assert isinstance(json.loads(response), dict)


def test_http_rejects_oversize_declaration_before_reading_body(http_server):
    status, _, _ = http_request(http_server, "POST", "/v1/experiments", body=b"x", headers={
        "Authorization": "Bearer test-service-token-0123456789abcdef01234567", "Content-Type": "application/json",
        "Content-Length": "1048577",
    })
    assert status == 413


def test_http_rejects_unsupported_transfer_encoding(http_server):
    status, _, _ = http_request(http_server, "POST", "/v1/experiments", body=b"0\r\n\r\n", headers={
        "Authorization": "Bearer test-service-token-0123456789abcdef01234567", "Content-Type": "application/json",
        "Transfer-Encoding": "chunked",
    })
    assert status in {400, 411, 422}


def test_http_rejects_duplicate_content_lengths(http_server):
    connection = http.client.HTTPConnection(*http_server.server_address, timeout=3)
    try:
        connection.putrequest("POST", "/v1/experiments")
        connection.putheader("Authorization", "Bearer test-service-token-0123456789abcdef01234567")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "2")
        connection.putheader("Content-Length", "4")
        connection.endheaders(b"{}")
        response = connection.getresponse()
        assert response.status in {400, 411, 422}
        response.read()
    finally:
        connection.close()
