"""POST /audit/events, GET /audit/events and GET /audit/events/{eventId}."""

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.storage import Database, derive_event_id
from tests.api.conftest import auth
from tests.ingest.support import event_data, raw_connection, verify_store

SERVER_FIELDS = [
    "seq",
    "eventId",
    "recordedAt",
    "prevHash",
    "payloadRoot",
    "contentHash",
    "recordHash",
]


def _post(api: TestClient, **overrides: Any) -> dict[str, Any]:
    response = api.post("/audit/events", json=event_data(**overrides), headers=auth("writer"))
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _issues(response: Any) -> set[tuple[str, str]]:
    return {(i["field"], i["code"]) for i in response.json().get("issues", [])}


# --- POST -------------------------------------------------------------------------------------


def test_post_returns_201_with_server_fields(api: TestClient) -> None:
    response = api.post("/audit/events", json=event_data(), headers=auth("writer"))
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"seq", "eventId", "recordedAt", "timestamp", "contentHash", "recordHash"}
    assert body["seq"] == 1
    assert body["eventId"] == derive_event_id(body["recordHash"])
    assert response.headers["location"] == f"/audit/events/{body['eventId']}"
    assert len(response.headers["x-request-id"]) == 32


@pytest.mark.parametrize("name", SERVER_FIELDS)
def test_post_rejects_server_controlled_fields(api: TestClient, name: str) -> None:
    response = api.post(
        "/audit/events", json=event_data(**{name: "client-value"}), headers=auth("writer")
    )
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert (name, "extra_forbidden") in _issues(response)
    assert "client-value" not in response.text


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b'{"eventType":"A","eventType":"B"}', ("body", "invalid_json")),
        (b'{"payload":{"x":1.5}}', ("body", "invalid_json")),
        (b"\xff\xfe not utf-8", ("body", "invalid_utf8")),
        (b"[]", ("body", "not_an_object")),
    ],
)
def test_post_rejects_malformed_bodies(
    api: TestClient, body: bytes, expected: tuple[str, str]
) -> None:
    headers = {**auth("writer"), "content-type": "application/json"}
    response = api.post("/audit/events", content=body, headers=headers)
    assert response.status_code == 422
    assert expected in _issues(response)


def test_post_validation_errors_do_not_echo_values(api: TestClient) -> None:
    sensitive = "900-12-" + "3456"
    response = api.post(
        "/audit/events",
        json=event_data(actorId=sensitive + "\x00", payload={"ssn": sensitive, "f": 1.5}),
        headers=auth("writer"),
    )
    assert response.status_code == 422
    assert sensitive not in response.text


def test_post_requires_json_content_type(api: TestClient) -> None:
    headers = {**auth("writer"), "content-type": "text/plain"}
    response = api.post("/audit/events", content=json.dumps(event_data()), headers=headers)
    assert response.status_code == 415
    assert response.json()["code"] == "unsupported_media_type"


def test_post_rejects_future_and_reserved_events(api: TestClient) -> None:
    future = api.post(
        "/audit/events", json=event_data(timestamp="2027-01-01T00:00:00Z"), headers=auth("writer")
    )
    assert future.status_code == 422
    assert ("timestamp", "too_far_in_future") in _issues(future)
    system = api.post(
        "/audit/events", json=event_data(eventType="SYSTEM_REDACTION"), headers=auth("writer")
    )
    assert ("eventType", "reserved_event_type") in _issues(system)


def test_body_limit_with_content_length(api: TestClient) -> None:
    body = json.dumps(event_data(payload={"s": "x" * 140_000})).encode()
    headers = {**auth("writer"), "content-type": "application/json"}
    response = api.post("/audit/events", content=body, headers=headers)
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"


def test_body_limit_is_enforced_while_streaming(api: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"eventType":"A","actorId":"a","resourceType":"r","resourceId":"i","payload":{"s":"'
        for _ in range(3):
            yield b"x" * 65_536
        yield b'"}}'

    headers = {**auth("writer"), "content-type": "application/json"}
    response = api.post("/audit/events", content=chunks(), headers=headers)
    assert response.status_code == 413


def test_busy_database_returns_503_and_writes_nothing(api: TestClient, api_db: Path) -> None:
    holder = raw_connection(api_db, timeout=0.2)
    holder.execute("BEGIN IMMEDIATE")
    try:
        response = api.post("/audit/events", json=event_data(), headers=auth("writer"))
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert response.json()["code"] == "store_busy"
    assert _post(api)["seq"] == 1


class _IoError(sqlite3.OperationalError):
    pass


def test_unknown_commit_outcome_is_distinguishable(
    api: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_commit(dbapi_connection: Any) -> None:
        exc = _IoError("disk I/O error")
        exc.sqlite_errorcode = 10
        exc.sqlite_errorname = "SQLITE_IOERR"
        raise exc

    database: Database = api.app.state.database  # type: ignore[attr-defined]
    monkeypatch.setattr(database._engine.dialect, "do_commit", failing_commit)
    sensitive = "acct-" + "900123456"
    response = api.post(
        "/audit/events", json=event_data(payload={"n": sensitive}), headers=auth("writer")
    )
    assert response.status_code == 500
    assert response.json()["code"] == "commit_outcome_unknown"
    assert "check whether it exists before retrying" in response.json()["title"]
    assert sensitive not in response.text


def test_api_writes_recompute_from_storage(api: TestClient) -> None:
    payloads: list[dict[str, Any]] = [{"a": 1}, {"nested": {"list": [True, None, "x"]}}, {}]
    for payload in payloads:
        _post(api, payload=payload)
    database: Database = api.app.state.database  # type: ignore[attr-defined]
    assert verify_store(database, {i + 1: p for i, p in enumerate(payloads)}) == 3


# --- GET one ----------------------------------------------------------------------------------


def test_get_event_by_id(api: TestClient) -> None:
    created = _post(api, payload={"account": {"number": "900123456"}, "flags": [True]})
    response = api.get(f"/audit/events/{created['eventId']}", headers=auth("auditor"))
    assert response.status_code == 200
    body = response.json()
    assert body["payload"] == {"account": {"number": "900123456"}, "flags": [True]}
    assert body["recordHash"] == created["recordHash"]
    assert body["prevHash"] == "0" * 64


@pytest.mark.parametrize("event_id", ["evt_" + "0" * 32, "not-an-id", "evt_" + "G" * 32])
def test_get_unknown_or_malformed_id_is_404(api: TestClient, event_id: str) -> None:
    response = api.get(f"/audit/events/{event_id}", headers=auth("auditor"))
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


# --- GET list: filters and pagination ----------------------------------------------------------


def _seed(api: TestClient) -> None:
    rows = [
        ("USER_LOGIN", "alice", "SESSION", "s1", "2026-10-28T09:00:00Z"),
        ("RECORD_UPDATED", "alice", "CLIENT_ACCOUNT", "acct-1", "2026-10-28T10:00:00Z"),
        ("RECORD_UPDATED", "bob", "CLIENT_ACCOUNT", "acct-1", "2026-10-28T10:30:00Z"),
        ("PERMISSION_GRANTED", "bob", "CLIENT_ACCOUNT", "acct-2", "2026-10-28T11:00:00Z"),
        ("USER_LOGIN", "carol", "SESSION", "s2", "2026-10-28T11:30:00Z"),
    ]
    for event_type, actor, rtype, rid, ts in rows:
        _post(
            api,
            eventType=event_type,
            actorId=actor,
            resourceType=rtype,
            resourceId=rid,
            timestamp=ts,
        )


def _seqs(api: TestClient, **params: Any) -> list[int]:
    response = api.get("/audit/events", params=params, headers=auth("auditor"))
    assert response.status_code == 200, response.text
    return [item["seq"] for item in response.json()["items"]]


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({}, [1, 2, 3, 4, 5]),
        ({"actorId": "alice"}, [1, 2]),
        ({"resourceType": "CLIENT_ACCOUNT"}, [2, 3, 4]),
        ({"resourceType": "CLIENT_ACCOUNT", "resourceId": "acct-1"}, [2, 3]),
        ({"resourceId": "acct-2"}, [4]),
        ({"eventType": "USER_LOGIN"}, [1, 5]),
        ({"actorId": "bob", "eventType": "RECORD_UPDATED"}, [3]),
        ({"from": "2026-10-28T10:00:00Z"}, [2, 3, 4, 5]),
        ({"to": "2026-10-28T10:30:00Z"}, [1, 2]),
        ({"from": "2026-10-28T10:00:00Z", "to": "2026-10-28T11:00:00Z"}, [2, 3]),
        ({"from": "2026-10-28T12:00:00+02:00", "to": "2026-10-28T10:30:00.000001Z"}, [2, 3]),
        ({"actorId": "nobody"}, []),
    ],
)
def test_filters(api: TestClient, params: dict[str, str], expected: list[int]) -> None:
    _seed(api)
    assert _seqs(api, **params) == expected


def test_pagination_returns_every_record_once_with_concurrent_appends(api: TestClient) -> None:
    for i in range(7):
        _post(api, actorId=f"a{i}")
    seen: list[int] = []
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, Any] = {"limit": 3}
        if cursor is not None:
            params["cursor"] = cursor
        body = api.get("/audit/events", params=params, headers=auth("auditor")).json()
        seen.extend(item["seq"] for item in body["items"])
        pages += 1
        if pages == 1:
            _post(api, actorId="late")  # appended while paging: must appear, without duplicates
        cursor = body["nextCursor"]
        if cursor is None:
            break
    assert seen == list(range(1, 9))
    assert pages == 3


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"limit": "ten"},
        {"cursor": "abc"},
        {"cursor": "0"},
        {"cursor": "-1"},
        {"from": "yesterday"},
        {"to": "2026-02-30T00:00:00Z"},
        {"actorId": ""},
        {"actorId": "x" * 257},
    ],
)
def test_invalid_query_parameters(api: TestClient, params: dict[str, Any]) -> None:
    response = api.get("/audit/events", params=params, headers=auth("auditor"))
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_query_errors_do_not_echo_values(api: TestClient) -> None:
    sensitive = "x" * 250 + "SECRET9"  # too long once the prefix is added
    response = api.get(
        "/audit/events", params={"actorId": sensitive + "y" * 10}, headers=auth("auditor")
    )
    assert response.status_code == 422
    assert "SECRET9" not in response.text


def test_default_and_maximum_limit(api: TestClient) -> None:
    for i in range(52):
        _post(api, actorId=f"a{i}")
    body = api.get("/audit/events", headers=auth("auditor")).json()
    assert len(body["items"]) == 50
    assert body["nextCursor"] == "50"
    assert len(_seqs(api, limit=200)) == 52


def test_openapi_documents_the_endpoints(api: TestClient) -> None:
    paths = api.get("/openapi.json").json()["paths"]
    assert {"/audit/events", "/audit/events/{event_id}"} <= set(paths)
    assert "post" in paths["/audit/events"]
    assert "put" not in paths["/audit/events"]
    assert "delete" not in paths["/audit/events/{event_id}"]
