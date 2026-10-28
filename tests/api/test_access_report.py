"""Scenario C: GET /audit/reports/account-access."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.api import create_app
from aip.crypto.signing import generate_signing_key
from tests.api.conftest import auth, make_settings
from tests.ingest.support import FakeClock, event_data, raw_connection

SENSITIVE = "acct-" + "900123456"
URL = "/audit/reports/account-access"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def db_file(tmp_path: Path) -> Path:
    return tmp_path / "audit.db"


@pytest.fixture
def client(tmp_path: Path, db_file: Path, clock: FakeClock) -> Iterator[TestClient]:
    key = tmp_path / "keys" / "signing.pem"
    generate_signing_key(key)
    settings = make_settings(db_file, signing_key_path=str(key), retention_window_days=30)
    with TestClient(create_app(settings, clock=clock)) as test_client:
        yield test_client


def _write(client: TestClient, clock: FakeClock, **fields: Any) -> str:
    data = event_data(resourceType="CLIENT_ACCOUNT", payload={"ssn": SENSITIVE, "n": 1})
    data.update(fields)
    response = client.post("/audit/events", json=data, headers=auth("writer"))
    assert response.status_code == 201, response.text
    clock.advance(minutes=1)
    event_id: str = response.json()["eventId"]
    return event_id


def _seed(client: TestClient, clock: FakeClock) -> list[str]:
    return [
        _write(client, clock, eventType="ACCOUNT_VIEWED", actorId="advisor-1", resourceId="acct-1",
               timestamp="2026-10-01T09:00:00Z"),
        _write(client, clock, eventType="ACCOUNT_VIEWED", actorId="advisor-2", resourceId="acct-1",
               timestamp="2026-10-02T09:00:00Z"),
        _write(client, clock, eventType="ACCOUNT_UPDATED", actorId="advisor-1", resourceId="acct-1",
               timestamp="2026-10-03T09:00:00Z"),
        _write(client, clock, eventType="ACCOUNT_VIEWED", actorId="advisor-1", resourceId="acct-2",
               timestamp="2026-10-04T09:00:00Z"),
        _write(client, clock, eventType="ACCOUNT_VIEWED", actorId="advisor-1", resourceId="acct-1",
               resourceType="TRADE", timestamp="2026-10-05T09:00:00Z"),  # not a client account
    ]  # fmt: skip


def _report(client: TestClient, **params: str) -> dict[str, Any]:
    response = client.get(URL, params=params, headers=auth("auditor"))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert SENSITIVE not in response.text  # payload values are never returned
    return body


def test_report_for_one_account(client: TestClient, clock: FakeClock) -> None:
    ids = _seed(client, clock)
    body = _report(client, accountId="acct-1")
    assert [e["eventId"] for e in body["events"]] == ids[:3]
    assert body["scope"] == {
        "resourceType": "CLIENT_ACCOUNT",
        "accountId": "acct-1",
        "actorId": None,
        "eventType": None,
        "from": None,
        "to": None,
    }
    assert body["summary"] == {
        "totalEvents": 3,
        "accounts": ["acct-1"],
        "byEventType": {"ACCOUNT_UPDATED": 1, "ACCOUNT_VIEWED": 2},
        "byActor": {"advisor-1": 2, "advisor-2": 1},
        "firstTimestamp": "2026-10-01T09:00:00.000000Z",
        "lastTimestamp": "2026-10-03T09:00:00.000000Z",
        "eventsNotVerified": 0,
    }
    assert body["integrity"]["status"] == "VERIFIED"
    assert body["integrity"]["recordsChecked"] == 5
    assert {e["integrity"] for e in body["events"]} == {"VERIFIED"}
    assert set(body["events"][0]) == {
        "seq", "eventId", "eventType", "actorId", "accountId", "timestamp", "recordedAt",
        "recordHash", "redactedPaths", "archived", "integrity",
    }  # fmt: skip


def test_filters_by_actor_type_and_time(client: TestClient, clock: FakeClock) -> None:
    _seed(client, clock)
    by_actor = _report(client, actorId="advisor-1")
    assert by_actor["summary"]["accounts"] == ["acct-1", "acct-2"]
    assert by_actor["summary"]["totalEvents"] == 3
    viewed = _report(client, accountId="acct-1", eventType="ACCOUNT_VIEWED")
    assert viewed["summary"]["byEventType"] == {"ACCOUNT_VIEWED": 2}
    window = _report(
        client, accountId="acct-1", **{"from": "2026-10-02T00:00:00Z", "to": "2026-10-03T09:00:00Z"}
    )
    assert [e["actorId"] for e in window["events"]] == ["advisor-2"]
    assert window["scope"]["from"] == "2026-10-02T00:00:00.000000Z"
    empty = _report(client, accountId="acct-unknown")
    assert (empty["summary"]["totalEvents"], empty["summary"]["firstTimestamp"]) == (0, None)


def test_redacted_and_archived_events(client: TestClient, clock: FakeClock) -> None:
    ids = _seed(client, clock)
    redaction = client.post(
        f"/audit/events/{ids[1]}/redactions",
        json={"paths": [["ssn"]], "reason": "privacy"},
        headers=auth("admin"),
    )
    assert redaction.status_code == 201
    clock.advance(days=31)
    _write(client, clock, eventType="ACCOUNT_VIEWED", actorId="advisor-3", resourceId="acct-1")
    run = client.post("/audit/retention/runs", json={"dryRun": False}, headers=auth("admin"))
    assert run.status_code == 201
    body = _report(client, accountId="acct-1")
    events = body["events"]
    assert [e["archived"] for e in events] == [True, True, True, False]
    # an archived record's leaves (and so its redacted paths) live in the archive file
    assert [e["redactedPaths"] for e in events] == [[], [], [], []]
    # archived content is verified against the archive file, so everything is VERIFIED
    assert body["integrity"]["status"] == "VERIFIED"
    assert {e["integrity"] for e in events} == {"VERIFIED"}


def test_redaction_is_reported_and_indeterminate_without_a_trusted_key(
    tmp_path: Path, client: TestClient, clock: FakeClock, db_file: Path
) -> None:
    ids = _seed(client, clock)
    client.post(
        f"/audit/events/{ids[0]}/redactions",
        json={"paths": [["ssn"]], "reason": "privacy"},
        headers=auth("admin"),
    )
    assert _report(client, accountId="acct-1")["events"][0]["redactedPaths"] == [["ssn"]]
    # The same database served without the signing key: the redaction cannot be checked.
    with TestClient(create_app(make_settings(db_file), clock=clock)) as unsigned:
        response = unsigned.get(URL, params={"accountId": "acct-1"}, headers=auth("auditor"))
    body = response.json()
    assert body["integrity"]["status"] == "INDETERMINATE"
    assert [e["integrity"] for e in body["events"]] == ["INDETERMINATE", "VERIFIED", "VERIFIED"]
    assert body["summary"]["eventsNotVerified"] == 1


def test_tampering_is_reported_per_event(
    client: TestClient, clock: FakeClock, db_file: Path
) -> None:
    _seed(client, clock)
    conn = raw_connection(db_file)
    try:
        conn.execute("DROP TRIGGER audit_records_no_update")
        conn.execute("UPDATE audit_records SET actor_id = 'advisor-9' WHERE seq = 2")
    finally:
        conn.close()
    body = _report(client, accountId="acct-1")
    assert body["integrity"]["status"] == "TAMPERED"
    assert (body["integrity"]["firstInconsistencySeq"], body["integrity"]["violationType"]) == (
        2,
        "CONTENT_HASH_MISMATCH",
    )
    assert [e["integrity"] for e in body["events"]] == ["VERIFIED", "TAMPERED", "UNVERIFIED"]
    assert body["summary"]["eventsNotVerified"] == 2


def test_authorization(client: TestClient, clock: FakeClock) -> None:
    _seed(client, clock)
    assert client.get(URL, params={"accountId": "acct-1"}).status_code == 401
    writer = client.get(URL, params={"accountId": "acct-1"}, headers=auth("writer"))
    assert writer.status_code == 403
    admin = client.get(URL, params={"accountId": "acct-1"}, headers=auth("admin"))
    assert admin.status_code == 200


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"eventType": "ACCOUNT_VIEWED"},
        {"accountId": ""},
        {"accountId": "acct-1", "from": "yesterday"},
        {"accountId": "acct-1", "to": "2026-13-01T00:00:00Z"},
    ],
)
def test_invalid_requests(client: TestClient, params: dict[str, str]) -> None:
    response = client.get(URL, params=params, headers=auth("auditor"))
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"
