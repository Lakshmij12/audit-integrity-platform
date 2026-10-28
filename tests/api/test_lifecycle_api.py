"""Admin-only redaction and retention through the HTTP API, and verification of their results."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.api import create_app
from aip.crypto.signing import generate_signing_key
from tests.api.conftest import auth, make_settings
from tests.ingest.support import FakeClock, event_data

SENSITIVE = "acct-" + "900123456"
REDACT = {"paths": [["ssn"]], "reason": "client privacy request"}


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def signed(tmp_path: Path, clock: FakeClock) -> Iterator[TestClient]:
    key = tmp_path / "keys" / "signing.pem"
    generate_signing_key(key)
    settings = make_settings(
        tmp_path / "audit.db", signing_key_path=str(key), retention_window_days=30
    )
    with TestClient(create_app(settings, clock=clock)) as client:
        yield client


def _write(client: TestClient, count: int) -> list[str]:
    ids = []
    for i in range(count):
        response = client.post(
            "/audit/events",
            json=event_data(payload={"n": i, "ssn": SENSITIVE}),
            headers=auth("writer"),
        )
        assert response.status_code == 201
        ids.append(response.json()["eventId"])
    return ids


def _verify(client: TestClient) -> dict[str, Any]:
    body: dict[str, Any] = client.get("/audit/verify", headers=auth("auditor")).json()
    return body


def _redact(client: TestClient, event_id: str, body: Any = None, role: str = "admin") -> Any:
    return client.post(
        f"/audit/events/{event_id}/redactions", json=REDACT if body is None else body,
        headers=auth(role),
    )  # fmt: skip


def test_lifecycle_endpoints_are_admin_only(signed: TestClient) -> None:
    ids = _write(signed, 1)
    for role in ("writer", "auditor"):
        assert _redact(signed, ids[0], role=role).status_code == 403
        assert signed.post("/audit/retention/runs", headers=auth(role)).status_code == 403
    assert signed.post(f"/audit/events/{ids[0]}/redactions", json=REDACT).status_code == 401
    assert signed.post("/audit/retention/runs").status_code == 401


def test_redaction_through_the_api(signed: TestClient) -> None:
    ids = _write(signed, 2)
    before = signed.get(f"/audit/events/{ids[0]}", headers=auth("auditor")).json()
    response = _redact(signed, ids[0])
    assert response.status_code == 201
    body = response.json()
    assert (body["targetEventId"], body["redactedPaths"], body["redactionSeq"]) == (
        ids[0],
        [["ssn"]],
        3,
    )

    after = signed.get(f"/audit/events/{ids[0]}", headers=auth("auditor")).json()
    assert after["payload"] == {"n": 0, "ssn": None}
    assert (after["redactedPaths"], after["archived"]) == ([["ssn"]], False)
    for name in ("payloadRoot", "contentHash", "recordHash", "prevHash"):
        assert after[name] == before[name]

    system = signed.get(f"/audit/events/{body['redactionEventId']}", headers=auth("auditor"))
    assert system.json()["eventType"] == "SYSTEM_REDACTION"
    assert SENSITIVE not in system.text

    verified = _verify(signed)
    assert (verified["status"], verified["intact"]) == ("VERIFIED", True)
    assert verified["authorized"]["redactedLeaves"] == 1

    again = _redact(signed, ids[0])
    assert again.status_code == 200
    assert again.json()["alreadyRedactedPaths"] == [["ssn"]]


@pytest.mark.parametrize(
    ("event_id", "body", "status", "code"),
    [
        ("evt_" + "0" * 32, None, 404, "not_found"),
        ("not-an-id", None, 404, "not_found"),
        (None, {"paths": [["nope"]], "reason": "r"}, 422, "validation_failed"),
        (None, {"paths": [], "reason": "r"}, 422, "validation_failed"),
        (None, {"paths": [["ssn"]]}, 422, "validation_failed"),
        (None, {"paths": [["ssn"]], "reason": "r", "extra": 1}, 422, "validation_failed"),
        (None, {"paths": [[1.5]], "reason": "r"}, 422, "validation_failed"),
    ],
)
def test_redaction_errors(
    signed: TestClient, event_id: str | None, body: Any, status: int, code: str
) -> None:
    ids = _write(signed, 1)
    response = _redact(signed, event_id or ids[0], body)
    assert response.status_code == status
    assert response.json()["code"] == code
    assert SENSITIVE not in response.text


def test_redaction_conflicts_and_media_type(signed: TestClient) -> None:
    ids = _write(signed, 1)
    system_id = _redact(signed, ids[0]).json()["redactionEventId"]
    conflict = _redact(signed, system_id, {"paths": [["signature"]], "reason": "r"})
    assert (conflict.status_code, conflict.json()["code"]) == (409, "conflict")
    wrong_type = signed.post(
        f"/audit/events/{ids[0]}/redactions",
        content=b"paths",
        headers={**auth("admin"), "content-type": "text/plain"},
    )
    assert wrong_type.status_code == 415


def test_without_a_signing_key_mutations_return_503(api: TestClient) -> None:
    ids = _write(api, 1)
    response = _redact(api, ids[0])
    assert (response.status_code, response.json()["code"]) == (503, "service_unavailable")
    run = api.post("/audit/retention/runs", json={"dryRun": False}, headers=auth("admin"))
    assert run.status_code == 503
    dry = api.post("/audit/retention/runs", headers=auth("admin"))
    assert (dry.status_code, dry.json()["dryRun"]) == (200, True)


def test_retention_through_the_api(signed: TestClient, clock: FakeClock, tmp_path: Path) -> None:
    old = _write(signed, 2)
    clock.advance(days=31)
    _write(signed, 1)

    dry = signed.post("/audit/retention/runs", headers=auth("admin"))  # empty body: dry run
    assert dry.status_code == 200
    assert (dry.json()["dryRun"], dry.json()["recordCount"], dry.json()["runId"]) == (True, 2, None)
    assert _verify(signed)["status"] == "VERIFIED"

    run = signed.post("/audit/retention/runs", json={"dryRun": False}, headers=auth("admin"))
    assert run.status_code == 201
    body = run.json()
    assert (body["recordCount"], body["fromSeq"], body["toSeq"]) == (2, 1, 2)
    archive = tmp_path / "archives" / body["archiveFile"]
    assert archive.exists()

    view = signed.get(f"/audit/events/{old[0]}", headers=auth("auditor")).json()
    assert (view["archived"], view["payload"]) == (True, {})
    verified = _verify(signed)
    assert verified["status"] == "VERIFIED"
    assert verified["authorized"]["archivedRecords"] == 2

    redact_archived = _redact(signed, old[0])
    assert redact_archived.status_code == 409

    archive.write_bytes(archive.read_bytes() + b" ")
    tampered = _verify(signed)
    assert (tampered["status"], tampered["firstInconsistency"]["violationType"]) == (
        "TAMPERED",
        "ARCHIVE_CONTENT_MISMATCH",
    )
    assert SENSITIVE not in str(tampered)
    signed_checkpoint = signed.get("/audit/checkpoints/latest", headers=auth("auditor"))
    assert signed_checkpoint.status_code == 409  # never signs a chain that fails verification


@pytest.mark.parametrize("body", [{"dryRun": "false"}, {"dryRun": 0}, {"other": True}, [1]])
def test_retention_rejects_ambiguous_bodies(signed: TestClient, body: Any) -> None:
    response = signed.post("/audit/retention/runs", json=body, headers=auth("admin"))
    assert response.status_code == 422
