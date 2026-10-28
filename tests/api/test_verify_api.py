"""GET /audit/verify and GET /audit/checkpoints/latest through the HTTP API."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.api import create_app
from aip.crypto.signing import generate_signing_key, verify_checkpoint
from tests.api.conftest import auth, make_settings
from tests.ingest.support import FakeClock, event_data, raw_connection

SENSITIVE = "acct-" + "900123456"


@pytest.fixture
def signed_api(tmp_path: Path) -> Iterator[tuple[TestClient, Path]]:
    key = tmp_path / "keys" / "signing.pem"
    generate_signing_key(key)
    db_path = tmp_path / "audit.db"
    app = create_app(make_settings(db_path, signing_key_path=str(key)), clock=FakeClock())
    with TestClient(app) as client:
        yield client, db_path


def _write(client: TestClient, count: int) -> None:
    for i in range(count):
        response = client.post(
            "/audit/events",
            json=event_data(actorId=f"actor-{i}", payload={"n": i, "ssn": SENSITIVE}),
            headers=auth("writer"),
        )
        assert response.status_code == 201


def _tamper(db_path: Path, statement: str) -> None:
    conn = raw_connection(db_path)
    try:
        conn.execute("DROP TRIGGER payload_leaves_no_update")
        conn.execute("DROP TRIGGER audit_records_no_update")
        conn.execute("DROP TRIGGER audit_records_no_delete")
        conn.execute("DROP TRIGGER payload_leaves_no_delete")
        conn.execute(statement)
    finally:
        conn.close()


def _verify(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/audit/verify", params=params, headers=auth("auditor"))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def test_verify_requires_a_reader_role(api: TestClient) -> None:
    assert api.get("/audit/verify").status_code == 401
    assert api.get("/audit/verify", headers=auth("writer")).status_code == 403
    assert api.get("/audit/verify", headers=auth("auditor")).status_code == 200
    assert api.get("/audit/verify", headers=auth("admin")).status_code == 200


def test_verify_reports_an_intact_chain(api: TestClient) -> None:
    _write(api, 4)
    body = _verify(api)
    assert (body["status"], body["intact"]) == ("VERIFIED", True)
    assert (body["recordsChecked"], body["headSeq"]) == (4, 4)
    assert body["firstInconsistency"] is None
    assert body["anchor"] is None
    assert body["unverified"] == {
        "redactedLeaves": 0,
        "archivedRecords": 0,
        "archivedContentUnavailable": 0,
    }
    assert body["authorized"] == {"redactedLeaves": 0, "archivedRecords": 0}
    assert any("trusted anchor" in note for note in body["notes"])


def test_direct_sqlite_modification_is_detected_through_the_api(
    api: TestClient, api_db: Path
) -> None:
    """The assignment's validation flow: write, query, verify, modify the store, verify again."""
    _write(api, 5)
    assert len(api.get("/audit/events", headers=auth("auditor")).json()["items"]) == 5
    assert _verify(api)["intact"] is True
    _tamper(
        api_db,
        "UPDATE payload_leaves SET value = '\"tampered\"' WHERE seq = 4 AND path = '[\"ssn\"]'",
    )
    body = _verify(api)
    assert (body["status"], body["intact"]) == ("TAMPERED", False)
    problem = body["firstInconsistency"]
    assert problem["violationType"] == "LEAF_COMMITMENT_MISMATCH"
    assert (problem["seq"], problem["leafPath"]) == (4, ["ssn"])
    assert problem["eventId"].startswith("evt_")
    assert body["recordsChecked"] == 3
    assert SENSITIVE not in str(body)
    assert "tampered" not in str(body)


def test_deleted_record_is_reported(api: TestClient, api_db: Path) -> None:
    _write(api, 3)
    conn = raw_connection(api_db)
    try:
        conn.execute("DROP TRIGGER payload_leaves_no_delete")
        conn.execute("DROP TRIGGER audit_records_no_delete")
        conn.execute("DELETE FROM payload_leaves WHERE seq = 2")
        conn.execute("DELETE FROM audit_records WHERE seq = 2")
    finally:
        conn.close()
    problem = _verify(api)["firstInconsistency"]
    assert (problem["violationType"], problem["seq"]) == ("SEQUENCE_GAP", 2)


def test_unauthorized_redaction_is_tampered(api: TestClient, api_db: Path) -> None:
    """A nulled value and salt without a signed SYSTEM_REDACTION authorization is unauthorized
    data removal, never a valid redaction."""
    _write(api, 3)
    _tamper(
        api_db,
        "UPDATE payload_leaves SET salt = NULL, value = NULL WHERE seq = 2 AND path = '[\"ssn\"]'",
    )
    body = _verify(api)
    assert (body["status"], body["intact"]) == ("TAMPERED", False)
    problem = body["firstInconsistency"]
    assert (problem["violationType"], problem["seq"]) == ("UNAUTHORIZED_REDACTION", 2)
    assert problem["leafPath"] == ["ssn"]


@pytest.mark.parametrize(
    "params",
    [
        {"anchorSeq": 1},
        {"anchorHash": "a" * 64},
        {"anchorSeq": 1, "anchorHash": "A" * 64},
        {"anchorSeq": 0, "anchorHash": "a" * 64},
        {"anchorSeq": "x", "anchorHash": "a" * 64},
    ],
)
def test_invalid_anchor_parameters(api: TestClient, params: dict[str, Any]) -> None:
    response = api.get("/audit/verify", params=params, headers=auth("auditor"))
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_checkpoint_is_signed_and_anchors_verification(
    signed_api: tuple[TestClient, Path],
) -> None:
    client, db_path = signed_api
    _write(client, 3)
    response = client.get("/audit/checkpoints/latest", headers=auth("auditor"))
    assert response.status_code == 200
    checkpoint = response.json()
    public_key = checkpoint.pop("publicKey")
    assert checkpoint["seq"] == 3
    assert verify_checkpoint(checkpoint, public_key)
    assert not verify_checkpoint({**checkpoint, "seq": 2}, public_key)

    anchor = {"anchorSeq": checkpoint["seq"], "anchorHash": checkpoint["recordHash"]}
    _write(client, 1)
    matched = _verify(client, **anchor)
    assert matched["intact"] is True
    assert matched["anchor"] == {"seq": 3, "recordHash": checkpoint["recordHash"], "matched": True}

    conn = raw_connection(db_path)
    try:
        conn.execute("DROP TRIGGER payload_leaves_no_delete")
        conn.execute("DROP TRIGGER audit_records_no_delete")
        conn.execute("DELETE FROM payload_leaves WHERE seq >= 3")
        conn.execute("DELETE FROM audit_records WHERE seq >= 3")
    finally:
        conn.close()
    assert _verify(client)["intact"] is True  # truncation is invisible without an anchor
    truncated = _verify(client, **anchor)
    assert truncated["intact"] is False
    assert truncated["firstInconsistency"]["violationType"] == "TRUNCATED"
    assert truncated["anchor"]["matched"] is False


def test_checkpoint_roles_and_states(api: TestClient, signed_api: tuple[TestClient, Path]) -> None:
    unsigned = api.get("/audit/checkpoints/latest", headers=auth("auditor"))
    assert unsigned.status_code == 503
    assert unsigned.json()["code"] == "service_unavailable"
    client, _ = signed_api
    assert client.get("/audit/checkpoints/latest", headers=auth("writer")).status_code == 403
    empty = client.get("/audit/checkpoints/latest", headers=auth("auditor"))
    assert empty.status_code == 404


def test_checkpoint_refuses_to_sign_a_tampered_chain(
    signed_api: tuple[TestClient, Path],
) -> None:
    client, db_path = signed_api
    _write(client, 3)
    _tamper(db_path, "UPDATE audit_records SET actor_id = 'someone-else' WHERE seq = 2")
    response = client.get("/audit/checkpoints/latest", headers=auth("auditor"))
    assert response.status_code == 409
    assert response.json()["code"] == "conflict"
    assert "signature" not in response.json()


def test_unusable_signing_key_fails_at_startup(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a key")
    with pytest.raises(ValueError, match="signing key"):
        create_app(make_settings(tmp_path / "db.sqlite3", signing_key_path=str(bad)))
