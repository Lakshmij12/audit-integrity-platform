"""API-key authentication, role checks, key configuration and the key-generation CLI."""

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aip.api import create_app
from aip.api.auth import authenticate, hash_api_key, parse_api_keys
from aip.cli import main as cli_main
from tests.api.conftest import KEYS, auth, make_settings
from tests.ingest.support import event_data


def test_missing_and_invalid_keys_are_rejected(api: TestClient) -> None:
    for headers in ({}, {"X-API-Key": ""}, {"X-API-Key": "not-a-valid-key"}):
        response = api.get("/audit/events", headers=headers)
        assert response.status_code == 401
        assert response.headers["content-type"] == "application/problem+json"
        assert response.json()["code"] == "unauthorized"


@pytest.mark.parametrize(
    ("role", "write_status", "read_status"),
    [("writer", 201, 403), ("auditor", 403, 200), ("admin", 201, 200)],
)
def test_role_permissions(api: TestClient, role: str, write_status: int, read_status: int) -> None:
    assert api.post("/audit/events", json=event_data(), headers=auth(role)).status_code == (
        write_status
    )
    assert api.get("/audit/events", headers=auth(role)).status_code == read_status


def test_forbidden_is_a_problem_response(api: TestClient) -> None:
    response = api.get("/audit/events", headers=auth("writer"))
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"


def test_no_configured_keys_fails_closed(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path / "db.sqlite3", api_keys=""))
    with TestClient(app) as client:
        response = client.post("/audit/events", json=event_data(), headers=auth("admin"))
    assert response.status_code == 401


@pytest.mark.parametrize(
    "raw",
    ["writer", "writer:", "reader:" + "0" * 64, "admin:" + "A" * 64, "admin:" + "0" * 63],
)
def test_malformed_key_configuration_fails_at_startup(tmp_path: Path, raw: str) -> None:
    with pytest.raises(ValueError, match="AIP_API_KEYS") as caught:
        create_app(make_settings(tmp_path / "db.sqlite3", api_keys=raw))
    assert raw not in str(caught.value)


def test_parse_and_authenticate() -> None:
    entries = parse_api_keys(f" writer:{hash_api_key('k1')} , ,auditor:{hash_api_key('k2')} ")
    assert [e.role for e in entries] == ["writer", "auditor"]
    principal = authenticate("k2", entries)
    assert principal is not None
    assert principal.role == "auditor"
    assert principal.key_id == hash_api_key("k2")[:8]
    assert authenticate("k3", entries) is None
    assert authenticate(None, entries) is None


def test_keys_never_appear_in_logs(api: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="aip")
    api.post("/audit/events", json=event_data(), headers=auth("writer"))
    api.get("/audit/events", headers={"X-API-Key": "wrong-key-value"})
    access = [r for r in caplog.records if r.name == "aip.api.access"]
    assert len(access) == 2
    assert {getattr(r, "status", None) for r in access} == {201, 401}
    assert getattr(access[0], "role", None) == "writer"
    for key in [*KEYS.values(), "wrong-key-value"]:
        assert key not in caplog.text


def test_cli_generates_a_key_and_its_hash(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["new-api-key", "--role", "auditor"]) == 0
    lines = capsys.readouterr().out.splitlines()
    key = lines[0].split(": ", 1)[1]
    entry = lines[1].split(":  ", 1)[1]
    assert len(key) >= 40
    assert entry == f"auditor:{hash_api_key(key)}"
    assert parse_api_keys(entry)[0].role == "auditor"


def test_cli_rejects_unknown_roles(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli_main(["new-api-key", "--role", "superuser"])
    assert caught.value.code == 2
