"""API test fixtures: an app on a temporary database with one key per role and a fake clock."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.api import create_app
from aip.api.auth import hash_api_key
from aip.config import Settings
from tests.ingest.support import FakeClock

KEYS = {
    "writer": "test-writer-key-" + "w" * 32,
    "auditor": "test-auditor-key-" + "a" * 32,
    "admin": "test-admin-key-" + "x" * 32,
}


def make_settings(db_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "db_path": str(db_path),
        "busy_timeout_ms": 500,
        "api_keys": ",".join(f"{role}:{hash_api_key(key)}" for role, key in KEYS.items()),
    }
    values.update(overrides)
    return Settings(**values)


def auth(role: str) -> dict[str, str]:
    return {"X-API-Key": KEYS[role]}


@pytest.fixture
def api_db(tmp_path: Path) -> Path:
    return tmp_path / "api" / "audit.db"


@pytest.fixture
def api_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def api(api_db: Path, api_clock: FakeClock) -> Iterator[TestClient]:
    app = create_app(make_settings(api_db), clock=api_clock)
    with TestClient(app) as client:
        yield client
