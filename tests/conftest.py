"""Fixtures for storage and ingestion tests: a fresh SQLite file, a fake clock, the service."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from aip.ingest import IngestService
from aip.storage import Database, DatabaseConfig, open_database
from tests.ingest.support import FakeClock


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.db"


@pytest.fixture
def database(db_path: Path) -> Iterator[Database]:
    db = open_database(DatabaseConfig(db_path, busy_timeout_ms=2000))
    yield db
    db.close()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def service(database: Database, clock: FakeClock) -> IngestService:
    return IngestService(database, clock=clock)
