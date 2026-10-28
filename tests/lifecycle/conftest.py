"""Fixtures for redaction and retention: a signer, an archive directory and the service."""

from pathlib import Path
from typing import Any

import pytest

from aip.crypto.signing import Signer, generate_signing_key
from aip.ingest import IngestService
from aip.lifecycle import LifecycleService
from aip.storage import Database
from aip.verify import VerifyReport, verify_database
from tests.ingest.support import FakeClock, make_event

SENSITIVE = "acct-" + "900123456"
WINDOW_DAYS = 30


@pytest.fixture
def signer(tmp_path: Path) -> Signer:
    generate_signing_key(tmp_path / "keys" / "signing.pem")
    return Signer.from_pem_file(tmp_path / "keys" / "signing.pem")


@pytest.fixture
def archive_dir(tmp_path: Path) -> Path:
    return tmp_path / "archives"


@pytest.fixture
def lifecycle(
    database: Database, signer: Signer, clock: FakeClock, archive_dir: Path
) -> LifecycleService:
    return LifecycleService(
        database, signer=signer, clock=clock, archive_dir=archive_dir, window_days=WINDOW_DAYS
    )


def seed(service: IngestService, clock: FakeClock, count: int, **overrides: Any) -> list[str]:
    """Append ``count`` events one second apart; return their eventIds."""
    ids = []
    for i in range(count):
        result = service.append(
            make_event(payload={"n": i, "ssn": SENSITIVE, "tags": ["a", "b"]}, **overrides)
        )
        ids.append(result.event_id)
        clock.advance(seconds=1)
    return ids


def verify(
    database: Database, signer: Signer | None, archive_dir: Path | None = None
) -> VerifyReport:
    keys = {} if signer is None else {signer.key_id: signer.public_key}
    return verify_database(database, trusted_keys=keys, archive_dir=archive_dir)
