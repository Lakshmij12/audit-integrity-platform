"""Shared helpers for storage and ingestion tests (importable by spawned worker processes)."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aip.crypto import (
    LeafStatus,
    check_chain,
    check_leaf,
    content_hash,
    payload_root,
    unflatten,
)
from aip.ingest import EventInput, IngestService, validate_event
from aip.storage import (
    Database,
    DatabaseConfig,
    derive_event_id,
    iter_chain_entries,
    load_leaves,
    open_database,
    read_record,
)

START = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)


class FakeClock:
    """Settable clock; ``now()`` returns the current value."""

    def __init__(self, start: datetime = START) -> None:
        self.current = start

    def now(self) -> datetime:
        return self.current

    def advance(self, **delta: float) -> None:
        self.current = self.current + timedelta(**delta)


def event_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "eventType": "RECORD_UPDATED",
        "actorId": "user-0042",
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": "acct-0001",
        "payload": {"field": "email", "changed": True},
    }
    data.update(overrides)
    return data


def make_event(**overrides: Any) -> EventInput:
    return validate_event(event_data(**overrides))


def raw_connection(path: Path, *, timeout: float = 0.2) -> sqlite3.Connection:
    """Direct sqlite3 connection that bypasses the application (autocommit, foreign keys on)."""
    conn = sqlite3.connect(path, isolation_level=None, timeout=timeout)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def count_rows(path: Path) -> tuple[int, int]:
    conn = raw_connection(path)
    try:
        records = conn.execute("SELECT count(*) FROM audit_records").fetchone()[0]
        leaves = conn.execute("SELECT count(*) FROM payload_leaves").fetchone()[0]
        return int(records), int(leaves)
    finally:
        conn.close()


def verify_store(database: Database, payloads: dict[int, dict[str, Any]] | None = None) -> int:
    """Recompute every stored record from its stored fields and leaves; return the record count.

    Checks: every leaf commitment (C5), payload root, contentHash (C3), chain links and recordHash
    (C1, C2, C4 via check_chain), the eventId derivation, and optionally the rebuilt payloads.
    """
    with database.read_transaction() as conn:
        entries = list(iter_chain_entries(conn, batch_size=7))
        assert check_chain(entries) is None
        for entry in entries:
            assert isinstance(entry.seq, int)
            record = read_record(conn, entry.seq)
            assert record is not None
            assert record.event_id == derive_event_id(record.record_hash)
            leaves = load_leaves(conn, record.seq)
            assert {check_leaf(leaf) for leaf in leaves} == {LeafStatus.VALID}
            assert payload_root(leaves) == record.payload_root
            assert (
                content_hash(
                    event_type=record.event_type,
                    actor_id=record.actor_id,
                    resource_type=record.resource_type,
                    resource_id=record.resource_id,
                    timestamp=record.timestamp,
                    payload_root=record.payload_root,
                )
                == record.content_hash
            )
            if payloads is not None and record.seq in payloads:
                assert unflatten(leaves) == payloads[record.seq]
        return len(entries)


def append_worker(db_path: str, count: int, tag: str) -> None:
    """Entry point for multiprocess tests: open the database and append ``count`` events."""
    database = open_database(DatabaseConfig(Path(db_path), busy_timeout_ms=30_000))
    try:
        service = IngestService(database)
        for i in range(count):
            service.append(make_event(actorId=f"{tag}-{i}", payload={"worker": tag, "i": i}))
    finally:
        database.close()
