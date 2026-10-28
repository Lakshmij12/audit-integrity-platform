"""Schema v1 -> v2 migration and the narrowly scoped v2 guard triggers."""

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import text

from aip.ingest import IngestService
from aip.storage import Database, DatabaseConfig, StorageIntegrityError, open_database
from aip.storage import schema as schema_module
from aip.storage.schema import DDL, V2_TRIGGERS
from tests.ingest.support import FakeClock, make_event, raw_connection, verify_store


def _create_v1(path: Path) -> None:
    """A database exactly as commit 6/7/8 created it (schema v1)."""
    conn = raw_connection(path)
    try:
        conn.execute("BEGIN")
        for statement in DDL:
            conn.execute(statement)
        conn.execute("INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')")
        conn.execute("COMMIT")
    finally:
        conn.close()


def _version(path: Path) -> str:
    conn = raw_connection(path)
    try:
        return str(conn.execute("SELECT value FROM schema_meta").fetchone()[0])
    finally:
        conn.close()


def test_new_database_is_created_at_v2(database: Database, db_path: Path) -> None:
    assert _version(db_path) == "2"


def test_v1_database_with_data_is_migrated(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    _create_v1(path)
    # Data written by the v2 code path, then the file is rolled back to the v1 triggers.
    db = open_database(DatabaseConfig(path))
    IngestService(db, clock=FakeClock()).append(make_event())
    db.close()
    conn = raw_connection(path)
    try:
        conn.execute("BEGIN")
        for name in V2_TRIGGERS:
            conn.execute(f"DROP TRIGGER {name}")
        for statement in DDL:
            if any(f"TRIGGER {name}" in statement for name in V2_TRIGGERS):
                conn.execute(statement)
        conn.execute("UPDATE schema_meta SET value = '1'")
        conn.execute("COMMIT")
    finally:
        conn.close()
    assert _version(path) == "1"
    migrated = open_database(DatabaseConfig(path))
    try:
        assert _version(path) == "2"
        assert verify_store(migrated) == 1
    finally:
        migrated.close()


def test_failed_migration_leaves_v1_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "v1.db"
    _create_v1(path)
    broken = dict(V2_TRIGGERS)
    broken["payload_leaves_no_delete"] = "CREATE TRIGGER this is not valid SQL"
    monkeypatch.setattr(schema_module, "V2_TRIGGERS", broken)
    with pytest.raises(Exception):  # noqa: B017, PT011 - any database error rolls back
        open_database(DatabaseConfig(path))
    assert _version(path) == "1"
    conn = raw_connection(path)
    try:
        triggers = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
    finally:
        conn.close()
    assert len(triggers) == 4  # nothing dropped
    monkeypatch.setattr(schema_module, "V2_TRIGGERS", V2_TRIGGERS)
    open_database(DatabaseConfig(path)).close()
    assert _version(path) == "2"


def test_v1_trigger_under_a_v2_version_fails_closed(database: Database, db_path: Path) -> None:
    database.close()
    conn = raw_connection(db_path)
    try:
        conn.execute("DROP TRIGGER payload_leaves_no_update")
        conn.execute(
            "CREATE TRIGGER payload_leaves_no_update BEFORE UPDATE ON payload_leaves "
            "BEGIN SELECT 1; END"
        )
    finally:
        conn.close()
    with pytest.raises(StorageIntegrityError, match="differ from schema v2"):
        open_database(DatabaseConfig(db_path))


@pytest.fixture
def two_records(service: IngestService, db_path: Path) -> Path:
    service.append(make_event(payload={"a": "x", "b": 1}))
    service.append(make_event(eventType="RECORD_UPDATED", payload={"a": "y"}))
    conn = raw_connection(db_path)
    try:  # make seq 2 look like a SYSTEM_* event (bypassing the hash chain; triggers only)
        conn.execute("DROP TRIGGER audit_records_no_update")
        conn.execute("UPDATE audit_records SET event_type = 'SYSTEM_REDACTION' WHERE seq = 2")
        conn.execute(V2_TRIGGERS["audit_records_no_update"])
    finally:
        conn.close()
    return db_path


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE payload_leaves SET salt = NULL, value = NULL WHERE seq = 1 AND path = '[\"a\"]'",
        "UPDATE audit_records SET archived_at = '2026-01-01T00:00:00.000000Z', "
        "archive_run_id = 'run_x' WHERE seq = 1",
    ],
)
def test_v2_allows_exactly_redaction_and_archive_marking(two_records: Path, statement: str) -> None:
    conn = raw_connection(two_records)
    try:
        conn.execute(statement)
    finally:
        conn.close()


def test_v2_allows_deleting_leaves_of_archived_records_only(two_records: Path) -> None:
    conn = raw_connection(two_records)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM payload_leaves WHERE seq = 1")
        conn.execute(
            "UPDATE audit_records SET archived_at = '2026-01-01T00:00:00.000000Z', "
            "archive_run_id = 'run_x' WHERE seq = 1"
        )
        conn.execute("DELETE FROM payload_leaves WHERE seq = 1")
    finally:
        conn.close()


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM audit_records WHERE seq = 1",
        "UPDATE audit_records SET actor_id = 'someone-else' WHERE seq = 1",
        "UPDATE audit_records SET archived_at = '2026-01-01T00:00:00.000000Z', "
        "archive_run_id = 'r', actor_id = 'x' WHERE seq = 1",
        "UPDATE audit_records SET archived_at = '2026-01-01T00:00:00.000000Z', "
        "archive_run_id = 'r' WHERE seq = 2",  # SYSTEM_* events are never archived
        "UPDATE payload_leaves SET value = '\"z\"' WHERE seq = 1 AND path = '[\"a\"]'",
        "UPDATE payload_leaves SET commitment = '" + "0" * 64 + "', salt = NULL, value = NULL "
        "WHERE seq = 1 AND path = '[\"a\"]'",
        "UPDATE payload_leaves SET salt = NULL, value = NULL WHERE seq = 2",  # SYSTEM_*
        "DELETE FROM payload_leaves WHERE seq = 2",
    ],
)
def test_v2_blocks_everything_else(two_records: Path, statement: str) -> None:
    conn = raw_connection(two_records)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(statement)
    finally:
        conn.close()


def test_archived_records_cannot_be_unarchived(two_records: Path) -> None:
    conn = raw_connection(two_records)
    try:
        conn.execute(
            "UPDATE audit_records SET archived_at = '2026-01-01T00:00:00.000000Z', "
            "archive_run_id = 'run_x' WHERE seq = 1"
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE audit_records SET archived_at = NULL, archive_run_id = NULL WHERE seq = 1"
            )
    finally:
        conn.close()


def test_migration_runs_inside_the_write_transaction(database: Database) -> None:
    with database.read_transaction() as conn:
        names = conn.execute(text("SELECT name FROM sqlite_master WHERE type = 'trigger'")).all()
    assert {row[0] for row in names} >= set(V2_TRIGGERS)
