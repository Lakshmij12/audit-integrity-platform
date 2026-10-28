"""Schema v1: objects, STRICT typing, CHECK/UNIQUE/FK constraints, triggers, startup checks."""

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from aip.crypto.hashing import GENESIS_HASH
from aip.storage import Database, DatabaseConfig, StorageIntegrityError, open_database
from aip.storage.schema import EXPECTED_OBJECTS, SCHEMA_VERSION, STRICT_TABLES
from tests.ingest.support import raw_connection


def _record(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "seq": 1,
        "event_id": "evt_" + "a" * 32,
        "event_type": "RECORD_UPDATED",
        "actor_id": "user",
        "resource_type": "ACCOUNT",
        "resource_id": "acct",
        "timestamp": "2026-10-28T12:00:00.000000Z",
        "recorded_at": "2026-10-28T12:00:00.000000Z",
        "payload_root": "b" * 64,
        "content_hash": "c" * 64,
        "prev_hash": GENESIS_HASH,
        "record_hash": "a" * 64,
        "hash_version": 1,
    }
    row.update(overrides)
    return row


def _insert_record(conn: sqlite3.Connection, **overrides: Any) -> None:
    row = _record(**overrides)
    columns = ", ".join(row)
    params = ", ".join(f":{name}" for name in row)
    conn.execute(f"INSERT INTO audit_records ({columns}) VALUES ({params})", row)  # noqa: S608


def _insert_leaf(conn: sqlite3.Connection, **overrides: Any) -> None:
    row: dict[str, Any] = {
        "seq": 1,
        "path": '["a"]',
        "commitment": "d" * 64,
        "salt": b"\x00" * 32,
        "value": '"x"',
    }
    row.update(overrides)
    conn.execute(
        "INSERT INTO payload_leaves (seq, path, commitment, salt, value) "
        "VALUES (:seq, :path, :commitment, :salt, :value)",
        row,
    )


def test_new_database_has_exactly_the_v1_objects(database: Database, db_path: Path) -> None:
    conn = raw_connection(db_path)
    try:
        objects = {
            (kind, name)
            for kind, name in conn.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        assert objects == set(EXPECTED_OBJECTS)
        version = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'")
        assert version.fetchone()[0] == str(SCHEMA_VERSION)
        strict = {row[1]: row[5] for row in conn.execute("PRAGMA table_list")}
        assert all(strict[name] == 1 for name in STRICT_TABLES)
    finally:
        conn.close()


def test_connection_pragmas(database: Database) -> None:
    with database.read_transaction() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        assert conn.execute(text("PRAGMA journal_mode")).scalar_one() == "wal"
        assert conn.execute(text("PRAGMA synchronous")).scalar_one() == 2  # FULL
        assert conn.execute(text("PRAGMA secure_delete")).scalar_one() == 1
        assert conn.execute(text("PRAGMA busy_timeout")).scalar_one() == 2000


@pytest.mark.parametrize("timeout", [-1, True, 1.5])
def test_database_config_rejects_invalid_busy_timeout(db_path: Path, timeout: object) -> None:
    with pytest.raises(ValueError, match="busy_timeout_ms"):
        DatabaseConfig(db_path, busy_timeout_ms=timeout)  # type: ignore[arg-type]


def test_reopen_existing_database(database: Database, db_path: Path) -> None:
    again = open_database(DatabaseConfig(db_path))
    again.close()


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'",
        "DROP TRIGGER audit_records_no_update",
        "DROP TRIGGER payload_leaves_no_delete",
        "DROP INDEX ix_records_actor",
        "CREATE TABLE extra (x INTEGER)",
    ],
)
def test_reopen_fails_closed_on_unexpected_schema(
    database: Database, db_path: Path, tamper: str
) -> None:
    database.close()
    conn = raw_connection(db_path)
    conn.execute(tamper)
    conn.close()
    with pytest.raises(StorageIntegrityError):
        open_database(DatabaseConfig(db_path))


def test_strict_tables_reject_wrong_types(database: Database, db_path: Path) -> None:
    conn = raw_connection(db_path)
    try:
        # STRICT still applies lossless conversions (e.g. text "1" -> 1), so use values that
        # cannot be converted to the declared column type.
        with pytest.raises(sqlite3.IntegrityError):
            _insert_record(conn, seq="abc")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_record(conn, hash_version=b"\x01")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_record(conn, actor_id=b"bytes-in-a-text-column")
    finally:
        conn.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"seq": 0},
        {"event_id": "evt_short"},
        {"event_id": "uid_" + "a" * 32},
        {"event_type": ""},
        {"actor_id": "x" * 257},
        {"timestamp": "2026-10-28T12:00:00Z"},
        {"record_hash": "A" * 64},
        {"content_hash": "g" * 64},
        {"payload_root": "b" * 63},
        {"hash_version": 2},
        {"prev_hash": "1" * 64},  # seq 1 must link to the genesis value
        {"archived_at": "2026-10-28T12:00:00.000000Z"},  # without archive_run_id
    ],
)
def test_check_constraints(database: Database, db_path: Path, overrides: dict[str, Any]) -> None:
    conn = raw_connection(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_record(conn, **overrides)
    finally:
        conn.close()


def test_non_genesis_record_cannot_use_genesis_prev_hash(database: Database, db_path: Path) -> None:
    conn = raw_connection(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_record(conn, seq=2)
    finally:
        conn.close()


def test_unique_constraints_reject_forks(database: Database, db_path: Path) -> None:
    conn = raw_connection(db_path)
    try:
        _insert_record(conn)
        _insert_record(
            conn, seq=2, event_id="evt_" + "e" * 32, record_hash="e" * 64, prev_hash="a" * 64
        )
        with pytest.raises(sqlite3.IntegrityError):  # same prev_hash as seq 2: a fork
            _insert_record(
                conn, seq=3, event_id="evt_" + "f" * 32, record_hash="f" * 64, prev_hash="a" * 64
            )
        with pytest.raises(sqlite3.IntegrityError):  # duplicate record_hash / event_id
            _insert_record(conn, seq=3, prev_hash="e" * 64)
    finally:
        conn.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"seq": 99},  # no such record (foreign key)
        {"salt": None},  # salt NULL but value present
        {"value": None},  # value NULL but salt present
        {"salt": b"\x00" * 31},
        {"commitment": "D" * 64},
        {"salt": "not-bytes"},
    ],
)
def test_leaf_constraints(database: Database, db_path: Path, overrides: dict[str, Any]) -> None:
    conn = raw_connection(db_path)
    try:
        _insert_record(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_leaf(conn, **overrides)
    finally:
        conn.close()


def test_redacted_leaf_shape_is_allowed_by_constraints(database: Database, db_path: Path) -> None:
    conn = raw_connection(db_path)
    try:
        _insert_record(conn)
        _insert_leaf(conn, salt=None, value=None)
    finally:
        conn.close()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_records SET actor_id = 'someone-else'",
        "DELETE FROM audit_records",
        "UPDATE payload_leaves SET value = '\"y\"'",
        "DELETE FROM payload_leaves",
    ],
)
def test_guard_triggers_block_update_and_delete(
    database: Database, db_path: Path, statement: str
) -> None:
    conn = raw_connection(db_path)
    try:
        _insert_record(conn)
        _insert_leaf(conn)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(statement)
    finally:
        conn.close()
