"""BEGIN IMMEDIATE locking, contention, rollback, commit-time failure and error classification."""

import sqlite3
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, event, text

import aip.storage.database as database_module
from aip.crypto.commitments import Leaf
from aip.ingest import IngestService, IngestValidationError
from aip.storage import (
    Database,
    DatabaseConfig,
    StorageCommitUnknownError,
    StorageError,
    StorageIntegrityError,
    StoreBusyError,
    open_database,
    repository,
)
from aip.storage.errors import classify
from tests.ingest.support import FakeClock, count_rows, make_event, raw_connection


def test_write_transaction_holds_the_write_lock(database: Database, db_path: Path) -> None:
    with database.write_transaction():
        other = raw_connection(db_path, timeout=0.2)
        try:
            with pytest.raises(sqlite3.OperationalError) as caught:
                other.execute("BEGIN IMMEDIATE")
            assert caught.value.sqlite_errorname == "SQLITE_BUSY"
            # WAL: readers are not blocked by the writer
            assert other.execute("SELECT count(*) FROM audit_records").fetchone()[0] == 0
        finally:
            other.close()


def test_read_transaction_does_not_block_writers(database: Database, db_path: Path) -> None:
    with database.read_transaction() as conn:
        conn.execute(text("SELECT count(*) FROM audit_records")).scalar_one()
        other = raw_connection(db_path, timeout=0.2)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("ROLLBACK")
        finally:
            other.close()


def test_lock_contention_raises_store_busy_and_writes_nothing(db_path: Path) -> None:
    database = open_database(DatabaseConfig(db_path, busy_timeout_ms=200))
    try:
        service = IngestService(database, clock=FakeClock())
        holder = raw_connection(db_path, timeout=0.2)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(StoreBusyError, match="nothing was written"):
                service.append(make_event())
        finally:
            holder.execute("ROLLBACK")
            holder.close()
        assert count_rows(db_path) == (0, 0)
        assert service.append(make_event()).seq == 1
    finally:
        database.close()


def test_failure_after_partial_insert_rolls_back_everything(
    service: IngestService, db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(conn: Connection, seq: int, leaves: Any) -> None:
        raise RuntimeError("simulated failure after the record row was inserted")

    monkeypatch.setattr(repository, "_insert_leaves", broken)
    with pytest.raises(RuntimeError, match="simulated"):
        service.append(make_event())
    assert count_rows(db_path) == (0, 0)
    monkeypatch.undo()
    assert service.append(make_event()).seq == 1


def test_database_error_after_partial_insert_rolls_back(
    service: IngestService, db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = repository._insert_leaves

    def bad_commitment(conn: Connection, seq: int, leaves: Any) -> None:
        original(conn, seq, leaves)
        conn.execute(
            text("INSERT INTO payload_leaves (seq, path, commitment) VALUES (:s, '[\"z\"]', 'X')"),
            {"s": seq},
        )

    monkeypatch.setattr(repository, "_insert_leaves", bad_commitment)
    with pytest.raises(StorageIntegrityError, match="transaction"):
        service.append(make_event())
    assert count_rows(db_path) == (0, 0)


def test_commit_time_failure_is_reported_and_rolled_back(
    service: IngestService, db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real failure raised by SQLite at COMMIT: a deferred foreign-key violation."""
    original = repository.insert_record

    def insert_then_orphan(conn: Connection, record: Any, leaves: Any) -> None:
        original(conn, record, leaves)
        conn.execute(text("PRAGMA defer_foreign_keys = ON"))
        conn.execute(
            text(
                "INSERT INTO payload_leaves (seq, path, commitment, salt, value) "
                "VALUES (999999, '[\"orphan\"]', :c, :s, '\"secret-value\"')"
            ),
            {"c": "d" * 64, "s": b"\x00" * 32},
        )

    monkeypatch.setattr(repository, "insert_record", insert_then_orphan)
    secret = "SSN-" + "900123456"  # built at runtime so it is not in any traceback source line
    event_input = make_event(payload={"ssn": secret})
    with pytest.raises(StorageIntegrityError, match="COMMIT") as caught:
        service.append(event_input)
    assert count_rows(db_path) == (0, 0)
    # hide_parameters: no SQL parameters (payload values) anywhere in the exception chain
    chain: list[BaseException] = []
    current: BaseException | None = caught.value
    while current is not None:
        chain.append(current)
        current = current.__cause__ or current.__context__
    assert len(chain) >= 2
    assert all(secret not in str(e) and secret not in repr(e) for e in chain)
    assert secret not in "".join(traceback.format_exception(caught.value))
    monkeypatch.undo()
    assert service.append(make_event()).seq == 1


def test_non_database_errors_pass_through_after_rollback(
    service: IngestService, clock: FakeClock, db_path: Path
) -> None:
    far_future = "2030-01-01T00:00:00Z"
    with pytest.raises(IngestValidationError):
        service.append(make_event(timestamp=far_future))
    assert count_rows(db_path) == (0, 0)


class _FakeSqliteError(sqlite3.OperationalError):
    pass


def _db_error(code: int | None, cls: type[sqlite3.Error] = _FakeSqliteError) -> sqlite3.Error:
    exc = cls("message that must not be copied")
    if code is not None:
        exc.sqlite_errorcode = code
        exc.sqlite_errorname = f"CODE_{code}"
    return exc


@pytest.mark.parametrize(
    ("during", "exc", "expected"),
    [
        ("transaction", _db_error(5), StoreBusyError),  # SQLITE_BUSY
        ("transaction", _db_error(517), StoreBusyError),  # SQLITE_BUSY_SNAPSHOT (extended)
        ("transaction", _db_error(6), StoreBusyError),  # SQLITE_LOCKED
        ("transaction", _db_error(262), StoreBusyError),  # SQLITE_LOCKED_SHAREDCACHE
        ("transaction", _db_error(19, sqlite3.IntegrityError), StorageIntegrityError),
        ("transaction", _db_error(None, sqlite3.IntegrityError), StorageIntegrityError),
        ("transaction", _db_error(10), StorageError),  # SQLITE_IOERR before COMMIT
        ("BEGIN IMMEDIATE", _db_error(13), StorageError),  # SQLITE_FULL before COMMIT
        ("transaction", _db_error(None), StorageError),
        # At COMMIT: busy and constraint failures leave SQLite's transaction open (rolled back);
        # anything else means the persistence outcome is unknown.
        ("COMMIT", _db_error(5), StoreBusyError),
        ("COMMIT", _db_error(6), StoreBusyError),
        ("COMMIT", _db_error(19, sqlite3.IntegrityError), StorageIntegrityError),
        ("COMMIT", _db_error(10), StorageCommitUnknownError),  # SQLITE_IOERR
        ("COMMIT", _db_error(266), StorageCommitUnknownError),  # SQLITE_IOERR_READ (extended)
        ("COMMIT", _db_error(13), StorageCommitUnknownError),  # SQLITE_FULL
        ("COMMIT", _db_error(7), StorageCommitUnknownError),  # SQLITE_NOMEM
        ("COMMIT", _db_error(None), StorageCommitUnknownError),
    ],
)
def test_classify(during: str, exc: sqlite3.Error, expected: type[StorageError]) -> None:
    result = classify(exc, during=during)
    assert type(result) is expected
    assert "must not be copied" not in str(result)
    if expected is StorageCommitUnknownError:
        assert "unknown" in str(result)
        assert "check whether it exists before retrying" in str(result)
    else:
        assert "may or may not" not in str(result)


def _failing_commit(code: int) -> Callable[[Any], None]:
    """Replacement for the dialect's do_commit that fails the way SQLite would."""

    def do_commit(dbapi_connection: Any) -> None:
        raise _db_error(code)

    return do_commit


def _record_invalidations(database: Database) -> list[object]:
    invalidated: list[object] = []

    def listener(dbapi_connection: Any, _record: Any, _exc: Any) -> None:
        invalidated.append(dbapi_connection)

    event.listen(database._engine, "invalidate", listener)
    return invalidated


def _write_lock_free(db_path: Path) -> bool:
    probe = raw_connection(db_path, timeout=0.2)
    try:
        probe.execute("BEGIN IMMEDIATE")
        probe.execute("ROLLBACK")
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        probe.close()


def _assert_not_in_chain(exc: BaseException, sensitive: str) -> None:
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None:
        chain.append(current)
        current = current.__cause__ or current.__context__
    assert len(chain) >= 2
    assert all(sensitive not in str(e) and sensitive not in repr(e) for e in chain)


@pytest.mark.parametrize(
    ("code", "expected", "message"),
    [
        (10, StorageCommitUnknownError, "check whether it exists before retrying"),  # IOERR
        (13, StorageCommitUnknownError, "outcome is unknown"),  # FULL
        (5, StoreBusyError, "nothing was written"),  # BUSY at COMMIT
    ],
)
def test_commit_failure_classification_and_cleanup(
    service: IngestService,
    database: Database,
    db_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    expected: type[StorageError],
    message: str,
) -> None:
    invalidated = _record_invalidations(database)
    monkeypatch.setattr(database._engine.dialect, "do_commit", _failing_commit(code))
    sensitive = "SSN-" + "900123456"
    event_input = make_event(payload={"ssn": sensitive})
    with pytest.raises(expected, match=message) as caught:
        service.append(event_input)
    assert type(caught.value) is expected
    _assert_not_in_chain(caught.value, sensitive)
    assert len(invalidated) == 1  # the connection was discarded, not returned to the pool
    assert _write_lock_free(db_path)
    monkeypatch.undo()
    assert service.append(make_event()).seq == 1  # the simulated COMMIT never reached SQLite


class _FailingDriver:
    """Stands in for the sqlite3 connection: still in a transaction, and ROLLBACK raises."""

    in_transaction = True

    def execute(self, sql: str) -> None:
        raise sqlite3.OperationalError("simulated ROLLBACK failure")


@pytest.mark.parametrize(
    ("code", "expected"), [(10, StorageCommitUnknownError), (5, StoreBusyError)]
)
def test_rollback_failure_after_failed_commit_still_discards_the_connection(
    service: IngestService,
    database: Database,
    db_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    expected: type[StorageError],
) -> None:
    invalidated = _record_invalidations(database)
    monkeypatch.setattr(database._engine.dialect, "do_commit", _failing_commit(code))
    monkeypatch.setattr(database_module, "_driver_connection", lambda conn: _FailingDriver())
    with pytest.raises(StorageError) as caught:
        service.append(make_event())
    assert type(caught.value) is expected  # the COMMIT classification is preserved
    assert "ROLLBACK" not in str(caught.value)
    assert len(invalidated) == 1  # invalidated even though the rollback raised
    monkeypatch.undo()
    assert _write_lock_free(db_path)  # closing the invalidated connection released SQLite's lock
    assert service.append(make_event()).seq == 1


def test_append_requires_event_input(service: IngestService) -> None:
    with pytest.raises(TypeError):
        service.append({"eventType": "X"})  # type: ignore[arg-type]


def test_insert_record_rejects_mismatched_event_id(database: Database) -> None:
    record = repository.StoredRecord(
        seq=1,
        event_id="evt_" + "0" * 32,
        event_type="E",
        actor_id="a",
        resource_type="r",
        resource_id="i",
        timestamp="2026-10-28T12:00:00.000000Z",
        recorded_at="2026-10-28T12:00:00.000000Z",
        payload_root="b" * 64,
        content_hash="c" * 64,
        prev_hash="0" * 64,
        record_hash="a" * 64,
        hash_version=1,
    )
    leaves: list[Leaf] = []

    def attempt() -> None:
        with database.write_transaction() as conn:
            repository.insert_record(conn, record, leaves)

    with pytest.raises(StorageIntegrityError, match="eventId"):
        attempt()
