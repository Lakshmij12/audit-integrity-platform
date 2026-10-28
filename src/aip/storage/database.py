"""SQLite engine, connection settings and explicit transactions.

pysqlite's implicit transaction handling is disabled on every connection
(``isolation_level = None``) and each transaction is opened explicitly by the ``begin`` event:

* ``write_transaction()`` issues ``BEGIN IMMEDIATE``, taking SQLite's single write lock *before* any
  read, so two writers can never read the same chain head;
* ``read_transaction()`` issues ``BEGIN DEFERRED`` for a consistent read snapshot (WAL mode lets
  readers proceed while a writer holds the lock).

A write is reported successful only when COMMIT returns. Any exception before or during COMMIT is
followed by a ROLLBACK attempt and raised as a StorageError (or re-raised unchanged if it is not a
database error, e.g. input validation).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, create_engine, event
from sqlalchemy.exc import DBAPIError

from aip.storage.errors import COMMIT, StorageError, classify
from aip.storage.schema import MIN_SQLITE_VERSION, ensure_schema

_BEGIN_OPTION = "aip_begin"


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    path: Path
    busy_timeout_ms: int = 5000

    def __post_init__(self) -> None:
        if type(self.busy_timeout_ms) is not int or self.busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a non-negative int")


class Database:
    """One SQLite database file. Thread-safe: each transaction uses its own pooled connection."""

    def __init__(self, config: DatabaseConfig) -> None:
        if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
            raise StorageError(
                f"SQLite {sqlite3.sqlite_version} is too old; STRICT tables need 3.37 or later"
            )
        self.config = config
        self._engine: Engine = create_engine(
            f"sqlite:///{config.path}",
            connect_args={"check_same_thread": False, "timeout": config.busy_timeout_ms / 1000},
            hide_parameters=True,  # keep SQL parameters (payload values) out of error messages
        )
        event.listen(self._engine, "connect", self._on_connect)
        event.listen(self._engine, "begin", _on_begin)

    def _on_connect(self, dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None  # no implicit BEGIN/COMMIT from pysqlite
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute(f"PRAGMA busy_timeout = {self.config.busy_timeout_ms:d}")
            cursor.execute("PRAGMA secure_delete = ON")
            cursor.execute("PRAGMA synchronous = FULL")
            mode = cursor.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise StorageError(f"could not enable WAL journal mode (got {mode!r})")
        finally:
            cursor.close()

    @contextmanager
    def write_transaction(self) -> Iterator[Connection]:
        """BEGIN IMMEDIATE ... COMMIT. Rolls back on any exception; success = COMMIT returned."""
        with self._transaction("IMMEDIATE") as conn:
            yield conn

    @contextmanager
    def read_transaction(self) -> Iterator[Connection]:
        """BEGIN DEFERRED ... COMMIT: a consistent read snapshot."""
        with self._transaction("DEFERRED") as conn:
            yield conn

    @contextmanager
    def _transaction(self, mode: str) -> Iterator[Connection]:
        try:
            conn = self._engine.connect()
        except DBAPIError as exc:
            raise classify(exc, during="connect") from exc
        try:
            conn.execution_options(**{_BEGIN_OPTION: mode})
            try:
                trans = conn.begin()
            except DBAPIError as exc:
                raise classify(exc, during=f"BEGIN {mode}") from exc
            try:
                yield conn
            except BaseException as exc:
                _rollback_quietly(trans)
                if isinstance(exc, DBAPIError):
                    raise classify(exc, during="transaction") from exc
                raise
            try:
                trans.commit()
            except DBAPIError as exc:
                # SQLite can leave the transaction open after a failed COMMIT (e.g. a deferred
                # constraint or SQLITE_BUSY) while SQLAlchemy already treats it as finished.
                _discard_after_failed_commit(conn)
                raise classify(exc, during=COMMIT) from exc
        finally:
            conn.close()

    def open(self) -> Database:
        """Create schema v1 in a new file or check an existing one (fails closed on mismatch)."""
        with self.write_transaction() as conn:
            ensure_schema(conn)
        return self

    def close(self) -> None:
        self._engine.dispose()


def _on_begin(conn: Connection) -> None:
    mode = conn.get_execution_options().get(_BEGIN_OPTION, "DEFERRED")
    if mode not in ("IMMEDIATE", "DEFERRED"):
        raise StorageError(f"unsupported transaction mode {mode!r}")
    conn.exec_driver_sql(f"BEGIN {mode}")


def _rollback_quietly(trans: Any) -> None:
    try:
        if trans.is_active:
            trans.rollback()
    except Exception:  # noqa: S110 - the original error is the one to report
        pass


def _driver_connection(conn: Connection) -> Any:
    """The underlying sqlite3 connection (separate function so tests can simulate its failures)."""
    return conn.connection.dbapi_connection


def _discard_after_failed_commit(conn: Connection) -> None:
    """Roll back any transaction SQLite still holds, then invalidate the connection so it is never
    returned to the pool in an unknown state. Runs even if the rollback itself raises."""
    try:
        raw = _driver_connection(conn)
        if raw is not None and getattr(raw, "in_transaction", False):
            raw.execute("ROLLBACK")
    except Exception:  # noqa: S110 - the COMMIT error is the one to report
        pass
    finally:
        conn.invalidate()


def open_database(config: DatabaseConfig) -> Database:
    """Open (and if new, initialize) the database file."""
    database = Database(config)
    try:
        return database.open()
    except BaseException:
        database.close()
        raise
