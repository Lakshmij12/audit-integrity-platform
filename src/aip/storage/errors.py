"""Storage errors. Messages never include SQL parameters or stored values.

Outcome of a failed write, by error class:

* StoreBusyError, StorageIntegrityError, StorageError raised before COMMIT: the write was not
  committed (COMMIT was never reached, or SQLite rejected it and left the transaction open, and it
  was rolled back).
* StorageCommitUnknownError: COMMIT itself failed for another reason (for example SQLITE_IOERR or
  SQLITE_FULL). SQLite documents that after such errors a transaction "may or may not be rolled back
  automatically", so whether the write is durable is unknown; a rollback attempt afterwards does not
  prove it was never committed. Check whether the event exists before retrying.
"""

import sqlite3
from typing import Final

SQLITE_BUSY: Final = 5
SQLITE_LOCKED: Final = 6
SQLITE_CONSTRAINT: Final = 19
COMMIT: Final = "COMMIT"


class StorageError(RuntimeError):
    """A database operation failed. See the module docstring for what each subclass implies."""


class StoreBusyError(StorageError):
    """The database stayed locked (SQLITE_BUSY / SQLITE_LOCKED) past the busy timeout.

    Not committed: SQLite keeps the transaction open after a busy COMMIT, and it is rolled back.
    """


class StorageIntegrityError(StorageError):
    """A constraint or trigger rejected the write, or stored data / schema failed validation.

    Not committed: SQLite keeps the transaction open after a constraint failure at COMMIT, and it is
    rolled back.
    """


class StorageCommitUnknownError(StorageError):
    """COMMIT failed unexpectedly; whether the write was persisted cannot be guaranteed."""


def classify(exc: BaseException, *, during: str) -> StorageError:
    """Map a database exception to a StorageError without copying its message (it may hold SQL)."""
    orig = getattr(exc, "orig", exc)
    code = getattr(orig, "sqlite_errorcode", None)
    primary = code & 0xFF if type(code) is int else None
    name = getattr(orig, "sqlite_errorname", None) or type(orig).__name__
    if primary in (SQLITE_BUSY, SQLITE_LOCKED):
        return StoreBusyError(f"database busy during {during} ({name}); nothing was written")
    if isinstance(orig, sqlite3.IntegrityError) or primary == SQLITE_CONSTRAINT:
        return StorageIntegrityError(
            f"constraint or trigger rejected {during} ({name}); nothing was written"
        )
    if during == COMMIT:
        return StorageCommitUnknownError(
            f"COMMIT failed ({name}); the outcome is unknown and the event may or may not have "
            "been stored; check whether it exists before retrying"
        )
    return StorageError(f"unexpected database error during {during} ({name}); not committed")
