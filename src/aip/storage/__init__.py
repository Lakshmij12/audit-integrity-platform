"""SQLite persistence for the audit chain: schema v1, explicit transactions, row access."""

from aip.storage.database import Database, DatabaseConfig, open_database
from aip.storage.errors import (
    StorageCommitUnknownError,
    StorageError,
    StorageIntegrityError,
    StoreBusyError,
)
from aip.storage.repository import (
    ChainHead,
    StoredRecord,
    derive_event_id,
    insert_record,
    iter_chain_entries,
    load_leaves,
    read_head,
    read_record,
)
from aip.storage.schema import SCHEMA_VERSION

__all__ = [
    "SCHEMA_VERSION",
    "ChainHead",
    "Database",
    "DatabaseConfig",
    "StorageCommitUnknownError",
    "StorageError",
    "StorageIntegrityError",
    "StoreBusyError",
    "StoredRecord",
    "derive_event_id",
    "insert_record",
    "iter_chain_entries",
    "load_leaves",
    "open_database",
    "read_head",
    "read_record",
]
