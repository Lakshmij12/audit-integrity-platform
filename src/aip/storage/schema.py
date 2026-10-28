"""SQLite schema v1: explicit DDL, STRICT tables, append-only guard triggers.

The guard triggers block every UPDATE and DELETE. They catch application bugs only (anyone with
file access can drop them); tamper detection relies on the hash chain. Redaction and retention will
need narrowly scoped changes to these triggers, introduced by a controlled schema migration
(schema_version 2), not by editing this version.
"""

from typing import Final

from sqlalchemy import Connection, text

from aip.crypto.hashing import GENESIS_HASH, HASH_VERSION
from aip.storage.errors import StorageIntegrityError

SCHEMA_VERSION: Final = 1
MIN_SQLITE_VERSION: Final = (3, 37, 0)  # STRICT tables

_HEX64 = "length({c}) = 64 AND {c} NOT GLOB '*[^0-9a-f]*'"

DDL: Final[tuple[str, ...]] = (
    """CREATE TABLE schema_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) STRICT""",
    f"""CREATE TABLE audit_records (
        seq            INTEGER PRIMARY KEY CHECK (seq >= 1),
        event_id       TEXT NOT NULL UNIQUE CHECK (length(event_id) = 36 AND event_id GLOB 'evt_*'),
        event_type     TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
        actor_id       TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
        resource_type  TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 128),
        resource_id    TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 256),
        timestamp      TEXT NOT NULL CHECK (length(timestamp) = 27),
        recorded_at    TEXT NOT NULL CHECK (length(recorded_at) = 27),
        payload_root   TEXT NOT NULL CHECK ({_HEX64.format(c="payload_root")}),
        content_hash   TEXT NOT NULL CHECK ({_HEX64.format(c="content_hash")}),
        prev_hash      TEXT NOT NULL UNIQUE CHECK ({_HEX64.format(c="prev_hash")}),
        record_hash    TEXT NOT NULL UNIQUE CHECK ({_HEX64.format(c="record_hash")}),
        hash_version   INTEGER NOT NULL CHECK (hash_version = {HASH_VERSION}),
        archived_at    TEXT,
        archive_run_id TEXT,
        CHECK ((seq = 1) = (prev_hash = '{GENESIS_HASH}')),
        CHECK ((archived_at IS NULL) = (archive_run_id IS NULL))
    ) STRICT""",
    f"""CREATE TABLE payload_leaves (
        seq        INTEGER NOT NULL REFERENCES audit_records(seq),
        path       TEXT NOT NULL,
        commitment TEXT NOT NULL CHECK ({_HEX64.format(c="commitment")}),
        salt       BLOB CHECK (salt IS NULL OR length(salt) = 32),
        value      TEXT,
        CHECK ((salt IS NULL) = (value IS NULL)),
        PRIMARY KEY (seq, path)
    ) STRICT, WITHOUT ROWID""",
    "CREATE INDEX ix_records_actor ON audit_records (actor_id, seq)",
    "CREATE INDEX ix_records_resource ON audit_records (resource_type, resource_id, seq)",
    "CREATE INDEX ix_records_type ON audit_records (event_type, seq)",
    "CREATE INDEX ix_records_time ON audit_records (timestamp, seq)",
    """CREATE TRIGGER audit_records_no_update BEFORE UPDATE ON audit_records
       BEGIN SELECT RAISE(ABORT, 'audit_records is append-only'); END""",
    """CREATE TRIGGER audit_records_no_delete BEFORE DELETE ON audit_records
       BEGIN SELECT RAISE(ABORT, 'audit_records is append-only'); END""",
    """CREATE TRIGGER payload_leaves_no_update BEFORE UPDATE ON payload_leaves
       BEGIN SELECT RAISE(ABORT, 'payload_leaves is append-only'); END""",
    """CREATE TRIGGER payload_leaves_no_delete BEFORE DELETE ON payload_leaves
       BEGIN SELECT RAISE(ABORT, 'payload_leaves is append-only'); END""",
)

EXPECTED_OBJECTS: Final = frozenset(
    {
        ("table", "schema_meta"),
        ("table", "audit_records"),
        ("table", "payload_leaves"),
        ("index", "ix_records_actor"),
        ("index", "ix_records_resource"),
        ("index", "ix_records_type"),
        ("index", "ix_records_time"),
        ("trigger", "audit_records_no_update"),
        ("trigger", "audit_records_no_delete"),
        ("trigger", "payload_leaves_no_update"),
        ("trigger", "payload_leaves_no_delete"),
    }
)
STRICT_TABLES: Final = ("schema_meta", "audit_records", "payload_leaves")


def _user_objects(conn: Connection) -> set[tuple[str, str]]:
    rows = conn.execute(
        text("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
    ).all()
    return {(str(kind), str(name)) for kind, name in rows}


def ensure_schema(conn: Connection) -> None:
    """Create schema v1 in an empty database, or check an existing one. Call inside a write
    transaction so concurrent first-time openers are serialized."""
    present = _user_objects(conn)
    if not present:
        for statement in DDL:
            conn.execute(text(statement))
        conn.execute(
            text("INSERT INTO schema_meta (key, value) VALUES ('schema_version', :v)"),
            {"v": str(SCHEMA_VERSION)},
        )
        return
    check_schema(conn)


def check_schema(conn: Connection) -> None:
    """Fail closed unless the database holds exactly schema v1, its STRICT tables and triggers."""
    present = _user_objects(conn)
    missing = EXPECTED_OBJECTS - present
    unexpected = present - EXPECTED_OBJECTS
    if missing or unexpected:
        raise StorageIntegrityError(
            f"unexpected schema: missing {sorted(missing)}, unexpected {sorted(unexpected)}"
        )
    version = conn.execute(
        text("SELECT value FROM schema_meta WHERE key = 'schema_version'")
    ).scalar_one_or_none()
    if version != str(SCHEMA_VERSION):
        raise StorageIntegrityError(f"schema_version is {version!r}, expected {SCHEMA_VERSION}")
    strict = {str(row[1]): int(row[5]) for row in conn.execute(text("PRAGMA table_list")).all()}
    not_strict = [name for name in STRICT_TABLES if strict.get(name) != 1]
    if not_strict:
        raise StorageIntegrityError(f"tables are not STRICT: {not_strict}")
