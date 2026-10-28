"""SQLite schema: explicit DDL, STRICT tables, guard triggers, and the v1 -> v2 migration.

Version 1 (``DDL``, unchanged) blocks every UPDATE and DELETE. Version 2 (``V2_TRIGGERS``) keeps the
trigger names but narrows three of them so that exactly two mutations become possible:

* redaction: a leaf UPDATE that removes value and salt and changes nothing else (commitment, path
  and seq kept), only for a non-archived, non-``SYSTEM_*`` record;
* archival: a record UPDATE that only sets ``archived_at``/``archive_run_id`` on a non-archived,
  non-``SYSTEM_*`` record, then a DELETE of that record's leaves.

Records can never be deleted. The triggers catch application bugs only (anyone with file access can
drop them); tamper detection relies on the hash chain and on signed authorizations (verify/).
Every database is created as v1 and migrated to v2 inside the same ``BEGIN IMMEDIATE`` transaction,
so new and upgraded files take the same path and a failed migration leaves v1 untouched.
"""

from typing import Final

from sqlalchemy import Connection, text

from aip.crypto.hashing import GENESIS_HASH, HASH_VERSION
from aip.storage.errors import StorageIntegrityError

SCHEMA_VERSION: Final = 2
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

_SAME = " AND ".join(
    f"NEW.{c} IS OLD.{c}"
    for c in (
        "seq", "event_id", "event_type", "actor_id", "resource_type", "resource_id", "timestamp",
        "recorded_at", "payload_root", "content_hash", "prev_hash", "record_hash", "hash_version",
    )
)  # fmt: skip

V2_TRIGGERS: Final[dict[str, str]] = {
    "audit_records_no_update": f"""CREATE TRIGGER audit_records_no_update
       BEFORE UPDATE ON audit_records
       WHEN NOT (OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL
                 AND NEW.archive_run_id IS NOT NULL AND OLD.event_type NOT GLOB 'SYSTEM_*'
                 AND {_SAME})
       BEGIN SELECT RAISE(ABORT, 'audit_records is append-only (archive marking only)'); END""",
    "payload_leaves_no_update": """CREATE TRIGGER payload_leaves_no_update
       BEFORE UPDATE ON payload_leaves
       WHEN NOT (OLD.salt IS NOT NULL AND NEW.salt IS NULL AND NEW.value IS NULL
                 AND NEW.seq IS OLD.seq AND NEW.path IS OLD.path
                 AND NEW.commitment IS OLD.commitment
                 AND EXISTS (SELECT 1 FROM audit_records r WHERE r.seq = OLD.seq
                             AND r.archived_at IS NULL AND r.event_type NOT GLOB 'SYSTEM_*'))
       BEGIN SELECT RAISE(ABORT, 'payload_leaves is append-only (redaction only)'); END""",
    "payload_leaves_no_delete": """CREATE TRIGGER payload_leaves_no_delete
       BEFORE DELETE ON payload_leaves
       WHEN NOT EXISTS (SELECT 1 FROM audit_records r WHERE r.seq = OLD.seq
                        AND r.archived_at IS NOT NULL)
       BEGIN SELECT RAISE(ABORT, 'payload_leaves is append-only (archived records only)'); END""",
}

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
    """Create schema v1 in an empty database and migrate it to v2, migrate an existing v1 file,
    or check an existing v2 file. Call inside a write transaction: concurrent openers are
    serialized and a failed migration rolls back completely."""
    present = _user_objects(conn)
    if not present:
        for statement in DDL:
            conn.execute(text(statement))
        conn.execute(
            text("INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')"),
        )
    if _version(conn) == "1":
        _check_objects(conn)
        migrate_v1_to_v2(conn)
    check_schema(conn)


def migrate_v1_to_v2(conn: Connection) -> None:
    """Replace the three v1 guard triggers by their narrowly scoped v2 versions."""
    for name, statement in V2_TRIGGERS.items():
        conn.execute(text(f"DROP TRIGGER {name}"))
        conn.execute(text(statement))
    conn.execute(text("UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'"))


def _version(conn: Connection) -> object:
    return conn.execute(
        text("SELECT value FROM schema_meta WHERE key = 'schema_version'")
    ).scalar_one_or_none()


def _check_objects(conn: Connection) -> None:
    present = _user_objects(conn)
    missing = EXPECTED_OBJECTS - present
    unexpected = present - EXPECTED_OBJECTS
    if missing or unexpected:
        raise StorageIntegrityError(
            f"unexpected schema: missing {sorted(missing)}, unexpected {sorted(unexpected)}"
        )


def _normalized(sql: object) -> str:
    return " ".join(str(sql).split())


def check_schema(conn: Connection) -> None:
    """Fail closed unless the database holds exactly schema v2: its objects, STRICT tables and the
    v2 trigger definitions (a v1 trigger under a v2 version number is rejected)."""
    _check_objects(conn)
    version = _version(conn)
    if version != str(SCHEMA_VERSION):
        raise StorageIntegrityError(f"schema_version is {version!r}, expected {SCHEMA_VERSION}")
    rows = conn.execute(text("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'")).all()
    stored: dict[object, object] = {row[0]: row[1] for row in rows}
    changed = sorted(
        name
        for name, sql in V2_TRIGGERS.items()
        if _normalized(stored.get(name)) != _normalized(sql)
    )
    if changed:
        raise StorageIntegrityError(f"guard triggers differ from schema v2: {changed}")
    strict = {str(row[1]): int(row[5]) for row in conn.execute(text("PRAGMA table_list")).all()}
    not_strict = [name for name in STRICT_TABLES if strict.get(name) != 1]
    if not_strict:
        raise StorageIntegrityError(f"tables are not STRICT: {not_strict}")
