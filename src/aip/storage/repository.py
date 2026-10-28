"""Row-level reads and writes for audit records and payload leaves (SQLAlchemy Core, explicit SQL).

All functions take a Connection that is already inside a transaction from ``Database``.
Leaf paths and values are stored as the canonical JSON text that the commitments cover; a JSON
``null`` value is stored as the text 'null', while SQL NULL (with a NULL salt) means redacted.
"""

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from sqlalchemy import Connection, text

from aip.crypto.canonical import canonical_json, parse_strict_json
from aip.crypto.chain import ChainEntry
from aip.crypto.commitments import Leaf
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import HASH_VERSION, is_hex_digest
from aip.crypto.timestamps import is_canonical_timestamp
from aip.storage.errors import StorageIntegrityError

EVENT_ID_PREFIX: Final = "evt_"
EVENT_ID_HEX_CHARS: Final = 32


def derive_event_id(record_hash: str) -> str:
    """Public identifier: "evt_" + the first 32 hex characters (128 bits) of recordHash.

    A truncated hash-derived identifier, not a UUID. The full recordHash is authoritative.
    """
    if not is_hex_digest(record_hash):
        raise StorageIntegrityError("recordHash must be 64 lowercase hex characters")
    return EVENT_ID_PREFIX + record_hash[:EVENT_ID_HEX_CHARS]


@dataclass(frozen=True, slots=True)
class ChainHead:
    seq: int
    record_hash: str
    recorded_at: str


@dataclass(frozen=True, slots=True)
class StoredRecord:
    seq: int
    event_id: str
    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    timestamp: str
    recorded_at: str
    payload_root: str
    content_hash: str
    prev_hash: str
    record_hash: str
    hash_version: int


_RECORD_COLUMNS = (
    "seq, event_id, event_type, actor_id, resource_type, resource_id, timestamp, recorded_at, "
    "payload_root, content_hash, prev_hash, record_hash, hash_version"
)
# S608: the only interpolated text is the constant column list above; all values are bound params.
_INSERT_RECORD = text(
    f"INSERT INTO audit_records ({_RECORD_COLUMNS}) VALUES (:seq, :event_id, :event_type, "  # noqa: S608
    ":actor_id, :resource_type, :resource_id, :timestamp, :recorded_at, :payload_root, "
    ":content_hash, :prev_hash, :record_hash, :hash_version)"
)
_SELECT_RECORD = text(
    f"SELECT {_RECORD_COLUMNS} FROM audit_records WHERE seq = :seq"  # noqa: S608 - constant columns
)
_INSERT_LEAF = text(
    "INSERT INTO payload_leaves (seq, path, commitment, salt, value) "
    "VALUES (:seq, :path, :commitment, :salt, :value)"
)


def read_head(conn: Connection) -> ChainHead | None:
    """The last record's chain fields, or None for an empty chain. Fails closed if malformed."""
    row = conn.execute(
        text("SELECT seq, record_hash, recorded_at FROM audit_records ORDER BY seq DESC LIMIT 1")
    ).first()
    if row is None:
        return None
    seq, record_hash, recorded_at = row
    if (
        type(seq) is not int
        or seq < 1
        or not is_hex_digest(record_hash)
        or not is_canonical_timestamp(recorded_at)
    ):
        raise StorageIntegrityError("the stored chain head is malformed; refusing to append")
    return ChainHead(seq, record_hash, recorded_at)


def insert_record(conn: Connection, record: StoredRecord, leaves: Sequence[Leaf]) -> None:
    """Insert one record and its leaves. Must run inside the same write transaction as read_head."""
    if record.event_id != derive_event_id(record.record_hash):
        raise StorageIntegrityError("eventId does not match recordHash")
    conn.execute(
        _INSERT_RECORD,
        {
            "seq": record.seq,
            "event_id": record.event_id,
            "event_type": record.event_type,
            "actor_id": record.actor_id,
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "timestamp": record.timestamp,
            "recorded_at": record.recorded_at,
            "payload_root": record.payload_root,
            "content_hash": record.content_hash,
            "prev_hash": record.prev_hash,
            "record_hash": record.record_hash,
            "hash_version": record.hash_version,
        },
    )
    _insert_leaves(conn, record.seq, leaves)


def _insert_leaves(conn: Connection, seq: int, leaves: Sequence[Leaf]) -> None:
    rows = [
        {
            "seq": seq,
            "path": canonical_json(list(leaf.path)).decode("utf-8"),
            "commitment": leaf.commitment,
            "salt": leaf.salt,
            "value": None if leaf.salt is None else canonical_json(leaf.value).decode("utf-8"),
        }
        for leaf in leaves
    ]
    if rows:
        conn.execute(_INSERT_LEAF, rows)


def _to_record(row: Sequence[object]) -> StoredRecord:
    values = tuple(row)
    if len(values) != 13:
        raise StorageIntegrityError("unexpected audit_records row shape")
    seq, hash_version = values[0], values[12]
    texts = [str(v) for v in values[1:12] if type(v) is str]
    if type(seq) is not int or type(hash_version) is not int or len(texts) != 11:
        raise StorageIntegrityError("stored record has malformed fields")
    record = StoredRecord(
        seq=seq,
        event_id=texts[0],
        event_type=texts[1],
        actor_id=texts[2],
        resource_type=texts[3],
        resource_id=texts[4],
        timestamp=texts[5],
        recorded_at=texts[6],
        payload_root=texts[7],
        content_hash=texts[8],
        prev_hash=texts[9],
        record_hash=texts[10],
        hash_version=hash_version,
    )
    if hash_version != HASH_VERSION:
        raise StorageIntegrityError(f"unsupported hash_version {hash_version}")
    if not is_hex_digest(record.record_hash) or record.event_id != derive_event_id(
        record.record_hash
    ):
        raise StorageIntegrityError("stored eventId does not match its recordHash")
    return record


def read_record(conn: Connection, seq: int) -> StoredRecord | None:
    """One stored record, validated (including the eventId derivation), or None if absent."""
    row = conn.execute(_SELECT_RECORD, {"seq": seq}).first()
    return None if row is None else _to_record(row)


@dataclass(frozen=True, slots=True)
class RecordFilter:
    """Equality filters and a half-open [from_ts, to_ts) range on the canonical event timestamp."""

    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    event_type: str | None = None
    from_ts: str | None = None
    to_ts: str | None = None


_FILTER_CLAUSES: Final = (
    ("actor_id", "actor_id = :actor_id"),
    ("resource_type", "resource_type = :resource_type"),
    ("resource_id", "resource_id = :resource_id"),
    ("event_type", "event_type = :event_type"),
    ("from_ts", "timestamp >= :from_ts"),
    ("to_ts", "timestamp < :to_ts"),
)


def query_records(
    conn: Connection, filters: RecordFilter, *, after_seq: int, limit: int
) -> list[StoredRecord]:
    """Records matching every given filter, in seq order, with seq > after_seq (keyset paging).

    Returns at most ``limit`` records. Only constant SQL fragments are combined; every value is a
    bound parameter.
    """
    if type(after_seq) is not int or after_seq < 0 or type(limit) is not int or limit < 1:
        raise ValueError("after_seq must be >= 0 and limit >= 1")
    clauses = ["seq > :after_seq"]
    params: dict[str, object] = {"after_seq": after_seq, "limit": limit}
    for name, clause in _FILTER_CLAUSES:
        value = getattr(filters, name)
        if value is not None:
            clauses.append(clause)
            params[name] = value
    sql = (
        f"SELECT {_RECORD_COLUMNS} FROM audit_records WHERE "  # noqa: S608 - constant fragments
        + " AND ".join(clauses)
        + " ORDER BY seq LIMIT :limit"
    )
    return [_to_record(row) for row in conn.execute(text(sql), params).all()]


def read_record_by_event_id(conn: Connection, event_id: str) -> StoredRecord | None:
    row = conn.execute(
        text(f"SELECT {_RECORD_COLUMNS} FROM audit_records WHERE event_id = :e"),  # noqa: S608
        {"e": event_id},
    ).first()
    return None if row is None else _to_record(row)


RAW_RECORD_COLUMNS: Final = (
    "seq, event_id, event_type, actor_id, resource_type, resource_id, timestamp, recorded_at, "
    "payload_root, content_hash, prev_hash, record_hash, hash_version, archived_at"
)


def iter_raw_records(conn: Connection, *, batch_size: int = 500) -> Iterator[tuple[object, ...]]:
    """Every audit_records row in seq order, exactly as stored and unvalidated (for verification).

    Columns are RAW_RECORD_COLUMNS. Rows are read in keyset batches so memory stays bounded.
    """
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("batch_size must be a positive int")
    query = text(
        f"SELECT {RAW_RECORD_COLUMNS} FROM audit_records "  # noqa: S608 - constant columns
        "WHERE seq > :last ORDER BY seq LIMIT :limit"
    )
    last = 0
    while True:
        rows = conn.execute(query, {"last": last, "limit": batch_size}).all()
        for row in rows:
            yield tuple(row)
        if len(rows) < batch_size:
            return
        last_seq = rows[-1][0]
        if type(last_seq) is not int:
            return  # STRICT typing makes this unreachable in practice; stop rather than loop
        last = last_seq


def load_raw_leaves(conn: Connection, seq: object) -> list[tuple[object, ...]]:
    """(path, commitment, salt, value) rows of one record, exactly as stored and unvalidated."""
    return [
        tuple(row)
        for row in conn.execute(
            text("SELECT path, commitment, salt, value FROM payload_leaves WHERE seq = :seq"),
            {"seq": seq},
        ).all()
    ]


def iter_chain_entries(conn: Connection, *, batch_size: int = 1000) -> Iterator[ChainEntry]:
    """Stream the chain fields of every record in seq order, unvalidated, for ``check_chain``."""
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("batch_size must be a positive int")
    last = 0
    query = text(
        "SELECT seq, recorded_at, prev_hash, content_hash, record_hash FROM audit_records "
        "WHERE seq > :last ORDER BY seq LIMIT :limit"
    )
    while True:
        rows = conn.execute(query, {"last": last, "limit": batch_size}).all()
        for seq, recorded_at, prev_hash, content, record in rows:
            yield ChainEntry(seq, recorded_at, prev_hash, content, record)
        if len(rows) < batch_size:
            return
        last = rows[-1][0]


def load_leaves(conn: Connection, seq: int) -> list[Leaf]:
    """The stored leaves of one record as ``Leaf`` objects. Fails closed on malformed rows."""
    rows = conn.execute(
        text("SELECT path, commitment, salt, value FROM payload_leaves WHERE seq = :seq"),
        {"seq": seq},
    ).all()
    leaves = []
    for path_text, commitment, salt, value_text in rows:
        try:
            path = parse_strict_json(path_text)
            if type(path) is not list:
                raise StorageIntegrityError("stored leaf path is not a JSON array")
            value = None if value_text is None else parse_strict_json(value_text)
            leaves.append(Leaf(tuple(path), commitment, salt, value))  # type: ignore[arg-type]
        except CryptoInputError as exc:
            raise StorageIntegrityError(f"stored leaf for seq {seq} is malformed") from exc
    return leaves
