"""Append-only event ingestion.

Order of work for one append:

1. Outside any lock: enforce payload limits (depth, leaf count, string length, value types), then
   the canonical size limit, then generate salts and leaf commitments and the payload root.
2. Inside one ``BEGIN IMMEDIATE`` transaction: read the head, take one server clock reading,
   check the event timestamp against that real clock, assign seq / recordedAt / prevHash, compute
   contentHash and recordHash, insert the record and its leaves.
3. Report success only after COMMIT returns.

recordedAt is kept nondecreasing by clamping to the stored head's recordedAt. The clamp never
affects the future-timestamp check, which always uses the real clock reading, and an omitted
timestamp defaults to the real clock reading, not to the clamped recordedAt.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from sqlalchemy import Connection

from aip.crypto.canonical import canonical_json
from aip.crypto.commitments import Leaf, build_leaves, payload_root
from aip.crypto.hashing import GENESIS_HASH, HASH_VERSION, content_hash, record_hash
from aip.crypto.timestamps import format_timestamp, parse_timestamp
from aip.ingest.models import (
    EventInput,
    IngestLimits,
    IngestValidationError,
    Issue,
    check_payload_limits,
)
from aip.storage import repository
from aip.storage.database import Database
from aip.storage.repository import StoredRecord, derive_event_id

FUTURE_TOLERANCE: Final = timedelta(minutes=5)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AppendResult:
    seq: int
    event_id: str
    recorded_at: str
    timestamp: str
    content_hash: str
    record_hash: str


class IngestService:
    def __init__(
        self,
        database: Database,
        *,
        clock: Clock | None = None,
        limits: IngestLimits | None = None,
    ) -> None:
        self._database = database
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._limits = limits if limits is not None else IngestLimits()

    def append(self, event: EventInput) -> AppendResult:
        """Append one client event. Returns only after COMMIT succeeded."""
        if not isinstance(event, EventInput):
            raise TypeError("append() requires an EventInput")
        check_payload_limits(event.payload, self._limits)
        if len(canonical_json(event.payload)) > self._limits.max_payload_bytes:
            raise IngestValidationError([Issue("payload", "too_large")])
        leaves = build_leaves(event.payload)
        root = payload_root(leaves)

        with self._database.write_transaction() as conn:
            result = append_in_transaction(
                conn,
                self._clock,
                event_type=event.event_type,
                actor_id=event.actor_id,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                timestamp=event.timestamp,
                leaves=leaves,
                root=root,
            )
        # Reached only if COMMIT returned without error.
        return result


def append_in_transaction(
    conn: Connection,
    clock: Clock,
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    timestamp: str | None,
    leaves: Sequence[Leaf],
    root: str,
) -> AppendResult:
    """Append one record inside the caller's ``BEGIN IMMEDIATE`` transaction.

    Used by ``IngestService.append`` (client events, validated by ``EventInput``) and by the
    lifecycle service for ``SYSTEM_*`` events, so a mutation and the event authorizing it commit or
    roll back together. The caller has validated the envelope and built ``leaves``/``root`` (outside
    the lock where possible).
    """
    head = repository.read_head(conn)
    now = clock.now()
    now_text = format_timestamp(now)  # rejects naive or non-datetime clock output
    recorded_at = now_text if head is None else max(now_text, head.recorded_at)
    if timestamp is None:
        timestamp = now_text
    elif parse_timestamp(timestamp) > now + FUTURE_TOLERANCE:
        raise IngestValidationError([Issue("timestamp", "too_far_in_future")])
    seq = 1 if head is None else head.seq + 1
    prev_hash = GENESIS_HASH if head is None else head.record_hash
    content = content_hash(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=timestamp,
        payload_root=root,
    )
    digest = record_hash(
        seq=seq, recorded_at=recorded_at, prev_hash=prev_hash, content_hash=content
    )
    record = StoredRecord(
        seq=seq,
        event_id=derive_event_id(digest),
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=timestamp,
        recorded_at=recorded_at,
        payload_root=root,
        content_hash=content,
        prev_hash=prev_hash,
        record_hash=digest,
        hash_version=HASH_VERSION,
    )
    repository.insert_record(conn, record, leaves)
    return AppendResult(seq, record.event_id, recorded_at, timestamp, content, digest)
