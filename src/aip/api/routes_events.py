"""Write and query endpoints: POST /audit/events, GET /audit/events, GET /audit/events/{eventId}."""

import re
from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import Connection
from starlette.concurrency import run_in_threadpool

from aip.api.auth import Principal, require_reader, require_writer
from aip.api.errors import PayloadTooLargeError
from aip.api.schemas import AppendResponse, EventPage, EventView
from aip.crypto import Leaf, normalize_timestamp, unflatten
from aip.crypto.errors import CryptoInputError
from aip.ingest import IngestService, IngestValidationError, Issue, parse_event_json
from aip.storage import Database, StoredRecord, load_leaves
from aip.storage.repository import RecordFilter, query_records, read_record_by_event_id

DEFAULT_LIMIT: Final = 50
MAX_LIMIT: Final = 200
_EVENT_ID = re.compile(r"evt_[0-9a-f]{32}", re.ASCII)
_CURSOR = re.compile(r"[1-9][0-9]{0,15}", re.ASCII)
_DISPLAY_SALT: Final = bytes(32)

router = APIRouter(prefix="/audit", tags=["events"])


async def _read_limited_body(request: Request, limit: int) -> bytes:
    """Read the body while counting bytes; stop as soon as it exceeds ``limit``."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise PayloadTooLargeError
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise PayloadTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "/events",
    status_code=status.HTTP_201_CREATED,
    response_model=AppendResponse,
    summary="Append an audit event",
)
async def append_event(
    request: Request,
    response: Response,
    _principal: Annotated[Principal, Depends(require_writer)],
) -> AppendResponse:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";")[0].strip().lower() != "application/json":
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "use application/json")
    body = await _read_limited_body(request, request.app.state.settings.max_body_bytes)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise IngestValidationError([Issue("body", "invalid_utf8")]) from None
    event = parse_event_json(text)
    service: IngestService = request.app.state.ingest
    result = await run_in_threadpool(service.append, event)
    response.headers["Location"] = f"/audit/events/{result.event_id}"
    return AppendResponse(
        seq=result.seq,
        event_id=result.event_id,
        recorded_at=result.recorded_at,
        timestamp=result.timestamp,
        content_hash=result.content_hash,
        record_hash=result.record_hash,
    )


def _view(conn: Connection, record: StoredRecord) -> EventView:
    leaves = load_leaves(conn, record.seq)
    redacted = [list(leaf.path) for leaf in leaves if leaf.is_redacted]
    # For display only: a redacted leaf is shown as null. The placeholder salt is never stored,
    # hashed or returned; the commitment shown in proofs is the original one.
    shown = [
        Leaf(leaf.path, leaf.commitment, _DISPLAY_SALT, None) if leaf.is_redacted else leaf
        for leaf in leaves
    ]
    return EventView(
        seq=record.seq,
        event_id=record.event_id,
        event_type=record.event_type,
        actor_id=record.actor_id,
        resource_type=record.resource_type,
        resource_id=record.resource_id,
        timestamp=record.timestamp,
        recorded_at=record.recorded_at,
        payload=unflatten(shown) if shown else {},  # no leaves: archived (payload in the archive)
        redacted_paths=redacted,
        archived=not leaves,
        payload_root=record.payload_root,
        content_hash=record.content_hash,
        prev_hash=record.prev_hash,
        record_hash=record.record_hash,
    )


def _normalize_bound(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    try:
        return normalize_timestamp(value)
    except CryptoInputError:
        raise IngestValidationError([Issue(field, "invalid_timestamp")]) from None


_Filter = Annotated[str | None, Query(min_length=1, max_length=256)]


@router.get("/events", response_model=EventPage, summary="Query audit events")
def list_events(
    request: Request,
    _principal: Annotated[Principal, Depends(require_reader)],
    actor_id: Annotated[_Filter, Query(alias="actorId")] = None,
    resource_type: Annotated[_Filter, Query(alias="resourceType")] = None,
    resource_id: Annotated[_Filter, Query(alias="resourceId")] = None,
    event_type: Annotated[_Filter, Query(alias="eventType")] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=64)] = None,
    to: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(max_length=16)] = None,
) -> EventPage:
    """Filters are combined with AND; ``from`` is inclusive and ``to`` exclusive. Results are in
    seq order; pass ``nextCursor`` back as ``cursor`` for the next page."""
    if cursor is not None and not _CURSOR.fullmatch(cursor):
        raise IngestValidationError([Issue("cursor", "invalid_cursor")])
    filters = RecordFilter(
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        event_type=event_type,
        from_ts=_normalize_bound(from_, "from"),
        to_ts=_normalize_bound(to, "to"),
    )
    database: Database = request.app.state.database
    with database.read_transaction() as conn:
        records = query_records(
            conn, filters, after_seq=int(cursor) if cursor else 0, limit=limit + 1
        )
        page = records[:limit]
        items = [_view(conn, record) for record in page]
    next_cursor = str(page[-1].seq) if len(records) > limit else None
    return EventPage(items=items, next_cursor=next_cursor)


@router.get("/events/{event_id}", response_model=EventView, summary="Get one audit event")
def get_event(
    request: Request,
    event_id: str,
    _principal: Annotated[Principal, Depends(require_reader)],
) -> EventView:
    if not _EVENT_ID.fullmatch(event_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
    database: Database = request.app.state.database
    with database.read_transaction() as conn:
        record = read_record_by_event_id(conn, event_id)
        if record is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
        return _view(conn, record)
