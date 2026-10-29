"""Admin-only redaction and retention endpoints (DESIGN.md sections 6 and 7)."""

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from aip.api.auth import Principal, require_admin
from aip.api.routes_events import _read_limited_body
from aip.api.schemas import (
    RedactionRequest,
    RedactionResponse,
    RetentionRequest,
    RetentionResponse,
    json_request_body,
)
from aip.ingest import IngestValidationError, Issue
from aip.lifecycle import LifecycleService

_EVENT_ID = re.compile(r"evt_[0-9a-f]{32}", re.ASCII)

router = APIRouter(prefix="/audit", tags=["lifecycle"])


async def _parse[M: BaseModel](request: Request, model: type[M], *, empty_ok: bool = False) -> M:
    content_type = request.headers.get("content-type", "")
    body = await _read_limited_body(request, request.app.state.settings.max_body_bytes)
    if empty_ok and not body:
        return model()
    if content_type.split(";")[0].strip().lower() != "application/json":
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "use application/json")
    try:
        return model.model_validate_json(body)
    except ValidationError as exc:
        issues = [
            Issue(".".join(str(p) for p in err.get("loc", ())) or "body", str(err.get("type")))
            for err in exc.errors()
        ]
        raise IngestValidationError(issues) from None


@router.post(
    "/events/{event_id}/redactions",
    response_model=RedactionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Redact payload fields of one event (admin)",
    openapi_extra=json_request_body(
        RedactionRequest,
        required=True,
        example={"paths": [["ssn"]], "reason": "client privacy request"},
    ),
)
async def redact_event(
    request: Request,
    response: Response,
    event_id: str,
    principal: Annotated[Principal, Depends(require_admin)],
) -> RedactionResponse:
    """Removes the values (and salts) of the given leaf paths; commitments and every hash stay as
    they are. Appends a signed SYSTEM_REDACTION event in the same transaction. Returns 200 with no
    new event if every path was already redacted."""
    if not _EVENT_ID.fullmatch(event_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
    body = await _parse(request, RedactionRequest)
    service: LifecycleService = request.app.state.lifecycle
    result = await run_in_threadpool(
        service.redact, event_id, body.paths, body.reason, requested_by=principal.key_id
    )
    if result.redaction_event_id is None:
        response.status_code = status.HTTP_200_OK
    return RedactionResponse(
        target_event_id=result.target_event_id,
        redaction_event_id=result.redaction_event_id,
        redaction_seq=result.redaction_seq,
        redacted_paths=result.redacted_paths,
        already_redacted_paths=result.already_redacted_paths,
    )


@router.post(
    "/retention/runs",
    response_model=RetentionResponse,
    summary="Archive records older than the retention window (admin; dry run by default)",
    openapi_extra=json_request_body(RetentionRequest, required=False, example={"dryRun": True}),
)
async def run_retention(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_admin)],
) -> RetentionResponse:
    """``{"dryRun": true}`` (the default, also for an empty body) only reports what would be
    archived. ``{"dryRun": false}`` writes the archive file, appends a signed SYSTEM_RETENTION_RUN
    event, marks the records archived and removes their payload leaves from the database (201)."""
    body = await _parse(request, RetentionRequest, empty_ok=True)
    service: LifecycleService = request.app.state.lifecycle
    result = await run_in_threadpool(
        service.run_retention, dry_run=body.dry_run, requested_by=principal.key_id
    )
    if result.run_id is not None:
        response.status_code = status.HTTP_201_CREATED
    return RetentionResponse(
        dry_run=result.dry_run,
        cutoff=result.cutoff,
        window_days=result.window_days,
        record_count=result.record_count,
        from_seq=result.from_seq,
        to_seq=result.to_seq,
        run_id=result.run_id,
        retention_event_id=result.retention_event_id,
        archive_file=result.archive_file,
        archive_sha256=result.archive_sha256,
        wal_checkpointed=result.wal_checkpointed,
    )
