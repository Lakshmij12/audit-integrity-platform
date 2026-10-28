"""GET /audit/verify and GET /audit/checkpoints/latest."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from starlette.concurrency import run_in_threadpool

from aip.api.auth import Principal, require_reader
from aip.api.schemas import (
    AnchorView,
    CheckpointResponse,
    InconsistencyView,
    UnverifiedView,
    VerifyResponse,
)
from aip.crypto.hashing import is_hex_digest
from aip.crypto.signing import Signer, public_key_hex, sign_checkpoint
from aip.crypto.timestamps import format_timestamp
from aip.ingest import Clock, IngestValidationError, Issue
from aip.storage import Database
from aip.verify import Anchor, VerifyReport, VerifyStatus, verify_database

router = APIRouter(prefix="/audit", tags=["verification"])


def _to_response(report: VerifyReport) -> VerifyResponse:
    problem = report.first_inconsistency
    status = report.status
    return VerifyResponse(
        status=status.value,
        intact=None if status is VerifyStatus.INDETERMINATE else report.intact,
        records_checked=report.records_checked,
        head_seq=report.head_seq,
        head_record_hash=report.head_record_hash,
        first_inconsistency=None
        if problem is None
        else InconsistencyView(
            seq=problem.seq,
            violation_type=problem.violation.value,
            event_id=problem.event_id,
            field=problem.field,
            leaf_path=problem.leaf_path,
            expected=problem.expected,
            actual=problem.actual,
        ),
        anchor=None
        if report.anchor is None
        else AnchorView(
            seq=report.anchor.seq,
            record_hash=report.anchor.record_hash,
            matched=report.anchor_matched,
        ),
        unverified=UnverifiedView(
            redacted_leaves=report.redacted_leaves_unverified,
            archived_records=report.archived_records_unverified,
        ),
        notes=report.notes,
    )


@router.get("/verify", response_model=VerifyResponse, summary="Verify the whole audit chain")
async def verify(
    request: Request,
    _principal: Annotated[Principal, Depends(require_reader)],
    anchor_seq: Annotated[int | None, Query(alias="anchorSeq", ge=1)] = None,
    anchor_hash: Annotated[str | None, Query(alias="anchorHash", max_length=64)] = None,
) -> VerifyResponse:
    """Walks every stored record. Pass a previously saved checkpoint as ``anchorSeq`` and
    ``anchorHash`` to also detect rewriting or truncation relative to that trusted anchor."""
    if (anchor_seq is None) != (anchor_hash is None):
        raise IngestValidationError([Issue("anchor", "anchorSeq_and_anchorHash_go_together")])
    anchor = None
    if anchor_seq is not None:
        if not is_hex_digest(anchor_hash):
            raise IngestValidationError([Issue("anchorHash", "not_a_hex_digest")])
        anchor = Anchor(anchor_seq, anchor_hash)
    database: Database = request.app.state.database
    report = await run_in_threadpool(verify_database, database, anchor=anchor)
    return _to_response(report)


@router.get(
    "/checkpoints/latest",
    response_model=CheckpointResponse,
    summary="Signed checkpoint of the current chain head",
)
def latest_checkpoint(
    request: Request,
    _principal: Annotated[Principal, Depends(require_reader)],
) -> CheckpointResponse:
    """Verifies the whole chain, then signs its head. Refuses (409) to sign a chain with a
    violation. Keep the result outside this service: it is a trusted anchor only if an attacker
    with database access cannot alter it."""
    signer: Signer | None = request.app.state.signer
    if signer is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "signing key not configured")
    database: Database = request.app.state.database
    report = verify_database(database)
    if not report.intact:
        raise HTTPException(status.HTTP_409_CONFLICT, "the chain failed verification; not signed")
    if report.head_seq == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "the audit log is empty")
    clock: Clock = request.app.state.clock
    checkpoint = sign_checkpoint(
        signer,
        seq=report.head_seq,
        record_hash=report.head_record_hash,
        signed_at=format_timestamp(clock.now()),
    )
    return CheckpointResponse(
        seq=checkpoint.seq,
        record_hash=checkpoint.record_hash,
        signed_at=checkpoint.signed_at,
        key_id=checkpoint.key_id,
        signature=checkpoint.signature,
        public_key=public_key_hex(signer.public_key),
    )
