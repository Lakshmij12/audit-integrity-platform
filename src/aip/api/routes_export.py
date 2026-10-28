"""GET /audit/export: a signed bundle of all records for one actorId or resourceId."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from starlette.concurrency import run_in_threadpool

from aip.api.auth import Principal, require_reader
from aip.api.routes_verify import _verify_app
from aip.crypto.signing import Signer
from aip.crypto.timestamps import format_timestamp
from aip.export import MAX_EXPORT_RECORDS, ExportTooLargeError, build_bundle
from aip.ingest import Clock, IngestValidationError, Issue
from aip.storage import Database

router = APIRouter(prefix="/audit", tags=["export"])

_Id = Annotated[str | None, Query(min_length=1, max_length=256)]


def _export(request: Request, actor_id: str | None, resource_id: str | None) -> bytes:
    signer: Signer | None = request.app.state.signer
    if signer is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "signing key not configured")
    if not _verify_app(request).intact:
        raise HTTPException(status.HTTP_409_CONFLICT, "the chain failed verification; not exported")
    database: Database = request.app.state.database
    clock: Clock = request.app.state.clock
    with database.read_transaction() as conn:
        try:
            return build_bundle(
                conn,
                signer,
                actor_id=actor_id,
                resource_id=resource_id,
                exported_at=format_timestamp(clock.now()),
            )
        except ExportTooLargeError:
            raise IngestValidationError(
                [Issue("filter", f"more_than_{MAX_EXPORT_RECORDS}_records")]
            ) from None


@router.get(
    "/export",
    summary="Export all records for one actorId or resourceId as a signed, verifiable bundle",
    responses={200: {"content": {"application/json": {}}}},
)
async def export(
    request: Request,
    _principal: Annotated[Principal, Depends(require_reader)],
    actor_id: Annotated[_Id, Query(alias="actorId")] = None,
    resource_id: Annotated[_Id, Query(alias="resourceId")] = None,
) -> Response:
    """Pass exactly one of ``actorId`` or ``resourceId``. Verify the result offline with
    ``python tools/verify_bundle.py bundle.json --trusted-key <public key hex>``; the key must be
    obtained independently, not from the bundle. The chain is verified first (409 if it fails)."""
    if (actor_id is None) == (resource_id is None):
        raise IngestValidationError([Issue("filter", "exactly_one_of_actorId_or_resourceId")])
    body = await run_in_threadpool(_export, request, actor_id, resource_id)
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="aip-export.json"'},
    )
