"""GET /audit/reports/account-access (Scenario C, docs/SCENARIO_C.md)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from starlette.concurrency import run_in_threadpool

from aip.api.auth import Principal, require_reader
from aip.api.routes_events import _normalize_bound
from aip.api.routes_verify import _verify_app
from aip.api.schemas import (
    AccessEventView,
    AccessReportResponse,
    AccessSummaryView,
    ReportIntegrityView,
    ReportScopeView,
)
from aip.crypto.timestamps import format_timestamp
from aip.ingest import Clock, IngestValidationError, Issue
from aip.reports import MAX_REPORT_EVENTS, AccessReport, ReportTooLargeError, build_access_report
from aip.storage import Database

router = APIRouter(prefix="/audit/reports", tags=["reports"])

_Text = Annotated[str | None, Query(min_length=1, max_length=256)]


def _build(
    request: Request,
    account_id: str | None,
    actor_id: str | None,
    event_type: str | None,
    from_ts: str | None,
    to_ts: str | None,
) -> AccessReport:
    verification = _verify_app(request)
    database: Database = request.app.state.database
    clock: Clock = request.app.state.clock
    with database.read_transaction() as conn:
        try:
            return build_access_report(
                conn,
                verification,
                resource_type=request.app.state.settings.account_resource_type,
                account_id=account_id,
                actor_id=actor_id,
                event_type=event_type,
                from_ts=from_ts,
                to_ts=to_ts,
                generated_at=format_timestamp(clock.now()),
            )
        except ReportTooLargeError:
            raise IngestValidationError(
                [Issue("filter", f"more_than_{MAX_REPORT_EVENTS}_events_narrow_the_range")]
            ) from None


def _to_response(report: AccessReport) -> AccessReportResponse:
    verification = report.verification
    problem = verification.first_inconsistency
    status = verification.status
    return AccessReportResponse(
        generated_at=report.generated_at,
        scope=ReportScopeView(
            resource_type=report.resource_type,
            account_id=report.account_id,
            actor_id=report.actor_id,
            event_type=report.event_type,
            from_=report.from_ts,
            to=report.to_ts,
        ),
        integrity=ReportIntegrityView(
            status=status.value,
            records_checked=verification.records_checked,
            head_seq=verification.head_seq,
            first_inconsistency_seq=None if problem is None else problem.seq,
            violation_type=None if problem is None else problem.violation.value,
            notes=verification.notes,
        ),
        summary=AccessSummaryView(
            total_events=len(report.events),
            accounts=report.accounts,
            by_event_type=report.by_event_type,
            by_actor=report.by_actor,
            first_timestamp=min((e.timestamp for e in report.events), default=None),
            last_timestamp=max((e.timestamp for e in report.events), default=None),
            events_not_verified=sum(1 for e in report.events if e.integrity != "VERIFIED"),
        ),
        events=[
            AccessEventView(
                seq=e.seq,
                event_id=e.event_id,
                event_type=e.event_type,
                actor_id=e.actor_id,
                account_id=e.account_id,
                timestamp=e.timestamp,
                recorded_at=e.recorded_at,
                record_hash=e.record_hash,
                redacted_paths=e.redacted_paths,
                archived=e.archived,
                integrity=e.integrity,
            )
            for e in report.events
        ],
    )


@router.get(
    "/account-access",
    response_model=AccessReportResponse,
    summary="Who accessed client account data, when and how, with integrity status",
)
async def account_access_report(
    request: Request,
    _principal: Annotated[Principal, Depends(require_reader)],
    account_id: Annotated[_Text, Query(alias="accountId")] = None,
    actor_id: Annotated[_Text, Query(alias="actorId")] = None,
    event_type: Annotated[_Text, Query(alias="eventType")] = None,
    from_: Annotated[str | None, Query(alias="from", max_length=64)] = None,
    to: Annotated[str | None, Query(max_length=64)] = None,
) -> AccessReportResponse:
    """Events on client-account resources (``AIP_ACCOUNT_RESOURCE_TYPE``, default
    ``CLIENT_ACCOUNT``) for ``accountId`` and/or ``actorId`` (at least one), optionally one
    ``eventType`` and a ``[from, to)`` range on the event timestamp. No payload values are returned.
    The whole chain is verified for every report; ``integrity`` gives the overall status and each
    event its own (VERIFIED, INDETERMINATE, TAMPERED or UNVERIFIED)."""
    if account_id is None and actor_id is None:
        raise IngestValidationError([Issue("filter", "accountId_or_actorId_required")])
    from_ts = _normalize_bound(from_, "from")
    to_ts = _normalize_bound(to, "to")
    report = await run_in_threadpool(
        _build, request, account_id, actor_id, event_type, from_ts, to_ts
    )
    return _to_response(report)
