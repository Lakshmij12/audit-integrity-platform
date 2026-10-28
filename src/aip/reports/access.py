"""Account-access report for regulators (Scenario C, docs/SCENARIO_C.md).

Clarified requirement: given a client account (or an actor) and a time range, list every recorded
event on client-account resources (who, what, when) together with an explicit integrity status for
the report as a whole and for each listed event, without returning payload values.

Integrity mapping from one full-chain verification (``verify_database``), which stops at the first
violation:

* chain VERIFIED: every listed event is VERIFIED;
* chain INDETERMINATE (no violation, but some redaction/archive evidence could not be checked):
  redacted or archived events are INDETERMINATE, the others VERIFIED;
* chain TAMPERED at seq k: events before k are VERIFIED (or INDETERMINATE as above), the event at k
  is TAMPERED, and events after k are UNVERIFIED because verification stopped at k.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Final

from sqlalchemy import Connection

from aip.storage import repository
from aip.storage.repository import RecordFilter
from aip.verify import VerifyReport, VerifyStatus

MAX_REPORT_EVENTS: Final = 10_000
_PAGE: Final = 500


class ReportTooLargeError(Exception):
    """More events match than one report may hold; narrow the time range."""


@dataclass(frozen=True, slots=True)
class AccessEvent:
    seq: int
    event_id: str
    event_type: str
    actor_id: str
    resource_type: str
    account_id: str
    timestamp: str
    recorded_at: str
    record_hash: str
    redacted_paths: list[list[str | int]]
    archived: bool
    integrity: str


@dataclass(slots=True)
class AccessReport:
    resource_type: str
    account_id: str | None
    actor_id: str | None
    event_type: str | None
    from_ts: str | None
    to_ts: str | None
    generated_at: str
    verification: VerifyReport
    events: list[AccessEvent] = field(default_factory=list)

    @property
    def by_event_type(self) -> dict[str, int]:
        return dict(sorted(Counter(event.event_type for event in self.events).items()))

    @property
    def by_actor(self) -> dict[str, int]:
        return dict(sorted(Counter(event.actor_id for event in self.events).items()))

    @property
    def accounts(self) -> list[str]:
        return sorted({event.account_id for event in self.events})


def _event_integrity(
    verification: VerifyReport, seq: int, *, redacted: bool, archived: bool
) -> str:
    problem = verification.first_inconsistency
    if problem is not None:
        if seq == problem.seq:
            return VerifyStatus.TAMPERED.value
        if seq > problem.seq:
            return "UNVERIFIED"
    if verification.status is not VerifyStatus.VERIFIED and (redacted or archived):
        return VerifyStatus.INDETERMINATE.value
    return VerifyStatus.VERIFIED.value


def build_access_report(
    conn: Connection,
    verification: VerifyReport,
    *,
    resource_type: str,
    account_id: str | None,
    actor_id: str | None,
    event_type: str | None,
    from_ts: str | None,
    to_ts: str | None,
    generated_at: str,
) -> AccessReport:
    """Events on ``resource_type`` resources matching every given filter, in seq order.

    ``account_id`` or ``actor_id`` must be given. Payload values are never included; only the
    paths of redacted leaves and whether the record is archived.
    """
    if account_id is None and actor_id is None:
        raise ValueError("account_id or actor_id is required")
    filters = RecordFilter(
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=account_id,
        event_type=event_type,
        from_ts=from_ts,
        to_ts=to_ts,
    )
    report = AccessReport(
        resource_type, account_id, actor_id, event_type, from_ts, to_ts, generated_at, verification
    )
    after = 0
    while True:
        page = repository.query_records(conn, filters, after_seq=after, limit=_PAGE)
        for record in page:
            leaves = repository.load_leaves(conn, record.seq)
            redacted = [list(leaf.path) for leaf in leaves if leaf.is_redacted]
            archived = repository.archive_state(conn, record.seq) is not None
            report.events.append(
                AccessEvent(
                    seq=record.seq,
                    event_id=record.event_id,
                    event_type=record.event_type,
                    actor_id=record.actor_id,
                    resource_type=record.resource_type,
                    account_id=record.resource_id,
                    timestamp=record.timestamp,
                    recorded_at=record.recorded_at,
                    record_hash=record.record_hash,
                    redacted_paths=redacted,
                    archived=archived,
                    integrity=_event_integrity(
                        verification, record.seq, redacted=bool(redacted), archived=archived
                    ),
                )
            )
        if len(report.events) > MAX_REPORT_EVENTS:
            raise ReportTooLargeError(f"more than {MAX_REPORT_EVENTS} events match")
        if len(page) < _PAGE:
            return report
        after = page[-1].seq
