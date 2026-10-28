"""Full-chain verification of the stored audit log (DESIGN.md section 4).

For every stored record, in seq order, inside one read snapshot:

* C1/C2/C4/C4a via ``check_chain``: contiguous seq, prevHash links (genesis for seq 1), recomputed
  recordHash, well-formed chain fields;
* the eventId derivation (``"evt_" + recordHash[:32]``);
* C5: each revealed leaf's commitment recomputes from its stored path, salt and value;
* the payload root recomputes from the stored leaves and equals the stored ``payload_root``;
* C3: contentHash recomputes from the stored envelope fields and payload root.

Verification stops at the first violation and reports its location (seq, eventId, field, leaf path)
and code. It never includes stored values, salts or keys: only hashes, field names and paths.

What this proves (guarantee level L1): the stored records are internally consistent. An attacker who
rewrites a record and recomputes every later hash, or deletes records from the end, produces a chain
that still passes. Detecting that needs a trusted anchor kept outside the database, such as a signed
checkpoint saved earlier; pass it as ``anchor``.

Future states: leaves whose value and salt are absent (redaction) and rows marked archived are
counted as *unverified*, not reported as tampering, and the overall status becomes INDETERMINATE
rather than VERIFIED: someone with file access could fake either state to hide an edit, so neither
is trusted until its signed authorization is checked (C6, C7, C8, with redaction and retention).
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum

from sqlalchemy import Connection

from aip.crypto.canonical import parse_strict_json
from aip.crypto.chain import ChainEntry, check_chain
from aip.crypto.commitments import Leaf, LeafStatus, check_leaf, payload_root
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import GENESIS_HASH, HASH_VERSION, content_hash, is_hex_digest
from aip.storage.database import Database
from aip.storage.repository import iter_raw_records, load_raw_leaves


class Violation(StrEnum):
    SEQUENCE_GAP = "SEQUENCE_GAP"
    PREV_HASH_MISMATCH = "PREV_HASH_MISMATCH"
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    EVENT_ID_MISMATCH = "EVENT_ID_MISMATCH"
    MALFORMED_LEAF = "MALFORMED_LEAF"
    LEAF_COMMITMENT_MISMATCH = "LEAF_COMMITMENT_MISMATCH"
    PAYLOAD_ROOT_MISMATCH = "PAYLOAD_ROOT_MISMATCH"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    TRUNCATED = "TRUNCATED"
    ANCHOR_MISMATCH = "ANCHOR_MISMATCH"


class VerifyStatus(StrEnum):
    VERIFIED = "VERIFIED"  # every record and leaf checked, no violation
    INDETERMINATE = "INDETERMINATE"  # no violation, but redacted/archived content was not checked
    TAMPERED = "TAMPERED"  # a violation was found


@dataclass(frozen=True, slots=True)
class Inconsistency:
    seq: int
    violation: Violation
    event_id: str | None = None
    field: str | None = None
    leaf_path: list[str | int] | None = None
    expected: str | None = None  # only ever a hash or a seq number
    actual: str | None = None  # only ever a hash or a seq number


@dataclass(frozen=True, slots=True)
class Anchor:
    """A trusted (seq, recordHash) pair kept outside the database, e.g. from a signed checkpoint."""

    seq: int
    record_hash: str


@dataclass(slots=True)
class VerifyReport:
    intact: bool = True
    records_checked: int = 0
    head_seq: int = 0
    head_record_hash: str = GENESIS_HASH
    first_inconsistency: Inconsistency | None = None
    anchor: Anchor | None = None
    anchor_matched: bool | None = None
    redacted_leaves_unverified: int = 0
    archived_records_unverified: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def status(self) -> VerifyStatus:
        """TAMPERED on any violation; INDETERMINATE while some content could not be checked."""
        if not self.intact:
            return VerifyStatus.TAMPERED
        if self.redacted_leaves_unverified or self.archived_records_unverified:
            return VerifyStatus.INDETERMINATE
        return VerifyStatus.VERIFIED


_EVENT_ID_PREFIX = "evt_"
_EVENT_ID = re.compile(r"evt_[0-9a-f]{32}", re.ASCII)
_DIGITS = re.compile(r"[0-9]{1,20}", re.ASCII)


def _safe(value: object) -> str | None:
    """Expose a stored value only if it is a well-formed hash or a seq number, never other text."""
    if is_hex_digest(value):
        return value
    if type(value) is str and _DIGITS.fullmatch(value):
        return value
    return None


def _event_id_or_none(value: object) -> str | None:
    return value if type(value) is str and _EVENT_ID.fullmatch(value) else None


def _malformed_field(label: str) -> str:
    for name in ("recordedAt", "prevHash", "contentHash"):
        if name in label:
            return name
    return "chain"


def verify_database(
    database: Database, *, anchor: Anchor | None = None, batch_size: int = 500
) -> VerifyReport:
    """Verify every stored record; stop at the first violation."""
    with database.read_transaction() as conn:
        report = _verify(conn, iter_raw_records(conn, batch_size=batch_size), anchor)
    return report


def _verify(
    conn: Connection, rows: Iterator[tuple[object, ...]], anchor: Anchor | None
) -> VerifyReport:
    report = VerifyReport(anchor=anchor)
    expected_seq, expected_prev = 1, GENESIS_HASH
    anchor_hash_seen: str | None = None
    for row in rows:
        problem = _check_record(conn, report, expected_seq, expected_prev, row)
        if problem is not None:
            return _fail(report, problem)
        # _check_record established that seq == expected_seq and recordHash is well-formed.
        record_hash = str(row[11])
        report.records_checked += 1
        report.head_seq, report.head_record_hash = expected_seq, record_hash
        if anchor is not None and expected_seq == anchor.seq:
            anchor_hash_seen = record_hash
        expected_seq, expected_prev = expected_seq + 1, record_hash
    if anchor is not None:
        if report.head_seq < anchor.seq:
            return _fail(
                report,
                Inconsistency(
                    report.head_seq + 1,
                    Violation.TRUNCATED,
                    expected=str(anchor.seq),
                    actual=str(report.head_seq),
                ),
            )
        if anchor_hash_seen != anchor.record_hash:
            return _fail(
                report,
                Inconsistency(
                    anchor.seq,
                    Violation.ANCHOR_MISMATCH,
                    expected=anchor.record_hash,
                    actual=anchor_hash_seen,
                ),
            )
        report.anchor_matched = True
    else:
        report.notes.append(
            "internal consistency only: without a trusted anchor, a coordinated rewrite of the "
            "chain or removal of its newest records cannot be detected"
        )
    if report.redacted_leaves_unverified or report.archived_records_unverified:
        report.notes.append(
            "indeterminate: redacted leaves and archived records were not checked because their "
            "authorization checks are not implemented yet; they are not reported as tampering"
        )
    return report


def _fail(report: VerifyReport, problem: Inconsistency) -> VerifyReport:
    report.intact = False
    report.first_inconsistency = problem
    if report.anchor is not None:
        report.anchor_matched = (
            False if problem.violation in (Violation.TRUNCATED, Violation.ANCHOR_MISMATCH) else None
        )
    return report


def _check_record(
    conn: Connection,
    report: VerifyReport,
    expected_seq: int,
    expected_prev: str,
    row: tuple[object, ...],
) -> Inconsistency | None:
    (seq, event_id, event_type, actor_id, resource_type, resource_id, timestamp,
     recorded_at, stored_root, stored_content, prev_hash, stored_record,
     hash_version, archived_at) = row  # fmt: skip
    # Chain links and recordHash (C1, C2, C4, C4a), reusing the pure chain check.
    chain = check_chain(
        [ChainEntry(seq, recorded_at, prev_hash, stored_content, stored_record)],
        expected_seq=expected_seq,
        expected_prev=expected_prev,
    )
    shown_id = _event_id_or_none(event_id)
    if chain is not None:
        violation = Violation(chain.violation_type.value)
        if violation is Violation.MALFORMED_RECORD:
            return Inconsistency(
                expected_seq, violation, shown_id, field=_malformed_field(chain.expected)
            )
        return Inconsistency(
            expected_seq,
            violation,
            event_id=shown_id,
            expected=_safe(chain.expected),
            actual=_safe(chain.actual),
        )
    if type(seq) is not int or not is_hex_digest(stored_record):  # pragma: no cover - by C1/C4
        return Inconsistency(expected_seq, Violation.MALFORMED_RECORD, shown_id, field="chain")
    if hash_version != HASH_VERSION:
        return Inconsistency(seq, Violation.MALFORMED_RECORD, shown_id, field="hashVersion")
    if event_id != _EVENT_ID_PREFIX + stored_record[:32]:
        return Inconsistency(seq, Violation.EVENT_ID_MISMATCH, shown_id, field="eventId")
    if not is_hex_digest(stored_root):
        return Inconsistency(seq, Violation.MALFORMED_RECORD, shown_id, field="payloadRoot")

    if archived_at is None:
        problem = _check_leaves(conn, report, seq, shown_id, stored_root)
        if problem is not None:
            return problem
    else:
        report.archived_records_unverified += 1  # leaves live in the archive (future state)

    try:
        recomputed = content_hash(
            event_type=event_type,  # type: ignore[arg-type]
            actor_id=actor_id,  # type: ignore[arg-type]
            resource_type=resource_type,  # type: ignore[arg-type]
            resource_id=resource_id,  # type: ignore[arg-type]
            timestamp=timestamp,  # type: ignore[arg-type]
            payload_root=stored_root,
        )
    except CryptoInputError:
        return Inconsistency(seq, Violation.MALFORMED_RECORD, shown_id, field="envelope")
    if recomputed != stored_content:
        return Inconsistency(
            seq,
            Violation.CONTENT_HASH_MISMATCH,
            shown_id,
            expected=recomputed,
            actual=_safe(stored_content),
        )
    return None


def _check_leaves(
    conn: Connection, report: VerifyReport, seq: int, shown_id: str | None, stored_root: str
) -> Inconsistency | None:
    leaves: list[Leaf] = []
    redacted = 0
    for path_text, commitment, salt, value_text in load_raw_leaves(conn, seq):
        try:
            path = parse_strict_json(path_text) if type(path_text) is str else None
            if type(path) is not list:
                raise CryptoInputError("path is not a JSON array")
            value = None if value_text is None else parse_strict_json(value_text)  # type: ignore[arg-type]
            leaf = Leaf(tuple(path), commitment, salt, value)  # type: ignore[arg-type]
        except CryptoInputError:
            return Inconsistency(seq, Violation.MALFORMED_LEAF, shown_id, field="leaves")
        status = check_leaf(leaf)
        if status is LeafStatus.INVALID:
            return Inconsistency(
                seq,
                Violation.LEAF_COMMITMENT_MISMATCH,
                shown_id,
                field="payload",
                leaf_path=list(leaf.path),
            )
        if status is LeafStatus.REDACTED_UNVERIFIED:
            redacted += 1
        leaves.append(leaf)
    try:
        root = payload_root(leaves)
    except CryptoInputError:
        return Inconsistency(seq, Violation.MALFORMED_LEAF, shown_id, field="leaves")
    if root != stored_root:
        return Inconsistency(
            seq, Violation.PAYLOAD_ROOT_MISMATCH, shown_id, expected=root, actual=stored_root
        )
    report.redacted_leaves_unverified += redacted
    return None
