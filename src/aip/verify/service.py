"""Full-chain verification of the stored audit log (DESIGN.md section 4).

First, every ``SYSTEM_REDACTION`` and ``SYSTEM_RETENTION_RUN`` event is read and its Ed25519
signature checked against the trusted public keys passed in (from configuration, never from the
database). Then, for every stored record, in seq order, inside the same read snapshot:

* C1/C2/C4/C4a via ``check_chain``: contiguous seq, prevHash links (genesis for seq 1), recomputed
  recordHash, well-formed chain fields;
* the eventId derivation (``"evt_" + recordHash[:32]``);
* C5: each revealed leaf's commitment recomputes from its stored path, salt and value;
* C6: each redacted leaf (value and salt absent) is covered by a later, validly signed redaction
  authorization bound to this record's seq, eventId, contentHash and that exact path;
* the payload root recomputes from the stored leaves and equals the stored ``payload_root``;
* C7: an archived record is covered by a later, validly signed retention run (runId, seq range,
  cutoff, archivedAt, not a SYSTEM_* event) and has no leaves left in the database;
* C8: if the run's archive file is available, its SHA-256 equals the signed digest, each leaf in it
  recomputes and the leaves recompute the stored payload root;
* C3: contentHash recomputes from the stored envelope fields and payload root;
* a SYSTEM_* event with a malformed or invalid signature is itself a violation.

Verification stops at the first violation and reports its location (seq, eventId, field, leaf path)
and code. It never includes stored values, salts or keys: only hashes, field names and paths.

Status: TAMPERED on a violation. INDETERMINATE when no violation was found but something could not
be checked: an authorization whose key is not trusted here (for example no key configured), or an
archive file that is not available. VERIFIED otherwise. Legitimate redaction and archival with valid
evidence are VERIFIED, never TAMPERED; unauthorized removal is never VERIFIED.

What this proves (guarantee level L1): the stored records are internally consistent. An attacker who
rewrites a record and recomputes every later hash, or deletes records from the end, produces a chain
that still passes. Detecting that needs a trusted anchor kept outside the database, such as a signed
checkpoint saved earlier; pass it as ``anchor``.
"""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Connection

from aip.crypto.canonical import canonical_json, parse_strict_json
from aip.crypto.chain import ChainEntry, check_chain
from aip.crypto.commitments import Leaf, LeafStatus, check_leaf, payload_root, unflatten
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import GENESIS_HASH, HASH_VERSION, content_hash, is_hex_digest, sha256_hex
from aip.crypto.signing import verify_document
from aip.lifecycle.archive import ArchiveError, archive_file_name, is_run_id, parse_archive
from aip.lifecycle.service import (
    REDACTION_EVENT,
    REDACTION_TAG,
    RETENTION_EVENT,
    RETENTION_TAG,
)
from aip.storage.database import Database
from aip.storage.repository import (
    SYSTEM_EVENT_PREFIX,
    iter_raw_records,
    load_raw_leaves,
    system_record_seqs,
)


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
    UNAUTHORIZED_REDACTION = "UNAUTHORIZED_REDACTION"
    INVALID_ARCHIVE = "INVALID_ARCHIVE"
    ARCHIVE_CONTENT_MISMATCH = "ARCHIVE_CONTENT_MISMATCH"
    INVALID_AUTHORIZATION = "INVALID_AUTHORIZATION"
    TRUNCATED = "TRUNCATED"
    ANCHOR_MISMATCH = "ANCHOR_MISMATCH"


class VerifyStatus(StrEnum):
    VERIFIED = "VERIFIED"  # everything checked, no violation
    INDETERMINATE = "INDETERMINATE"  # no violation, but some evidence could not be checked
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
    redacted_leaves_authorized: int = 0
    redacted_leaves_unverified: int = 0
    archived_records_verified: int = 0
    archived_records_unverified: int = 0
    archived_content_unavailable: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def status(self) -> VerifyStatus:
        """TAMPERED on any violation; INDETERMINATE while some evidence could not be checked."""
        if not self.intact:
            return VerifyStatus.TAMPERED
        if (
            self.redacted_leaves_unverified
            or self.archived_records_unverified
            or self.archived_content_unavailable
        ):
            return VerifyStatus.INDETERMINATE
        return VerifyStatus.VERIFIED


_EVENT_ID_PREFIX = "evt_"
_EVENT_ID = re.compile(r"evt_[0-9a-f]{32}", re.ASCII)
_DIGITS = re.compile(r"[0-9]{1,20}", re.ASCII)
_UNAVAILABLE: Final = "unavailable"


class _Auth(StrEnum):
    VALID = "VALID"
    UNVERIFIABLE = "UNVERIFIABLE"  # signed by a key that is not trusted here


@dataclass(frozen=True, slots=True)
class _Grant:
    system_seq: int
    status: _Auth
    document: dict[str, Any]


@dataclass(slots=True)
class _Evidence:
    redactions: dict[tuple[int, str], _Grant] = field(default_factory=dict)
    runs: dict[str, _Grant] = field(default_factory=dict)
    invalid_system: set[int] = field(default_factory=set)
    archives: dict[str, dict[int, list[Leaf]] | Violation | str] = field(default_factory=dict)
    trusted_keys: Mapping[str, Ed25519PublicKey] = field(default_factory=dict)
    archive_dir: Path | None = None


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
    database: Database,
    *,
    anchor: Anchor | None = None,
    trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
    archive_dir: Path | None = None,
    batch_size: int = 500,
) -> VerifyReport:
    """Verify every stored record; stop at the first violation."""
    with database.read_transaction() as conn:
        evidence = _load_evidence(conn, trusted_keys or {}, archive_dir)
        report = _verify(conn, iter_raw_records(conn, batch_size=batch_size), anchor, evidence)
    return report


def _parse_leaves(raw: list[tuple[object, ...]]) -> list[Leaf]:
    leaves = []
    for path_text, commitment, salt, value_text in raw:
        path = parse_strict_json(path_text) if type(path_text) is str else None
        if type(path) is not list:
            raise CryptoInputError("path is not a JSON array")
        value = None if value_text is None else parse_strict_json(value_text)  # type: ignore[arg-type]
        leaves.append(Leaf(tuple(path), commitment, salt, value))  # type: ignore[arg-type]
    return leaves


_REDACTION_FIELDS: Final = frozenset(
    {"t", "v", "targetSeq", "targetEventId", "targetContentHash", "paths", "reason",
     "requestedBy", "requestedAt", "keyId"}
)  # fmt: skip
_RETENTION_FIELDS: Final = frozenset(
    {"t", "v", "runId", "cutoff", "windowDays", "fromSeq", "toSeq", "recordCount", "archiveFile",
     "archiveSha256", "archivedAt", "requestedBy", "keyId"}
)  # fmt: skip


def _load_evidence(
    conn: Connection, trusted_keys: Mapping[str, Ed25519PublicKey], archive_dir: Path | None
) -> _Evidence:
    """Read and signature-check every authorization. A SYSTEM_* event that does not hold a
    well-formed, validly signed authorization grants nothing and is reported when it is reached."""
    evidence = _Evidence(trusted_keys=trusted_keys, archive_dir=archive_dir)
    for seq, event_type in system_record_seqs(conn, [REDACTION_EVENT, RETENTION_EVENT]):
        try:
            payload = unflatten(_parse_leaves(load_raw_leaves(conn, seq)))
        except CryptoInputError:
            evidence.invalid_system.add(seq)  # leaves malformed or redacted
            continue
        document, signature = payload.get("authorization"), payload.get("signature")
        tag, fields = (
            (REDACTION_TAG, _REDACTION_FIELDS)
            if event_type == REDACTION_EVENT
            else (RETENTION_TAG, _RETENTION_FIELDS)
        )
        if type(document) is not dict or set(document) != fields or document["t"] != tag:
            evidence.invalid_system.add(seq)
            continue
        key = trusted_keys.get(str(document["keyId"]))
        if key is None:
            status = _Auth.UNVERIFIABLE
        elif verify_document(document, signature, key):
            status = _Auth.VALID
        else:
            evidence.invalid_system.add(seq)
            continue
        grant = _Grant(seq, status, document)
        if event_type == REDACTION_EVENT:
            paths = document["paths"]
            if type(document["targetSeq"]) is not int or type(paths) is not list:
                evidence.invalid_system.add(seq)
                continue
            for path in paths:
                try:
                    key_text = canonical_json(path).decode("utf-8")
                except CryptoInputError:
                    evidence.invalid_system.add(seq)
                    break
                evidence.redactions.setdefault((document["targetSeq"], key_text), grant)
        elif is_run_id(document["runId"]):
            evidence.runs.setdefault(str(document["runId"]), grant)
        else:
            evidence.invalid_system.add(seq)
    return evidence


def _verify(
    conn: Connection,
    rows: Iterator[tuple[object, ...]],
    anchor: Anchor | None,
    evidence: _Evidence,
) -> VerifyReport:
    report = VerifyReport(anchor=anchor)
    expected_seq, expected_prev = 1, GENESIS_HASH
    anchor_hash_seen: str | None = None
    for row in rows:
        problem = _check_record(conn, report, evidence, expected_seq, expected_prev, row)
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
            "indeterminate: some redaction or retention authorizations are signed by a key that "
            "is not trusted here (is a signing key configured?); they are not reported as tampering"
        )
    if report.archived_content_unavailable:
        report.notes.append(
            "indeterminate: some archive files are not available, so the archived payloads could "
            "not be checked; their signed retention runs were verified"
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
    evidence: _Evidence,
    expected_seq: int,
    expected_prev: str,
    row: tuple[object, ...],
) -> Inconsistency | None:
    (seq, event_id, event_type, actor_id, resource_type, resource_id, timestamp,
     recorded_at, stored_root, stored_content, prev_hash, stored_record,
     hash_version, archived_at, archive_run_id) = row  # fmt: skip
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
    if not is_hex_digest(stored_root) or not is_hex_digest(stored_content):
        return Inconsistency(seq, Violation.MALFORMED_RECORD, shown_id, field="payloadRoot")

    target = _Target(seq, str(event_id), stored_content, stored_root)
    raw_leaves = load_raw_leaves(conn, seq)
    if archived_at is None and archive_run_id is None:
        problem = _check_leaves(report, evidence, target, shown_id, raw_leaves)
    else:
        problem = _check_archived(
            report, evidence, target, shown_id, row, raw_leaves, archived_at, archive_run_id
        )
    if problem is not None:
        return problem

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
    if seq in evidence.invalid_system:
        return Inconsistency(seq, Violation.INVALID_AUTHORIZATION, shown_id, field="authorization")
    return None


@dataclass(frozen=True, slots=True)
class _Target:
    seq: int
    event_id: str
    content_hash: str
    payload_root: str


def _judge_leaves(
    report: VerifyReport,
    evidence: _Evidence,
    target: _Target,
    shown_id: str | None,
    leaves: list[Leaf],
    *,
    mismatch: Violation,
) -> Inconsistency | None:
    """C5 for revealed leaves and C6 for redacted ones, then the payload root. Counts are added to
    ``report`` only if the whole record passes."""
    authorized = unverified = 0
    for leaf in leaves:
        status = check_leaf(leaf)
        if status is LeafStatus.INVALID:
            return Inconsistency(
                target.seq, mismatch, shown_id, field="payload", leaf_path=list(leaf.path)
            )
        if status is LeafStatus.REDACTED_UNVERIFIED:
            grant = evidence.redactions.get(
                (target.seq, canonical_json(list(leaf.path)).decode("utf-8"))
            )
            if (
                grant is None
                or grant.system_seq <= target.seq
                or grant.document["targetEventId"] != target.event_id
                or grant.document["targetContentHash"] != target.content_hash
            ):
                return Inconsistency(
                    target.seq,
                    Violation.UNAUTHORIZED_REDACTION,
                    shown_id,
                    field="payload",
                    leaf_path=list(leaf.path),
                )
            if grant.status is _Auth.VALID:
                authorized += 1
            else:
                unverified += 1
    try:
        root = payload_root(leaves)
    except CryptoInputError:
        root = None
    if root != target.payload_root:
        violation = (
            Violation.PAYLOAD_ROOT_MISMATCH
            if mismatch is Violation.LEAF_COMMITMENT_MISMATCH
            else mismatch
        )
        return Inconsistency(
            target.seq, violation, shown_id, expected=root, actual=target.payload_root
        )
    report.redacted_leaves_authorized += authorized
    report.redacted_leaves_unverified += unverified
    return None


def _check_leaves(
    report: VerifyReport,
    evidence: _Evidence,
    target: _Target,
    shown_id: str | None,
    raw_leaves: list[tuple[object, ...]],
) -> Inconsistency | None:
    try:
        leaves = _parse_leaves(raw_leaves)
        payload_root(leaves)  # structure only (unparsable rows, missing array items, no leaves)
    except CryptoInputError:
        return Inconsistency(target.seq, Violation.MALFORMED_LEAF, shown_id, field="leaves")
    return _judge_leaves(
        report, evidence, target, shown_id, leaves, mismatch=Violation.LEAF_COMMITMENT_MISMATCH
    )


def _check_archived(
    report: VerifyReport,
    evidence: _Evidence,
    target: _Target,
    shown_id: str | None,
    row: tuple[object, ...],
    raw_leaves: list[tuple[object, ...]],
    archived_at: object,
    run_id: object,
) -> Inconsistency | None:
    """C7 (the signed run covers this record) and C8 (archive content, when available)."""
    event_type, recorded_at = row[2], row[7]
    grant = evidence.runs.get(run_id) if type(run_id) is str else None
    if (
        grant is None
        or raw_leaves
        or grant.system_seq <= target.seq
        or type(event_type) is not str
        or event_type.startswith(SYSTEM_EVENT_PREFIX)
        or type(recorded_at) is not str
        or not recorded_at < str(grant.document["cutoff"])
        or archived_at != grant.document["archivedAt"]
        or type(grant.document["fromSeq"]) is not int
        or type(grant.document["toSeq"]) is not int
        or not grant.document["fromSeq"] <= target.seq <= grant.document["toSeq"]
    ):
        return Inconsistency(target.seq, Violation.INVALID_ARCHIVE, shown_id, field="archive")
    if grant.status is not _Auth.VALID:
        report.archived_records_unverified += 1
        return None
    archive = _load_archive(evidence, str(run_id), grant.document)
    if archive == _UNAVAILABLE:
        report.archived_content_unavailable += 1
        return None
    if isinstance(archive, Violation):
        return Inconsistency(target.seq, archive, shown_id, field="archive")
    leaves = archive.get(target.seq) if isinstance(archive, dict) else None
    if not leaves:
        return Inconsistency(
            target.seq, Violation.ARCHIVE_CONTENT_MISMATCH, shown_id, field="archive"
        )
    problem = _judge_leaves(
        report, evidence, target, shown_id, leaves, mismatch=Violation.ARCHIVE_CONTENT_MISMATCH
    )
    if problem is None:
        report.archived_records_verified += 1
    return problem


def _load_archive(
    evidence: _Evidence, run_id: str, document: dict[str, Any]
) -> dict[int, list[Leaf]] | Violation | str:
    """The parsed archive of one run (cached), ``_UNAVAILABLE``, or a violation if the file does
    not match its signed digest or is malformed."""
    if run_id in evidence.archives:
        return evidence.archives[run_id]
    result: dict[int, list[Leaf]] | Violation | str
    if evidence.archive_dir is None or document["archiveFile"] != archive_file_name(run_id):
        result = _UNAVAILABLE if evidence.archive_dir is None else Violation.INVALID_ARCHIVE
    else:
        try:
            data = (evidence.archive_dir / archive_file_name(run_id)).read_bytes()
        except OSError:
            result = _UNAVAILABLE
        else:
            if sha256_hex(data) != document["archiveSha256"]:
                result = Violation.ARCHIVE_CONTENT_MISMATCH
            else:
                try:
                    result = parse_archive(data, run_id)
                except ArchiveError:  # pragma: no cover - a signed digest matched a bad file
                    result = Violation.ARCHIVE_CONTENT_MISMATCH
    evidence.archives[run_id] = result
    return result
