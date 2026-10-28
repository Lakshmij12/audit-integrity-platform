"""Pure hash-chain link checks over an ordered stream of stored records.

``check_chain`` verifies invariants C1 (contiguous seq), C2 (prevHash links, genesis for seq 1)
and C4 (recomputed recordHash) from DESIGN.md, and reports malformed stored fields. It trusts the
stored contentHash; recomputing contentHash from stored leaves (C3, C5) is a separate step.

Internal consistency is all it proves: an attacker who rewrites a record and recomputes every
later hash produces a chain that passes. Detecting that requires an external trust anchor, such
as a previously observed or signed head hash.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from aip.crypto.errors import CryptoInputError, HashInputError
from aip.crypto.hashing import GENESIS_HASH, is_hex_digest, record_hash
from aip.crypto.timestamps import is_canonical_timestamp


class ViolationType(StrEnum):
    SEQUENCE_GAP = "SEQUENCE_GAP"
    PREV_HASH_MISMATCH = "PREV_HASH_MISMATCH"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"


@dataclass(frozen=True, slots=True)
class ChainEntry:
    """Chain fields of one stored record, exactly as read from storage.

    Fields are deliberately typed ``object`` and not validated on construction: tampered or
    corrupted rows must be reported as violations, not crash the check.
    """

    seq: object
    recorded_at: object
    prev_hash: object
    content_hash: object
    record_hash: object


@dataclass(frozen=True, slots=True)
class ChainViolation:
    """The first inconsistency found. ``seq`` is the position (expected seq) where it was found."""

    seq: int
    violation_type: ViolationType
    expected: str
    actual: str


def _show(value: object) -> str:
    text = value if type(value) is str else repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def check_chain(
    entries: Iterable[ChainEntry],
    *,
    expected_seq: int = 1,
    expected_prev: str = GENESIS_HASH,
) -> ChainViolation | None:
    """Return the first violation in ``entries`` (in stored order), or None if all links hold.

    ``expected_seq``/``expected_prev`` allow checking a segment that starts after seq 1.
    """
    if type(expected_seq) is not int or expected_seq < 1:
        raise HashInputError("expected_seq must be an int >= 1")
    if not is_hex_digest(expected_prev):
        raise HashInputError("expected_prev must be 64 lowercase hex characters")
    for entry in entries:
        seq = entry.seq
        if type(seq) is not int or seq != expected_seq:
            return ChainViolation(
                expected_seq, ViolationType.SEQUENCE_GAP, str(expected_seq), _show(seq)
            )
        prev = entry.prev_hash
        if not is_hex_digest(prev):
            return ChainViolation(seq, ViolationType.MALFORMED_RECORD, "hex prevHash", _show(prev))
        if prev != expected_prev:
            return ChainViolation(seq, ViolationType.PREV_HASH_MISMATCH, expected_prev, prev)
        recorded_at, content = entry.recorded_at, entry.content_hash
        if not is_canonical_timestamp(recorded_at):
            return ChainViolation(
                seq, ViolationType.MALFORMED_RECORD, "canonical recordedAt", _show(recorded_at)
            )
        if not is_hex_digest(content):
            return ChainViolation(
                seq, ViolationType.MALFORMED_RECORD, "hex contentHash", _show(content)
            )
        try:
            recomputed = record_hash(
                seq=seq, recorded_at=recorded_at, prev_hash=expected_prev, content_hash=content
            )
        except CryptoInputError as exc:
            return ChainViolation(seq, ViolationType.MALFORMED_RECORD, "valid fields", str(exc))
        if entry.record_hash != recomputed:
            return ChainViolation(
                seq, ViolationType.RECORD_HASH_MISMATCH, recomputed, _show(entry.record_hash)
            )
        expected_prev = recomputed
        expected_seq += 1
    return None
