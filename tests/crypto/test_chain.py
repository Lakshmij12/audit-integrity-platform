"""Chain link checks: valid chains, tampering, gaps, malformed rows and undetectable rewrites."""

import dataclasses
from collections.abc import Iterator

import pytest

from aip.crypto.chain import ChainEntry, ViolationType, check_chain
from aip.crypto.errors import HashInputError
from aip.crypto.hashing import GENESIS_HASH, record_hash, sha256_hex


def _content(label: str) -> str:
    return sha256_hex(f"content-{label}".encode())


def _at(seq: int) -> str:
    return f"2026-10-28T12:00:{seq:02d}.000000Z"


def build_chain(count: int, *, start_seq: int = 1, prev: str = GENESIS_HASH) -> list[ChainEntry]:
    entries = []
    for seq in range(start_seq, start_seq + count):
        content = _content(str(seq))
        digest = record_hash(seq=seq, recorded_at=_at(seq), prev_hash=prev, content_hash=content)
        entries.append(ChainEntry(seq, _at(seq), prev, content, digest))
        prev = digest
    return entries


def rehash_from(entries: list[ChainEntry], index: int) -> list[ChainEntry]:
    """What an attacker with write access does: recompute every hash from ``index`` onward."""
    out = list(entries[:index])
    prev = out[-1].record_hash if out else GENESIS_HASH
    for entry in entries[index:]:
        assert isinstance(entry.seq, int)
        assert isinstance(entry.recorded_at, str)
        assert isinstance(entry.content_hash, str)
        assert isinstance(prev, str)
        digest = record_hash(
            seq=entry.seq,
            recorded_at=entry.recorded_at,
            prev_hash=prev,
            content_hash=entry.content_hash,
        )
        out.append(dataclasses.replace(entry, prev_hash=prev, record_hash=digest))
        prev = digest
    return out


def test_valid_chain_and_empty_chain() -> None:
    assert check_chain(build_chain(5)) is None
    assert check_chain([]) is None


def test_first_record_must_link_to_genesis() -> None:
    chain = rehash_from(build_chain(3), 0)
    forged = [dataclasses.replace(chain[0], prev_hash="1" * 64), *chain[1:]]
    violation = check_chain(forged)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (1, ViolationType.PREV_HASH_MISMATCH)
    assert violation.expected == GENESIS_HASH


@pytest.mark.parametrize(
    "field_change",
    [
        {"content_hash": _content("tampered")},
        {"recorded_at": "2026-10-28T13:00:00.000000Z"},
        {"record_hash": "f" * 64},
    ],
)
def test_altered_field_is_detected_at_that_record(field_change: dict[str, object]) -> None:
    chain = build_chain(4)
    chain[1] = dataclasses.replace(chain[1], **field_change)
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (2, ViolationType.RECORD_HASH_MISMATCH)


def test_rehashing_one_record_breaks_the_next_link() -> None:
    chain = build_chain(4)
    prev = chain[0].record_hash
    assert isinstance(prev, str)
    new_content = _content("tampered")
    new_hash = record_hash(seq=2, recorded_at=_at(2), prev_hash=prev, content_hash=new_content)
    chain[1] = dataclasses.replace(chain[1], content_hash=new_content, record_hash=new_hash)
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (3, ViolationType.PREV_HASH_MISMATCH)


def test_deleted_record_is_a_sequence_gap() -> None:
    chain = build_chain(4)
    del chain[1]
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (2, ViolationType.SEQUENCE_GAP)
    assert (violation.expected, violation.actual) == ("2", "3")


def test_reordered_records_are_detected() -> None:
    chain = build_chain(4)
    chain[1], chain[2] = chain[2], chain[1]
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (2, ViolationType.SEQUENCE_GAP)


def test_duplicated_record_is_detected() -> None:
    chain = build_chain(3)
    chain.insert(2, chain[1])
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (3, ViolationType.SEQUENCE_GAP)


@pytest.mark.parametrize(
    ("field_change", "expected_type"),
    [
        ({"seq": "2"}, ViolationType.SEQUENCE_GAP),
        ({"seq": 2.0}, ViolationType.SEQUENCE_GAP),
        ({"seq": None}, ViolationType.SEQUENCE_GAP),
        ({"prev_hash": None}, ViolationType.MALFORMED_RECORD),
        ({"prev_hash": "NOT-HEX"}, ViolationType.MALFORMED_RECORD),
        ({"recorded_at": "2026-10-28T12:00:02Z"}, ViolationType.MALFORMED_RECORD),
        ({"recorded_at": None}, ViolationType.MALFORMED_RECORD),
        ({"content_hash": "A" * 64}, ViolationType.MALFORMED_RECORD),
        ({"content_hash": b"0" * 64}, ViolationType.MALFORMED_RECORD),
        ({"record_hash": None}, ViolationType.RECORD_HASH_MISMATCH),
        ({"record_hash": "x" * 1000}, ViolationType.RECORD_HASH_MISMATCH),
    ],
)
def test_malformed_rows_are_reported_not_raised(
    field_change: dict[str, object], expected_type: ViolationType
) -> None:
    chain = build_chain(3)
    chain[1] = dataclasses.replace(chain[1], **field_change)
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (2, expected_type)
    assert len(violation.actual) <= 80


@pytest.mark.parametrize(
    ("prev_hash", "expected_type"),
    [
        ("1" * 64, ViolationType.PREV_HASH_MISMATCH),  # well-formed but wrong link
        (GENESIS_HASH, ViolationType.PREV_HASH_MISMATCH),  # well-formed but wrong link
        ("A" * 64, ViolationType.MALFORMED_RECORD),  # uppercase hex
        ("0" * 63, ViolationType.MALFORMED_RECORD),  # too short
        ("0" * 65, ViolationType.MALFORMED_RECORD),  # too long
        (b"0" * 64, ViolationType.MALFORMED_RECORD),  # bytes, not str
        (None, ViolationType.MALFORMED_RECORD),
    ],
)
def test_prev_hash_malformed_versus_wrong_link(
    prev_hash: object, expected_type: ViolationType
) -> None:
    chain = build_chain(3)
    chain[1] = dataclasses.replace(chain[1], prev_hash=prev_hash)
    violation = check_chain(chain)
    assert violation is not None
    assert (violation.seq, violation.violation_type) == (2, expected_type)
    if expected_type is ViolationType.PREV_HASH_MISMATCH:
        assert violation.expected == chain[0].record_hash
        assert violation.actual == prev_hash


def test_bool_seq_is_rejected() -> None:
    chain = build_chain(1)
    violation = check_chain([dataclasses.replace(chain[0], seq=True)])
    assert violation is not None
    assert violation.violation_type is ViolationType.SEQUENCE_GAP


def test_segment_check_with_explicit_start() -> None:
    chain = build_chain(6)
    head = chain[2].record_hash
    assert isinstance(head, str)
    assert check_chain(chain[3:]) is not None
    assert check_chain(chain[3:], expected_seq=4, expected_prev=head) is None


@pytest.mark.parametrize(
    "kwargs",
    [{"expected_seq": 0}, {"expected_seq": True}, {"expected_prev": "A" * 64}],
)
def test_invalid_start_parameters(kwargs: dict[str, object]) -> None:
    with pytest.raises(HashInputError):
        check_chain([], **kwargs)  # type: ignore[arg-type]


def test_check_is_streaming_and_stops_at_first_violation() -> None:
    chain = build_chain(5)
    chain[1] = dataclasses.replace(chain[1], record_hash="f" * 64)
    consumed: list[int] = []

    def stream() -> Iterator[ChainEntry]:
        for entry in chain:
            assert isinstance(entry.seq, int)
            consumed.append(entry.seq)
            yield entry

    violation = check_chain(stream())
    assert violation is not None
    assert violation.seq == 2
    assert consumed == [1, 2]


# --- What hash links alone cannot detect (internal consistency only, guarantee level L1) ------


def test_full_attacker_rewrite_passes_without_an_external_anchor() -> None:
    original = build_chain(5)
    trusted_head = original[-1].record_hash  # e.g. a head previously observed or signed elsewhere
    tampered = list(original)
    tampered[1] = dataclasses.replace(tampered[1], content_hash=_content("attacker"))
    rewritten = rehash_from(tampered, 1)

    assert check_chain(rewritten) is None  # undetectable from the chain itself
    assert rewritten[-1].record_hash != trusted_head  # detectable only against an external anchor


def test_tail_truncation_passes_without_an_external_anchor() -> None:
    original = build_chain(5)
    truncated = original[:3]
    assert check_chain(truncated) is None
    assert len(truncated) < len(original)
