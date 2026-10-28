"""Content and record hashes: known answers, field sensitivity and input validation."""

import hashlib
from typing import Any

import pytest

from aip.crypto.canonical import MAX_SAFE_INTEGER, canonical_json
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import GENESIS_HASH, content_hash, is_hex_digest, record_hash, sha256_hex
from tests.crypto import vectors as kat


def _content(**overrides: Any) -> str:
    return content_hash(**{**kat.ENVELOPE, "payload_root": kat.PAYLOAD_ROOT, **overrides})


def _record(**overrides: Any) -> str:
    fields: dict[str, Any] = {
        "seq": 1,
        "recorded_at": kat.RECORD_1_AT,
        "prev_hash": GENESIS_HASH,
        "content_hash": kat.CONTENT_HASH,
    }
    return record_hash(**{**fields, **overrides})


def test_genesis_is_64_zeros() -> None:
    assert GENESIS_HASH == "0" * 64
    assert GENESIS_HASH.encode() == kat.GENESIS_BYTES


def test_content_hash_vector() -> None:
    preimage = {
        "t": "aip.content",
        "v": 1,
        "eventType": "RECORD_UPDATED",
        "actorId": "user-0042",
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": "acct-0001",
        "timestamp": "2026-10-28T12:00:00.000000Z",
        "payloadRoot": kat.PAYLOAD_ROOT,
    }
    assert canonical_json(preimage) == kat.CONTENT_BYTES
    assert hashlib.sha256(kat.CONTENT_BYTES).hexdigest() == kat.CONTENT_HASH
    assert _content() == kat.CONTENT_HASH


def test_record_hash_vectors_seq_1_and_2() -> None:
    assert hashlib.sha256(kat.RECORD_1_BYTES).hexdigest() == kat.RECORD_1_HASH
    assert hashlib.sha256(kat.RECORD_2_BYTES).hexdigest() == kat.RECORD_2_HASH
    assert _record() == kat.RECORD_1_HASH
    assert (
        record_hash(
            seq=2,
            recorded_at=kat.RECORD_2_AT,
            prev_hash=kat.RECORD_1_HASH,
            content_hash=kat.CONTENT_HASH,
        )
        == kat.RECORD_2_HASH
    )


@pytest.mark.parametrize(
    "override",
    [
        {"event_type": "RECORD_DELETED"},
        {"actor_id": "user-0043"},
        {"resource_type": "CLIENT_PROFILE"},
        {"resource_id": "acct-0002"},
        {"timestamp": "2026-10-28T12:00:00.000001Z"},
        {"payload_root": "f" * 64},
    ],
)
def test_content_hash_depends_on_every_field(override: dict[str, Any]) -> None:
    assert _content(**override) != kat.CONTENT_HASH


@pytest.mark.parametrize(
    "override",
    [
        {"seq": 2},
        {"recorded_at": "2026-10-28T12:00:01.000001Z"},
        {"prev_hash": "1" + "0" * 63},
        {"content_hash": "f" * 64},
    ],
)
def test_record_hash_depends_on_every_field(override: dict[str, Any]) -> None:
    assert _record(**override) != kat.RECORD_1_HASH


@pytest.mark.parametrize(
    "override",
    [
        {"event_type": ""},
        {"actor_id": 42},
        {"resource_type": None},
        {"resource_id": "e\u0301"},
        {"event_type": "\ud800"},
        {"timestamp": "2026-10-28T12:00:00Z"},
        {"timestamp": "2026-02-30T00:00:00.000000Z"},
        {"payload_root": "F" * 64},
        {"payload_root": "0" * 63},
        {"payload_root": "z" * 64},
        {"payload_root": b"0" * 64},
    ],
)
def test_content_hash_rejects_invalid_inputs(override: dict[str, Any]) -> None:
    with pytest.raises(CryptoInputError):
        _content(**override)


@pytest.mark.parametrize(
    "override",
    [
        {"seq": 0},
        {"seq": -1},
        {"seq": True},
        {"seq": 1.0},
        {"seq": "1"},
        {"seq": MAX_SAFE_INTEGER + 1},
        {"recorded_at": "2026-10-28T12:00:01Z"},
        {"recorded_at": "2026-10-28T12:00:01.000000+00:00"},
        {"prev_hash": "A" * 64},
        {"prev_hash": ""},
        {"content_hash": None},
    ],
)
def test_record_hash_rejects_invalid_inputs(override: dict[str, Any]) -> None:
    with pytest.raises(CryptoInputError):
        _record(**override)


def test_record_hash_accepts_max_seq() -> None:
    assert is_hex_digest(_record(seq=MAX_SAFE_INTEGER))


def test_sha256_hex_requires_bytes() -> None:
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    with pytest.raises(CryptoInputError):
        sha256_hex("text")  # type: ignore[arg-type]
    with pytest.raises(CryptoInputError):
        sha256_hex(bytearray(b"x"))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("0" * 64, True), ("a" * 64, True), ("A" * 64, False), ("0" * 65, False), (None, False)],
)
def test_is_hex_digest(value: object, expected: bool) -> None:
    assert is_hex_digest(value) is expected
