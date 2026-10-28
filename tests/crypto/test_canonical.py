"""Canonical JSON encoding and strict parsing."""

import hashlib
import json
from datetime import UTC, datetime
from enum import IntEnum

import pytest

from aip.crypto.canonical import (
    MAX_DEPTH,
    MAX_SAFE_INTEGER,
    JsonValue,
    canonical_json,
    parse_strict_json,
)
from aip.crypto.errors import CanonicalizationError
from tests.crypto.vectors import (
    CANONICAL_VECTORS,
    RFC8785_SORT_EXPECTED_ORDER,
    RFC8785_SORT_SAMPLE_FULL,
)


def _nested_lists(depth: int) -> JsonValue:
    value: JsonValue = []
    for _ in range(depth - 1):
        value = [value]
    return value


def _nested_objects(depth: int) -> JsonValue:
    value: JsonValue = {}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


@pytest.mark.parametrize(
    ("name", "value", "expected", "digest"),
    CANONICAL_VECTORS,
    ids=[v[0] for v in CANONICAL_VECTORS],
)
def test_canonical_vectors(name: str, value: JsonValue, expected: bytes, digest: str) -> None:
    assert canonical_json(value) == expected
    assert hashlib.sha256(expected).hexdigest() == digest


def test_key_insertion_order_does_not_matter() -> None:
    assert canonical_json({"a": 1, "b": {"y": 2, "x": 3}}) == canonical_json(
        {"b": {"x": 3, "y": 2}, "a": 1}
    )


def test_rfc8785_sort_sample_is_rejected_because_u_fb33_is_not_nfc() -> None:
    with pytest.raises(CanonicalizationError, match="NFC"):
        canonical_json(RFC8785_SORT_SAMPLE_FULL)


def test_rfc8785_sort_order_for_the_nfc_keys() -> None:
    sample = {k: v for k, v in RFC8785_SORT_SAMPLE_FULL.items() if k != "\ufb33"}
    decoded = json.loads(canonical_json(sample).decode("utf-8"))
    assert list(decoded.values()) == RFC8785_SORT_EXPECTED_ORDER[:6]


@pytest.mark.parametrize("value", [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER, 0])
def test_integer_boundaries_accepted(value: int) -> None:
    assert canonical_json(value) == str(value).encode()


class _Color(IntEnum):
    RED = 1


class _MyStr(str):
    pass


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        float("nan"),
        float("inf"),
        float("-inf"),
        2**53,
        -(2**53),
        {1: "integer key"},
        {"k": "e\u0301"},
        {"e\u0301": 1},
        "\ud800",
        {"k": "x\udfff"},
        b"bytes",
        bytearray(b"x"),
        (1, 2),
        {1, 2},
        datetime(2026, 10, 28, tzinfo=UTC),
        _Color.RED,
        _MyStr("subclass"),
        object(),
    ],
    ids=lambda v: type(v).__name__ + ":" + ascii(v)[:30],
)
def test_invalid_values_rejected(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(value)


@pytest.mark.parametrize("make", [_nested_lists, _nested_objects])
def test_max_depth_is_inclusive(make: object) -> None:
    assert callable(make)
    canonical_json(make(MAX_DEPTH))
    with pytest.raises(CanonicalizationError, match="MAX_DEPTH"):
        canonical_json(make(MAX_DEPTH + 1))


def test_very_deep_value_is_rejected_without_recursion_error() -> None:
    with pytest.raises(CanonicalizationError, match="MAX_DEPTH"):
        canonical_json(_nested_lists(100_000))


def test_parse_round_trip_of_canonical_bytes() -> None:
    for _, value, expected, _ in CANONICAL_VECTORS:
        assert parse_strict_json(expected.decode("utf-8")) == value


def test_parse_accepts_max_depth() -> None:
    parse_strict_json("[" * MAX_DEPTH + "]" * MAX_DEPTH)


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":2}',
        '{"a":{"b":1,"b":1}}',
        "1.0",
        "1e3",
        "-0.0",
        "NaN",
        "Infinity",
        "-Infinity",
        '{"a":1} trailing',
        "[",
        "",
        '"\\ud800"',
        '"e\\u0301"',
        '{"e\\u0301":1}',
        "9007199254740992",
        "[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1),
        "[" * 100_000 + "]" * 100_000,
        "1" * 5000,
    ],
    ids=lambda t: ascii(t)[:30],
)
def test_parse_rejects(text: str) -> None:
    with pytest.raises(CanonicalizationError):
        parse_strict_json(text)


def test_parse_rejects_non_str_input() -> None:
    with pytest.raises(CanonicalizationError):
        parse_strict_json(b"{}")  # type: ignore[arg-type]
