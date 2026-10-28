"""RFC 3339 parsing and canonical timestamps."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from aip.crypto.errors import TimestampError
from aip.crypto.timestamps import (
    format_timestamp,
    is_canonical_timestamp,
    normalize_timestamp,
    parse_timestamp,
    require_canonical_timestamp,
)


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("2026-10-28T12:00:00Z", "2026-10-28T12:00:00.000000Z"),
        ("2026-10-28T12:00:00.1Z", "2026-10-28T12:00:00.100000Z"),
        ("2026-10-28T12:00:00.123Z", "2026-10-28T12:00:00.123000Z"),
        ("2026-10-28T12:00:00.123456Z", "2026-10-28T12:00:00.123456Z"),
        ("2026-10-28T14:30:00+02:30", "2026-10-28T12:00:00.000000Z"),
        ("2026-10-28T00:30:00-01:00", "2026-10-28T01:30:00.000000Z"),
        ("2026-12-31T23:30:00-01:00", "2027-01-01T00:30:00.000000Z"),
        ("2027-01-01T00:30:00+01:00", "2026-12-31T23:30:00.000000Z"),
        ("2024-02-29T00:00:00Z", "2024-02-29T00:00:00.000000Z"),
        ("2026-10-28T12:00:00+23:59", "2026-10-27T12:01:00.000000Z"),
        ("2026-10-28T12:00:00+00:00", "2026-10-28T12:00:00.000000Z"),
    ],
)
def test_normalize(text: str, canonical: str) -> None:
    assert normalize_timestamp(text) == canonical
    assert parse_timestamp(text).tzinfo is UTC


@pytest.mark.parametrize(
    "text",
    [
        "2026-10-28T12:00:00",
        "2026-10-28 12:00:00Z",
        "2026-10-28t12:00:00Z",
        "2026-10-28T12:00:00z",
        "2026-10-28T12:00:00.1234567Z",
        "2026-10-28T12:00:00.Z",
        "2026-10-28T12:00:60Z",
        "2026-10-28T24:00:00Z",
        "2026-10-28T12:60:00Z",
        "2026-02-30T12:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-10-28T12:00:00+24:00",
        "2026-10-28T12:00:00+05:60",
        "2026-10-28T12:00:00-00:00",
        "2026-10-28T12:00:00+0200",
        "2026-10-28T12:00:00+02",
        "0000-01-01T00:00:00Z",
        "9999-12-31T23:59:59-01:00",
        "0001-01-01T00:00:00+01:00",
        "\uff12\uff10\uff12\uff16-10-28T12:00:00Z",
        " 2026-10-28T12:00:00Z",
        "2026-10-28T12:00:00Z ",
        "",
    ],
    ids=lambda t: ascii(t),
)
def test_parse_rejects(text: str) -> None:
    with pytest.raises(TimestampError):
        parse_timestamp(text)


def test_parse_rejects_non_str() -> None:
    with pytest.raises(TimestampError):
        parse_timestamp(1730116800)  # type: ignore[arg-type]


def test_format_converts_to_utc_with_six_digits() -> None:
    moment = datetime(2026, 10, 28, 14, 30, 0, 5, tzinfo=timezone(timedelta(hours=2, minutes=30)))
    assert format_timestamp(moment) == "2026-10-28T12:00:00.000005Z"


class _ShiftedDatetime(datetime):
    """A subclass that lies about its UTC conversion."""

    def astimezone(self, tz: object = None) -> datetime:  # type: ignore[override]
        return datetime(2000, 1, 1, tzinfo=UTC)


def test_format_rejects_datetime_subclasses() -> None:
    moment = _ShiftedDatetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    with pytest.raises(TimestampError, match="expected datetime"):
        format_timestamp(moment)


def test_format_rejects_naive_and_non_datetime() -> None:
    with pytest.raises(TimestampError, match="naive"):
        format_timestamp(datetime(2026, 10, 28, 12, 0, 0))
    with pytest.raises(TimestampError):
        format_timestamp("2026-10-28T12:00:00Z")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-28T12:00:00.000000Z", True),
        ("2026-10-28T12:00:00Z", False),
        ("2026-10-28T12:00:00.000000+00:00", False),
        ("2026-02-30T00:00:00.000000Z", False),
        ("2026-10-28T12:00:60.000000Z", False),
        (None, False),
        (1730116800, False),
    ],
)
def test_is_canonical_timestamp(value: object, expected: bool) -> None:
    assert is_canonical_timestamp(value) is expected


def test_require_canonical_timestamp() -> None:
    assert require_canonical_timestamp("2026-10-28T12:00:00.000000Z") == (
        "2026-10-28T12:00:00.000000Z"
    )
    with pytest.raises(TimestampError):
        require_canonical_timestamp("2026-10-28T12:00:00Z")
