"""RFC 3339 timestamps and their canonical form: ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` in UTC."""

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import TypeGuard

from aip.crypto.errors import TimestampError

# Accepted input: uppercase 'T' separator, optional 1-6 fractional digits, and either 'Z' or a
# +/-HH:MM offset. re.ASCII keeps \d to the digits 0-9.
_RFC3339 = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,6}))?"
    r"(?:(?P<zulu>Z)|(?P<sign>[+-])(?P<off_hour>\d{2}):(?P<off_minute>\d{2}))",
    re.ASCII,
)
_CANONICAL = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", re.ASCII)


def parse_timestamp(text: str) -> datetime:
    """Parse a strict RFC 3339 timestamp and return it as an aware UTC datetime."""
    if type(text) is not str:
        raise TimestampError(f"timestamp must be str, got {type(text).__name__}")
    match = _RFC3339.fullmatch(text)
    if match is None:
        raise TimestampError(
            "timestamp must be RFC 3339 with a 'T' separator, at most 6 fractional digits "
            "and a 'Z' or +/-HH:MM offset"
        )
    hour, minute, second = int(match["hour"]), int(match["minute"]), int(match["second"])
    if second == 60:
        raise TimestampError("leap seconds are not supported")
    if hour > 23 or minute > 59 or second > 59:
        raise TimestampError("time of day out of range")
    if match["zulu"]:
        tz = UTC
    else:
        off_hour, off_minute = int(match["off_hour"]), int(match["off_minute"])
        if off_hour > 23 or off_minute > 59:
            raise TimestampError("UTC offset out of range")
        if match["sign"] == "-" and off_hour == 0 and off_minute == 0:
            raise TimestampError("offset -00:00 (unknown local offset) is not accepted")
        sign = 1 if match["sign"] == "+" else -1
        tz = timezone(sign * timedelta(hours=off_hour, minutes=off_minute))
    microsecond = int((match["fraction"] or "").ljust(6, "0"))
    try:
        local = datetime(
            int(match["year"]),
            int(match["month"]),
            int(match["day"]),
            hour,
            minute,
            second,
            microsecond,
            tzinfo=tz,
        )
        return local.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise TimestampError(f"invalid date or time: {exc}") from exc


def format_timestamp(moment: datetime) -> str:
    """Return the canonical form of an aware datetime: UTC, exactly 6 fractional digits, 'Z'."""
    # Exact type, as elsewhere: a datetime subclass could override astimezone() or its fields.
    if type(moment) is not datetime:
        raise TimestampError(f"expected datetime, got {type(moment).__name__}")
    if moment.utcoffset() is None:
        raise TimestampError("naive datetime: a UTC offset is required")
    try:
        utc = moment.astimezone(UTC)
    except OverflowError as exc:
        raise TimestampError(f"timestamp out of range in UTC: {exc}") from exc
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}.{utc.microsecond:06d}Z"
    )


def normalize_timestamp(text: str) -> str:
    """Parse an RFC 3339 timestamp and return its canonical form."""
    return format_timestamp(parse_timestamp(text))


def is_canonical_timestamp(value: object) -> TypeGuard[str]:
    """True if ``value`` is already a valid timestamp in canonical form.

    TypeGuard, not TypeIs: a False result does not mean "not a str".
    """
    if type(value) is not str or _CANONICAL.fullmatch(value) is None:
        return False
    try:
        return normalize_timestamp(value) == value
    except TimestampError:
        return False


def require_canonical_timestamp(value: object, what: str = "timestamp") -> str:
    """Return ``value`` if it is a canonical timestamp, otherwise raise TimestampError."""
    if not is_canonical_timestamp(value):
        raise TimestampError(f"{what} must be a canonical timestamp YYYY-MM-DDTHH:MM:SS.ffffffZ")
    return value
