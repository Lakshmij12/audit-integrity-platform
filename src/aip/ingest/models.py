"""Client-supplied event input, validation and resource limits.

Only the six fields from the specification are accepted; every server-controlled field (seq,
eventId, recordedAt, prevHash, payloadRoot, contentHash, recordHash) is rejected as an unknown
field. Validation errors name the field and a rule code, never the submitted value.
"""

import unicodedata
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aip.crypto.canonical import MAX_DEPTH, MAX_SAFE_INTEGER, parse_strict_json
from aip.crypto.errors import CryptoInputError
from aip.crypto.timestamps import normalize_timestamp

RESERVED_EVENT_PREFIX: Final = "SYSTEM_"


@dataclass(frozen=True, slots=True)
class Issue:
    field: str
    code: str


class IngestValidationError(ValueError):
    """The event was rejected. ``issues`` lists (field, rule code) pairs; no values are included."""

    def __init__(self, issues: list[Issue]) -> None:
        self.issues = tuple(issues)
        summary = ", ".join(f"{i.field} ({i.code})" for i in self.issues)
        super().__init__(f"invalid event: {summary}")


@dataclass(frozen=True, slots=True)
class IngestLimits:
    max_payload_bytes: int = 65_536  # canonical JSON bytes of the payload
    max_leaves: int = 1_000
    max_string_chars: int = 8_192  # any string value or object key inside the payload

    def __post_init__(self) -> None:
        for name in ("max_payload_bytes", "max_leaves", "max_string_chars"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive int")


def _check_identifier(value: str) -> str:
    if not unicodedata.is_normalized("NFC", value):
        raise ValueError("not_nfc")
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise ValueError("control_character")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("lone_surrogate")
    return value


class EventInput(BaseModel):
    """The client-supplied part of an audit event (field names as in the specification)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    event_type: str = Field(alias="eventType", pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    actor_id: str = Field(alias="actorId", min_length=1, max_length=256)
    resource_type: str = Field(alias="resourceType", min_length=1, max_length=128)
    resource_id: str = Field(alias="resourceId", min_length=1, max_length=256)
    payload: dict[str, Any]
    timestamp: str | None = None

    @field_validator("event_type")
    @classmethod
    def _not_reserved(cls, value: str) -> str:
        if value.startswith(RESERVED_EVENT_PREFIX):
            raise ValueError("reserved_event_type")
        return value

    @field_validator("actor_id", "resource_type", "resource_id")
    @classmethod
    def _identifier(cls, value: str) -> str:
        return _check_identifier(value)

    @field_validator("timestamp")
    @classmethod
    def _normalize(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return normalize_timestamp(value)
        except CryptoInputError:
            raise ValueError("invalid_timestamp") from None


def _issues_from(exc: ValidationError) -> list[Issue]:
    issues = []
    for error in exc.errors(include_input=False, include_url=False):
        field = ".".join(str(part) for part in error["loc"]) or "body"
        code = error["type"]
        if code == "value_error":
            code = str(error.get("ctx", {}).get("error", "value_error"))
        issues.append(Issue(field, code))
    return issues


def validate_event(data: object) -> EventInput:
    """Validate already-parsed input; raises IngestValidationError (no values in the message)."""
    if not isinstance(data, dict):
        raise IngestValidationError([Issue("body", "not_an_object")])
    try:
        return EventInput.model_validate(data)
    except ValidationError as exc:
        raise IngestValidationError(_issues_from(exc)) from None


def parse_event_json(text: str) -> EventInput:
    """Parse raw JSON strictly (duplicate keys, floats, NaN rejected), then validate."""
    try:
        data = parse_strict_json(text)
    except CryptoInputError:
        raise IngestValidationError([Issue("body", "invalid_json")]) from None
    return validate_event(data)


def check_payload_limits(payload: object, limits: IngestLimits) -> None:
    """Enforce depth, leaf count, string length and value rules before any commitment work.

    Walks the payload iteratively and stops at the first violation, so oversized input is
    rejected before salts are generated or anything is hashed.
    """
    if type(payload) is not dict:
        raise IngestValidationError([Issue("payload", "not_an_object")])
    leaves = 0
    stack: list[tuple[object, int]] = [(payload, 1)]
    while stack:
        value, depth = stack.pop()
        if type(value) is dict or type(value) is list:
            if depth > MAX_DEPTH:
                raise IngestValidationError([Issue("payload", "too_deep")])
            if not value:
                leaves += 1
            elif type(value) is dict:
                for key, child in value.items():
                    _check_payload_string(key, limits, "key")
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in value)
        else:
            leaves += 1
            _check_scalar(value, limits)
        if leaves > limits.max_leaves:
            raise IngestValidationError([Issue("payload", "too_many_leaves")])


def _check_payload_string(value: object, limits: IngestLimits, kind: str) -> None:
    if type(value) is not str:
        raise IngestValidationError([Issue("payload", f"{kind}_not_string")])
    if len(value) > limits.max_string_chars:
        raise IngestValidationError([Issue("payload", f"{kind}_too_long")])
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise IngestValidationError([Issue("payload", f"{kind}_lone_surrogate")])
    if not unicodedata.is_normalized("NFC", value):
        raise IngestValidationError([Issue("payload", f"{kind}_not_nfc")])


def _check_scalar(value: object, limits: IngestLimits) -> None:
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise IngestValidationError([Issue("payload", "integer_out_of_range")])
        return
    if type(value) is str:
        _check_payload_string(value, limits, "string")
        return
    if type(value) is float:
        raise IngestValidationError([Issue("payload", "float_not_allowed")])
    raise IngestValidationError([Issue("payload", "unsupported_type")])
