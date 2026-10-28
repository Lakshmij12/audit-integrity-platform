"""Event input validation, server-field rejection, strict parsing and payload limits."""

from typing import Any

import pytest

from aip.crypto.canonical import MAX_DEPTH, MAX_SAFE_INTEGER
from aip.ingest import (
    IngestLimits,
    IngestValidationError,
    check_payload_limits,
    parse_event_json,
    validate_event,
)
from tests.ingest.support import event_data

SERVER_FIELDS = [
    "seq",
    "eventId",
    "recordedAt",
    "prevHash",
    "payloadRoot",
    "contentHash",
    "recordHash",
]


def _codes(exc: IngestValidationError) -> set[tuple[str, str]]:
    return {(issue.field, issue.code) for issue in exc.issues}


def test_valid_event_uses_specification_field_names() -> None:
    event = validate_event(event_data(timestamp="2026-10-28T14:30:00.5+02:30"))
    assert event.event_type == "RECORD_UPDATED"
    assert event.actor_id == "user-0042"
    assert event.timestamp == "2026-10-28T12:00:00.500000Z"
    assert validate_event(event_data()).timestamp is None


@pytest.mark.parametrize("name", SERVER_FIELDS)
def test_server_controlled_fields_are_rejected(name: str) -> None:
    with pytest.raises(IngestValidationError) as caught:
        validate_event(event_data(**{name: "anything"}))
    assert (name, "extra_forbidden") in _codes(caught.value)


def test_snake_case_names_are_not_accepted() -> None:
    data = event_data()
    data["event_type"] = data.pop("eventType")
    with pytest.raises(IngestValidationError) as caught:
        validate_event(data)
    assert ("eventType", "missing") in _codes(caught.value)
    assert ("event_type", "extra_forbidden") in _codes(caught.value)


@pytest.mark.parametrize("name", ["eventType", "actorId", "resourceType", "resourceId", "payload"])
def test_required_fields(name: str) -> None:
    data = event_data()
    del data[name]
    with pytest.raises(IngestValidationError) as caught:
        validate_event(data)
    assert (name, "missing") in _codes(caught.value)


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"actorId": 42}, ("actorId", "string_type")),
        ({"resourceId": None}, ("resourceId", "string_type")),
        ({"payload": ["not", "an", "object"]}, ("payload", "dict_type")),
        ({"payload": "{}"}, ("payload", "dict_type")),
        ({"timestamp": 1730116800}, ("timestamp", "string_type")),
        ({"eventType": "user_login"}, ("eventType", "string_pattern_mismatch")),
        ({"eventType": "USER LOGIN"}, ("eventType", "string_pattern_mismatch")),
        ({"eventType": "1ABC"}, ("eventType", "string_pattern_mismatch")),
        ({"eventType": ""}, ("eventType", "string_pattern_mismatch")),
        ({"eventType": "USER_LOGIN\n"}, ("eventType", "string_pattern_mismatch")),
        ({"eventType": "A" * 129}, ("eventType", "string_pattern_mismatch")),
        ({"eventType": "SYSTEM_REDACTION"}, ("eventType", "reserved_event_type")),
        ({"actorId": ""}, ("actorId", "string_too_short")),
        ({"actorId": "x" * 257}, ("actorId", "string_too_long")),
        ({"resourceType": "x" * 129}, ("resourceType", "string_too_long")),
        ({"actorId": "e\u0301"}, ("actorId", "not_nfc")),
        ({"resourceId": "a\x00b"}, ("resourceId", "control_character")),
        ({"resourceId": "a\x7fb"}, ("resourceId", "control_character")),
        # Pydantic rejects lone surrogates itself (before the custom validator runs)
        ({"actorId": "x\ud800"}, ("actorId", "string_unicode")),
        ({"timestamp": "2026-10-28T12:00:00"}, ("timestamp", "invalid_timestamp")),
        ({"timestamp": "2026-02-30T12:00:00Z"}, ("timestamp", "invalid_timestamp")),
    ],
)
def test_field_validation(overrides: dict[str, Any], expected: tuple[str, str]) -> None:
    with pytest.raises(IngestValidationError) as caught:
        validate_event(event_data(**overrides))
    assert expected in _codes(caught.value)


@pytest.mark.parametrize("event_type", ["A", "USER_LOGIN", "PERMISSION_GRANTED", "A" * 128])
def test_valid_event_types(event_type: str) -> None:
    assert validate_event(event_data(eventType=event_type)).event_type == event_type


def test_body_must_be_an_object() -> None:
    with pytest.raises(IngestValidationError) as caught:
        validate_event(["not", "an", "object"])
    assert _codes(caught.value) == {("body", "not_an_object")}


@pytest.mark.parametrize(
    "body",
    [
        '{"eventType":"A","eventType":"B","actorId":"a","resourceType":"r","resourceId":"i",'
        '"payload":{}}',
        '{"eventType":"A","actorId":"a","resourceType":"r","resourceId":"i","payload":{"x":1.5}}',
        '{"eventType":"A","actorId":"a","resourceType":"r","resourceId":"i","payload":{"x":NaN}}',
        '{"eventType":"A","actorId":"a","resourceType":"r","resourceId":"i","payload":{}} trailing',
        '{"eventType":"A","actorId":"a","resourceType":"r","resourceId":"i","payload":{"a":1,"a":2}}',
    ],
)
def test_parse_event_json_rejects_ambiguous_json(body: str) -> None:
    with pytest.raises(IngestValidationError) as caught:
        parse_event_json(body)
    assert _codes(caught.value) == {("body", "invalid_json")}


def test_parse_event_json_accepts_valid_json() -> None:
    body = (
        '{"eventType":"USER_LOGIN","actorId":"a","resourceType":"r","resourceId":"i",'
        '"payload":{"n":1}}'
    )
    assert parse_event_json(body).payload == {"n": 1}


SENSITIVE = "900-12-3456-" + "PRIVATE"


@pytest.mark.parametrize(
    "data",
    [
        event_data(actorId=SENSITIVE + "\x00"),
        event_data(eventType=SENSITIVE),
        event_data(timestamp=SENSITIVE),
        event_data(**{"recordHash": SENSITIVE}),
        event_data(payload={"ssn": SENSITIVE + "e\u0301"}),
    ],
)
def test_errors_never_contain_submitted_values(data: dict[str, Any]) -> None:
    def attempt() -> None:
        event = validate_event(data)
        check_payload_limits(event.payload, IngestLimits())

    with pytest.raises(IngestValidationError) as caught:
        attempt()
    assert SENSITIVE not in str(caught.value)
    assert SENSITIVE not in repr(caught.value.issues)
    assert caught.value.__cause__ is None


# --- payload limits ---------------------------------------------------------------------------


def _nested(depth: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


@pytest.mark.parametrize(
    ("payload", "limits", "code"),
    [
        (_nested(MAX_DEPTH + 1), IngestLimits(), "too_deep"),
        ({str(i): i for i in range(11)}, IngestLimits(max_leaves=10), "too_many_leaves"),
        ({"a": [[] for _ in range(11)]}, IngestLimits(max_leaves=10), "too_many_leaves"),
        ({"s": "x" * 9}, IngestLimits(max_string_chars=8), "string_too_long"),
        ({"k" * 9: 1}, IngestLimits(max_string_chars=8), "key_too_long"),
        ({"f": 1.5}, IngestLimits(), "float_not_allowed"),
        ({"i": MAX_SAFE_INTEGER + 1}, IngestLimits(), "integer_out_of_range"),
        ({"s": "e\u0301"}, IngestLimits(), "string_not_nfc"),
        ({"e\u0301": 1}, IngestLimits(), "key_not_nfc"),
        ({"s": "\ud800"}, IngestLimits(), "string_lone_surrogate"),
        ({1: "x"}, IngestLimits(), "key_not_string"),
        ({"t": (1, 2)}, IngestLimits(), "unsupported_type"),
        ({"b": b"x"}, IngestLimits(), "unsupported_type"),
    ],
)
def test_payload_limits(payload: dict[Any, Any], limits: IngestLimits, code: str) -> None:
    with pytest.raises(IngestValidationError) as caught:
        check_payload_limits(payload, limits)
    assert _codes(caught.value) == {("payload", code)}


def test_payload_limits_at_the_boundary_pass() -> None:
    check_payload_limits(_nested(MAX_DEPTH), IngestLimits())
    check_payload_limits({str(i): i for i in range(10)}, IngestLimits(max_leaves=10))
    check_payload_limits({"s": "x" * 8, "k" * 8: True}, IngestLimits(max_string_chars=8))
    check_payload_limits({"i": MAX_SAFE_INTEGER, "n": None, "e": [], "o": {}}, IngestLimits())


@pytest.mark.parametrize(
    "kwargs", [{"max_leaves": 0}, {"max_payload_bytes": -1}, {"max_string_chars": True}]
)
def test_invalid_limits(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="positive int"):
        IngestLimits(**kwargs)
