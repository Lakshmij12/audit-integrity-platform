"""Append-only ingestion: stored-record recomputation, timestamps, restart, fail-closed reads."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aip.crypto import GENESIS_HASH, format_timestamp
from aip.ingest import IngestLimits, IngestService, IngestValidationError
from aip.ingest import service as service_module
from aip.storage import (
    Database,
    DatabaseConfig,
    StorageIntegrityError,
    derive_event_id,
    load_leaves,
    open_database,
    read_record,
)
from tests.ingest.support import (
    START,
    FakeClock,
    count_rows,
    make_event,
    raw_connection,
    verify_store,
)

PAYLOADS: list[dict[str, Any]] = [
    {"field": "email", "changed": True},
    {"account": {"number": "900123456", "type": "BROKERAGE"}, "flags": [True, None]},
    {},
    {"empty_list": [], "empty_obj": {}, "nested": [{"a": []}, [[]]]},
    {"note": "caf\u00e9 \u20ac", "n": -9007199254740991, "zero": 0},
    {"0": "numeric key", "list": ["x", "y", "z"]},
]


def test_first_append(service: IngestService, database: Database) -> None:
    result = service.append(make_event())
    assert result.seq == 1
    assert result.event_id == derive_event_id(result.record_hash)
    assert result.event_id.startswith("evt_")
    assert len(result.event_id) == 36
    assert result.recorded_at == format_timestamp(START)
    assert result.timestamp == result.recorded_at  # omitted timestamp -> server clock
    with database.read_transaction() as conn:
        record = read_record(conn, 1)
    assert record is not None
    assert record.prev_hash == GENESIS_HASH
    assert (record.record_hash, record.content_hash) == (result.record_hash, result.content_hash)


def test_every_stored_record_recomputes(
    service: IngestService, database: Database, clock: FakeClock
) -> None:
    expected: dict[int, dict[str, Any]] = {}
    for i, payload in enumerate(PAYLOADS * 4):
        result = service.append(make_event(actorId=f"actor-{i}", payload=payload))
        expected[result.seq] = payload
        clock.advance(milliseconds=7)
    assert verify_store(database, expected) == len(PAYLOADS) * 4


def test_json_null_is_stored_as_text_not_as_redaction(
    service: IngestService, db_path: Path
) -> None:
    service.append(make_event(payload={"n": None}))
    conn = raw_connection(db_path)
    try:
        salt, value = conn.execute("SELECT salt, value FROM payload_leaves").fetchone()
    finally:
        conn.close()
    assert value == "null"
    assert salt is not None


@pytest.mark.parametrize(
    ("supplied", "stored"),
    [
        ("2026-10-28T14:30:00+02:30", "2026-10-28T12:00:00.000000Z"),
        ("2026-10-28T12:05:00Z", "2026-10-28T12:05:00.000000Z"),  # exactly +5 minutes: allowed
        ("2020-01-01T00:00:00Z", "2020-01-01T00:00:00.000000Z"),  # past: allowed
    ],
)
def test_supplied_timestamp_is_normalized(
    service: IngestService, supplied: str, stored: str
) -> None:
    assert service.append(make_event(timestamp=supplied)).timestamp == stored


def test_timestamp_more_than_five_minutes_ahead_is_rejected(
    service: IngestService, db_path: Path
) -> None:
    with pytest.raises(IngestValidationError) as caught:
        service.append(make_event(timestamp="2026-10-28T12:05:00.000001Z"))
    assert {(i.field, i.code) for i in caught.value.issues} == {("timestamp", "too_far_in_future")}
    assert count_rows(db_path) == (0, 0)


def test_clock_rollback_clamps_recorded_at_but_not_timestamp_checks(
    service: IngestService, clock: FakeClock
) -> None:
    first = service.append(make_event())
    clock.current = START - timedelta(hours=1)  # server clock moves backwards
    second = service.append(make_event())
    assert second.recorded_at == first.recorded_at  # nondecreasing: clamped to the head
    assert second.timestamp == format_timestamp(START - timedelta(hours=1))  # real clock
    # The future limit uses the real clock, not the clamped recordedAt:
    within_clamp = format_timestamp(START - timedelta(minutes=54))  # < recordedAt, > now + 5 min
    with pytest.raises(IngestValidationError):
        service.append(make_event(timestamp=within_clamp))


def test_head_far_ahead_of_the_clock_does_not_relax_future_checks(
    database: Database,
) -> None:
    clock = FakeClock(datetime(2030, 1, 1, tzinfo=UTC))
    service = IngestService(database, clock=clock)
    service.append(make_event())  # head recordedAt is in 2030
    clock.current = START  # back to 2026-10-28
    result = service.append(make_event())
    assert result.recorded_at == "2030-01-01T00:00:00.000000Z"  # clamped to the head
    assert result.timestamp == format_timestamp(START)  # default uses the real clock
    for supplied in ("2027-01-01T00:00:00Z", "2026-10-28T12:10:00Z"):
        with pytest.raises(IngestValidationError):
            service.append(make_event(timestamp=supplied))
    assert service.append(make_event(timestamp="2026-10-28T12:04:00Z")).seq == 3


def test_recorded_at_is_nondecreasing_with_a_jittering_clock(
    service: IngestService, database: Database, clock: FakeClock
) -> None:
    previous = ""
    for step in [5, -3, 10, -20, 1, 0, -1, 30]:
        clock.advance(seconds=step)
        recorded = service.append(make_event()).recorded_at
        assert recorded >= previous
        previous = recorded
    assert verify_store(database) == 8


def test_restart_persistence(db_path: Path) -> None:
    clock = FakeClock()
    first = open_database(DatabaseConfig(db_path))
    try:
        service = IngestService(first, clock=clock)
        for i in range(3):
            service.append(make_event(payload={"i": i}))
    finally:
        first.close()
    clock.advance(seconds=1)
    second = open_database(DatabaseConfig(db_path))
    try:
        service = IngestService(second, clock=clock)
        assert service.append(make_event(payload={"i": 3})).seq == 4
        assert service.append(make_event(payload={"i": 4})).seq == 5
        assert verify_store(second, {i + 1: {"i": i} for i in range(5)}) == 5
    finally:
        second.close()


def _tamper(db_path: Path, *statements: str) -> None:
    """Simulate direct file access: drop the guard triggers, then modify rows."""
    conn = raw_connection(db_path)
    try:
        conn.execute("DROP TRIGGER audit_records_no_update")
        conn.execute("DROP TRIGGER payload_leaves_no_update")
        for statement in statements:
            conn.execute(statement)
    finally:
        conn.close()


def test_read_record_validates_event_id_derivation(
    service: IngestService, database: Database, db_path: Path
) -> None:
    service.append(make_event())
    _tamper(db_path, "UPDATE audit_records SET event_id = 'evt_' || substr(content_hash, 1, 32)")
    with pytest.raises(StorageIntegrityError, match="eventId"), database.read_transaction() as conn:
        read_record(conn, 1)


def test_malformed_head_fails_closed(
    service: IngestService, database: Database, db_path: Path
) -> None:
    service.append(make_event())
    _tamper(db_path, "UPDATE audit_records SET recorded_at = 'not-a-canonical-timestamp-x'")
    with pytest.raises(StorageIntegrityError, match="malformed"):
        service.append(make_event())
    assert count_rows(db_path)[0] == 1


def test_malformed_leaf_rows_fail_closed(
    service: IngestService, database: Database, db_path: Path
) -> None:
    service.append(make_event(payload={"a": 1}))
    _tamper(db_path, 'UPDATE payload_leaves SET path = \'{"not":"an array"}\'')
    with pytest.raises(StorageIntegrityError), database.read_transaction() as conn:
        load_leaves(conn, 1)


def test_limits_are_enforced_before_salts_are_generated(
    database: Database, monkeypatch: pytest.MonkeyPatch, db_path: Path
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(service_module, "build_leaves", lambda payload: calls.append(payload))
    service = IngestService(
        database, clock=FakeClock(), limits=IngestLimits(max_leaves=5, max_payload_bytes=64)
    )
    with pytest.raises(IngestValidationError, match="too_many_leaves"):
        service.append(make_event(payload={str(i): i for i in range(6)}))
    with pytest.raises(IngestValidationError, match="too_large"):
        service.append(make_event(payload={"s": "x" * 100}))
    assert calls == []
    assert count_rows(db_path) == (0, 0)


def test_append_result_matches_the_committed_row(
    service: IngestService, database: Database
) -> None:
    results = [service.append(make_event(payload={"i": i})) for i in range(3)]
    with database.read_transaction() as conn:
        for result in results:
            record = read_record(conn, result.seq)
            assert record is not None
            assert (record.event_id, record.recorded_at, record.timestamp) == (
                result.event_id,
                result.recorded_at,
                result.timestamp,
            )
