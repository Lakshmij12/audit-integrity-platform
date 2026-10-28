"""Full-chain verification: valid chains, tampering, malformed rows, future states, anchors."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from aip.crypto import Leaf, canonical_json, commit_leaf, content_hash, payload_root, record_hash
from aip.ingest import IngestService
from aip.storage import Database, load_leaves
from aip.verify import Anchor, VerifyReport, VerifyStatus, Violation, verify_database
from tests.ingest.support import FakeClock, make_event, raw_connection

SENSITIVE = "acct-" + "900123456"


def _seed(service: IngestService, clock: FakeClock, count: int = 5) -> None:
    for i in range(count):
        service.append(
            make_event(
                actorId=f"actor-{i}",
                payload={"n": i, "ssn": SENSITIVE, "tags": ["a", "b"], "empty": {}},
            )
        )
        clock.advance(seconds=1)


def _tamper(db_path: Path, *statements: str) -> None:
    conn = raw_connection(db_path)
    try:
        for trigger in (
            "audit_records_no_update",
            "audit_records_no_delete",
            "payload_leaves_no_update",
            "payload_leaves_no_delete",
        ):
            conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        for statement in statements:
            conn.execute(statement)
    finally:
        conn.close()


def _problem(report: VerifyReport) -> tuple[Any, ...]:
    assert report.first_inconsistency is not None
    p = report.first_inconsistency
    return (p.violation, p.seq, p.field, p.leaf_path)


def _assert_no_values(report: VerifyReport, *values: str) -> None:
    dumped = json.dumps(asdict(report), default=str)
    for value in values:
        assert value not in dumped


def test_empty_chain_is_intact(database: Database) -> None:
    report = verify_database(database)
    assert (report.intact, report.records_checked, report.head_seq) == (True, 0, 0)
    assert any("internal consistency only" in note for note in report.notes)


def test_valid_chain_is_intact_across_batches(
    service: IngestService, database: Database, clock: FakeClock
) -> None:
    _seed(service, clock, 7)
    report = verify_database(database, batch_size=3)
    assert report.intact
    assert report.records_checked == 7
    assert report.head_seq == 7
    assert report.first_inconsistency is None


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (
            "UPDATE payload_leaves SET value = '4242' WHERE seq = 3 AND path = '[\"n\"]'",
            (Violation.LEAF_COMMITMENT_MISMATCH, 3, "payload", ["n"]),
        ),
        (
            "UPDATE payload_leaves SET value = '\"z\"' WHERE seq = 3 AND path = '[\"tags\",1]'",
            (Violation.LEAF_COMMITMENT_MISMATCH, 3, "payload", ["tags", 1]),
        ),
        (
            "UPDATE payload_leaves SET commitment = '" + "0" * 64 + "' "
            "WHERE seq = 3 AND path = '[\"n\"]'",
            (Violation.LEAF_COMMITMENT_MISMATCH, 3, "payload", ["n"]),
        ),
        (
            "UPDATE audit_records SET payload_root = '" + "1" * 64 + "' WHERE seq = 3",
            (Violation.PAYLOAD_ROOT_MISMATCH, 3, None, None),
        ),
        (
            "UPDATE audit_records SET actor_id = 'someone-else' WHERE seq = 3",
            (Violation.CONTENT_HASH_MISMATCH, 3, None, None),
        ),
        (
            "UPDATE audit_records SET timestamp = '2020-01-01T00:00:00.000000Z' WHERE seq = 3",
            (Violation.CONTENT_HASH_MISMATCH, 3, None, None),
        ),
        (
            "UPDATE audit_records SET content_hash = '" + "2" * 64 + "' WHERE seq = 3",
            (Violation.RECORD_HASH_MISMATCH, 3, None, None),
        ),
        (
            "UPDATE audit_records SET record_hash = '" + "3" * 64 + "' WHERE seq = 3",
            (Violation.RECORD_HASH_MISMATCH, 3, None, None),
        ),
        (
            "UPDATE audit_records SET prev_hash = '" + "4" * 64 + "' WHERE seq = 3",
            (Violation.PREV_HASH_MISMATCH, 3, None, None),
        ),
        (
            "UPDATE audit_records SET event_id = 'evt_' || substr(content_hash, 1, 32) "
            "WHERE seq = 3",
            (Violation.EVENT_ID_MISMATCH, 3, "eventId", None),
        ),
    ],
)
def test_direct_tampering_is_detected(
    service: IngestService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    statement: str,
    expected: tuple[Any, ...],
) -> None:
    _seed(service, clock)
    _tamper(db_path, statement)
    report = verify_database(database)
    assert report.intact is False
    assert _problem(report) == expected
    assert report.records_checked == 2  # stopped at the first violation
    _assert_no_values(report, SENSITIVE, "someone-else", "4242")


def test_deleted_record_is_a_sequence_gap(
    service: IngestService, database: Database, db_path: Path, clock: FakeClock
) -> None:
    _seed(service, clock)
    _tamper(
        db_path,
        "DELETE FROM payload_leaves WHERE seq = 2",
        "DELETE FROM audit_records WHERE seq = 2",
    )
    report = verify_database(database)
    assert _problem(report) == (Violation.SEQUENCE_GAP, 2, None, None)
    assert report.first_inconsistency is not None
    assert (report.first_inconsistency.expected, report.first_inconsistency.actual) == ("2", "3")


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (  # 27 characters, so the schema's length CHECK still passes
            "UPDATE audit_records SET recorded_at = 'SECRET-VALUE-not-timestamp!' WHERE seq = 3",
            (Violation.MALFORMED_RECORD, 3, "recordedAt", None),
        ),
        (  # not NFC-normalized: contentHash cannot be computed
            "UPDATE audit_records SET actor_id = 'e' || char(769) WHERE seq = 3",
            (Violation.MALFORMED_RECORD, 3, "envelope", None),
        ),
        (
            "UPDATE payload_leaves SET path = '{\"SECRET-VALUE\":1}' "
            "WHERE seq = 3 AND path = '[\"n\"]'",
            (Violation.MALFORMED_LEAF, 3, "leaves", None),
        ),
        (
            "UPDATE payload_leaves SET value = 'SECRET-VALUE not json' "
            "WHERE seq = 3 AND path = '[\"n\"]'",
            (Violation.MALFORMED_LEAF, 3, "leaves", None),
        ),
        (
            "DELETE FROM payload_leaves WHERE seq = 3 AND path = '[\"tags\",0]'",
            (Violation.MALFORMED_LEAF, 3, "leaves", None),
        ),
        (
            "DELETE FROM payload_leaves WHERE seq = 3 AND path = '[\"n\"]'",
            (Violation.PAYLOAD_ROOT_MISMATCH, 3, None, None),
        ),
    ],
)
def test_malformed_rows_are_reported_without_their_values(
    service: IngestService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    statement: str,
    expected: tuple[Any, ...],
) -> None:
    _seed(service, clock)
    _tamper(db_path, statement)
    report = verify_database(database)
    assert report.intact is False
    assert _problem(report) == expected
    _assert_no_values(report, "SECRET-VALUE", SENSITIVE)


def test_redacted_leaf_is_counted_as_unverified_not_tampered(
    service: IngestService, database: Database, db_path: Path, clock: FakeClock
) -> None:
    _seed(service, clock)
    _tamper(
        db_path,
        "UPDATE payload_leaves SET salt = NULL, value = NULL WHERE seq = 2 AND path = '[\"ssn\"]'",
    )
    report = verify_database(database)
    assert report.intact is True
    assert report.status is VerifyStatus.INDETERMINATE
    assert report.redacted_leaves_unverified == 1
    assert any("not implemented" in note for note in report.notes)


def test_archived_record_is_counted_as_unverified_not_tampered(
    service: IngestService, database: Database, db_path: Path, clock: FakeClock
) -> None:
    _seed(service, clock)
    _tamper(
        db_path,
        "DELETE FROM payload_leaves WHERE seq = 1",
        "UPDATE audit_records SET archived_at = '2026-10-29T00:00:00.000000Z', "
        "archive_run_id = 'run-1' WHERE seq = 1",
    )
    report = verify_database(database)
    assert report.intact is True
    assert report.status is VerifyStatus.INDETERMINATE
    assert report.archived_records_unverified == 1


def _rewrite_from(database: Database, db_path: Path, seq: int, new_value: int) -> None:
    """A coordinated rewrite by someone with file access: change a value, then recompute the
    commitment, payload root, contentHash, recordHash and eventId of that record and every later
    record. No secret is needed: salts are stored next to the values."""
    with database.read_transaction() as conn:
        leaves = load_leaves(conn, seq)
        rows = conn.exec_driver_sql(
            "SELECT seq, event_type, actor_id, resource_type, resource_id, timestamp, "
            "recorded_at, payload_root, prev_hash FROM audit_records WHERE seq >= ? ORDER BY seq",
            (seq,),
        ).all()
    target = next(leaf for leaf in leaves if leaf.path == ("n",))
    assert target.salt is not None
    commitment = commit_leaf(target.path, target.salt, new_value)
    new_leaves = [
        Leaf(leaf.path, commitment, leaf.salt, new_value) if leaf.path == ("n",) else leaf
        for leaf in leaves
    ]
    value_text = canonical_json(new_value).decode()
    statements = [
        f"UPDATE payload_leaves SET commitment = '{commitment}', value = '{value_text}' "  # noqa: S608
        f"WHERE seq = {seq} AND path = '[\"n\"]'"
    ]
    prev = rows[0][8]
    for s, etype, actor, rtype, rid, ts, rec_at, stored_root, _stored_prev in rows:
        root = payload_root(new_leaves) if s == seq else stored_root
        content = content_hash(
            event_type=etype,
            actor_id=actor,
            resource_type=rtype,
            resource_id=rid,
            timestamp=ts,
            payload_root=root,
        )
        digest = record_hash(seq=s, recorded_at=rec_at, prev_hash=prev, content_hash=content)
        statements.append(
            f"UPDATE audit_records SET payload_root = '{root}', content_hash = '{content}', "  # noqa: S608
            f"prev_hash = '{prev}', record_hash = '{digest}', event_id = 'evt_{digest[:32]}' "
            f"WHERE seq = {s}"
        )
        prev = digest
    _tamper(db_path, *statements)


def test_coordinated_rewrite_needs_a_trusted_anchor(
    service: IngestService, database: Database, db_path: Path, clock: FakeClock
) -> None:
    _seed(service, clock)
    saved = verify_database(database)
    anchor = Anchor(saved.head_seq, saved.head_record_hash)
    _rewrite_from(database, db_path, 2, 777)
    plain = verify_database(database)
    assert plain.intact is True  # internal consistency only: the rewrite is not visible
    anchored = verify_database(database, anchor=anchor)
    assert anchored.intact is False
    assert _problem(anchored) == (Violation.ANCHOR_MISMATCH, 5, None, None)
    assert anchored.anchor_matched is False


def test_truncation_needs_a_trusted_anchor(
    service: IngestService, database: Database, db_path: Path, clock: FakeClock
) -> None:
    _seed(service, clock)
    saved = verify_database(database)
    _tamper(
        db_path,
        "DELETE FROM payload_leaves WHERE seq >= 4",
        "DELETE FROM audit_records WHERE seq >= 4",
    )
    assert verify_database(database).intact is True
    anchored = verify_database(database, anchor=Anchor(saved.head_seq, saved.head_record_hash))
    assert _problem(anchored) == (Violation.TRUNCATED, 4, None, None)


def test_matching_anchor(service: IngestService, database: Database, clock: FakeClock) -> None:
    _seed(service, clock)
    earlier = verify_database(database)
    service.append(make_event())  # the chain may grow past the anchor
    report = verify_database(database, anchor=Anchor(earlier.head_seq, earlier.head_record_hash))
    assert report.intact is True
    assert report.anchor_matched is True
    assert not any("internal consistency only" in note for note in report.notes)
