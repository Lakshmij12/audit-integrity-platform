"""Authorized redaction: hashes kept, signed authorization, verification statuses, failures."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from aip.crypto.signing import Signer, generate_signing_key
from aip.ingest import IngestService, IngestValidationError
from aip.lifecycle import (
    REDACTION_EVENT,
    LifecycleService,
    SigningUnavailableError,
    TargetConflictError,
    TargetNotFoundError,
)
from aip.storage import Database, DatabaseConfig, open_database, repository
from aip.storage.errors import StorageError
from aip.verify import VerifyStatus, Violation, verify_database
from tests.ingest.support import FakeClock, make_event, raw_connection
from tests.lifecycle.conftest import SENSITIVE, WINDOW_DAYS, seed, verify


def _chain_snapshot(db_path: Path) -> list[tuple[Any, ...]]:
    conn = raw_connection(db_path)
    try:
        records = conn.execute(
            "SELECT seq, payload_root, content_hash, prev_hash, record_hash FROM audit_records "
            "WHERE seq <= 3 ORDER BY seq"
        ).fetchall()
        commitments = conn.execute(
            "SELECT seq, path, commitment FROM payload_leaves WHERE seq <= 3 ORDER BY seq, path"
        ).fetchall()
        return records + commitments
    finally:
        conn.close()


def test_redaction_keeps_every_hash_and_verifies(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
) -> None:
    ids = seed(service, clock, 3)
    before = _chain_snapshot(db_path)
    result = lifecycle.redact(ids[1], [["ssn"], ["tags", 0]], "privacy request", requested_by="k1")
    assert result.redacted_paths == [["ssn"], ["tags", 0]]
    assert result.redaction_seq == 4
    assert _chain_snapshot(db_path) == before  # commitments, roots and hashes untouched

    conn = raw_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT path, salt, value FROM payload_leaves WHERE seq = 2 AND salt IS NULL"
        ).fetchall()
        system = conn.execute("SELECT event_type, resource_id FROM audit_records WHERE seq = 4")
        assert system.fetchone() == (REDACTION_EVENT, ids[1])
    finally:
        conn.close()
    assert sorted(row[0] for row in rows) == ['["ssn"]', '["tags",0]']
    assert all(row[1] is None and row[2] is None for row in rows)

    report = verify(database, signer)
    assert report.status is VerifyStatus.VERIFIED
    assert report.redacted_leaves_authorized == 2
    assert SENSITIVE not in json.dumps(asdict(report), default=str)


def test_redacted_value_is_gone_from_the_database_files(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
) -> None:
    """With secure_delete and a WAL checkpoint, the value is not in the main file or the WAL.
    Backups, copies and archive files are out of scope (LIMITATIONS.md)."""
    marker = "REDACT-ME-" + "7" * 12
    ids = [service.append(_event(marker)).event_id]
    lifecycle.redact(ids[0], [["secret"]], "privacy", requested_by="k1")
    database.close()
    for path in (db_path, db_path.with_name(db_path.name + "-wal")):
        if path.exists():
            assert marker.encode() not in path.read_bytes()


def _event(secret: str) -> Any:
    return make_event(payload={"secret": secret, "keep": 1})


def test_already_redacted_paths_are_a_no_op(
    service: IngestService, lifecycle: LifecycleService, clock: FakeClock
) -> None:
    ids = seed(service, clock, 1)
    lifecycle.redact(ids[0], [["ssn"]], "first", requested_by="k1")
    again = lifecycle.redact(ids[0], [["ssn"]], "again", requested_by="k1")
    assert (again.redaction_event_id, again.redacted_paths) == (None, [])
    assert again.already_redacted_paths == [["ssn"]]
    mixed = lifecycle.redact(ids[0], [["ssn"], ["n"]], "more", requested_by="k1")
    assert (mixed.redacted_paths, mixed.already_redacted_paths) == ([["n"]], [["ssn"]])


@pytest.mark.parametrize(
    ("paths", "reason", "code"),
    [
        ([], "r", "must_be_1_to_100_paths"),
        ("ssn", "r", "must_be_1_to_100_paths"),
        ([[]], "r", "invalid_path"),
        ([["ssn", -1]], "r", "invalid_path"),
        ([["nope"]], "r", "unknown_path"),
        ([["tags"]], "r", "unknown_path"),  # a container, not a leaf
        ([["ssn"]], "", "must_be_1_to_500_valid_chars"),
        ([["ssn"]], "x" * 501, "must_be_1_to_500_valid_chars"),
        ([["ssn"]], "\ud800", "must_be_1_to_500_valid_chars"),
    ],
)
def test_invalid_redaction_requests(
    service: IngestService,
    lifecycle: LifecycleService,
    clock: FakeClock,
    paths: object,
    reason: object,
    code: str,
) -> None:
    ids = seed(service, clock, 1)
    with pytest.raises(IngestValidationError) as info:
        lifecycle.redact(ids[0], paths, reason, requested_by="k1")
    assert info.value.issues[0].code == code


def test_redaction_targets_that_cannot_change(
    service: IngestService, lifecycle: LifecycleService, clock: FakeClock
) -> None:
    ids = seed(service, clock, 1)
    with pytest.raises(TargetNotFoundError):
        lifecycle.redact("evt_" + "0" * 32, [["ssn"]], "r", requested_by="k1")
    system_id = lifecycle.redact(ids[0], [["ssn"]], "r", requested_by="k1").redaction_event_id
    assert system_id is not None
    with pytest.raises(TargetConflictError, match="SYSTEM_"):
        lifecycle.redact(system_id, [["signature"]], "r", requested_by="k1")


def test_redaction_needs_a_signing_key(
    service: IngestService, database: Database, clock: FakeClock, archive_dir: Path
) -> None:
    ids = seed(service, clock, 1)
    unsigned = LifecycleService(
        database, signer=None, clock=clock, archive_dir=archive_dir, window_days=WINDOW_DAYS
    )
    with pytest.raises(SigningUnavailableError):
        unsigned.redact(ids[0], [["ssn"]], "r", requested_by="k1")


def test_failure_inside_the_transaction_changes_nothing(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = seed(service, clock, 2)

    def fail(*_args: object) -> None:
        raise StorageError("simulated failure after the SYSTEM_REDACTION insert")

    monkeypatch.setattr(repository, "redact_leaves", fail)
    with pytest.raises(StorageError):
        lifecycle.redact(ids[0], [["ssn"]], "r", requested_by="k1")
    conn = raw_connection(db_path)
    try:
        assert conn.execute("SELECT count(*) FROM audit_records").fetchone()[0] == 2
        assert (
            conn.execute("SELECT count(*) FROM payload_leaves WHERE salt IS NULL").fetchone()[0]
            == 0
        )
    finally:
        conn.close()
    assert verify(database, signer).status is VerifyStatus.VERIFIED


def test_redaction_survives_a_restart(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
) -> None:
    ids = seed(service, clock, 2)
    lifecycle.redact(ids[0], [["ssn"]], "r", requested_by="k1")
    database.close()
    reopened = open_database(DatabaseConfig(db_path))
    try:
        report = verify(reopened, signer)
        assert (report.status, report.redacted_leaves_authorized) == (VerifyStatus.VERIFIED, 1)
    finally:
        reopened.close()


def test_without_a_trusted_key_redaction_is_indeterminate(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
) -> None:
    ids = seed(service, clock, 1)
    lifecycle.redact(ids[0], [["ssn"]], "r", requested_by="k1")
    report = verify(database, None)
    assert (report.status, report.redacted_leaves_unverified) == (VerifyStatus.INDETERMINATE, 1)
    assert report.first_inconsistency is None


def test_authorization_under_the_wrong_key_is_not_accepted(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
    signer: Signer,
    tmp_path: Path,
) -> None:
    """A trusted key with the same keyId but a different public key: the signature fails, so the
    redaction is unauthorized (reported at the target, the first record affected)."""
    ids = seed(service, clock, 1)
    lifecycle.redact(ids[0], [["ssn"]], "r", requested_by="k1")
    generate_signing_key(tmp_path / "other.pem")
    other = Signer.from_pem_file(tmp_path / "other.pem")
    report = verify_database(database, trusted_keys={signer.key_id: other.public_key})
    assert report.status is VerifyStatus.TAMPERED
    assert report.first_inconsistency is not None
    assert report.first_inconsistency.violation is Violation.UNAUTHORIZED_REDACTION


@pytest.mark.parametrize(
    ("statement", "violation", "seq"),
    [
        (  # an authorization for ["ssn"] does not cover ["n"]
            "UPDATE payload_leaves SET salt = NULL, value = NULL "
            "WHERE seq = 1 AND path = '[\"n\"]'",
            Violation.UNAUTHORIZED_REDACTION,
            1,
        ),
        (  # nor the same path of another record
            "UPDATE payload_leaves SET salt = NULL, value = NULL "
            "WHERE seq = 2 AND path = '[\"ssn\"]'",
            Violation.UNAUTHORIZED_REDACTION,
            2,
        ),
        (  # an altered authorization fails its signature, so it covers nothing; the first
            # record affected is the redacted target
            "UPDATE payload_leaves SET value = '\"other reason\"' "
            'WHERE seq = 3 AND path = \'["authorization","reason"]\'',
            Violation.UNAUTHORIZED_REDACTION,
            1,
        ),
        (  # an authorization cannot be removed to hide the redaction
            "DELETE FROM payload_leaves WHERE seq = 3",
            Violation.UNAUTHORIZED_REDACTION,
            1,
        ),
    ],
)
def test_redaction_tampering_is_detected(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
    statement: str,
    violation: Violation,
    seq: int,
) -> None:
    ids = seed(service, clock, 2)
    lifecycle.redact(ids[0], [["ssn"]], "r", requested_by="k1")
    conn = raw_connection(db_path)
    try:
        for trigger in ("payload_leaves_no_update", "payload_leaves_no_delete"):
            conn.execute(f"DROP TRIGGER {trigger}")
        conn.execute(statement)
    finally:
        conn.close()
    report = verify(database, signer)
    assert report.status is VerifyStatus.TAMPERED
    assert report.first_inconsistency is not None
    assert (report.first_inconsistency.violation, report.first_inconsistency.seq) == (
        violation,
        seq,
    )
    assert SENSITIVE not in json.dumps(asdict(report), default=str)


def test_indeterminate_seqs_name_only_the_unverifiable_redaction(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
    signer: Signer,
) -> None:
    ids = seed(service, clock, 3)
    lifecycle.redact(ids[1], [["ssn"]], "r", requested_by="k1")
    assert verify(database, signer).indeterminate_seqs == set()
    assert verify(database, None).indeterminate_seqs == {2}
