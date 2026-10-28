"""Retention and archival: dry run, signed runs, archive evidence, tampering, failure handling."""

import json
from pathlib import Path

import pytest

from aip.crypto.hashing import sha256_hex
from aip.crypto.signing import Signer
from aip.ingest import IngestService
from aip.lifecycle import (
    RETENTION_EVENT,
    LifecycleService,
    SigningUnavailableError,
    TargetConflictError,
)
from aip.lifecycle.archive import (
    ArchiveError,
    archive_file_name,
    parse_archive,
    write_archive,
)
from aip.storage import Database, DatabaseConfig, open_database, repository
from aip.storage.errors import StorageCommitUnknownError, StorageError
from aip.verify import VerifyStatus, Violation
from tests.ingest.support import FakeClock, count_rows, raw_connection
from tests.lifecycle.conftest import SENSITIVE, WINDOW_DAYS, seed, verify


def _age(service: IngestService, clock: FakeClock, old: int, new: int) -> list[str]:
    """``old`` events, then WINDOW_DAYS + 1 days later ``new`` events."""
    ids = seed(service, clock, old)
    clock.advance(days=WINDOW_DAYS + 1)
    return ids + seed(service, clock, new)


def _archive(lifecycle: LifecycleService) -> tuple[str, str]:
    result = lifecycle.run_retention(dry_run=False, requested_by="k1")
    assert result.run_id is not None
    assert result.archive_file is not None
    return result.run_id, result.archive_file


def test_dry_run_reports_and_changes_nothing(
    service: IngestService, lifecycle: LifecycleService, db_path: Path, clock: FakeClock
) -> None:
    _age(service, clock, 3, 2)
    before = count_rows(db_path)
    result = lifecycle.run_retention(dry_run=True, requested_by="k1")
    assert (result.dry_run, result.record_count, result.from_seq, result.to_seq) == (
        True,
        3,
        1,
        3,
    )
    assert result.run_id is None
    assert count_rows(db_path) == before


def test_retention_archives_old_records_and_verifies(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
) -> None:
    _age(service, clock, 3, 2)
    result = lifecycle.run_retention(dry_run=False, requested_by="k1")
    assert (result.record_count, result.from_seq, result.to_seq) == (3, 1, 3)
    assert result.archive_file is not None
    assert result.run_id is not None
    data = (archive_dir / result.archive_file).read_bytes()
    assert sha256_hex(data) == result.archive_sha256
    assert sorted(parse_archive(data, result.run_id)) == [1, 2, 3]
    assert result.wal_checkpointed is True

    conn = raw_connection(db_path)
    try:
        archived = conn.execute(
            "SELECT seq FROM audit_records WHERE archived_at IS NOT NULL ORDER BY seq"
        ).fetchall()
        leaves = conn.execute("SELECT DISTINCT seq FROM payload_leaves ORDER BY seq").fetchall()
        last = conn.execute("SELECT event_type FROM audit_records ORDER BY seq DESC LIMIT 1")
        assert last.fetchone()[0] == RETENTION_EVENT
    finally:
        conn.close()
    assert [row[0] for row in archived] == [1, 2, 3]
    assert [row[0] for row in leaves] == [4, 5, 6]

    report = verify(database, signer, archive_dir)
    assert report.status is VerifyStatus.VERIFIED
    assert report.archived_records_verified == 3
    # the SYSTEM_RETENTION_RUN event is never selected by a later run
    again = lifecycle.run_retention(dry_run=True, requested_by="k1")
    assert again.record_count == 0


def test_nothing_to_archive_appends_nothing(
    service: IngestService, lifecycle: LifecycleService, db_path: Path, clock: FakeClock
) -> None:
    seed(service, clock, 2)
    result = lifecycle.run_retention(dry_run=False, requested_by="k1")
    assert (result.record_count, result.run_id) == (0, None)
    assert count_rows(db_path)[0] == 2


def test_missing_archive_file_is_indeterminate_not_tampered(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
) -> None:
    _age(service, clock, 2, 1)
    _, name = _archive(lifecycle)
    (archive_dir / name).unlink()
    report = verify(database, signer, archive_dir)
    assert report.status is VerifyStatus.INDETERMINATE
    assert report.archived_content_unavailable == 2
    assert report.first_inconsistency is None
    assert verify(database, signer, None).status is VerifyStatus.INDETERMINATE


def test_without_a_trusted_key_archival_is_indeterminate(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
    archive_dir: Path,
) -> None:
    _age(service, clock, 2, 1)
    _archive(lifecycle)
    report = verify(database, None, archive_dir)
    assert (report.status, report.archived_records_unverified) == (VerifyStatus.INDETERMINATE, 2)


def test_altered_archive_file_is_detected(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
) -> None:
    _age(service, clock, 2, 1)
    _, name = _archive(lifecycle)
    path = archive_dir / name
    data = path.read_bytes()
    assert data.count(b'"value":1}') == 1  # record 2's "n"
    path.write_bytes(data.replace(b'"value":1}', b'"value":9}'))
    report = verify(database, signer, archive_dir)
    assert report.status is VerifyStatus.TAMPERED
    assert report.first_inconsistency is not None
    assert report.first_inconsistency.violation is Violation.ARCHIVE_CONTENT_MISMATCH
    assert SENSITIVE not in json.dumps(str(report))


@pytest.mark.parametrize(
    ("statements", "violation", "seq"),
    [
        (  # archived without any run
            [
                "UPDATE audit_records SET archived_at = '2026-12-01T00:00:00.000000Z', "
                "archive_run_id = 'run_" + "0" * 32 + "' WHERE seq = 4",
                "DELETE FROM payload_leaves WHERE seq = 4",
            ],
            Violation.INVALID_ARCHIVE,
            4,
        ),
        (  # a recent record smuggled into the existing run (outside its signed range and cutoff)
            [
                "UPDATE audit_records SET (archived_at, archive_run_id) = "
                "(SELECT archived_at, archive_run_id FROM audit_records WHERE seq = 1) "
                "WHERE seq = 4",
                "DELETE FROM payload_leaves WHERE seq = 4",
            ],
            Violation.INVALID_ARCHIVE,
            4,
        ),
        (  # leaves of a live record deleted (no archive marking)
            ["DELETE FROM payload_leaves WHERE seq = 4"],
            Violation.MALFORMED_LEAF,
            4,
        ),
        (  # the run event removed: its archived records lose their evidence
            ["DELETE FROM payload_leaves WHERE seq = 5"],
            Violation.INVALID_ARCHIVE,
            1,
        ),
        (  # archived row with its leaves restored in the database is not a clean archive
            [
                "INSERT INTO payload_leaves (seq, path, commitment, salt, value) "
                "SELECT 1, path, commitment, salt, value FROM payload_leaves WHERE seq = 4",
            ],
            Violation.INVALID_ARCHIVE,
            1,
        ),
    ],
)
def test_unauthorized_archival_is_detected(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
    statements: list[str],
    violation: Violation,
    seq: int,
) -> None:
    _age(service, clock, 2, 2)  # seqs 1-2 old, 3-4 recent; the run becomes seq 5
    run_id, _ = _archive(lifecycle)
    assert run_id
    conn = raw_connection(db_path)
    try:
        for trigger in ("audit_records_no_update", "payload_leaves_no_delete"):
            conn.execute(f"DROP TRIGGER {trigger}")
        for statement in statements:
            conn.execute(statement)
    finally:
        conn.close()
    report = verify(database, signer, archive_dir)
    assert report.status is VerifyStatus.TAMPERED
    assert report.first_inconsistency is not None
    assert (report.first_inconsistency.violation, report.first_inconsistency.seq) == (
        violation,
        seq,
    )


def test_redacted_then_archived_record_verifies(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
) -> None:
    ids = _age(service, clock, 2, 1)
    lifecycle.redact(ids[0], [["ssn"]], "privacy", requested_by="k1")
    run_id, name = _archive(lifecycle)
    archived = parse_archive((archive_dir / name).read_bytes(), run_id)
    ssn = [leaf for leaf in archived[1] if leaf.path == ("ssn",)]
    assert [(leaf.is_redacted, leaf.value) for leaf in ssn] == [(True, None)]
    report = verify(database, signer, archive_dir)
    assert report.status is VerifyStatus.VERIFIED
    assert (report.archived_records_verified, report.redacted_leaves_authorized) == (2, 1)
    with pytest.raises(TargetConflictError, match="archived"):
        lifecycle.redact(ids[1], [["ssn"]], "too late", requested_by="k1")


def test_retention_needs_a_signing_key_except_for_dry_runs(
    service: IngestService, database: Database, clock: FakeClock, archive_dir: Path
) -> None:
    _age(service, clock, 1, 1)
    unsigned = LifecycleService(
        database, signer=None, clock=clock, archive_dir=archive_dir, window_days=WINDOW_DAYS
    )
    assert unsigned.run_retention(dry_run=True, requested_by="k1").record_count == 1
    with pytest.raises(SigningUnavailableError):
        unsigned.run_retention(dry_run=False, requested_by="k1")
    assert not archive_dir.exists()


def test_failure_before_commit_rolls_back_and_removes_the_file(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _age(service, clock, 2, 1)
    before = count_rows(db_path)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise StorageError("simulated failure while marking records archived")

    monkeypatch.setattr(repository, "archive_record", fail)
    with pytest.raises(StorageError):
        lifecycle.run_retention(dry_run=False, requested_by="k1")
    assert count_rows(db_path) == before
    assert list(archive_dir.iterdir()) == []
    assert verify(database, signer, archive_dir).status is VerifyStatus.VERIFIED


def test_unknown_commit_outcome_keeps_the_archive_file(
    service: IngestService,
    lifecycle: LifecycleService,
    clock: FakeClock,
    archive_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _age(service, clock, 1, 1)

    def unknown(*_args: object, **_kwargs: object) -> None:
        raise StorageCommitUnknownError("simulated: COMMIT outcome unknown")

    monkeypatch.setattr(repository, "archive_record", unknown)
    with pytest.raises(StorageCommitUnknownError):
        lifecycle.run_retention(dry_run=False, requested_by="k1")
    assert len(list(archive_dir.glob("run_*.json"))) == 1  # possibly referenced: never deleted


def test_retention_survives_a_restart(
    service: IngestService,
    lifecycle: LifecycleService,
    database: Database,
    db_path: Path,
    clock: FakeClock,
    signer: Signer,
    archive_dir: Path,
) -> None:
    _age(service, clock, 2, 1)
    _archive(lifecycle)
    database.close()
    reopened = open_database(DatabaseConfig(db_path))
    try:
        report = verify(reopened, signer, archive_dir)
        assert (report.status, report.archived_records_verified) == (VerifyStatus.VERIFIED, 2)
    finally:
        reopened.close()


def test_window_must_be_positive(database: Database, clock: FakeClock, archive_dir: Path) -> None:
    with pytest.raises(ValueError, match="window_days"):
        LifecycleService(database, signer=None, clock=clock, archive_dir=archive_dir, window_days=0)


@pytest.mark.parametrize(
    "data",
    [
        b"\xff",
        b"[]",
        b'{"t":"aip.archive","v":1,"runId":"run_other","records":[]}',
        b'{"t":"aip.archive","v":1,"runId":"RUN","records":[{"seq":"1","leaves":[]}]}',
        b'{"t":"aip.archive","v":1,"runId":"RUN","records":[{"seq":1,"leaves":[{"path":"a",'
        b'"commitment":"x","salt":null,"value":null}]}]}',
        b'{"t":"aip.archive","v":1,"runId":"RUN","records":[{"seq":1}]}',
    ],
)
def test_malformed_archive_files_are_rejected(data: bytes) -> None:
    with pytest.raises(ArchiveError):
        parse_archive(data, "RUN")


def test_archive_names_and_files_are_never_overwritten(tmp_path: Path) -> None:
    with pytest.raises(ArchiveError):
        archive_file_name("../escape")
    path = tmp_path / (archive_file_name("run_" + "a" * 32))
    write_archive(path, b"{}")
    with pytest.raises(FileExistsError):
        write_archive(path, b"{}")
