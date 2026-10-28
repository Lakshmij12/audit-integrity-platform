"""Authorized redaction and retention (DESIGN.md sections 6 and 7).

Both operations keep every commitment, payload root, contentHash and recordHash exactly as stored;
nothing in the chain is recomputed. Each one appends a signed ``SYSTEM_*`` event in the same
``BEGIN IMMEDIATE`` transaction as the mutation, so the change and its authorization commit or roll
back together.

Redaction: remove value and salt of chosen leaves of one record; the signed authorization binds the
target seq, eventId, contentHash and the exact paths.

Retention: records with recordedAt older than the configured window are written to an archive file
first (fsync, then rename), then marked archived and their leaves deleted, together with a signed
run that records the archive's SHA-256. Failure handling:

* failure before COMMIT: the transaction rolls back and the new archive file is deleted;
* COMMIT outcome unknown (``StorageCommitUnknownError``): the file is kept, because the database may
  reference it. An archive file whose runId has no ``SYSTEM_RETENTION_RUN`` event is an orphan and
  can be deleted by an operator; it never affects verification.

After a successful COMMIT the WAL is checkpointed (best effort). That removes old values from the
WAL file only; it is not secure deletion (LIMITATIONS.md).
"""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Final

from aip.crypto.canonical import JsonValue, canonical_json, parse_strict_json, validate_json_value
from aip.crypto.commitments import build_leaves, payload_root, validate_path
from aip.crypto.errors import CryptoInputError
from aip.crypto.signing import Signer, sign_document
from aip.crypto.timestamps import format_timestamp
from aip.ingest.models import IngestValidationError, Issue
from aip.ingest.service import Clock, append_in_transaction
from aip.lifecycle.archive import archive_file_name, build_archive, new_run_id, write_archive
from aip.storage import repository
from aip.storage.database import Database
from aip.storage.errors import StorageCommitUnknownError
from aip.storage.repository import SYSTEM_EVENT_PREFIX

REDACTION_EVENT: Final = "SYSTEM_REDACTION"
RETENTION_EVENT: Final = "SYSTEM_RETENTION_RUN"
REDACTION_TAG: Final = "aip.redaction"
RETENTION_TAG: Final = "aip.retention"
AUTHORIZATION_VERSION: Final = 1
MAX_REDACTION_PATHS: Final = 100
MAX_REASON_CHARS: Final = 500
MAX_RUN_RECORDS: Final = 10_000


class LifecycleError(Exception):
    """Base class; messages never include payload values."""


class TargetNotFoundError(LifecycleError):
    pass


class TargetConflictError(LifecycleError):
    """The target cannot be changed (a SYSTEM_* event, or an archived record)."""


class SigningUnavailableError(LifecycleError):
    """No signing key is configured, so no authorization can be produced."""


@dataclass(frozen=True, slots=True)
class RedactionResult:
    target_event_id: str
    redaction_event_id: str | None  # None when every path was already redacted
    redaction_seq: int | None
    redacted_paths: list[list[str | int]]
    already_redacted_paths: list[list[str | int]]


@dataclass(frozen=True, slots=True)
class RetentionResult:
    dry_run: bool
    cutoff: str
    window_days: int
    record_count: int
    from_seq: int | None
    to_seq: int | None
    run_id: str | None = None
    retention_event_id: str | None = None
    archive_file: str | None = None
    archive_sha256: str | None = None
    wal_checkpointed: bool | None = None


def _system_payload(authorization: dict[str, Any], signature: str) -> dict[str, JsonValue]:
    return {"authorization": authorization, "signature": signature}


def _validate_paths(paths: object) -> list[str]:
    """Canonical path texts (as stored in payload_leaves), deduplicated and sorted."""
    if type(paths) is not list or not 1 <= len(paths) <= MAX_REDACTION_PATHS:
        raise IngestValidationError([Issue("paths", "must_be_1_to_100_paths")])
    texts = set()
    for path in paths:
        try:
            if type(path) is not list or not path:
                raise CryptoInputError("empty or non-list path")
            texts.add(canonical_json(list(validate_path(tuple(path)))).decode("utf-8"))
        except CryptoInputError:
            raise IngestValidationError([Issue("paths", "invalid_path")]) from None
    return sorted(texts)


def _validate_reason(reason: object) -> str:
    try:
        if type(reason) is not str or not 1 <= len(reason) <= MAX_REASON_CHARS:
            raise CryptoInputError("bad length")
        validate_json_value(reason)
    except CryptoInputError:
        raise IngestValidationError([Issue("reason", "must_be_1_to_500_valid_chars")]) from None
    return reason


class LifecycleService:
    def __init__(
        self,
        database: Database,
        *,
        signer: Signer | None,
        clock: Clock,
        archive_dir: Path,
        window_days: int,
    ) -> None:
        if type(window_days) is not int or window_days < 1:
            raise ValueError("window_days must be a positive int")
        self._database = database
        self._signer = signer
        self._clock = clock
        self._archive_dir = archive_dir
        self._window_days = window_days

    def _require_signer(self) -> Signer:
        if self._signer is None:
            raise SigningUnavailableError("signing key not configured")
        return self._signer

    def redact(
        self, event_id: str, paths: object, reason: object, *, requested_by: str
    ) -> RedactionResult:
        path_texts = _validate_paths(paths)
        reason_text = _validate_reason(reason)
        signer = self._require_signer()
        with self._database.write_transaction() as conn:
            record = repository.read_record_by_event_id(conn, event_id)
            if record is None:
                raise TargetNotFoundError("event not found")
            if record.event_type.startswith(SYSTEM_EVENT_PREFIX):
                raise TargetConflictError("SYSTEM_* events cannot be redacted")
            if repository.archive_state(conn, record.seq) is not None:
                raise TargetConflictError("archived records cannot be redacted")
            stored = {
                canonical_json(list(leaf.path)).decode("utf-8"): leaf
                for leaf in repository.load_leaves(conn, record.seq)
            }
            if any(text not in stored for text in path_texts):
                raise IngestValidationError([Issue("paths", "unknown_path")])
            to_redact = [text for text in path_texts if not stored[text].is_redacted]
            already = [parse_strict_json(text) for text in path_texts if text not in to_redact]
            if not to_redact:
                return RedactionResult(record.event_id, None, None, [], already)  # type: ignore[arg-type]
            authorization: dict[str, Any] = {
                "t": REDACTION_TAG,
                "v": AUTHORIZATION_VERSION,
                "targetSeq": record.seq,
                "targetEventId": record.event_id,
                "targetContentHash": record.content_hash,
                "paths": [parse_strict_json(text) for text in to_redact],
                "reason": reason_text,
                "requestedBy": requested_by,
                "requestedAt": format_timestamp(self._clock.now()),
                "keyId": signer.key_id,
            }
            payload = _system_payload(authorization, sign_document(signer, authorization))
            leaves = build_leaves(payload)
            appended = append_in_transaction(
                conn,
                self._clock,
                event_type=REDACTION_EVENT,
                actor_id=f"apikey:{requested_by}",
                resource_type="AUDIT_RECORD",
                resource_id=record.event_id,
                timestamp=None,
                leaves=leaves,
                root=payload_root(leaves),
            )
            repository.redact_leaves(conn, record.seq, to_redact)
        self._database.checkpoint_wal()
        return RedactionResult(
            record.event_id,
            appended.event_id,
            appended.seq,
            authorization["paths"],
            already,  # type: ignore[arg-type]
        )

    def run_retention(self, *, dry_run: bool, requested_by: str) -> RetentionResult:
        now = self._clock.now()
        now_text = format_timestamp(now)
        cutoff = format_timestamp(now - timedelta(days=self._window_days))
        if dry_run:
            with self._database.read_transaction() as conn:
                seqs = repository.retention_candidates(conn, cutoff, limit=MAX_RUN_RECORDS)
            return self._summary(True, cutoff, seqs)
        signer = self._require_signer()
        run_id = new_run_id()
        name = archive_file_name(run_id)
        path = self._archive_dir / name
        written = False
        try:
            with self._database.write_transaction() as conn:
                seqs = repository.retention_candidates(conn, cutoff, limit=MAX_RUN_RECORDS)
                if not seqs:
                    return self._summary(False, cutoff, seqs)
                records = []
                for seq in seqs:
                    record = repository.read_record(conn, seq)
                    if record is None:  # pragma: no cover - selected in this transaction
                        raise TargetNotFoundError("record vanished during retention")
                    records.append((record, repository.load_leaves(conn, seq)))
                digest = write_archive(path, build_archive(run_id, records))
                written = True
                authorization: dict[str, Any] = {
                    "t": RETENTION_TAG,
                    "v": AUTHORIZATION_VERSION,
                    "runId": run_id,
                    "cutoff": cutoff,
                    "windowDays": self._window_days,
                    "fromSeq": seqs[0],
                    "toSeq": seqs[-1],
                    "recordCount": len(seqs),
                    "archiveFile": name,
                    "archiveSha256": digest,
                    "archivedAt": now_text,
                    "requestedBy": requested_by,
                    "keyId": signer.key_id,
                }
                payload = _system_payload(authorization, sign_document(signer, authorization))
                leaves = build_leaves(payload)
                appended = append_in_transaction(
                    conn,
                    self._clock,
                    event_type=RETENTION_EVENT,
                    actor_id=f"apikey:{requested_by}",
                    resource_type="AUDIT_LOG",
                    resource_id=run_id,
                    timestamp=None,
                    leaves=leaves,
                    root=payload_root(leaves),
                )
                for seq in seqs:
                    repository.archive_record(conn, seq, archived_at=now_text, run_id=run_id)
        except StorageCommitUnknownError:
            raise  # keep the archive file: the database may reference it
        except BaseException:
            if written:
                path.unlink(missing_ok=True)
            raise
        summary = self._summary(False, cutoff, seqs)
        return RetentionResult(
            dry_run=False,
            cutoff=cutoff,
            window_days=self._window_days,
            record_count=summary.record_count,
            from_seq=summary.from_seq,
            to_seq=summary.to_seq,
            run_id=run_id,
            retention_event_id=appended.event_id,
            archive_file=name,
            archive_sha256=digest,
            wal_checkpointed=self._database.checkpoint_wal(),
        )

    def _summary(self, dry_run: bool, cutoff: str, seqs: list[int]) -> RetentionResult:
        return RetentionResult(
            dry_run=dry_run,
            cutoff=cutoff,
            window_days=self._window_days,
            record_count=len(seqs),
            from_seq=seqs[0] if seqs else None,
            to_seq=seqs[-1] if seqs else None,
        )
