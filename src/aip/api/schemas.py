"""Response bodies (field names follow the specification's camelCase)."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Response(BaseModel):
    model_config = ConfigDict(populate_by_name=True, frozen=True)


class AppendResponse(_Response):
    seq: int
    event_id: str = Field(alias="eventId")
    recorded_at: str = Field(alias="recordedAt")
    timestamp: str
    content_hash: str = Field(alias="contentHash")
    record_hash: str = Field(alias="recordHash")


class EventView(_Response):
    seq: int
    event_id: str = Field(alias="eventId")
    event_type: str = Field(alias="eventType")
    actor_id: str = Field(alias="actorId")
    resource_type: str = Field(alias="resourceType")
    resource_id: str = Field(alias="resourceId")
    timestamp: str
    recorded_at: str = Field(alias="recordedAt")
    payload: dict[str, Any]  # redacted leaves read as null; {} for an archived record
    redacted_paths: list[list[str | int]] = Field(alias="redactedPaths")
    archived: bool
    payload_root: str = Field(alias="payloadRoot")
    content_hash: str = Field(alias="contentHash")
    prev_hash: str = Field(alias="prevHash")
    record_hash: str = Field(alias="recordHash")


class EventPage(_Response):
    items: list[EventView]
    next_cursor: str | None = Field(alias="nextCursor")


class InconsistencyView(_Response):
    seq: int
    violation_type: str = Field(alias="violationType")
    event_id: str | None = Field(alias="eventId")
    field: str | None
    leaf_path: list[str | int] | None = Field(alias="leafPath")
    expected: str | None
    actual: str | None


class AnchorView(_Response):
    seq: int
    record_hash: str = Field(alias="recordHash")
    matched: bool | None


class UnverifiedView(_Response):
    redacted_leaves: int = Field(alias="redactedLeaves")
    archived_records: int = Field(alias="archivedRecords")
    archived_content_unavailable: int = Field(alias="archivedContentUnavailable")


class AuthorizedView(_Response):
    redacted_leaves: int = Field(alias="redactedLeaves")
    archived_records: int = Field(alias="archivedRecords")


class RedactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    paths: list[list[str | int]] = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


class RedactionResponse(_Response):
    target_event_id: str = Field(alias="targetEventId")
    redaction_event_id: str | None = Field(alias="redactionEventId")
    redaction_seq: int | None = Field(alias="redactionSeq")
    redacted_paths: list[list[str | int]] = Field(alias="redactedPaths")
    already_redacted_paths: list[list[str | int]] = Field(alias="alreadyRedactedPaths")


class RetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)
    dry_run: bool = Field(default=True, alias="dryRun")


class RetentionResponse(_Response):
    dry_run: bool = Field(alias="dryRun")
    cutoff: str
    window_days: int = Field(alias="windowDays")
    record_count: int = Field(alias="recordCount")
    from_seq: int | None = Field(alias="fromSeq")
    to_seq: int | None = Field(alias="toSeq")
    run_id: str | None = Field(alias="runId")
    retention_event_id: str | None = Field(alias="retentionEventId")
    archive_file: str | None = Field(alias="archiveFile")
    archive_sha256: str | None = Field(alias="archiveSha256")
    wal_checkpointed: bool | None = Field(alias="walCheckpointed")


class VerifyResponse(_Response):
    status: Literal["VERIFIED", "INDETERMINATE", "TAMPERED"]
    intact: bool | None  # null when INDETERMINATE: neither confirmed intact nor tampered
    records_checked: int = Field(alias="recordsChecked")
    head_seq: int = Field(alias="headSeq")
    head_record_hash: str = Field(alias="headRecordHash")
    first_inconsistency: InconsistencyView | None = Field(alias="firstInconsistency")
    anchor: AnchorView | None
    authorized: AuthorizedView
    unverified: UnverifiedView
    notes: list[str]


class CheckpointResponse(_Response):
    seq: int
    record_hash: str = Field(alias="recordHash")
    signed_at: str = Field(alias="signedAt")
    key_id: str = Field(alias="keyId")
    signature: str
    public_key: str = Field(alias="publicKey")
