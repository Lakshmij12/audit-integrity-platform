"""Response bodies (field names follow the specification's camelCase)."""

from typing import Any

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
    payload: dict[str, Any]
    payload_root: str = Field(alias="payloadRoot")
    content_hash: str = Field(alias="contentHash")
    prev_hash: str = Field(alias="prevHash")
    record_hash: str = Field(alias="recordHash")


class EventPage(_Response):
    items: list[EventView]
    next_cursor: str | None = Field(alias="nextCursor")
