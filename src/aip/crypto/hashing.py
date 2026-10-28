"""SHA-256 content and record hashes, and the chain's genesis value."""

import hashlib
import re
from typing import Final, TypeGuard

from aip.crypto.canonical import MAX_SAFE_INTEGER, canonical_json, validate_string
from aip.crypto.errors import HashInputError
from aip.crypto.timestamps import require_canonical_timestamp

GENESIS_HASH: Final = "0" * 64
"""prevHash of the first record (seq 1)."""

CONTENT_TAG: Final = "aip.content"
RECORD_TAG: Final = "aip.record"
HASH_VERSION: Final = 1

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of ``data``."""
    if type(data) is not bytes:
        raise HashInputError(f"expected bytes, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()


def is_hex_digest(value: object) -> TypeGuard[str]:
    """True if ``value`` is exactly 64 lowercase hexadecimal characters.

    TypeGuard, not TypeIs: a False result does not mean "not a str" (most strings are not digests),
    so type checkers must not narrow the negative branch.
    """
    return type(value) is str and _HEX_DIGEST.fullmatch(value) is not None


def require_hex_digest(value: object, what: str) -> str:
    if not is_hex_digest(value):
        raise HashInputError(f"{what} must be 64 lowercase hex characters")
    return value


def _require_identifier(value: object, what: str) -> str:
    text = validate_string(value, what)
    if not text:
        raise HashInputError(f"{what} must not be empty")
    return text


def content_hash(
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    timestamp: str,
    payload_root: str,
) -> str:
    """Hash of a record's own content: its envelope fields and the root of its payload leaves."""
    preimage = {
        "t": CONTENT_TAG,
        "v": HASH_VERSION,
        "eventType": _require_identifier(event_type, "eventType"),
        "actorId": _require_identifier(actor_id, "actorId"),
        "resourceType": _require_identifier(resource_type, "resourceType"),
        "resourceId": _require_identifier(resource_id, "resourceId"),
        "timestamp": require_canonical_timestamp(timestamp, "timestamp"),
        "payloadRoot": require_hex_digest(payload_root, "payloadRoot"),
    }
    return sha256_hex(canonical_json(preimage))


def record_hash(*, seq: int, recorded_at: str, prev_hash: str, content_hash: str) -> str:
    """Hash linking a record to its predecessor: position, server time, prevHash and contentHash."""
    if type(seq) is not int or not 1 <= seq <= MAX_SAFE_INTEGER:
        raise HashInputError(f"seq must be an int in [1, {MAX_SAFE_INTEGER}]")
    preimage = {
        "t": RECORD_TAG,
        "v": HASH_VERSION,
        "seq": seq,
        "recordedAt": require_canonical_timestamp(recorded_at, "recordedAt"),
        "prevHash": require_hex_digest(prev_hash, "prevHash"),
        "contentHash": require_hex_digest(content_hash, "contentHash"),
    }
    return sha256_hex(canonical_json(preimage))
