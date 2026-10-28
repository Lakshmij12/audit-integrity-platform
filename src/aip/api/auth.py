"""API-key authentication and role-based authorization.

Clients send ``X-API-Key``. The service stores only SHA-256 hashes of keys (``AIP_API_KEYS``),
hashes the presented key and compares it against every configured hash with
``hmac.compare_digest``. With no keys configured every request is rejected (fail closed).

Roles: ``writer`` may append events; ``auditor`` may read; ``admin`` may do both.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Final

from fastapi import HTTPException, Request, status

ROLES: Final = frozenset({"writer", "auditor", "admin"})
CAN_WRITE: Final = frozenset({"writer", "admin"})
CAN_READ: Final = frozenset({"auditor", "admin"})
API_KEY_HEADER: Final = "X-API-Key"
_HASH = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True, slots=True)
class ApiKeyEntry:
    role: str
    key_hash: str


@dataclass(frozen=True, slots=True)
class Principal:
    role: str
    key_id: str  # first 8 hex characters of the key hash, safe to log


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """A new random API key (256 bits of entropy, URL-safe)."""
    return secrets.token_urlsafe(32)


def parse_api_keys(raw: str) -> tuple[ApiKeyEntry, ...]:
    """Parse ``role:sha256hex`` entries; raises ValueError (without echoing values) if malformed."""
    entries = []
    for position, item in enumerate(part.strip() for part in raw.split(",")):
        if not item:
            continue
        role, sep, key_hash = item.partition(":")
        if not sep or role not in ROLES or not _HASH.fullmatch(key_hash):
            raise ValueError(f"AIP_API_KEYS entry {position + 1} is not 'role:sha256hex'")
        entries.append(ApiKeyEntry(role, key_hash))
    return tuple(entries)


def authenticate(presented: str | None, entries: tuple[ApiKeyEntry, ...]) -> Principal | None:
    if not presented:
        return None
    digest = hash_api_key(presented)
    match: ApiKeyEntry | None = None
    for entry in entries:  # compare against every entry; no early exit
        if hmac.compare_digest(digest, entry.key_hash):
            match = entry
    return None if match is None else Principal(match.role, match.key_hash[:8])


def _require(request: Request, allowed: frozenset[str]) -> Principal:
    entries: tuple[ApiKeyEntry, ...] = request.app.state.api_keys
    principal = authenticate(request.headers.get(API_KEY_HEADER), entries)
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or invalid API key")
    if principal.role not in allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "role not permitted for this operation")
    request.state.principal = principal
    return principal


def require_writer(request: Request) -> Principal:
    return _require(request, CAN_WRITE)


def require_reader(request: Request) -> Principal:
    return _require(request, CAN_READ)
