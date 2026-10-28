"""Salted per-leaf commitments over typed paths, and the payload root.

A payload (a JSON object) is flattened into leaves. Each leaf is addressed by a *typed path*: a
tuple whose items are ``str`` for object keys and ``int`` for array indices, so ``("a", 0)`` (the
first element of an array) and ``("a", "0")`` (an object key "0") are different paths and hash
differently. Scalars and empty containers are leaves; non-empty containers are not.

    leafCommitment = SHA256(canon(["aip-leaf-v1", path, saltHex, value]))
    payloadRoot    = SHA256(canon({"t": "aip.payload", "v": 1,
                                   "leaves": [[path, leafCommitment], ...]}))

Leaves in the payload root are ordered by the bytes of canon(path).

The payload root depends only on paths and commitments, so deleting a leaf's value and salt
(redaction) leaves it unchanged. A redacted leaf can no longer be checked against its value.
"""

import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from aip.crypto.canonical import (
    MAX_DEPTH,
    MAX_SAFE_INTEGER,
    JsonValue,
    canonical_json,
    validate_json_value,
    validate_string,
)
from aip.crypto.errors import CanonicalizationError, LeafError
from aip.crypto.hashing import is_hex_digest, sha256_hex

LEAF_TAG: Final = "aip-leaf-v1"
PAYLOAD_TAG: Final = "aip.payload"
PAYLOAD_VERSION: Final = 1
SALT_BYTES: Final = 32

type PathToken = str | int
type TypedPath = tuple[PathToken, ...]


class LeafStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    REDACTED_UNVERIFIED = "REDACTED_UNVERIFIED"
    """Value and salt are absent: the commitment cannot be checked. Whether the redaction was
    authorized is decided elsewhere (signed authorizations, not part of this module)."""


def validate_path(path: object) -> TypedPath:
    """Return ``path`` if it is a tuple of NFC strings and non-negative ints, <= MAX_DEPTH long."""
    if type(path) is not tuple:
        raise LeafError(f"path must be a tuple, got {type(path).__name__}")
    if len(path) > MAX_DEPTH:
        raise LeafError(f"path longer than MAX_DEPTH={MAX_DEPTH}")
    for token in path:
        if type(token) is int:
            if not 0 <= token <= MAX_SAFE_INTEGER:
                raise LeafError("array index must be a non-negative safe integer")
        elif type(token) is str:
            try:
                validate_string(token, "object key")
            except CanonicalizationError as exc:
                raise LeafError(str(exc)) from exc
        else:
            raise LeafError(f"path token must be str or int, got {type(token).__name__}")
    validated: TypedPath = path
    return validated


def validate_leaf_value(path: TypedPath, value: object) -> JsonValue:
    """A leaf value is a scalar, or an empty container that keeps the payload within MAX_DEPTH.

    The root leaf ``()`` exists only for the empty payload, so its value must be the empty object.
    """
    if path == () and (type(value) is not dict or value):
        raise LeafError("the root leaf () must hold the empty object {}")
    if type(value) in (list, dict):
        if value:
            raise LeafError("a leaf value must be a scalar or an empty container")
        if len(path) + 1 > MAX_DEPTH:
            raise LeafError(f"empty container at this path exceeds MAX_DEPTH={MAX_DEPTH}")
    try:
        validate_json_value(value)
    except CanonicalizationError as exc:
        raise LeafError(f"invalid leaf value: {exc}") from exc
    validated: JsonValue = value  # type: ignore[assignment]
    return validated


def _validate_salt(salt: object) -> bytes:
    if type(salt) is not bytes or len(salt) != SALT_BYTES:
        raise LeafError(f"salt must be exactly {SALT_BYTES} bytes")
    return salt


def _path_sort_key(path: TypedPath) -> bytes:
    return canonical_json(list(path))


@dataclass(frozen=True, slots=True)
class Leaf:
    """One committed payload leaf. ``salt is None`` means the leaf is redacted."""

    path: TypedPath
    commitment: str
    salt: bytes | None = field(default=None, repr=False)
    value: JsonValue = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_path(self.path)
        if not is_hex_digest(self.commitment):
            raise LeafError("commitment must be 64 lowercase hex characters")
        if self.salt is None:
            if self.path == ():
                raise LeafError("the root leaf () holds no data and cannot be redacted")
            if self.value is not None:
                raise LeafError("a redacted leaf must not carry a value")
        else:
            _validate_salt(self.salt)
            validate_leaf_value(self.path, self.value)

    @property
    def is_redacted(self) -> bool:
        return self.salt is None

    def redacted(self) -> Leaf:
        """The same leaf with its value and salt removed (logical redaction)."""
        return Leaf(self.path, self.commitment)


def commit_leaf(path: TypedPath, salt: bytes, value: JsonValue) -> str:
    """Commitment to one leaf: binds its typed path, its salt and its value."""
    validate_path(path)
    _validate_salt(salt)
    validate_leaf_value(path, value)
    return sha256_hex(canonical_json([LEAF_TAG, list(path), salt.hex(), value]))


def check_leaf(leaf: Leaf) -> LeafStatus:
    """VALID or INVALID for revealed leaves; REDACTED_UNVERIFIED when value and salt are absent."""
    if leaf.salt is None:
        return LeafStatus.REDACTED_UNVERIFIED
    if commit_leaf(leaf.path, leaf.salt, leaf.value) == leaf.commitment:
        return LeafStatus.VALID
    return LeafStatus.INVALID


def flatten_payload(payload: object) -> list[tuple[TypedPath, JsonValue]]:
    """Split a payload object into (typed path, leaf value) pairs, ordered by canonical path."""
    if type(payload) is not dict:
        raise LeafError("payload must be a JSON object")
    try:
        validate_json_value(payload)
    except CanonicalizationError as exc:
        raise LeafError(f"invalid payload: {exc}") from exc
    out: list[tuple[TypedPath, JsonValue]] = []
    _flatten(payload, (), out)
    out.sort(key=lambda item: _path_sort_key(item[0]))
    return out


def _flatten(value: JsonValue, path: TypedPath, out: list[tuple[TypedPath, JsonValue]]) -> None:
    # Recursion depth is bounded by MAX_DEPTH, validated by the caller.
    if type(value) is dict and value:
        for key, child in value.items():
            _flatten(child, (*path, key), out)
    elif type(value) is list and value:
        for index, child in enumerate(value):
            _flatten(child, (*path, index), out)
    else:
        out.append((path, value))


def _new_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def build_leaves(payload: object, *, salt_factory: Callable[[], bytes] = _new_salt) -> list[Leaf]:
    """Flatten ``payload`` and commit every leaf with a fresh salt.

    ``salt_factory`` exists only so tests can use fixed salts; production code must use the
    default (the operating system's CSPRNG via ``secrets``).
    """
    leaves = []
    for path, value in flatten_payload(payload):
        salt = salt_factory()
        leaves.append(Leaf(path, commit_leaf(path, salt, value), salt, value))
    return leaves


def validate_leaf_set(leaves: Iterable[Leaf]) -> list[Leaf]:
    """Check the leaves could come from exactly one payload; return them in canonical order.

    Rules: at least one leaf; unique paths; no leaf path is a prefix of another; under each parent
    the child tokens are all str (object) or all int (array); array indices are exactly 0..n-1;
    the root is an object (first tokens are str), or the single leaf () for the empty payload.
    """
    items = list(leaves)
    for leaf in items:
        if not isinstance(leaf, Leaf):
            raise LeafError(f"expected Leaf, got {type(leaf).__name__}")
    ordered = sorted(items, key=lambda leaf: _path_sort_key(leaf.path))
    paths = [leaf.path for leaf in ordered]
    if not paths:
        raise LeafError("a payload has at least one leaf")
    if len(set(paths)) != len(paths):
        raise LeafError("duplicate leaf paths")
    if () in paths:
        if len(paths) > 1:
            raise LeafError("the root leaf () cannot coexist with other leaves")
        return ordered
    prefixes = {path[:i] for path in paths for i in range(1, len(path))}
    for path in paths:
        if path in prefixes:
            raise LeafError(f"leaf path {list(path)} is also a container of other leaves")
    children: dict[TypedPath, set[PathToken]] = {}
    for path in paths:
        for i, token in enumerate(path):
            children.setdefault(path[:i], set()).add(token)
    for parent, tokens in children.items():
        kinds = {type(token) for token in tokens}
        if len(kinds) > 1:
            raise LeafError(f"mixed object keys and array indices under {list(parent)}")
        if parent == () and kinds != {str}:
            raise LeafError("the payload root must be an object")
        if kinds == {int} and sorted(tokens, key=int) != list(range(len(tokens))):
            raise LeafError(f"array indices under {list(parent)} are not exactly 0..n-1")
    return ordered


def payload_root(leaves: Iterable[Leaf]) -> str:
    """Root over the typed paths and commitments of a well-formed leaf set.

    Values and salts are not used, so a matching root does NOT verify revealed payload contents:
    a value changed without its commitment leaves the root unchanged. Callers must also run
    ``check_leaf`` on every leaf (DESIGN.md C5).
    """
    ordered = validate_leaf_set(leaves)
    entries = [[list(leaf.path), leaf.commitment] for leaf in ordered]
    return sha256_hex(canonical_json({"t": PAYLOAD_TAG, "v": PAYLOAD_VERSION, "leaves": entries}))


class _LeafValue:
    __slots__ = ("value",)

    def __init__(self, value: JsonValue) -> None:
        self.value = value


type _Node = dict[PathToken, _Node | _LeafValue]


def unflatten(leaves: Iterable[Leaf]) -> dict[str, JsonValue]:
    """Rebuild the payload from a well-formed, fully revealed leaf set."""
    ordered = validate_leaf_set(leaves)
    if any(leaf.is_redacted for leaf in ordered):
        raise LeafError("cannot rebuild a payload that contains redacted leaves")
    if ordered[0].path == ():
        return {}  # Leaf guarantees a root leaf is revealed and holds {}
    tree: _Node = {}
    for leaf in ordered:
        node = tree
        for token in leaf.path[:-1]:
            child = node.setdefault(token, {})
            if not isinstance(child, dict):
                raise LeafError("conflicting leaf paths")
            node = child
        node[leaf.path[-1]] = _LeafValue(leaf.value)
    result = _build(tree)
    if type(result) is not dict:
        raise LeafError("the payload root must be an object")
    try:
        validate_json_value(result)
    except CanonicalizationError as exc:
        raise LeafError(f"rebuilt payload is invalid: {exc}") from exc
    return result


def _build(node: _Node | _LeafValue) -> JsonValue:
    # Recursion depth is bounded by path length, which validate_path caps at MAX_DEPTH.
    if isinstance(node, _LeafValue):
        value = node.value
        if type(value) is list:
            return []
        if type(value) is dict:
            return {}
        return value
    if all(type(token) is int for token in node):
        return [_build(node[index]) for index in range(len(node))]
    return {str(key): _build(child) for key, child in node.items()}
