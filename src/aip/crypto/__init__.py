"""Pure cryptographic foundations: canonical JSON, timestamps, commitments, hashes, chain checks.

No I/O, no global state, no framework imports. See docs/DESIGN.md sections 1, 2 and 4.
"""

from aip.crypto.canonical import (
    MAX_DEPTH,
    MAX_SAFE_INTEGER,
    JsonValue,
    canonical_json,
    parse_strict_json,
    validate_json_value,
)
from aip.crypto.chain import ChainEntry, ChainViolation, ViolationType, check_chain
from aip.crypto.commitments import (
    Leaf,
    LeafStatus,
    TypedPath,
    build_leaves,
    check_leaf,
    commit_leaf,
    flatten_payload,
    payload_root,
    unflatten,
    validate_leaf_set,
)
from aip.crypto.errors import (
    CanonicalizationError,
    CryptoInputError,
    HashInputError,
    LeafError,
    TimestampError,
)
from aip.crypto.hashing import GENESIS_HASH, content_hash, record_hash, sha256_hex
from aip.crypto.timestamps import (
    format_timestamp,
    is_canonical_timestamp,
    normalize_timestamp,
    parse_timestamp,
)

__all__ = [
    "GENESIS_HASH",
    "MAX_DEPTH",
    "MAX_SAFE_INTEGER",
    "CanonicalizationError",
    "ChainEntry",
    "ChainViolation",
    "CryptoInputError",
    "HashInputError",
    "JsonValue",
    "Leaf",
    "LeafError",
    "LeafStatus",
    "TimestampError",
    "TypedPath",
    "ViolationType",
    "build_leaves",
    "canonical_json",
    "check_chain",
    "check_leaf",
    "commit_leaf",
    "content_hash",
    "flatten_payload",
    "format_timestamp",
    "is_canonical_timestamp",
    "normalize_timestamp",
    "parse_strict_json",
    "parse_timestamp",
    "payload_root",
    "record_hash",
    "sha256_hex",
    "unflatten",
    "validate_json_value",
    "validate_leaf_set",
]
