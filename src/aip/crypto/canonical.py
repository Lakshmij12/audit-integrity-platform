"""Canonical JSON: the exact bytes that are hashed.

The encoding is the RFC 8785 (JCS) serialization restricted to the values this service accepts:
``null``, booleans, integers in [-(2**53 - 1), 2**53 - 1], NFC-normalized strings without lone
surrogates, arrays, and objects with string keys. Floats are never accepted, so the RFC 8785
number-formatting rules never apply. One deliberate difference from JCS: strings and keys that
are not NFC-normalized are rejected rather than encoded as-is.

Depth: a scalar has depth 0; an array or object has depth 1 + the largest depth of its members,
so an empty container has depth 1. A value is accepted only if its depth is at most MAX_DEPTH.
The same rule is enforced when encoding, parsing, flattening and reconstructing payloads.
"""

import json
import re
import unicodedata
from typing import Any, Final

from aip.crypto.errors import CanonicalizationError

MAX_SAFE_INTEGER: Final = 2**53 - 1
MAX_DEPTH: Final = 32

type JsonValue = bool | int | str | list[JsonValue] | dict[str, JsonValue] | None

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def validate_string(text: object, what: str = "string") -> str:
    """Return ``text`` if it is an exact ``str``, has no lone surrogates and is NFC-normalized."""
    if type(text) is not str:
        raise CanonicalizationError(f"{what} must be str, got {type(text).__name__}")
    if _LONE_SURROGATE.search(text):
        raise CanonicalizationError(f"{what} contains a lone surrogate")
    if not unicodedata.is_normalized("NFC", text):
        raise CanonicalizationError(f"{what} is not NFC-normalized")
    return text


def validate_json_value(value: object) -> None:
    """Raise CanonicalizationError unless ``value`` is an allowed JSON value within MAX_DEPTH."""
    _validate(value, 0)


def _validate(value: object, depth: int) -> None:
    # Exact type checks: bool is a subclass of int, and str/int/list/dict subclasses could
    # change how values print, so only the built-in types themselves are accepted.
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer outside +/-{MAX_SAFE_INTEGER}")
        return
    if type(value) is str:
        validate_string(value)
        return
    if type(value) is list:
        _check_depth(depth)
        for item in value:
            _validate(item, depth + 1)
        return
    if type(value) is dict:
        _check_depth(depth)
        for key, item in value.items():
            validate_string(key, "object key")
            _validate(item, depth + 1)
        return
    if type(value) is float:
        raise CanonicalizationError("floats are not allowed; send decimal values as strings")
    raise CanonicalizationError(f"unsupported type {type(value).__name__}")


def _check_depth(depth: int) -> None:
    # Called before descending into a container at ``depth``; the container itself is depth + 1.
    if depth + 1 > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than MAX_DEPTH={MAX_DEPTH}")


def canonical_json(value: object) -> bytes:
    """Return the canonical UTF-8 bytes of ``value`` (validated first)."""
    validate_json_value(value)
    return _encode(value).encode("utf-8")


def _utf16_key(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare in the same order as UTF-16 code units (RFC 8785 3.2.3).
    return key.encode("utf-16-be")


def _encode_string(text: str) -> str:
    # With ensure_ascii=False, json.dumps escapes exactly what RFC 8785 3.2.2.2 requires:
    # '"' and '\\', the short forms \b \t \n \f \r, other U+0000..U+001F as lowercase \u00xx,
    # and everything else (including '/', U+007F, U+2028, U+2029) as-is.
    return json.dumps(text, ensure_ascii=False)


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return _encode_string(value)
    if type(value) is list:
        return "[" + ",".join(_encode(item) for item in value) + "]"
    members = (
        _encode_string(key) + ":" + _encode(value[key]) for key in sorted(value, key=_utf16_key)
    )
    return "{" + ",".join(members) + "}"


def parse_strict_json(text: str) -> JsonValue:
    """Parse JSON text, rejecting duplicate keys, floats, NaN/Infinity and invalid values."""
    if type(text) is not str:
        raise CanonicalizationError(f"JSON text must be str, got {type(text).__name__}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except RecursionError as exc:
        raise CanonicalizationError(f"nesting deeper than MAX_DEPTH={MAX_DEPTH}") from exc
    except ValueError as exc:
        raise CanonicalizationError(f"invalid JSON: {exc}") from exc
    validate_json_value(value)
    result: JsonValue = value
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_float(literal: str) -> None:
    raise CanonicalizationError(f"non-integer number {literal!r}; send decimal values as strings")


def _reject_constant(literal: str) -> None:
    raise CanonicalizationError(f"{literal} is not allowed")
