"""Redaction commitment proof of concept (spike, not production code).

Questions this spike answers before the real implementation is written:
  1. Can a payload leaf be redacted without changing the record's contentHash?
  2. Is tampering with a revealed value, a commitment, or a leaf's path still detected?
  3. Why does each leaf need its own random salt, and what happens if a salt survives redaction?

Redaction here is logical: the value and salt are removed from an in-memory data structure.
This spike does not demonstrate secure deletion from any storage medium.

Standard library only. Run from the repository root:  python poc/redaction_poc.py
Exits 0 only if every check behaves as expected. All data is synthetic.
Timings are machine-dependent and printed for illustration only; they are not asserted.
"""

import copy
import hashlib
import json
import secrets
import time
from collections.abc import Iterable
from typing import Any

LEAF_TAG = "aip-leaf-v1"
Leaves = dict[str, dict[str, Any]]

ENVELOPE = {
    "eventType": "RECORD_UPDATED",
    "actorId": "user-0042",
    "resourceType": "CLIENT_ACCOUNT",
    "resourceId": "acct-0001",
    "timestamp": "2026-10-28T12:00:00.000000Z",
}
PAYLOAD = {  # synthetic; 9xx-prefixed 9-digit numbers are not valid SSNs
    "account": {"number": "900123456", "type": "BROKERAGE"},
    "pin": "4821",
    "note": "address change requested",
    "tags": [],
    "a/b~c": "escaping test",
}


def canon(obj: Any) -> bytes:
    """Deterministic JSON (simplified: the real version also enforces NFC and integer rules)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")  # RFC 6901: "~" first, then "/"


def flatten(value: Any, path: str = "") -> dict[str, Any]:
    """Map JSON Pointer paths to scalar leaves. Empty objects/arrays are leaves too."""
    if isinstance(value, dict) and value:
        items: Iterable[tuple[str, Any]] = ((_escape(k), v) for k, v in value.items())
    elif isinstance(value, list) and value:
        items = ((str(i), v) for i, v in enumerate(value))
    else:
        return {path: value}
    out: dict[str, Any] = {}
    for token, child in items:
        out.update(flatten(child, f"{path}/{token}"))
    return out


def commit(path: str, salt_hex: str, value: Any) -> str:
    return sha256_hex(canon([LEAF_TAG, path, salt_hex, value]))


def build_leaves(payload: dict[str, Any]) -> Leaves:
    leaves: Leaves = {}
    for path, value in flatten(payload).items():
        salt_hex = secrets.token_bytes(32).hex()
        leaves[path] = {"value": value, "salt": salt_hex, "commitment": commit(path, salt_hex, value)}
    return leaves


def content_hash(envelope: dict[str, Any], leaves: Leaves) -> str:
    commitments = {path: leaf["commitment"] for path, leaf in leaves.items()}
    payload_root = sha256_hex(canon({"v": 1, "leaves": commitments}))
    return sha256_hex(canon({"v": 1, **envelope, "payloadRoot": payload_root}))


def mismatched_leaves(leaves: Leaves) -> list[str]:
    """Revealed leaves whose value and salt no longer reproduce the stored commitment."""
    return [
        path
        for path, leaf in leaves.items()
        if "value" in leaf and commit(path, leaf["salt"], leaf["value"]) != leaf["commitment"]
    ]


def redact(leaves: Leaves, path: str) -> None:
    """Logical redaction: remove value and salt from the in-memory structure; keep the commitment.

    This is not secure deletion; it says nothing about copies on disk, in backups or elsewhere.
    """
    leaves[path].pop("value")
    leaves[path].pop("salt")


def brute_force(
    path: str, commitment: str, salt_hex: str, candidates: Iterable[str]
) -> tuple[str | None, int, float]:
    start = time.perf_counter()
    attempts = 0
    for guess in candidates:
        attempts += 1
        if commit(path, salt_hex, guess) == commitment:
            return guess, attempts, time.perf_counter() - start
    return None, attempts, time.perf_counter() - start


_failures: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        _failures.append(label)


def main() -> int:
    print("1. Canonical encoding is independent of key order")
    check(
        "reordered keys give identical bytes",
        canon({"b": 1, "a": {"y": 2, "x": 3}}) == canon({"a": {"x": 3, "y": 2}, "b": 1}),
    )

    print("2. Commit every payload leaf")
    leaves = build_leaves(PAYLOAD)
    original = content_hash(ENVELOPE, leaves)
    for path, leaf in leaves.items():
        print(f"     {path:<18} commitment={leaf['commitment'][:16]}...")
    check("all revealed leaves match their commitments", mismatched_leaves(leaves) == [])
    check("key 'a/b~c' maps to JSON Pointer '/a~1b~0c'", "/a~1b~0c" in leaves)
    check("empty array is kept as a leaf", leaves.get("/tags", {}).get("value") == [])

    print("3. Logically redact /account/number (remove value and salt from the in-memory")
    print("   structure, keep the commitment; not secure deletion)")
    redacted = copy.deepcopy(leaves)
    redact(redacted, "/account/number")
    check("contentHash unchanged after redaction", content_hash(ENVELOPE, redacted) == original)
    check(
        "value and salt removed from the in-memory structure",
        redacted["/account/number"].keys() == {"commitment"},
    )
    check("remaining leaves still verify", mismatched_leaves(redacted) == [])
    print("     still visible after redaction: the path '/account/number' and its commitment")

    print("4. Tamper with a revealed value")
    tampered = copy.deepcopy(redacted)
    tampered["/note"]["value"] = "no change requested"
    check("modified value detected", mismatched_leaves(tampered) == ["/note"])

    print("5. Tamper with a stored commitment")
    tampered = copy.deepcopy(redacted)
    tampered["/account/number"]["commitment"] = "0" * 64
    check("modified commitment changes contentHash", content_hash(ENVELOPE, tampered) != original)

    print("6. Move a leaf to a different path")
    tampered = copy.deepcopy(leaves)
    tampered["/pin"], tampered["/note"] = tampered["/note"], tampered["/pin"]
    check(
        "swapped leaves fail verification (commitments are bound to their path)",
        sorted(mismatched_leaves(tampered)) == ["/note", "/pin"],
    )

    print("7. Equal values do not produce equal commitments")
    other = build_leaves(PAYLOAD)
    check(
        "same value with fresh salts gives different commitments, so equality cannot be "
        "inferred by comparing commitments alone (other fields may still link records)",
        other["/account/type"]["commitment"] != leaves["/account/type"]["commitment"],
    )

    print("8. Low-entropy values without a salt")
    pins = [f"{n:04d}" for n in range(10_000)]
    found, attempts, secs = brute_force("/pin", commit("/pin", "", "4821"), "", pins)
    print(f"     unsalted PIN recovered: {found!r} after {attempts} guesses in {secs:.3f}s")
    check("unsalted 4-digit value is recoverable (demonstrates the risk)", found == "4821")
    sample = (f"{i:09d}" for i in range(100_000))
    _, n, secs = brute_force("/account/number", "x" * 64, "", sample)
    print(
        f"     {n} unsalted 9-digit guesses took {secs:.3f}s; "
        f"all 10^9 would take ~{secs * 1e9 / n / 60:.0f} min on one core"
    )

    print("9. Salted, then salt removed by redaction")
    redacted_pin = copy.deepcopy(leaves)
    redact(redacted_pin, "/pin")
    target = redacted_pin["/pin"]["commitment"]
    found, _, _ = brute_force("/pin", target, "", pins)
    check("all 10^4 PINs tried without the salt: no match (illustrative)", found is None)
    print("     recovery needs the 256-bit salt; this rests on SHA-256 preimage resistance,")
    print("     not on this check")

    print("10. Salt retained elsewhere (backup, log, earlier export)")
    leaked_salt = leaves["/pin"]["salt"]
    found, attempts, secs = brute_force("/pin", target, leaked_salt, pins)
    print(f"     with leaked salt, PIN recovered: {found!r} after {attempts} guesses in {secs:.3f}s")
    check("leaked salt makes the redacted value recoverable (demonstrates the risk)", found == "4821")

    print()
    if _failures:
        print(f"RESULT: {len(_failures)} check(s) failed")
        return 1
    print("RESULT: all checks behaved as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
