"""Standalone verifier for audit export bundles (docs/DESIGN.md section 8.1).

Independent of the service: imports nothing from the ``aip`` package and needs no database or
running API. It re-implements the published specifications (canonical JSON, contentHash,
recordHash, typed-path leaf commitments, payload root, Ed25519 signed documents) from the docs.
Its only third-party dependency is ``cryptography`` (Ed25519).

Usage:
    python tools/verify_bundle.py bundle.json --trusted-key <64 hex chars>
    python tools/verify_bundle.py bundle.json --trusted-key-file key.hex \
        [--anchor-seq N --anchor-hash H]

Trust comes only from ``--trusted-key``: a public key obtained independently of the bundle (for
example from the operator, out of band). The ``signerPublicKey`` inside the bundle is never trusted.

Output: a JSON report on stdout. Exit codes: 0 VERIFIED, 3 INDETERMINATE (no problem found, but
archived payloads are not in the bundle and could not be checked), 1 FAILED, 2 usage or unreadable
input. Reports contain codes, seqs and leaf paths only, never payload values.

What VERIFIED means: the bundle was signed under the trusted key and not altered since; every record
recomputes, belongs to the signed chain skeleton at its position, matches the filter, and every
redaction or archival in it is covered by a signed authorization. It does NOT prove that every
matching record in the source database was exported (completeness is asserted by the signer), nor
that the chain was not rewritten before export unless ``--anchor-*`` gives an independently held
checkpoint that the bundle's skeleton must contain.
"""

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

GENESIS: Final = "0" * 64
MAX_SAFE_INTEGER: Final = 2**53 - 1
MAX_DEPTH: Final = 32
EXIT_VERIFIED, EXIT_FAILED, EXIT_USAGE, EXIT_INDETERMINATE = 0, 1, 2, 3

_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", re.ASCII)
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

BUNDLE_KEYS: Final = frozenset(
    {"format", "v", "manifest", "signature", "signerPublicKey", "records", "authorizations",
     "skeleton"}
)  # fmt: skip
MANIFEST_KEYS: Final = frozenset(
    {"t", "v", "hashVersion", "filter", "exportedAt", "head", "recordCount", "recordSeqs",
     "recordsSha256", "authorizationsSha256", "skeletonSha256", "completeness", "keyId"}
)  # fmt: skip
RECORD_KEYS: Final = frozenset(
    {"seq", "eventId", "eventType", "actorId", "resourceType", "resourceId", "timestamp",
     "recordedAt", "payloadRoot", "contentHash", "prevHash", "recordHash", "archivedAt",
     "archiveRunId", "leaves"}
)  # fmt: skip
SKELETON_KEYS: Final = frozenset({"seq", "recordedAt", "prevHash", "contentHash", "recordHash"})
LEAF_KEYS: Final = frozenset({"path", "commitment", "salt", "value"})
REDACTION_KEYS: Final = frozenset(
    {"t", "v", "targetSeq", "targetEventId", "targetContentHash", "paths", "reason",
     "requestedBy", "requestedAt", "keyId"}
)  # fmt: skip
RETENTION_KEYS: Final = frozenset(
    {"t", "v", "runId", "cutoff", "windowDays", "fromSeq", "toSeq", "recordCount", "archiveFile",
     "archiveSha256", "archivedAt", "requestedBy", "keyId"}
)  # fmt: skip


class Problem(Exception):  # noqa: N818 - a verification finding, reported rather than raised out
    """The first problem found. ``detail`` is a fixed description, never a bundle value."""

    def __init__(self, code: str, *, seq: int | None = None, path: list[Any] | None = None) -> None:
        super().__init__(code)
        self.code, self.seq, self.path = code, seq, path


# ---------------------------------------------------------------- canonical JSON (DESIGN.md §1)


def _validate(value: object, depth: int = 0) -> None:
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise Problem("MALFORMED_BUNDLE")
        return
    if type(value) is str:
        if _LONE_SURROGATE.search(value) or not unicodedata.is_normalized("NFC", value):
            raise Problem("MALFORMED_BUNDLE")
        return
    if isinstance(value, list | dict) and type(value) in (list, dict):
        if depth + 1 > MAX_DEPTH:
            raise Problem("MALFORMED_BUNDLE")
        if isinstance(value, dict):
            for key, item in value.items():
                _validate(key, depth)
                _validate(item, depth + 1)
        else:
            for item in value:
                _validate(item, depth + 1)
        return
    raise Problem("MALFORMED_BUNDLE")


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
        return json.dumps(value, ensure_ascii=False)
    if type(value) is list:
        return "[" + ",".join(_encode(item) for item in value) + "]"
    keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
    return (
        "{"
        + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _encode(value[k]) for k in keys)
        + "}"
    )


def canon(value: object) -> bytes:
    """RFC 8785 serialization of null, bool, safe integers, NFC strings, arrays and objects."""
    _validate(value)
    return _encode(value).encode("utf-8")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Problem("MALFORMED_BUNDLE")
        result[key] = value
    return result


def _reject(_literal: str) -> None:
    raise Problem("MALFORMED_BUNDLE")


def parse_bundle(data: bytes) -> Any:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_reject,
            parse_constant=_reject,
        )
    except UnicodeDecodeError, ValueError, RecursionError:
        raise Problem("MALFORMED_BUNDLE") from None
    _validate(value)
    return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- hashes (DESIGN.md §2)


def content_hash(record: dict[str, Any]) -> str:
    return sha256(
        canon(
            {
                "t": "aip.content",
                "v": 1,
                "eventType": record["eventType"],
                "actorId": record["actorId"],
                "resourceType": record["resourceType"],
                "resourceId": record["resourceId"],
                "timestamp": record["timestamp"],
                "payloadRoot": record["payloadRoot"],
            }
        )
    )


def record_hash(seq: int, recorded_at: str, prev_hash: str, content: str) -> str:
    return sha256(
        canon(
            {
                "t": "aip.record",
                "v": 1,
                "seq": seq,
                "recordedAt": recorded_at,
                "prevHash": prev_hash,
                "contentHash": content,
            }
        )
    )


def commit_leaf(path: list[Any], salt_hex: str, value: Any) -> str:
    return sha256(canon(["aip-leaf-v1", path, salt_hex, value]))


def payload_root(leaves: Sequence[dict[str, Any]]) -> str:
    ordered = sorted(leaves, key=lambda leaf: canon(leaf["path"]))
    entries = [[leaf["path"], leaf["commitment"]] for leaf in ordered]
    return sha256(canon({"t": "aip.payload", "v": 1, "leaves": entries}))


def unflatten(leaves: Sequence[dict[str, Any]]) -> Any:
    """Rebuild a payload from fully revealed leaves (used for authorization events)."""
    if len(leaves) == 1 and leaves[0]["path"] == []:
        return leaves[0]["value"]
    tree: dict[Any, Any] = {}
    for leaf in leaves:
        path = leaf["path"]
        if not path:
            raise Problem("MALFORMED_BUNDLE")
        node = tree
        for token in path[:-1]:
            node = node.setdefault(token, {})
            if not isinstance(node, dict):
                raise Problem("MALFORMED_BUNDLE")
        node[path[-1]] = ("leaf", leaf["value"])
    return _build(tree)


def _build(node: Any) -> Any:
    if isinstance(node, tuple):
        return node[1]
    if node and all(type(key) is int for key in node):
        if sorted(node) != list(range(len(node))):
            raise Problem("MALFORMED_BUNDLE")
        return [_build(node[index]) for index in range(len(node))]
    if not all(type(key) is str for key in node):
        raise Problem("MALFORMED_BUNDLE")
    return {key: _build(child) for key, child in node.items()}


# ---------------------------------------------------------------- verification


def key_id(public_key: Ed25519PublicKey) -> str:
    return sha256(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))[:16]


def _signed(document: Any, signature: Any, key: Ed25519PublicKey) -> bool:
    try:
        if type(signature) is not str:
            return False
        key.verify(bytes.fromhex(signature), canon(document))
    except InvalidSignature, ValueError, Problem:
        return False
    return True


def _is_hex64(value: object) -> bool:
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _require(condition: bool, code: str, seq: int | None = None) -> None:
    if not condition:
        raise Problem(code, seq=seq)


@dataclass
class Report:
    status: str = "FAILED"
    problem: dict[str, Any] | None = None
    filter: dict[str, Any] | None = None
    head: dict[str, Any] | None = None
    records_checked: int = 0
    redacted_leaves_authorized: int = 0
    archived_records: int = 0
    archived_content_unavailable: int = 0
    anchor_matched: bool | None = None
    notes: list[str] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "problem": self.problem,
            "filter": self.filter,
            "head": self.head,
            "recordsChecked": self.records_checked,
            "redactedLeavesAuthorized": self.redacted_leaves_authorized,
            "archivedRecords": self.archived_records,
            "archivedContentUnavailable": self.archived_content_unavailable,
            "anchorMatched": self.anchor_matched,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Grant:
    seq: int
    document: dict[str, Any]


def _check_skeleton(skeleton: Any, head: Any) -> list[dict[str, Any]]:
    _require(type(skeleton) is list, "MALFORMED_BUNDLE")
    previous = GENESIS
    for index, entry in enumerate(skeleton):
        seq = index + 1
        _require(type(entry) is dict and set(entry) == SKELETON_KEYS, "MALFORMED_BUNDLE", seq)
        _require(entry["seq"] == seq, "CHAIN_SEQUENCE_GAP", seq)
        _require(
            all(_is_hex64(entry[k]) for k in ("prevHash", "contentHash", "recordHash"))
            and type(entry["recordedAt"]) is str
            and _TIMESTAMP.fullmatch(entry["recordedAt"]) is not None,
            "MALFORMED_BUNDLE",
            seq,
        )
        _require(entry["prevHash"] == previous, "CHAIN_LINK_BROKEN", seq)
        recomputed = record_hash(seq, entry["recordedAt"], entry["prevHash"], entry["contentHash"])
        _require(recomputed == entry["recordHash"], "RECORD_HASH_MISMATCH", seq)
        previous = entry["recordHash"]
    expected_head = (
        {"seq": len(skeleton), "recordHash": previous}
        if skeleton
        else {"seq": 0, "recordHash": GENESIS}
    )
    _require(head == expected_head, "HEAD_MISMATCH")
    return skeleton  # type: ignore[no-any-return]


def _check_record(record: Any, skeleton: list[dict[str, Any]]) -> dict[str, Any]:
    """Envelope, hashes, chain position and leaf commitments of one exported record."""
    _require(type(record) is dict and set(record) == RECORD_KEYS, "MALFORMED_BUNDLE")
    seq = record["seq"]
    _require(type(seq) is int and 1 <= seq <= len(skeleton), "RECORD_NOT_IN_CHAIN")
    entry = skeleton[seq - 1]
    for name in ("recordedAt", "prevHash", "contentHash", "recordHash"):
        _require(record[name] == entry[name], "RECORD_NOT_IN_CHAIN", seq)
    _require(record["eventId"] == "evt_" + record["recordHash"][:32], "EVENT_ID_MISMATCH", seq)
    _require(
        all(type(record[k]) is str and record[k] for k in ("eventType", "actorId", "resourceType",
                                                              "resourceId"))
        and type(record["timestamp"]) is str
        and _TIMESTAMP.fullmatch(record["timestamp"]) is not None
        and _is_hex64(record["payloadRoot"]),
        "MALFORMED_BUNDLE",
        seq,
    )  # fmt: skip
    _require(content_hash(record) == record["contentHash"], "CONTENT_HASH_MISMATCH", seq)
    archived = record["archivedAt"] is not None or record["archiveRunId"] is not None
    if archived:
        _require(
            record["leaves"] is None
            and type(record["archivedAt"]) is str
            and type(record["archiveRunId"]) is str,
            "MALFORMED_BUNDLE",
            seq,
        )
        return record  # type: ignore[no-any-return]
    leaves = record["leaves"]
    _require(type(leaves) is list and len(leaves) > 0, "MALFORMED_BUNDLE", seq)
    for leaf in leaves:
        _require(type(leaf) is dict and set(leaf) == LEAF_KEYS, "MALFORMED_BUNDLE", seq)
        _require(
            type(leaf["path"]) is list
            and all(type(t) is str or (type(t) is int and t >= 0) for t in leaf["path"])
            and _is_hex64(leaf["commitment"]),
            "MALFORMED_BUNDLE",
            seq,
        )
        if leaf["salt"] is None:
            if leaf["value"] is not None:
                raise Problem("MALFORMED_BUNDLE", seq=seq, path=leaf["path"])
            continue
        if not _is_hex64(leaf["salt"]):
            raise Problem("MALFORMED_BUNDLE", seq=seq, path=leaf["path"])
        if commit_leaf(leaf["path"], leaf["salt"], leaf["value"]) != leaf["commitment"]:
            raise Problem("LEAF_COMMITMENT_MISMATCH", seq=seq, path=leaf["path"])
    _require(payload_root(leaves) == record["payloadRoot"], "PAYLOAD_ROOT_MISMATCH", seq)
    return record  # type: ignore[no-any-return]


def _load_grants(
    authorizations: Any, skeleton: list[dict[str, Any]], key: Ed25519PublicKey, key_id_: str
) -> tuple[dict[tuple[int, bytes], Grant], dict[str, Grant]]:
    _require(type(authorizations) is list, "MALFORMED_BUNDLE")
    redactions: dict[tuple[int, bytes], Grant] = {}
    runs: dict[str, Grant] = {}
    for item in authorizations:
        record = _check_record(item, skeleton)
        seq = record["seq"]
        leaves = record["leaves"]
        _require(
            leaves is not None and all(leaf["salt"] is not None for leaf in leaves),
            "AUTHORIZATION_INVALID",
            seq,
        )
        payload = unflatten(leaves)
        _require(type(payload) is dict and set(payload) == {"authorization", "signature"},
                 "AUTHORIZATION_INVALID", seq)  # fmt: skip
        document = payload["authorization"]
        kind = record["eventType"]
        expected = {
            "SYSTEM_REDACTION": ("aip.redaction", REDACTION_KEYS),
            "SYSTEM_RETENTION_RUN": ("aip.retention", RETENTION_KEYS),
        }.get(kind)
        _require(
            expected is not None
            and type(document) is dict
            and set(document) == expected[1]
            and document["t"] == expected[0]
            and document["v"] == 1
            and document["keyId"] == key_id_
            and _signed(document, payload["signature"], key),
            "AUTHORIZATION_INVALID",
            seq,
        )
        grant = Grant(seq, document)
        if kind == "SYSTEM_REDACTION":
            _require(type(document["paths"]) is list, "AUTHORIZATION_INVALID", seq)
            for path in document["paths"]:
                redactions.setdefault((document["targetSeq"], canon(path)), grant)
        else:
            runs.setdefault(str(document["runId"]), grant)
    return redactions, runs


def verify_bundle(
    bundle: Any, trusted_key: Ed25519PublicKey, anchor: tuple[int, str] | None = None
) -> Report:
    report = Report()
    try:
        _verify(bundle, trusted_key, anchor, report)
    except Problem as problem:
        report.status = "FAILED"
        report.problem = {"code": problem.code, "seq": problem.seq, "leafPath": problem.path}
        return report
    report.status = "INDETERMINATE" if report.archived_content_unavailable else "VERIFIED"
    return report


def _verify(
    bundle: Any, key: Ed25519PublicKey, anchor: tuple[int, str] | None, report: Report
) -> None:
    _require(type(bundle) is dict and set(bundle) == BUNDLE_KEYS, "MALFORMED_BUNDLE")
    _require(bundle["format"] == "aip.export-bundle" and bundle["v"] == 1, "UNSUPPORTED_FORMAT")
    manifest = bundle["manifest"]
    _require(type(manifest) is dict and set(manifest) == MANIFEST_KEYS, "MALFORMED_BUNDLE")
    _require(
        manifest["t"] == "aip.export" and manifest["v"] == 1 and manifest["hashVersion"] == 1,
        "UNSUPPORTED_FORMAT",
    )
    # E1: authenticity under the independently trusted key, then integrity of every section.
    trusted_id = key_id(key)
    _require(manifest["keyId"] == trusted_id, "UNTRUSTED_KEY")
    _require(_signed(manifest, bundle["signature"], key), "SIGNATURE_INVALID")
    for section, digest in (
        ("records", "recordsSha256"),
        ("authorizations", "authorizationsSha256"),
        ("skeleton", "skeletonSha256"),
    ):
        _require(sha256(canon(bundle[section])) == manifest[digest], "MANIFEST_DIGEST_MISMATCH")
    if bundle["signerPublicKey"] != key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex():
        report.notes.append("signerPublicKey in the bundle differs from the trusted key; ignored")
    report.filter, report.head = manifest["filter"], manifest["head"]

    # E3: the skeleton links from genesis to the signed head.
    skeleton = _check_skeleton(bundle["skeleton"], manifest["head"])

    # Signed record list: no removal, reordering or duplication relative to the manifest.
    records = bundle["records"]
    _require(type(records) is list, "MALFORMED_BUNDLE")
    seqs = [record.get("seq") if type(record) is dict else None for record in records]
    ints = [s for s in seqs if type(s) is int]
    _require(
        seqs == manifest["recordSeqs"]
        and len(seqs) == manifest["recordCount"]
        and len(ints) == len(seqs)
        and all(a < b for a, b in pairwise(ints)),
        "RECORD_SET_MISMATCH",
    )
    filt = manifest["filter"]
    _require(
        type(filt) is dict
        and len(filt) == 1
        and next(iter(filt)) in ("actorId", "resourceId")
        and type(next(iter(filt.values()))) is str,
        "MALFORMED_BUNDLE",
    )
    ((field_name, field_value),) = filt.items()

    redactions, runs = _load_grants(bundle["authorizations"], skeleton, key, trusted_id)

    for raw in records:
        record = _check_record(raw, skeleton)  # E2 and chain membership
        seq = record["seq"]
        _require(record[field_name] == field_value, "FILTER_MISMATCH", seq)
        if record["leaves"] is None:
            _check_archived(record, runs)
            report.archived_records += 1
            report.archived_content_unavailable += 1
        else:
            for leaf in record["leaves"]:
                if leaf["salt"] is None:
                    _check_redaction(record, leaf, redactions)
                    report.redacted_leaves_authorized += 1
        report.records_checked += 1

    if anchor is not None:
        anchor_seq, anchor_hash = anchor
        if anchor_seq > len(skeleton):
            report.anchor_matched = False
            raise Problem("TRUNCATED", seq=anchor_seq)
        if skeleton[anchor_seq - 1]["recordHash"] != anchor_hash:
            report.anchor_matched = False
            raise Problem("ANCHOR_MISMATCH", seq=anchor_seq)
        report.anchor_matched = True
    else:
        report.notes.append(
            "no trusted checkpoint given: the chain head is authenticated only by the export "
            "signature; rewriting before export cannot be ruled out "
            "(use --anchor-seq/--anchor-hash)"
        )
    report.notes.append(
        "completeness is asserted by the signer: a record left out of the bundle that matched the "
        "filter cannot be detected from the bundle alone"
    )
    if report.archived_content_unavailable:
        report.notes.append(
            "archived records are exported without payloads: their hashes, chain position and "
            "signed retention run were checked, their archived payload content was not"
        )


def _check_redaction(
    record: dict[str, Any], leaf: dict[str, Any], redactions: dict[tuple[int, bytes], Grant]
) -> None:
    seq = record["seq"]
    grant = redactions.get((seq, canon(leaf["path"])))
    if (
        grant is None
        or grant.seq <= seq
        or grant.document["targetEventId"] != record["eventId"]
        or grant.document["targetContentHash"] != record["contentHash"]
    ):
        raise Problem("UNAUTHORIZED_REDACTION", seq=seq, path=leaf["path"])


def _check_archived(record: dict[str, Any], runs: dict[str, Grant]) -> None:
    seq = record["seq"]
    grant = runs.get(record["archiveRunId"])
    _require(grant is not None, "INVALID_ARCHIVE", seq)
    assert grant is not None  # noqa: S101 - narrowing after _require
    document = grant.document
    _require(
        grant.seq > seq
        and not record["eventType"].startswith("SYSTEM_")
        and type(document["fromSeq"]) is int
        and type(document["toSeq"]) is int
        and document["fromSeq"] <= seq <= document["toSeq"]
        and type(document["cutoff"]) is str
        and record["recordedAt"] < document["cutoff"]
        and record["archivedAt"] == document["archivedAt"],
        "INVALID_ARCHIVE",
        seq,
    )


# ---------------------------------------------------------------- command line


def _load_key(text: str) -> Ed25519PublicKey:
    value = text.strip().lower()
    if not _HEX64.fullmatch(value):
        raise ValueError("the trusted key must be 64 hex characters (raw Ed25519 public key)")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an audit export bundle offline.")
    parser.add_argument("bundle", type=Path, help="bundle JSON file from GET /audit/export")
    trust = parser.add_mutually_exclusive_group(required=True)
    trust.add_argument("--trusted-key", help="trusted Ed25519 public key, 64 hex characters")
    trust.add_argument("--trusted-key-file", type=Path, help="file holding the trusted key (hex)")
    parser.add_argument("--anchor-seq", type=int, help="seq of an independently held checkpoint")
    parser.add_argument("--anchor-hash", help="recordHash of that checkpoint")
    args = parser.parse_args(argv)
    if (args.anchor_seq is None) != (args.anchor_hash is None):
        parser.error("--anchor-seq and --anchor-hash go together")
    if args.anchor_seq is not None and (args.anchor_seq < 1 or not _is_hex64(args.anchor_hash)):
        parser.error("--anchor-seq must be >= 1 and --anchor-hash 64 lowercase hex characters")
    try:
        key_text = (
            args.trusted_key
            if args.trusted_key is not None
            else args.trusted_key_file.read_text(encoding="utf-8")
        )
        key = _load_key(key_text)
        data = args.bundle.read_bytes()
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: {type(exc).__name__}: cannot read the trusted key or bundle\n")
        return EXIT_USAGE
    try:
        bundle = parse_bundle(data)
    except Problem as problem:
        report = Report(problem={"code": problem.code, "seq": None, "leafPath": None})
    else:
        anchor = None if args.anchor_seq is None else (args.anchor_seq, args.anchor_hash)
        report = verify_bundle(bundle, key, anchor)
    sys.stdout.write(json.dumps(report.as_json(), indent=2, sort_keys=True) + "\n")
    return {"VERIFIED": EXIT_VERIFIED, "INDETERMINATE": EXIT_INDETERMINATE}.get(
        report.status, EXIT_FAILED
    )


if __name__ == "__main__":
    sys.exit(main())
