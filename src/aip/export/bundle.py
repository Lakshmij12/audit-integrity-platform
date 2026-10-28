"""Signed export bundles (DESIGN.md section 8.1).

A bundle is one canonical-JSON document::

    {"format": "aip.export-bundle", "v": 1,
     "manifest": {...}, "signature": hex, "signerPublicKey": hex,
     "records": [...], "authorizations": [...], "skeleton": [...]}

* ``records``: every record matching the filter (exactly one of actorId / resourceId), in seq order,
  with its envelope, hashes and leaves. Redacted leaves carry no value and no salt. Archived records
  carry no leaves (their payload is in the archive file, which is not exported).
* ``authorizations``: the SYSTEM_REDACTION events targeting exported records and the
  SYSTEM_RETENTION_RUN events that archived them, as full records, so a recipient can check them.
* ``skeleton``: ``seq, recordedAt, prevHash, contentHash, recordHash`` of every record from seq 1 to
  the head. Hashes only, no payloads; it lets a recipient check chain membership and order.
* ``manifest``: the filter, the head, the exported seqs and SHA-256 digests of the three arrays,
  signed with Ed25519 (``t = "aip.export"``). ``signerPublicKey`` is informational: recipients must
  verify against a key they obtained independently.

Completeness is asserted by the signer, not proven: a recipient cannot tell from hashes alone
whether a record left out of ``records`` matched the filter.
"""

from typing import Any, Final

from sqlalchemy import Connection

from aip.crypto.canonical import canonical_json
from aip.crypto.commitments import Leaf, unflatten
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import GENESIS_HASH, HASH_VERSION, sha256_hex
from aip.crypto.signing import Signer, public_key_hex, sign_document
from aip.lifecycle.service import REDACTION_EVENT, RETENTION_EVENT
from aip.storage import repository
from aip.storage.repository import RecordFilter, StoredRecord

BUNDLE_FORMAT: Final = "aip.export-bundle"
BUNDLE_VERSION: Final = 1
EXPORT_TAG: Final = "aip.export"
MAX_EXPORT_RECORDS: Final = 10_000
_PAGE: Final = 500


class ExportTooLargeError(Exception):
    """More records match than one bundle may hold."""


def _leaf_view(leaf: Leaf) -> dict[str, Any]:
    return {
        "path": list(leaf.path),
        "commitment": leaf.commitment,
        "salt": None if leaf.salt is None else leaf.salt.hex(),
        "value": leaf.value,  # None for a redacted leaf: the value is not stored anywhere
    }


def _record_view(conn: Connection, record: StoredRecord) -> dict[str, Any]:
    archive = repository.archive_state(conn, record.seq)
    return {
        "seq": record.seq,
        "eventId": record.event_id,
        "eventType": record.event_type,
        "actorId": record.actor_id,
        "resourceType": record.resource_type,
        "resourceId": record.resource_id,
        "timestamp": record.timestamp,
        "recordedAt": record.recorded_at,
        "payloadRoot": record.payload_root,
        "contentHash": record.content_hash,
        "prevHash": record.prev_hash,
        "recordHash": record.record_hash,
        "archivedAt": None if archive is None else archive[0],
        "archiveRunId": None if archive is None else archive[1],
        "leaves": None
        if archive is not None
        else [_leaf_view(leaf) for leaf in repository.load_leaves(conn, record.seq)],
    }


def _matching(conn: Connection, filters: RecordFilter) -> list[StoredRecord]:
    records: list[StoredRecord] = []
    after = 0
    while True:
        page = repository.query_records(conn, filters, after_seq=after, limit=_PAGE)
        records.extend(page)
        if len(records) > MAX_EXPORT_RECORDS:
            raise ExportTooLargeError(f"more than {MAX_EXPORT_RECORDS} records match")
        if len(page) < _PAGE:
            return records
        after = page[-1].seq


def _authorizations(conn: Connection, exported: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redacted_targets = {
        record["seq"]
        for record in exported
        if record["leaves"] and any(leaf["salt"] is None for leaf in record["leaves"])
    }
    run_ids = {record["archiveRunId"] for record in exported if record["archiveRunId"]}
    if not redacted_targets and not run_ids:
        return []
    selected = []
    for seq, event_type in repository.system_record_seqs(conn, [REDACTION_EVENT, RETENTION_EVENT]):
        try:
            document = unflatten(repository.load_leaves(conn, seq)).get("authorization")
        except CryptoInputError:
            continue  # cannot be relevant evidence; the chain check reports malformed events
        if type(document) is not dict:
            continue
        relevant = (
            document.get("targetSeq") in redacted_targets
            if event_type == REDACTION_EVENT
            else document.get("runId") in run_ids
        )
        record = repository.read_record(conn, seq)
        if relevant and record is not None:
            selected.append(_record_view(conn, record))
    return selected


def build_bundle(
    conn: Connection,
    signer: Signer,
    *,
    actor_id: str | None,
    resource_id: str | None,
    exported_at: str,
) -> bytes:
    """Canonical bytes of a signed bundle for exactly one of ``actor_id`` / ``resource_id``.

    Call inside one read transaction so records, authorizations and skeleton form one snapshot.
    """
    if (actor_id is None) == (resource_id is None):
        raise ValueError("exactly one of actor_id and resource_id is required")
    filters = RecordFilter(actor_id=actor_id, resource_id=resource_id)
    exported = [_record_view(conn, record) for record in _matching(conn, filters)]
    skeleton = [
        {
            "seq": entry.seq,
            "recordedAt": entry.recorded_at,
            "prevHash": entry.prev_hash,
            "contentHash": entry.content_hash,
            "recordHash": entry.record_hash,
        }
        for entry in repository.iter_chain_entries(conn)
    ]
    authorizations = _authorizations(conn, exported)
    head = skeleton[-1] if skeleton else {"seq": 0, "recordHash": GENESIS_HASH}
    manifest = {
        "t": EXPORT_TAG,
        "v": BUNDLE_VERSION,
        "hashVersion": HASH_VERSION,
        "filter": {"actorId": actor_id} if actor_id is not None else {"resourceId": resource_id},
        "exportedAt": exported_at,
        "head": {"seq": head["seq"], "recordHash": head["recordHash"]},
        "recordCount": len(exported),
        "recordSeqs": [record["seq"] for record in exported],
        "recordsSha256": sha256_hex(canonical_json(exported)),
        "authorizationsSha256": sha256_hex(canonical_json(authorizations)),
        "skeletonSha256": sha256_hex(canonical_json(skeleton)),
        "completeness": "signer-asserted",
        "keyId": signer.key_id,
    }
    return canonical_json(
        {
            "format": BUNDLE_FORMAT,
            "v": BUNDLE_VERSION,
            "manifest": manifest,
            "signature": sign_document(signer, manifest),
            "signerPublicKey": public_key_hex(signer.public_key),
            "records": exported,
            "authorizations": authorizations,
            "skeleton": skeleton,
        }
    )
