# Design: Hash Chain, Redaction, Retention and Export

**Status: Proposed — pending engineer approval.** Not implemented. This document will be marked
approved only after explicit approval by the engineer, and updated as features are built and tested.

## 1. Deterministic serialization
Canonical JSON: sorted keys, separators `,`/`:`, UTF-8 without escaping, strings NFC-normalized,
no NaN/Infinity, no floats, integers |n| ≤ 2^53, duplicate keys rejected at parse time, timestamps
RFC 3339 UTC with microseconds (`2026-10-28T12:00:00.000000Z`). Hash inputs are always canonical JSON
arrays/objects, never raw string concatenation, so field boundaries are unambiguous.

## 2. Record hashes and genesis
```
leafCommitment = SHA256(canon(["aip-leaf-v1", jsonPointer, saltHex, value]))   salt = 32 random bytes
payloadRoot    = SHA256(canon({"v":1, "leaves": {jsonPointer: leafCommitment, ...}}))
contentHash    = SHA256(canon({"v":1, "eventType", "actorId", "resourceType", "resourceId",
                               "timestamp", "payloadRoot"}))
recordHash     = SHA256(canon({"v":1, "seq", "recordedAt", "prevHash", "contentHash"}))
GENESIS        = 64 hex zeros — the prevHash of seq 1
```
`recordedAt` is in the record envelope so it remains protected after archival (retention depends on it).

**Why SHA-256:** 128-bit collision resistance; FIPS 180-4 approved; in the Python standard library and
every language a recipient might use. Length extension does not apply because no secret is hashed.
SHA-3/BLAKE2 would add no security need here and reduce recipient tooling ubiquity.

## 3. Transactional append
`BEGIN IMMEDIATE` (takes SQLite's write lock before the head is read) → read head → compute hashes →
insert record and leaves → `COMMIT`. `UNIQUE(seq)` and `UNIQUE(prevHash)` reject forks as a second guard.

Guard triggers (`BEFORE UPDATE/DELETE`) reject changes other than the controlled redaction and archive
updates. They catch application bugs only; anyone with direct access to the database file can drop
them. **Tamper detection never depends on the triggers** (see §10).

## 4. Verification invariants (`GET /audit/verify`, streamed in batches, stops at first violation)
| ID | Invariant | violationType |
|----|-----------|---------------|
| C1 | `seq` contiguous 1..N | `SEQUENCE_GAP` |
| C2 | `prevHash(1) = GENESIS`; `prevHash(n) = recordHash(n-1)` | `PREV_HASH_MISMATCH` |
| C3 | Recomputed `contentHash` equals stored | `CONTENT_HASH_MISMATCH` |
| C4 | Recomputed `recordHash` equals stored | `RECORD_HASH_MISMATCH` |
| C5 | Each revealed leaf: `commit(path, salt, value)` equals stored commitment | `LEAF_COMMITMENT_MISMATCH` |
| C6 | Each leaf without a value is covered by a valid signed redaction authorization (§6) | `UNAUTHORIZED_REDACTION` |
| C7 | Each archived row is covered by a valid signed retention authorization (§7) | `INVALID_ARCHIVE` |
| C8 | Archive file digest equals the signed digest, and each archived record's `payloadRoot` recomputes from the file | `ARCHIVE_CONTENT_MISMATCH` |
| C9 | Each checkpoint matches the chain and its signature verifies; chain is not shorter than any checkpoint | `CHECKPOINT_MISMATCH` / `TRUNCATED` |

The verifier recomputes every hash it can; it never trusts a stored hash or a status flag on its own.
Response: `intact`, `recordsChecked`, `headSeq`, `firstInconsistency {seq, eventId, violationType, detail}`,
`archive {archivedRecords, metadataConsistent, contentIntegrity}`, `checkpoints {checked, latestSeq}`.

## 5. Guarantee levels
| Level | Question | Established by | Not covered |
|-------|----------|----------------|-------------|
| L1 Internal consistency | Do stored records recompute and link? | C1–C5 | An attacker with DB write access can edit a record and recompute all later hashes; L1 still passes |
| L2 Historical modification | Did anything before point X change since X was observed? | A signed checkpoint at X held where the attacker cannot alter it | Changes after the latest trusted checkpoint |
| L3 Tail truncation | Were records removed from the end? | Chain shorter than a previously observed checkpoint → `TRUNCATED` | Truncation after the last checkpoint; checkpoints in the same DB can be deleted with the tail, so a copy must be held externally |
| L4 Authenticity | Did this service produce the head/authorization? | Ed25519 signature checked against trusted public keys from configuration (never from the DB) | Signing key is on the same host in this prototype; host compromise allows forgery |

## 6. Redaction authorization
Chaining a redaction event does not authenticate it: anyone with DB write access can append a
well-formed event. Authentication therefore uses signatures:

1. Admin API key checked; target must exist, not be archived, not be a `SYSTEM_*` event; requested
   paths must exist. Already-redacted paths are a no-op.
2. `BEGIN IMMEDIATE`.
3. Build authorization `A = {type:"redaction-v1", targetSeq, targetEventId, targetContentHash,
   paths (sorted), reason, requestedBy (API key id), requestedAt}`; sign `canon(A)` with Ed25519;
   append a `SYSTEM_REDACTION` event whose payload is `{authorization: A, signature, keyId}`.
4. Delete the target leaves' values and salts (commitments kept).
5. Append a signed checkpoint covering the new head.
6. `COMMIT`; then `PRAGMA wal_checkpoint(TRUNCATE)` (with `secure_delete=ON`).

C6 accepts a missing value only if a later `SYSTEM_REDACTION` event lists that path, its signature
verifies under a trusted key, and `targetContentHash` equals the target's recomputed `contentHash`.
Binding to `targetContentHash` and `targetSeq` prevents reusing an authorization on another record.

Steps 3–5 are one transaction, so there is no internal window between redaction and its checkpoint.
**Still unprotected:**
- Ordinary (non-system) events after the latest *externally held* checkpoint can be modified-and-recomputed or truncated by a DB-write attacker.
- Suppression: deleting the redaction event and its checkpoint from the tail leaves the blank leaves flagged as `UNAUTHORIZED_REDACTION` — detected, but reported as unauthorized rather than suppressed.
- The signature proves the service accepted an admin credential, not which human acted; a stolen admin API key yields a valid-looking redaction.
- Compromise of the host-stored signing key allows forged authorizations (L4).
- `SYSTEM_*` events are exempt from redaction and retention so authorizations cannot be removed by policy.

## 7. Retention and archive
1. Select rows with `recordedAt < cutoff` (`cutoff = now − windowDays`), excluding `SYSTEM_*` events and already-archived rows.
2. Write `archives/<runId>.json` (full records: envelope, leaves with values, salts and commitments), fsync, compute its SHA-256.
3. `BEGIN IMMEDIATE`; sign `R = {type:"retention-v1", runId, cutoff, windowDays, fromSeq, toSeq, archiveFile, archiveSha256, requestedBy, requestedAt}`; append a `SYSTEM_RETENTION_RUN` event; remove values, salts and commitments of the selected rows (envelope, `payloadRoot` and hashes kept); append a signed checkpoint; `COMMIT`.
4. If the transaction fails, the orphaned archive file is harmless and reported.

**Two separate claims:**
- *Retained metadata consistency* (C1–C4, C7): the kept envelope fields and `payloadRoot` still recompute `contentHash`/`recordHash`, and the row is covered by a signed run whose cutoff exceeds its `recordedAt` and whose range contains its `seq`. This says nothing about whether the archived payload still exists or is unaltered.
- *Archive content integrity* (C8): reported as `VERIFIED` only after the archive file's SHA-256 equals the signed `archiveSha256` **and** each archived record's `payloadRoot` recomputes from the file's leaves. If the file is unreachable, `contentIntegrity` is `UNAVAILABLE` — not a chain break, and never reported as verified.

In the baseline design the archive file is **plaintext** and an archived record cannot be redacted
(409), because rewriting the file would invalidate its signed digest (LIMITATIONS.md items 3–4).

### 7.1 Future improvement under evaluation: encrypted archives
Not in committed scope; to be decided by the engineer at the retention milestone.

- **Scheme:** encrypt each archived record with its own random 256-bit key using AES-256-GCM
  (`cryptography`, already a dependency), 96-bit random nonce, associated data `canon({seq, recordHash})`
  to bind each ciphertext to its chain position. The archive file holds only ciphertexts; the signed
  `archiveSha256` covers the ciphertext file. Record keys are stored in the database, separate from the file.
- **Redacting an archived record:** delete that record's key (crypto-shredding) under a signed
  `SYSTEM_REDACTION` authorization. The archive file and its signed digest are unchanged.
- **Verification:** the file digest check is unchanged; `payloadRoot` is recomputed for records whose key
  exists; shredded records are reported as `SHREDDED`, checked against their signed authorization.
- **Benefits:** a leaked archive file alone reveals no payload data; archived records become redactable.
- **Limits:** record-level, not field-level, granularity; keys in the same database mean that database plus
  archive compromise still reveals everything; deleted keys remain in database backups (same secure-deletion
  caveats); production key custody would need KMS.
- **Estimated cost:** about half a day including tests.

## 8. Export bundle (`GET /audit/export?actorId=` or `?resourceId=`)
Contents: `records.jsonl` (matching records, redactions applied; archived matches as stubs with `runId`),
`skeleton.jsonl` (`seq, recordedAt, prevHash, contentHash, recordHash` from the first match's predecessor
to the head), a signed checkpoint of the head, and `manifest.json` (filter, counts, algorithm versions,
file digests, `"completeness": "signer-asserted"`) with an Ed25519 signature.

| ID | Invariant | Establishes |
|----|-----------|-------------|
| E1 | Manifest signature valid under an out-of-band public key; file digests match | Bundle integrity since export |
| E2 | Each record's `contentHash`/`recordHash` recompute from its leaves | Record validity |
| E3 | Skeleton links contiguously; each record's `recordHash` equals its skeleton entry | Chain membership; gaps and reordering between matches detectable |
| E4 | Skeleton head equals the included signed checkpoint | Anchoring to an authenticated head |
| E5 | — | **Completeness is not provable**: the skeleton holds only hashes, so a recipient cannot tell whether an omitted record matched the filter |

## 9. Alternatives considered
| Alternative | Outcome | Reason |
|-------------|---------|--------|
| HMAC-keyed chain | Rejected | Recipients would need the secret to verify |
| Merkle tree log with inclusion/consistency proofs | Deferred | Strongest export proofs, but not achievable in the time budget |
| Unsalted field hashes | Rejected | Low-entropy values recoverable by brute force (to be demonstrated by the PoC) |
| Crypto-shredding (per-record keys) | Under evaluation (§7.1) | Enables redaction of archives; adds key management |
| Re-hashing the chain after redaction | Rejected | Destroys tamper evidence |
| Trusting the public key embedded in a bundle | Rejected | An attacker could re-sign with their own key |

## 10. Direct database tampering tests (planned, not implemented)
Purpose: prove that `GET /audit/verify` detects unauthorized modification **by recomputing hashes**,
not because the guard triggers block writes.

The tests distinguish two classes of attack:
- **Direct tampering** — editing, deleting or reordering stored rows without recomputing the chain.
  Detected by hash verification alone (C1–C8), with no trusted reference needed.
- **Full-chain rewrite** — editing a record and recomputing every later hash (and optionally deleting
  checkpoints stored in the database). The result is internally consistent, so hash verification alone
  cannot detect it. Detection requires an **independently trusted checkpoint** held outside the
  attacker's control (L2/L3 in §5).

Procedure (automated pytest test, plus `scripts/tamper_demo.py` for a manual walkthrough):
1. Create a fresh SQLite database in a temporary directory (never a shared or real database).
2. Write synthetic events through the API; confirm `GET /audit/verify` returns `intact: true`.
3. Open a separate raw `sqlite3` connection — bypassing the application, SQLAlchemy and the API —
   and execute `DROP TRIGGER` for every guard trigger, simulating an attacker with file access.
4. Apply one tampering case per test (table below) with raw SQL.
5. Call `GET /audit/verify`; assert `intact: false`, the expected `violationType` and the expected `seq`.

A separate test checks that the triggers, when present, block UPDATE/DELETE. That test covers defense
in depth only and is not counted as tamper detection.

| Tampering case (raw SQL, triggers dropped) | Expected result |
|---------------------------------------------|-----------------|
| Change a revealed payload value of record k | `LEAF_COMMITMENT_MISMATCH` at k |
| Change an envelope field (e.g. `actorId`) of record k | `CONTENT_HASH_MISMATCH` at k |
| Change the stored `recordHash` of record k | `RECORD_HASH_MISMATCH` at k |
| Delete record k | `SEQUENCE_GAP` at k |
| Swap the contents of records k and k+1 | Hash mismatch at k |
| Blank a leaf value and salt without authorization | `UNAUTHORIZED_REDACTION` at k |
| Mark record k archived and strip its payload without a signed run | `INVALID_ARCHIVE` at k |
| Alter an archive file | `ARCHIVE_CONTENT_MISMATCH` |
| Delete records after a checkpoint's seq | `TRUNCATED` |
| Edit record k and recompute all later hashes, with a checkpoint beyond k present | `CHECKPOINT_MISMATCH` |
| Edit and recompute, and also delete all checkpoints in the DB | **Not detected by the DB-only verifier** (L1 limit); detected only against an externally held checkpoint — test asserts both outcomes |
| Append a well-formed ordinary event at the tail | **Not detected** (ordinary events are unsigned); documented limitation |
