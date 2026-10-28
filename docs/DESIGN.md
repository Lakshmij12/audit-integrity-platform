# Design: Hash Chain, Redaction, Retention and Export

**Status: Proposed — pending engineer approval.** Partly implemented: §1, §2 and the chain link checks
(C1, C2, C4, C4a) of §4 exist as pure functions (commit 5); §3 persistence and append-only ingestion
exist as a service layer (commit 6) with the write and query HTTP API (commit 7, see
docs/DEVELOPMENT.md "Running the API"); everything else is not implemented. This
document will be marked
approved only after explicit approval by the engineer, and updated as features are built and tested.

## 1. Deterministic serialization
*Implemented in commit 5 (`src/aip/crypto/canonical.py`, `timestamps.py`).*

Canonical JSON is the RFC 8785 (JCS) serialization restricted to the values the service accepts:

| Element | Rule |
|---------|------|
| Encoding | UTF-8, no BOM, no whitespace, separators `,` and `:` |
| Object keys | `str` only, sorted by UTF-16 code units (RFC 8785 §3.2.3); duplicate keys rejected when parsing |
| Strings | Must already be NFC-normalized and free of lone surrogates, otherwise rejected (stricter than JCS). `"` → `\"`, `\` → `\\`; `\b \f \n \r \t`; other U+0000–U+001F as lowercase `\u00xx`; everything else, including `/`, U+007F, U+2028, U+2029, as raw UTF-8 |
| Integers | Plain decimal, in [−(2^53−1), 2^53−1] (JavaScript safe-integer range). `bool` is never treated as an integer |
| Other | `true`, `false`, `null`. Floats, NaN, ±Infinity and any non-JSON type are rejected; decimals travel as strings |
| Depth | A scalar has depth 0; a container has depth 1 + the deepest member (an empty container has depth 1). At most `MAX_DEPTH = 32`, enforced identically when encoding, parsing, flattening and rebuilding payloads |

Timestamps are hashed only in canonical form `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, exactly six fractional
digits). Accepted input is RFC 3339 with an uppercase `T`, 0–6 fractional digits and `Z` or `±HH:MM`
(converted to UTC). Rejected: missing offset, space or lowercase separators, lowercase `z`, more than six
fractional digits, leap second `:60`, out-of-range time or offset fields, `-00:00`, impossible dates, and
results outside years 0001–9999.

Hash inputs are always canonical JSON arrays/objects, never raw string concatenation, so field boundaries
are unambiguous. Cross-checks: RFC 8785 §3.2.2–3.2.4 string and literal sample (numbers removed) matches
byte-for-byte; the §3.2.3 sorting sample is *rejected* because its key U+FB33 is not NFC (it normalizes to
U+05D3 U+05BC), and its remaining six keys sort in the RFC's expected order.

## 2. Record hashes and genesis
*Implemented in commit 5 (`commitments.py`, `hashing.py`).*
```
leafCommitment = SHA256(canon(["aip-leaf-v1", typedPath, saltHex, value]))      salt = 32 random bytes
payloadRoot    = SHA256(canon({"t":"aip.payload","v":1,
                               "leaves":[[typedPath, leafCommitment], ...]}))  ordered by canon(typedPath)
contentHash    = SHA256(canon({"t":"aip.content","v":1,"eventType","actorId","resourceType",
                               "resourceId","timestamp","payloadRoot"}))
recordHash     = SHA256(canon({"t":"aip.record","v":1,"seq","recordedAt","prevHash","contentHash"}))
GENESIS        = 64 hex zeros — the prevHash of seq 1
```
- A **typed path** is a JSON array of the steps from the payload root to a leaf: strings for object keys,
  integers for array indices. Leaves are scalars and empty containers; non-empty containers are not leaves.
  The empty payload `{}` is the single leaf `[]` (path) with value `{}`. That root leaf is the only
  leaf with an empty path: it must be revealed and hold exactly `{}` (no array, scalar or `null`), and
  it cannot be redacted.
- `payloadRoot` uses only paths and commitments, never values or salts. A matching root therefore
  proves the commitments are intact, **not** that revealed values match them: a value changed without
  its commitment leaves the root unchanged and is caught only by the per-leaf check (C5). Verification
  must run both; a combined `verify_payload` API is deferred to the verification milestone.
- The `"t"` domain tags make each hash's purpose explicit; the structures were already distinct.
- All digests and salts are 64 lowercase hex characters; `seq` is an integer in [1, 2^53−1];
  `eventType`, `actorId`, `resourceType`, `resourceId` are non-empty NFC strings. Every input is
  validated before hashing.
- A leaf set is accepted only if it could come from exactly one payload: at least one leaf, unique paths,
  no leaf path is a prefix of another, children of one parent are all keys or all indices, indices are
  exactly 0..n−1, and the root is an object.

`recordedAt` is in the record envelope so it remains protected after archival (retention depends on it).

### 2.1 Post-spike finding: JSON Pointer paths were ambiguous
The commit 3 proof of concept, and the earlier version of this section, committed leaves under RFC 6901
JSON Pointer strings. A pointer such as `/a/0` does not say whether `0` is an array index or an object key,
so `{"a": ["x"]}` and `{"a": {"0": "x"}}` produced the same leaves, payload root and contentHash: an
attacker could change an array into an object with numeric keys (or back) without detection. The PoC's
14 checks did not cover this case. Commit 5 commits typed paths instead; the regression test
`test_typed_path_regression_vectors` shows the two payloads now have different roots. The commit 3 PoC is
kept unchanged as a historical record; JSON Pointer strings remain only as a way for API callers to name
a field, resolved against stored typed paths.

**Why SHA-256:** 128-bit collision resistance; FIPS 180-4 approved; in the Python standard library and
every language a recipient might use. Length extension does not apply because no secret is hashed.
SHA-3/BLAKE2 would add no security need here and reduce recipient tooling ubiquity.

## 3. Persistence and transactional append
*Implemented in commit 6 (`src/aip/storage/`, `src/aip/ingest/`) as a service layer; no HTTP API yet.*

**Schema v1** (explicit DDL in `storage/schema.py`, `STRICT` tables, SQLite ≥ 3.37; developed on 3.50.4):
- `audit_records`: `seq` (INTEGER PRIMARY KEY, ≥ 1, assigned as head + 1), `event_id` (UNIQUE), the four
  envelope identifiers, `timestamp` and `recorded_at` (the exact canonical strings that were hashed),
  `payload_root`, `content_hash`, `prev_hash` (UNIQUE), `record_hash` (UNIQUE), `hash_version`, and the
  reserved `archived_at` / `archive_run_id` (always NULL in v1). CHECKs enforce 64-lowercase-hex digests,
  length bounds, `hash_version = 1`, and that exactly seq 1 links to the genesis value.
- `payload_leaves`: `(seq, path)` primary key, `commitment`, `salt` (32-byte BLOB) and `value`. `path`
  and `value` are the canonical JSON text the commitment covers; JSON `null` is the text `'null'`, while
  SQL NULL in both `salt` and `value` means redacted (enforced: both NULL or neither).
- Indexes on `(actor_id, seq)`, `(resource_type, resource_id, seq)`, `(event_type, seq)`,
  `(timestamp, seq)` for later queries and keyset pagination.
- `schema_meta` records `schema_version = 1`. Opening a database fails closed unless exactly the v1
  tables, indexes and triggers exist, the version matches and the tables are `STRICT`.

**Connections:** pysqlite's implicit transactions are disabled; every connection sets
`foreign_keys=ON`, `journal_mode=WAL`, `synchronous=FULL`, `secure_delete=ON` and `busy_timeout`.
SQLAlchemy is created with `hide_parameters=True` so SQL parameters (payload values) never appear in
error messages.

**Append** (`IngestService.append`):
1. Outside the lock: validate the input (§3.1), enforce payload limits, then build salts, leaf
   commitments and the payload root.
2. `BEGIN IMMEDIATE` takes SQLite's single write lock *before* the head is read, so two writers (threads
   or processes) can never read the same head; a second writer waits up to `busy_timeout`, then fails
   with `StoreBusyError` having written nothing.
3. Read the head (fail closed if malformed); take one server clock reading `now`;
   `recordedAt = max(now, head.recordedAt)` (nondecreasing); `timestamp` = supplied value, or `now`;
   reject a supplied timestamp more than 5 minutes after the *real* `now` (the clamp never relaxes this).
4. Compute `contentHash`, `recordHash`, `eventId`; insert the record and its leaves; `COMMIT`.
5. Success is reported only after COMMIT returns. Any exception rolls back; after a failed COMMIT the
   connection is rolled back on the raw driver if SQLite still holds the transaction, then discarded
   (even if that rollback raises). Error classes: `StoreBusyError` (BUSY/LOCKED) and
   `StorageIntegrityError` (constraint or trigger) mean not committed; `StorageCommitUnknownError`
   means COMMIT failed for another reason and the outcome is unknown (LIMITATIONS 32).

`UNIQUE(seq)`, `UNIQUE(prev_hash)` and `UNIQUE(record_hash)` reject forks as a second guard.

**eventId** = `"evt_" + recordHash[:32]`: a truncated (128-bit) hash-derived identifier, not a UUID.
The full `recordHash` is authoritative. The derivation is re-checked whenever a record is read.

Guard triggers (`BEFORE UPDATE/DELETE`) block **every** update and delete in schema v1. They catch
application bugs only; anyone with direct access to the database file can drop them. **Tamper detection
never depends on the triggers** (see §10). Redaction (§6) and retention (§7) need narrowly scoped
exceptions to these triggers, which will be introduced by a controlled schema migration (v2), not by
editing v1.

### 3.1 Ingestion input
Only `eventType`, `actorId`, `resourceType`, `resourceId`, `payload` and optional `timestamp` are
accepted (strict types, unknown fields rejected, so server-controlled fields cannot be supplied).
`eventType` matches `^[A-Z][A-Z0-9_]{0,127}$` and must not start with `SYSTEM_`; identifiers are
1–256 characters (`resourceType` 1–128), NFC, without control characters. Raw JSON is parsed strictly
(duplicate keys, floats, NaN rejected). Payload limits, checked before any salt is generated: depth 32,
1,000 leaves, 8,192 characters per string or key, then 64 KiB of canonical JSON. Errors name the field
and a rule code, never the submitted value.

## 4. Verification invariants (`GET /audit/verify`, streamed in batches, stops at first violation)
| ID | Invariant | violationType |
|----|-----------|---------------|
| C1 | `seq` contiguous 1..N | `SEQUENCE_GAP` |
| C2 | `prevHash(1) = GENESIS`; `prevHash(n) = recordHash(n-1)` (for a well-formed `prevHash`) | `PREV_HASH_MISMATCH` |
| C3 | Recomputed `contentHash` equals stored | `CONTENT_HASH_MISMATCH` |
| C4 | Recomputed `recordHash` equals stored | `RECORD_HASH_MISMATCH` |
| C4a | Stored chain fields are well-formed (64-hex `prevHash` and `contentHash`, canonical `recordedAt`); malformed rows are reported, never raised | `MALFORMED_RECORD` |
| C5 | Each revealed leaf: `commit(path, salt, value)` equals stored commitment. Leaf checks return `VALID`, `INVALID` or `REDACTED_UNVERIFIED`; a redacted leaf is never reported as valid | `LEAF_COMMITMENT_MISMATCH` |
| C6 | Each leaf without a value is covered by a valid signed redaction authorization (§6) | `UNAUTHORIZED_REDACTION` |
| C7 | Each archived row is covered by a valid signed retention authorization (§7) | `INVALID_ARCHIVE` |
| C8 | Archive file digest equals the signed digest, and each archived record's `payloadRoot` recomputes from the file | `ARCHIVE_CONTENT_MISMATCH` |
| C9 | Each checkpoint matches the chain and its signature verifies; chain is not shorter than any checkpoint | `CHECKPOINT_MISMATCH` / `TRUNCATED` |

The verifier recomputes every hash it can; it never trusts a stored hash or a status flag on its own.
Response: `intact`, `recordsChecked`, `headSeq`, `firstInconsistency {seq, eventId, violationType, detail}`,
`archive {archivedRecords, metadataConsistent, contentIntegrity}`, `checkpoints {checked, latestSeq}`.

### 4.1 As implemented in commit 8
`src/aip/verify/service.py` reads every row in `seq` order, in keyset batches of 500, inside one read
snapshot. It reuses `check_chain`, `check_leaf`, `payload_root` and `content_hash` from `aip.crypto`.
Per record, in order: C1/C2/C4/C4a, `hashVersion`, `eventId = "evt_" + recordHash[:32]`
(`EVENT_ID_MISMATCH`), C5 for each leaf (`MALFORMED_LEAF` when a stored path or value cannot be parsed),
the payload root recomputed from the stored leaves (`PAYLOAD_ROOT_MISMATCH`, which also catches a
deleted or added leaf), then C3. It stops at the first violation.

- **Status.** `VERIFIED` (everything was checked), `TAMPERED` (a violation was found) or
  `INDETERMINATE` (no violation, but some redacted leaves or archived rows could not be checked).
  `intact` is `true`, `false` or `null` respectively. Redacted leaves and archived rows are counted in
  `unverified`, never reported as tampering, and never as verified: someone with file access could fake
  either state to hide an edit. Superseded in commit 9 (§6.1, §7.2): both states are now checked
  against signed authorizations, and INDETERMINATE remains only for evidence that cannot be checked.
- **No values in reports.** `firstInconsistency {seq, violationType, eventId, field, leafPath, expected,
  actual}`. `expected` and `actual` are only ever a well-formed hash or a `seq` number; anything else is
  replaced by `null`. Payload values, salts and keys never appear. `leafPath` names the payload key path
  of a leaf whose commitment failed (structure, not the value).
- **C9 (simplified).** Checkpoints are not stored in the database. `GET /audit/checkpoints/latest`
  verifies the chain, then returns an Ed25519-signed checkpoint `{seq, recordHash, signedAt, keyId,
  signature, publicKey}`. It refuses with 409 when verification finds a violation. The caller keeps the
  checkpoint outside the service, checks its signature (`aip.crypto.signing.verify_checkpoint`) and
  passes it back as `GET /audit/verify?anchorSeq=&anchorHash=`. A chain shorter than the anchor gives
  `TRUNCATED`. A different `recordHash` at the anchor's `seq` gives `ANCHOR_MISMATCH` (the
  `CHECKPOINT_MISMATCH` of the table above). Without an anchor the response carries a note that only
  internal consistency (L1) was established.
- **Signing.** Ed25519 (`cryptography`), message `canon({"t":"aip.checkpoint","v":1,seq,recordHash,
  signedAt,keyId})`, `keyId` = first 16 hex characters of SHA-256 of the raw public key. Keys come from
  `python -m aip.cli new-signing-key --out <file>`, which never overwrites an existing file, and are
  loaded from `AIP_SIGNING_KEY_PATH`. Without that key, verification still works and checkpoints return
  503.
- **Access.** Both endpoints need an `auditor` or `admin` key; `writer` gets 403.

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

### 6.1 As implemented in commit 9
- **Schema v2** (`storage/schema.py`). It is applied automatically at open, inside the same
  `BEGIN IMMEDIATE` transaction that checks the schema. Every file, new or v1, takes the same v1→v2
  path, and a failed migration rolls back and leaves v1 intact. The three guard triggers keep their
  names, and each gains a `WHEN` clause that allows exactly one shape of change:
  - **Leaf UPDATE:** `salt` and `value` become NULL, while `seq`, `path` and `commitment` stay as they
    were. Allowed only for a non-archived, non-`SYSTEM_*` record.
  - **Record UPDATE:** sets only `archived_at`/`archive_run_id`, and only from NULL, on a non-`SYSTEM_*`
    record. Every other column must stay the same.
  - **Leaf DELETE:** only for an archived record.

  Records can never be deleted. `check_schema` also compares the stored trigger SQL, so a v1 trigger
  under a v2 version number fails closed.
- **Authorization** `A = {t:"aip.redaction", v:1, targetSeq, targetEventId, targetContentHash, paths,
  reason, requestedBy, requestedAt, keyId}`.
  - `paths` are typed paths, sorted and deduplicated; already-redacted paths are left out.
  - `requestedBy` is the admin API key's 8-hex id.
  - The Ed25519 signature covers `canon(A)`. The `t` tag keeps a redaction signature from being replayed
    as a checkpoint or retention run.

  The `SYSTEM_REDACTION` event has `actorId = "apikey:<id>"`, `resourceType = AUDIT_RECORD`,
  `resourceId` set to the target eventId, and payload `{authorization: A, signature}`. Its own leaves
  are committed and chained like any other record.
- **One transaction.** Validate, sign, append the `SYSTEM_REDACTION` event, then null the values and
  salts. Commitments, `payloadRoot`, `contentHash` and `recordHash` are never recomputed. After COMMIT,
  a best-effort `wal_checkpoint(TRUNCATE)` runs. The plan's step 5 (append a checkpoint) is dropped:
  checkpoints are held outside the database (§4.1).
- **C6 in the verifier.** A leaf without a value is accepted only if a `SYSTEM_REDACTION` event with a
  higher `seq` lists that exact path for that `targetSeq` and its `targetEventId` and
  `targetContentHash` match the record. Its signature must also verify under a key passed to the
  verifier. That key comes from configuration (the service's own signing key), never from the database.
  - **Signed by a key not trusted here** (for example, no key configured): `INDETERMINATE`.
  - **Missing, altered or forged authorization:** `UNAUTHORIZED_REDACTION` at the target. A `SYSTEM_*`
    event whose authorization is malformed or fails its signature is also reported, as
    `INVALID_AUTHORIZATION`.
- **API.**
  - `POST /audit/events/{eventId}/redactions` takes `{"paths": [["ssn"], ["tags", 0]], "reason": "..."}`
    and is admin only.
  - It returns 201, or 200 as a no-op when every path was already redacted.
  - Errors: 404 for an unknown event; 409 for a `SYSTEM_*` or archived target; 422 for an unknown or
    container path or a bad body; 503 without a signing key.
  - Reads show a redacted leaf as `null` and list it in `redactedPaths`.

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

### 7.2 As implemented in commit 9
- **Endpoint.** `POST /audit/retention/runs` is admin only. It is a dry run by default: an empty body or
  `{"dryRun": true}` reports the count and seq range and changes nothing. `{"dryRun": false}` archives
  (201).
- **Settings.** `AIP_RETENTION_WINDOW_DAYS` (default 365) and `AIP_ARCHIVE_DIR` (default `archives/`,
  git-ignored). A run archives at most 10,000 records; the rest are left for the next run.
- **Order inside one `BEGIN IMMEDIATE` transaction:**
  1. Select the candidates.
  2. Write `<runId>.json` to `<name>.tmp` (exclusive create), fsync, then rename it into place.
  3. Sign `R = {t:"aip.retention", v:1, runId, cutoff, windowDays, fromSeq, toSeq, recordCount,
     archiveFile, archiveSha256, archivedAt, requestedBy, keyId}`.
  4. Append `SYSTEM_RETENTION_RUN`.
  5. Mark the rows archived (`archived_at = archivedAt`), then delete their leaves.
  6. COMMIT, then a best-effort WAL checkpoint.

  The archive file always exists, complete, before the database can reference it.
- **Failure and recovery:**
  - **Any error before COMMIT:** the transaction rolls back and the new file is deleted.
  - **COMMIT outcome unknown** (`commit_outcome_unknown`): the file is kept, because the database may
    reference it.
  - **Crash between rename and COMMIT:** leaves an orphan file. A file whose `runId` has no
    `SYSTEM_RETENTION_RUN` event is safe to delete; verification never reads it.
- **C7.** An archived row is valid only when all of the following hold:
  - A `SYSTEM_RETENTION_RUN` with a higher `seq` has that `runId`.
  - Its signature verifies.
  - `fromSeq ≤ seq ≤ toSeq`.
  - The row's `recordedAt` is earlier than the signed `cutoff`.
  - `archived_at` equals the signed `archivedAt`.
  - The row is not a `SYSTEM_*` event.
  - No leaves remain in the database.

  Otherwise the result is `INVALID_ARCHIVE`.
- **C8.** When the archive file is available:
  - its SHA-256 must equal the signed `archiveSha256`
  - the record must be in it
  - each revealed leaf must recompute its commitment
  - each redacted leaf must have its own C6 authorization
  - the leaves must recompute the stored `payloadRoot`

  Otherwise the result is `ARCHIVE_CONTENT_MISMATCH`.
- **Archive file unavailable:** the run's signature is verified but the content is not. The status is
  `INDETERMINATE`, never `VERIFIED` and never `TAMPERED`. A run signed by an untrusted key is also
  `INDETERMINATE`.
- **Reads:** an archived event shows `"archived": true` and an empty payload; the payload lives in the
  archive file.

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

## 10. Direct database tampering tests
Status after commit 8: implemented for the record, leaf, deletion, rewrite and truncation rows below
(`tests/verify/test_verify_service.py`, `tests/api/test_verify_api.py`, `scripts/tamper_demo.py`).
Commit 9 adds the redaction and archive rows (`tests/lifecycle/`, `tests/api/test_lifecycle_api.py`):
unauthorized blanking gives `UNAUTHORIZED_REDACTION`, archive marking without a valid run gives
`INVALID_ARCHIVE`, and an altered archive file gives `ARCHIVE_CONTENT_MISMATCH`. Checkpoints are held by the caller rather than in the
database, so the rewrite rows are tested with and without an anchor passed to `GET /audit/verify`.

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
