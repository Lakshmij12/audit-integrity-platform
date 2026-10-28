# Limitations and Remaining Risks

Implementation status (commit 7): the pure cryptographic foundations (`src/aip/crypto/`, commit 5),
SQLite persistence with append-only ingestion (`src/aip/storage/`, `src/aip/ingest/`, commit 6) and
the HTTP write and query API (`src/aip/api/`, commit 7) exist. There is no verification endpoint,
redaction, retention, archive, export or signing code yet; items about those describe the proposed
design in DESIGN.md and will be revised as they are implemented and tested.
Nothing in this repository is claimed to be production-ready, and no security control or test listed
here is claimed to be complete.

## Data protection
1. **Sensitive values are stored in plaintext** in SQLite, alongside their salts, until redacted or
   archived. Anyone with read access to the database file, its WAL file or any backup can read them.
   Production would need encryption at rest (e.g. SQLCipher or envelope encryption with KMS-held keys),
   restrictive file permissions and audited database access.
2. **Secure deletion is incomplete.** `PRAGMA secure_delete=ON` plus a WAL checkpoint overwrite freed
   pages in the live database only. Backups, filesystem snapshots, OS swap/page cache and SSD blocks
   remapped by wear-levelling may retain deleted values. Redaction is effective for the live database only.
3. **Archive files are plaintext.** Each archive holds full payload values and their salts. Anyone with
   read access to `archives/` or its backups can read every archived value, including values that would
   otherwise have been redacted.
4. **Archived records cannot be redacted** in the baseline design (409): rewriting the archive would
   invalidate its signed digest. Encrypted archives with per-record keys (DESIGN.md §7.1) would address
   items 3–4 at record granularity; this is under evaluation and not implemented.
5. **Prior exports retain data.** A bundle exported before a redaction contains the value and its salt
   and cannot be recalled.
6. **Retained metadata:** after redaction, JSON paths, array lengths, the redaction event (paths, reason,
   admin key id) and envelope identifiers remain visible. Envelope fields are assumed pseudonymous.

## Integrity and authenticity
7. Without a trusted external checkpoint, a DB-write attacker can edit a record and recompute later hashes.
8. Truncation after the last checkpoint is undetectable; checkpoints in the same database can be deleted too.
9. The Ed25519 signing key is a file on the same host as the database; host compromise allows forgery.
10. Ordinary events are authenticated only by API key at ingestion; they carry no per-event signature,
    so a DB-write attacker can append well-formed ordinary events undetected.
11. Signed authorizations identify an admin API key, not a human; a stolen admin key yields valid-looking actions.
12. Guard triggers protect only against application bugs; anyone with file access can drop them.

## Exports
13. Export completeness is asserted by the signer, not provable by the recipient.

## Operations
14. One writer per SQLite file; not suitable for multi-instance deployment.
15. Static API keys: no rotation workflow, MFA or rate limiting.
16. No migration tooling (schema version table only).
17. Archive files live on local disk; when unavailable, archive content is reported `UNAVAILABLE`, not verified.

## Canonicalization and hashing (implemented in commit 5)
18. **Hash links alone prove internal consistency only.** `check_chain` passes for a chain an attacker has
    rewritten and fully re-hashed, and for a truncated chain; tests assert both on purpose. Detection
    needs an external trust anchor (a previously observed or signed head), which is not implemented yet.
19. `check_chain` trusts the stored `contentHash`; recomputing it from stored leaves (C3, C5) and checking
    redaction authorization (C6) are later steps. A redacted leaf is reported `REDACTED_UNVERIFIED`,
    never valid, and nothing in commit 5 decides whether a redaction was authorized.
    **`payload_root` alone does not verify revealed payload contents**: it never reads values, so a
    value changed without its commitment leaves the root unchanged (regression test
    `test_value_change_keeps_root_but_fails_leaf_check`). Callers must also run `check_leaf` on every
    leaf; a combined `verify_payload` API is deferred to the verification milestone.
20. **Canonical JSON is an RFC 8785 subset, and stricter than it.** It is defined only for the accepted
    values (no floats). Non-NFC strings are rejected, so RFC 8785's own sorting sample (key U+FB33) is
    rejected; a recipient using a generic JCS library gets identical bytes only for NFC input.
21. **NFC depends on the Unicode version.** Validation uses Python 3.14's `unicodedata` (Unicode 16.0.0).
    Code points unassigned in that version could normalize differently in a later version, so another
    implementation could disagree on whether such a string is NFC.
22. **Typed paths reveal structure.** Object key names, array lengths, and whether each node is an array
    or an object remain visible after redaction.
23. **The genesis value is a public constant** (64 zeros), so a chain copied from another deployment would
    also start correctly; telling deployments apart needs signed checkpoints (later commit).
24. **Salt quality depends on the OS CSPRNG** (`secrets.token_bytes`). `build_leaves` accepts a keyword-only
    `salt_factory` for deterministic tests; production code must not pass one.
25. Hash comparisons are not constant-time; the compared values are public, so no timing secret is exposed.

### Deferred findings from the commit 5 review
26. **Vector independence is partial (M2).** Known-answer digests come from two external tools, but the
    canonical preimage bytes were hand-written by the same AI assistant that wrote the implementation,
    from the same specification, so a shared misreading of the spec would not be caught. Only the
    RFC 8785 vectors give external evidence, and only for string escaping and key sorting. Mitigations:
    candidate review of the preimages; an independent RFC 8785 cross-check was not run (it would need a
    new dependency); the generator script is not committed (DEVELOPMENT.md describes the method).
27. **Leaves can be mutated in place (L2).** `Leaf` is frozen, but an empty `[]`/`{}` value is still a
    mutable object; mutating it makes `check_leaf` raise `LeafError` instead of returning `INVALID`, and
    `hash()` of such a leaf raises `TypeError`. Leaves must be treated as immutable.
28. **Repeated validation (L4).** Each leaf is validated several times (flatten, commit, `Leaf`
    construction, canonical encoding). Kept for clarity; the cost grows linearly with payload size. The
    `except` around `record_hash` in `check_chain` is unreachable after the earlier checks.
29. **No size limits in the crypto layer (L6).** String length, identifier length and leaf count are not
    bounded there. Commit 6 enforces them in the ingestion layer (DESIGN §3.1); the HTTP raw-body
    limit is still to come (commit 7).
30. `warn_unreachable` was enabled on the command line for the commit 5 gates; since commit 6 it is set
    in `pyproject.toml`.

## Persistence and ingestion (implemented in commit 6)
31. **Single host, single writer.** SQLite file locks serialize writers across threads and processes on
    one machine; they are not reliable on network filesystems, and appends are strictly sequential.
32. **Commit outcome can be unknown to the caller.** An append is reported successful only after COMMIT
    returns. When it fails, the error class says what is known:
    - `StoreBusyError` and `StorageIntegrityError` (including a busy COMMIT or a constraint failure at
      COMMIT, after which SQLite keeps the transaction open) and any `StorageError` raised before
      COMMIT: the event was **not** committed; the transaction was rolled back.
    - `StorageCommitUnknownError`: COMMIT failed for another reason (for example `SQLITE_IOERR`,
      `SQLITE_FULL`, `SQLITE_NOMEM`). SQLite documents that after such errors a transaction "may or may
      not be rolled back automatically", so the outcome is **unknown**. A rollback attempt afterwards
      does not prove the event was never committed. The message advises checking whether the event
      exists before retrying.

    If the process crashes during or after COMMIT, the caller gets no answer at all. In both unknown
    cases a blind retry can create a duplicate. Idempotency keys are deferred to commit 7; until then,
    finding a stored event requires matching its content, because its eventId is derived from a hash
    the caller does not know in advance.
33. **eventId is a truncated hash** (`"evt_" + recordHash[:32]`, 128 bits), not a UUID and not a secret.
    The full recordHash is authoritative. A collision is improbable (birthday bound about 2^64 records)
    but would make the second append fail on the UNIQUE constraint rather than create an ambiguous id.
34. **recordedAt clamping.** recordedAt never decreases; if the server clock once ran far ahead, later
    records keep that stored recordedAt until real time catches up, which skews retention by recordedAt.
    The future-timestamp check always uses the real clock, and nothing alerts on clock jumps yet.
35. **Triggers block all updates and deletes in schema v1.** Redaction and retention need a controlled
    schema migration (v2) that narrows the triggers; none exists yet. Triggers remain bug guards only.
36. **Archived records will not be fully verifiable from the database alone.** After an archive run
    deletes leaf rows, the retained `payload_root` and hashes prove only that the remaining metadata is
    consistent; the archived payload's integrity needs the signed archive file and its digest (DESIGN
    §7, C8), which are not implemented.
37. **Plaintext at rest (concrete form of item 1).** Leaf values and their salts are stored in plaintext
    in `payload_leaves`; the database file and its `-wal`/`-shm` files must be protected and backed up
    together.
38. **Schema check is strict.** Any extra table, index or trigger (for example one added for debugging)
    makes the service refuse to open the database. This is deliberate fail-closed behavior.
39. `STRICT` tables still apply lossless conversions (text `"1"` is stored in an INTEGER column as 1);
    the application always binds exact types, and the CHECK constraints bound the rest.
40. Payload limits run on input that is already in memory; the HTTP body-size limit (commit 7) is what
    bounds memory use for large requests.

### Deferred findings from the commit 6 transaction review
41. **Cleanup after a failed rollback inside a transaction relies on SQLAlchemy (L2).** If an error occurs
    inside a write transaction and the rollback then also fails, the connection is discarded by
    SQLAlchemy's own close/reset handling (verified with a scratch probe: the write lock was released and
    the next append succeeded), not by an explicit check in `database.py`; no test covers that path.
    The failed-COMMIT path does have an explicit check and a test.
42. **Nested use blocks itself (L3).** Calling `write_transaction()` or `IngestService.append()` from
    inside another write transaction on the same thread waits for `busy_timeout` and then raises
    `StoreBusyError`. `read_transaction()` does not prevent writes inside it.
43. **Pool reset failures are logged by SQLAlchemy (L4).** A failed rollback when a connection returns to
    the pool is logged as "Exception during reset or similar" with a traceback (no SQL parameters).
    Commit 7 adds JSON logging for the `aip` loggers only; SQLAlchemy's own logging is unchanged.

## HTTP API (implemented in commit 7)
44. **Static API keys.** Keys are long random strings whose SHA-256 hashes are configured in the
    environment; there is no rotation workflow, expiry, revocation list, MFA or per-client identity
    beyond a key-hash prefix in logs. Changing keys requires a restart.
45. **No TLS and no rate limiting in the service.** Keys travel in a header, so the API must sit behind
    TLS (for example a reverse proxy) outside a local demo; nothing limits request rates.
46. **No idempotency keys** (still deferred): a client retrying after a timeout or a
    `commit_outcome_unknown` response can create a duplicate event.
47. **Writers cannot read and auditors cannot write**; `admin` can do both. There is no finer-grained
    authorization (for example per resource), and reads are not yet audited themselves (Scenario C).
48. **Query results include payload values in plaintext** for any auditor key; there is no field-level
    access control. Reading a redacted record is not supported yet (redaction arrives in commit 9).
49. **Filtering uses the caller-supplied event `timestamp`** (half-open `[from, to)`), not `recordedAt`;
    results are ordered by `seq`. Equality filters are exact matches; there is no full-text search.
50. **Logging is minimal**: one JSON access line per request and error events without messages or
    tracebacks (to avoid leaking data), so diagnosing unexpected errors relies on the request ID.
