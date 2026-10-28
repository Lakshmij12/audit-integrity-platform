# Limitations and Remaining Risks

Implementation status (commit 5): only the pure cryptographic foundations exist (canonical JSON,
timestamps, typed-path leaf commitments, content/record hashes and chain link checks, in
`src/aip/crypto/`). There is no API, database, retention, archive, export or signing code yet; items about
those describe the proposed design in DESIGN.md and will be revised as they are implemented and tested.
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
    bounded here; the API layer must enforce request size limits.
30. `warn_unreachable` is enabled on the command line for the commit 5 gates, not yet in `pyproject.toml`.
