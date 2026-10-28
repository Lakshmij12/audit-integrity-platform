# Limitations and Remaining Risks

Implementation status (commit 2): no application code exists yet. These items describe limitations of
the proposed design in DESIGN.md and will be revised as features are implemented and tested. Nothing in
this repository is claimed to be production-ready, and no security control or test listed here is
claimed to be complete.

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
