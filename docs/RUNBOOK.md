# Operational Runbook (prototype)

Responses to integrity and availability incidents for this prototype. **Every procedure here is
manual.** The service has no alerting, no automatic freeze, no repair tool and no restore endpoint;
those are listed as *not implemented* where they matter.

Conventions: `$base = "http://127.0.0.1:8000/audit"`; `$a` is an auditor key header and `$adm` an
admin key header (README "Example requests"). Errors are RFC 9457 `application/problem+json`; the
field to look at is `code`. Every response carries `X-Request-ID`, which matches the JSON access log.

## 0. Reading `GET /audit/verify`
| Field | Meaning |
|-------|---------|
| `status` | `VERIFIED` (everything checked), `INDETERMINATE` (no violation, but some evidence couldn't be checked) or `TAMPERED` (a violation) |
| `intact` | `true` / `null` / `false` for the three statuses |
| `firstInconsistency` | `seq`, `violationType`, `eventId`, `field`, `leafPath`, `expected`, `actual` (hashes or record numbers only, never values) |
| `authorized` | `redactedLeaves`, `archivedRecords` whose signed evidence verified |
| `unverified` | `redactedLeaves`, `archivedRecords` signed by a key not trusted here; `archivedContentUnavailable` archive files not found |
| `anchor` | With `?anchorSeq=&anchorHash=`: `seq`, `recordHash`, `matched` |
| `notes` | Plain-language caveats, such as "internal consistency only" |

Without an anchor, `VERIFIED` means the stored data is internally consistent. It does **not** rule out
a coordinated rewrite by someone with write access to the database file (ARCHITECTURE.md §5).
Always also verify against the latest checkpoint you hold outside the service.

## 1. Verification reports TAMPERED
**Symptom:** `status: "TAMPERED"`, `intact: false`, and `firstInconsistency` set. `GET
/audit/checkpoints/latest` and `GET /audit/export` return **409** `conflict` (they refuse to sign a
broken chain). The account-access report marks that record TAMPERED and later ones UNVERIFIED.

**Do not:**
- try to "repair" rows or recompute hashes
- delete records or archive files
- ask the service to sign anything new

**Steps (manual):**
1. **Record the finding:** `firstInconsistency` (`seq`, `violationType`, `eventId`, `field`,
   `leafPath`), `headSeq`, `headRecordHash`, the time, and the `X-Request-ID`.
2. **Decide whether to stop writers.** *Not implemented:* the service keeps accepting appends after
   tampering is detected. Stopping it is an operator decision.
3. **Preserve evidence:** stop the service so the WAL is checkpointed, then copy the database files
   read-only:
   ```powershell
   Copy-Item data\audit.db, data\audit.db-wal, data\audit.db-shm -Destination <evidence folder>   # copy the WAL/SHM only if they exist
   ```
   Also keep the archive directory and the access logs. Never copy the signing key into an evidence
   folder.
4. **Classify** using `violationType` (DESIGN.md §4, §6.1, §7.2):
   - `LEAF_COMMITMENT_MISMATCH`, `CONTENT_HASH_MISMATCH`, `RECORD_HASH_MISMATCH`, `SEQUENCE_GAP`,
     `PREV_HASH_MISMATCH`, `EVENT_ID_MISMATCH`, `MALFORMED_*`, `PAYLOAD_ROOT_MISMATCH`: stored rows were
     changed outside the application.
   - `UNAUTHORIZED_REDACTION`: a value was removed without a valid signed authorization.
   - `INVALID_ARCHIVE` / `ARCHIVE_CONTENT_MISMATCH`: archive marking or an archive file is wrong
     (section 3).
   - `INVALID_AUTHORIZATION`: a `SYSTEM_*` event's signature or structure is invalid.
5. **Compare with external evidence:** `GET $base/verify?anchorSeq=<seq>&anchorHash=<recordHash>` for
   each checkpoint you hold. Earlier export bundles can still be checked offline with
   `tools/verify_bundle.py <bundle> --trusted-key <hex>`.
6. **Recover** from a backup taken before the change (section 7). *Not implemented:* there is no way
   to re-ingest records written after that backup, other than producers resending them.

## 2. Verification reports INDETERMINATE
**Symptom:** `status: "INDETERMINATE"`, `intact: null`, `firstInconsistency: null`. The `notes` say
why. This is **not** tampering: some evidence could not be checked.

| Counter > 0 | Cause | Action |
|-------------|-------|--------|
| `unverified.redactedLeaves` or `unverified.archivedRecords` | Authorizations are signed by a key that isn't trusted here: `AIP_SIGNING_KEY_PATH` is unset, or points to a different key than the one that signed them | Start the service with the key that signed them. After a key change, see section 6: older authorizations stay unverifiable (*no multi-key trust implemented*). |
| `unverified.archivedContentUnavailable` | An archive file is missing from `AIP_ARCHIVE_DIR`, or the directory is wrong | Section 3 |

Re-run `GET $base/verify` after fixing the cause. Expect `VERIFIED`, with the records in `authorized`.

## 3. Missing or altered archive files
**Missing:** `INDETERMINATE` with `unverified.archivedContentUnavailable > 0`.
**Altered:** `TAMPERED` with `violationType: "ARCHIVE_CONTENT_MISMATCH"` and `field: "archive"`.

1. **Find the expected file.** Retention runs are `SYSTEM_RETENTION_RUN` events whose `resourceId` is
   the `runId`:
   ```powershell
   Invoke-RestMethod "$base/events?eventType=SYSTEM_RETENTION_RUN" -Headers $a
   ```
   Each event's `payload.authorization` holds `runId`, `archiveFile` (`run_<32 hex>.json`) and the
   signed `archiveSha256`.
2. **Restore** that exact file from a backup into `AIP_ARCHIVE_DIR`, then check it before relying on
   it:
   ```powershell
   (Get-FileHash -Algorithm SHA256 <archive dir>\run_<id>.json).Hash.ToLower()   # must equal archiveSha256
   ```
3. **Re-run `GET $base/verify`.** Never regenerate or edit an archive file: its digest is signed, so
   any rewritten file is `ARCHIVE_CONTENT_MISMATCH`.
4. **Orphan files:** a `run_*.json` whose `runId` has no `SYSTEM_RETENTION_RUN` event is left over from
   a run that never committed (DESIGN.md §7.2). It is never read by verification and can be removed by
   an operator. *Not implemented:* automatic orphan cleanup.

*Not implemented:* replication of archives, monitoring of archive availability, and encrypted
archives. The files are plaintext, so treat backups of them as sensitive (LIMITATIONS 3, 62).

## 4. `503` with `code: "store_busy"`
**Meaning:** the write lock was not obtained within `AIP_BUSY_TIMEOUT_MS` (default 5000 ms).
**Nothing was written.** The response includes `Retry-After: 1`.
(A `503` with `code: "service_unavailable"` is different: no signing key is configured for an endpoint
that needs one.)

1. Retry the same request after `Retry-After`, with backoff. This is safe: nothing was stored.
2. If it persists, look for a long write transaction:
   - a retention run (it holds the lock while writing its archive file, up to 10,000 records);
   - another process holding the database file open for writing, such as a manual tool or a copy;
   - a second service instance on the same file.
3. Only one writer exists by design (ADR-001). *Not implemented:* write queueing or multiple writers.

## 5. `500` with `code: "commit_outcome_unknown"`
**Meaning:** COMMIT failed in a way that SQLite does not guarantee was rolled back. The change **may
or may not** be stored. *Not implemented:* idempotency keys (LIMITATIONS 46), so a blind retry can
create a duplicate.

1. **Appended event:** look for it before retrying. Filter by the fields you sent; if you sent a
   `timestamp`, narrow the range around it (`from` inclusive, `to` exclusive):
   ```powershell
   Invoke-RestMethod "$base/events?actorId=<actor>&resourceId=<resource>&eventType=<type>&from=<timestamp>&to=<timestamp + 1 s>" -Headers $a
   ```
   If an event with the same envelope and payload is there, don't resend. Without a client
   identifier, two genuinely identical events can't be told apart; record that ambiguity.
2. **Redaction:** `GET $base/events/<eventId>` and check `redactedPaths`.
3. **Retention run:** the response with the `runId` was lost. List
   `GET $base/events?eventType=SYSTEM_RETENTION_RUN`, and compare with the newest `run_*.json` in
   `AIP_ARCHIVE_DIR`. If the file's `runId` has an event, the run committed; if not, the file is an
   orphan (section 3, step 4). The archive file is deliberately kept after this error.
4. Run `GET $base/verify` afterwards.

## 6. Signing-key compromise (or suspected compromise)
**Impact:** whoever holds the private key can forge redaction and retention authorizations,
checkpoints and export bundles that verify under that key (LIMITATIONS 54, 58, 68). There is **no
implemented protection** against this.

**Steps (manual):**
1. Stop the service. Treat every checkpoint and bundle signed after the suspected compromise time as
   untrusted.
2. Create a new key:
   ```powershell
   $env:PYTHONPATH = "src"
   .\.venv\Scripts\python.exe -m aip.cli new-signing-key --out <new path>\signing.pem   # refuses to overwrite
   ```
   Set `AIP_SIGNING_KEY_PATH` to it, and give the printed public key to recipients out of band.
3. Restart and verify. **Expect `INDETERMINATE`:** the verifier trusts exactly one key, so redactions
   and retention runs signed with the old key become unverifiable (`unverified.*`). Records with no
   such evidence still verify.
4. Rely on evidence created **before** the compromise: checkpoints and bundles saved by recipients,
   verified with the **old** public key (`tools/verify_bundle.py --trusted-key <old hex>`).
5. Remove the old key file from the host, and from any backups that hold it.

*Not implemented:*
- key rotation
- a list of trusted keys with validity periods
- re-signing existing authorizations under a new key
- a KMS or HSM
- revocation

These are the production answer (ADR-002, ARCHITECTURE.md §7).

## 7. Backup recovery and checkpoint comparison
*Not implemented:* there is no backup or restore feature; this is the manual procedure.

**Taking a backup:** stop the service, then copy `audit.db` (with `-wal` and `-shm` if present) and
the archive directory. Store the signing key separately and protected, never with the data. Backups
hold plaintext payloads and keep values redacted later (LIMITATIONS 2, 59).

**Restoring:**
1. Stop the service and replace the database files and the archive directory with the backup.
2. Start the service. Opening the database checks the schema and **fails closed**: if the triggers or
   version differ, the service refuses to start (`StorageIntegrityError: unexpected schema ...` /
   `guard triggers differ from schema v2`). A v1 file is migrated to v2 at this point.
3. `GET $base/verify` should be `VERIFIED` (or `INDETERMINATE` for archives not restored).
4. Compare with every checkpoint you hold, using `GET $base/verify?anchorSeq=<seq>&anchorHash=<hash>`:

   | Result | Meaning |
   |--------|---------|
   | `anchor.matched: true` | The restored chain contains that checkpoint unchanged. |
   | `TRUNCATED` | The checkpoint is newer than the backup. **Expected after restoring an older backup**: records after the backup are missing. |
   | `ANCHOR_MISMATCH` | The restored chain differs from what was signed at that point: the backup is not a faithful copy. |
5. **Re-apply redactions** made after the backup was taken: restoring brings their values back
   (redaction does not reach backups). Re-run the redaction requests; each one appends a new signed
   `SYSTEM_REDACTION`.
6. Take a new checkpoint (`GET $base/checkpoints/latest`) and store it outside the service.
