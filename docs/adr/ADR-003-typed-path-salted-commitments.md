# ADR-003: Typed-path salted leaf commitments for selective redaction

- **Status:** Accepted (prototype).
- **Recorded:** retrospectively, on 2026-10-28. The approach was proposed in DESIGN.md §2 and §6
  (commit `03e2d98`) and tried in the redaction spike (commit `dc2c264`, which used JSON Pointer
  paths). The switch to typed paths was decided in the commit 5 review (DESIGN.md §2.1) and
  implemented in commit `7b7e83e`; authorized redaction in commit `b3f4ff2`. This record summarizes
  those decisions; it was not written at the time.

## Context
Scenario B requires sensitive payload fields to be redactable without breaking the hash chain. If a
record's hash covers its values directly, removing a value changes the hash and every later link.
Recomputing the chain after a redaction would destroy its value as evidence.

## Alternatives
| Option | Outcome | Reason |
|--------|---------|--------|
| Hash the whole payload | Rejected | Any redaction breaks the chain |
| Re-hash the chain after redaction | Rejected | Destroys tamper evidence |
| Unsalted per-field hashes | Rejected | Low-entropy values (account numbers, dates) can be recovered by brute force |
| Salted per-field commitments with JSON Pointer paths | Replaced | The spike found JSON Pointer strings ambiguous: `"0"` as an object key versus array index 0 (DESIGN §2.1) |
| **Salted per-leaf commitments with typed paths** | Chosen | Removing a value and its salt leaves every hash unchanged; typed tokens (string or integer) make each path unique |
| Crypto-shredding (per-record encryption keys) | Deferred | Would also allow redacting archives, but adds key management (DESIGN §7.1) |

## Decision
- Flatten each payload into leaves identified by typed paths, such as `["tags", 0]`.
- Commit each leaf as `SHA-256(canon(["aip-leaf-v1", path, saltHex, value]))` with a fresh 32-byte
  random salt.
- `payloadRoot` covers only the sorted `[path, commitment]` pairs, and `contentHash` covers
  `payloadRoot`.
- Redaction nulls the value and salt and keeps the commitment. It is valid only with a later
  Ed25519-signed `SYSTEM_REDACTION` bound to the record's seq, eventId, contentHash and the exact path.
- Any other removal is reported as `UNAUTHORIZED_REDACTION`.

## Consequences
- **Positive:**
  - Redaction never recomputes a hash.
  - Unauthorized blanking is detected.
  - Equal values in different records can't be linked by comparing commitments.
  - Exports stay verifiable with redacted fields.
- **Negative:**
  - Paths, array lengths, the redaction reason and the admin key id remain visible (LIMITATIONS 6, 64).
  - Removing the value from the live database is not secure deletion: backups, earlier exports and
    archive files written before the redaction keep it (2, 5, 59).
  - Archived records can't be redacted (4).
  - Storage grows with one row per leaf.

## Production evolution
Encrypt archives with per-record keys so archived data can be crypto-shredded (DESIGN §7.1); make
backups respect redaction; require dual control for redaction requests. See ARCHITECTURE.md §7
(proposed, not implemented).
