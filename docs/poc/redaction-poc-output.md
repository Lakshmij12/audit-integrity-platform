# Redaction Proof of Concept: Recorded Run

| Item | Value |
|------|-------|
| Script | `poc/redaction_poc.py` |
| Command (repository root) | `.\.venv\Scripts\python.exe -I poc\redaction_poc.py` |
| Interpreter | `3.14.3 (tags/v3.14.3:323c59a, Feb  3 2026, 16:04:56) [MSC v.1944 64 bit (AMD64)]` |
| Platform | `Windows-10-10.0.19045-SP0` |
| Run started | 2026-10-28T01:53:13-04:00 |
| Exit code | 0 |
| stderr | empty (0 bytes) |
| Data | Synthetic only |

## Output (captured stdout with normalized line endings)

The block below is the captured stdout with normalized line endings (CRLF to LF). It was copied
programmatically from the capture file; it is not byte-for-byte output. Apart from the line-ending
normalization (2,215 bytes captured, 39 CR bytes removed, 2,176 embedded), the content has not been edited.

```text
1. Canonical encoding is independent of key order
  [PASS] reordered keys give identical bytes
2. Commit every payload leaf
     /account/number    commitment=a7c842ad4747e710...
     /account/type      commitment=789d075a5698d842...
     /pin               commitment=a381420a993fc220...
     /note              commitment=766036c5564e0c2c...
     /tags              commitment=5bda07894bbda1ed...
     /a~1b~0c           commitment=2bbdd44116253cc9...
  [PASS] all revealed leaves match their commitments
  [PASS] key 'a/b~c' maps to JSON Pointer '/a~1b~0c'
  [PASS] empty array is kept as a leaf
3. Logically redact /account/number (remove value and salt from the in-memory
   structure, keep the commitment; not secure deletion)
  [PASS] contentHash unchanged after redaction
  [PASS] value and salt removed from the in-memory structure
  [PASS] remaining leaves still verify
     still visible after redaction: the path '/account/number' and its commitment
4. Tamper with a revealed value
  [PASS] modified value detected
5. Tamper with a stored commitment
  [PASS] modified commitment changes contentHash
6. Move a leaf to a different path
  [PASS] swapped leaves fail verification (commitments are bound to their path)
7. Equal values do not produce equal commitments
  [PASS] same value with fresh salts gives different commitments, so equality cannot be inferred by comparing commitments alone (other fields may still link records)
8. Low-entropy values without a salt
     unsalted PIN recovered: '4821' after 4822 guesses in 0.037s
  [PASS] unsalted 4-digit value is recoverable (demonstrates the risk)
     100000 unsalted 9-digit guesses took 0.883s; all 10^9 would take ~147 min on one core
9. Salted, then salt removed by redaction
  [PASS] all 10^4 PINs tried without the salt: no match (illustrative)
     recovery needs the 256-bit salt; this rests on SHA-256 preimage resistance,
     not on this check
10. Salt retained elsewhere (backup, log, earlier export)
     with leaked salt, PIN recovered: '4821' after 4822 guesses in 0.048s
  [PASS] leaked salt makes the redacted value recoverable (demonstrates the risk)

RESULT: all checks behaved as expected
```

## Result summary
14 of 14 self-checks reported PASS; the script exited 0.

| Step | Check | Result | Meaning |
|------|-------|--------|---------|
| 1 | Reordered keys give identical bytes | PASS | Serialization is deterministic for key order |
| 2 | All revealed leaves match their commitments | PASS | Baseline |
| 2 | `a/b~c` maps to `/a~1b~0c` | PASS | RFC 6901 escaping prevents path collisions |
| 2 | Empty array kept as a leaf | PASS | Payload structure is preserved in the hash |
| 3 | `contentHash` unchanged after redaction | PASS | Logical redaction does not break the chain |
| 3 | Value and salt removed from the in-memory structure | PASS | Only the commitment remains in the structure |
| 3 | Remaining leaves still verify | PASS | Redaction affects only the target leaf |
| 4 | Modified value detected | PASS | Leaf tampering is detected |
| 5 | Modified commitment changes `contentHash` | PASS | Commitments cannot be replaced silently |
| 6 | Swapped leaves fail verification | PASS | Commitments are bound to their path |
| 7 | Same value with fresh salts gives different commitments | PASS | Equality cannot be inferred by comparing commitments alone |
| 8 | Unsalted 4-digit value recovered | PASS | Demonstrates the low-entropy risk |
| 9 | No match without the salt | PASS | Illustrative only |
| 10 | Leaked salt recovers the redacted value | PASS | Demonstrates the salt-retention risk |

**Not reproducible between runs:** commitment prefixes (salts are random) and timings (machine-dependent).

## Interpretation for the privacy risks
- **Low-entropy values (step 8):** without a salt, a 4-digit PIN was recovered in 4,822 guesses
  (0.037 s). The timings are illustrative only and are not a reliable estimate of real-world attack
  cost. The 9-digit figure (~147 min for 10^9 on one core) is a linear extrapolation from a
  100,000-guess sample using this unoptimized Python implementation on one machine; a native or GPU
  implementation would be much faster. The point demonstrated is that an unsalted low-entropy search
  space is exhaustible, not how long an attack would take.
- **Salt removal (steps 9–10):** the commitment protects a redacted low-entropy value only while the salt
  is unavailable. Step 9 is illustrative; the actual guarantee rests on SHA-256 preimage resistance and a
  256-bit random salt, not on that check. Step 10 shows that any surviving copy of the salt (backup, log,
  earlier export) makes the redacted value recoverable.
- **Retained metadata (steps 3, 7):** after redaction the path (`/account/number`) and its commitment
  remain visible. Step 7 shows only that commitments alone do not reveal equality; envelope fields such as
  `actorId` or `resourceId` may still link records.
- **Prior exports (step 10):** a bundle exported before a redaction carries the value and salt; step 10
  models what a holder of such a copy can do.

## What this spike does not show
- Secure deletion from SQLite, the WAL file, backups or any storage medium (redaction here is logical and
  in memory only).
- Signed redaction authorizations (DESIGN.md §6).
- Full canonicalization rules: NFC normalization, integer bounds, duplicate-key rejection.
- Persistence, concurrency or API behaviour.

## Status
Spike result only. DESIGN.md remains **Proposed**; implementing DESIGN.md §6 requires engineer approval.
