# ADR-002: SHA-256 hash chain, with Ed25519 signatures for authorizations and checkpoints

- **Status:** Accepted (prototype).
- **Recorded:** retrospectively, on 2026-10-28. The design is in DESIGN.md §2, §5 and §6 (commit
  `03e2d98`). The hash chain was implemented in commit `7b7e83e`; signatures, checkpoints and
  anchored verification in commit `75f9091`; signed authorizations in commit `b3f4ff2`. This record
  summarizes those decisions; it was not written at the time.

## Context
The brief requires each record to carry a hash of its own content and of the preceding record, so that
modifying or deleting a past record is detectable. Three further needs came out of the design:
1. A hash chain alone proves only internal consistency. Anyone who can write the database file can
   rewrite a record and recompute every later hash.
2. Redaction and retention change stored data legitimately, so the verifier needs to tell an
   *authorized* change from tampering. Appending an event to the chain does not authenticate it.
3. Export recipients must be able to verify a bundle without any secret.

## Alternatives
| Option | Outcome | Reason |
|--------|---------|--------|
| **SHA-256 over canonical JSON**, domain-separated by `t` and `v` tags | Chosen | Standard, fast and available everywhere; an independent verifier can reimplement it (`tools/verify_bundle.py` does) |
| HMAC-keyed chain | Rejected | Recipients would need the secret to verify |
| Merkle tree log with inclusion and consistency proofs | Deferred | Strongest proofs for exports and truncation, but not achievable in the time budget |
| Treating a chained `SYSTEM_*` event as authorization | Rejected | Anyone with database write access can append a well-formed event |
| **Ed25519 signatures** for authorizations, checkpoints and export manifests | Chosen | Small keys and signatures, deterministic, no parameter choices; verification needs only the public key |
| RSA or ECDSA signatures | Not chosen | Larger or more error-prone (ECDSA needs a good nonce for every signature) with no benefit here |

## Decision
- Records are hashed as `contentHash` (envelope plus payload root) and `recordHash` (`seq`,
  `recordedAt`, `prevHash`, `contentHash`). The genesis `prevHash` is 64 zeros.
- One Ed25519 service key signs checkpoints, redaction and retention authorizations, and export
  manifests. Each signed document carries its own `t` tag so it can't be replayed as another type.
- Verifiers trust only a public key from configuration or the command line, never one stored in the
  database or embedded in a bundle.
- Detection of a full rewrite or truncation is only claimed against a checkpoint held outside the
  service (`anchorSeq`/`anchorHash`, `--anchor-*`).

## Consequences
- **Positive:**
  - Direct tampering is located at the first changed record.
  - Authorized and unauthorized changes are distinguished cryptographically.
  - Bundles verify offline with only a public key.
  - Results are never overstated: evidence that can't be checked is INDETERMINATE.
- **Negative:**
  - The signing key is an unencrypted PEM on the same host, so host compromise allows forgery
    (LIMITATIONS 54, 58).
  - One key, with no rotation; after a key change, older authorizations can no longer be verified.
  - Checkpoints are only produced on request, and the caller has to store them (53).
  - Verification walks the whole chain every time (57).

## Production evolution
Sign in a KMS or HSM; keep a list of trusted public keys with validity periods, so rotation doesn't
orphan old authorizations; publish checkpoints on a schedule to an independent append-only store; add
Merkle proofs for export completeness. See ARCHITECTURE.md §7 (proposed, not implemented).
