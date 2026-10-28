# Final Engineering Summary

## 1. Plan and rationale
The work was split into 12 reviewed commits, each implemented, tested and staged by the AI assistant,
then approved by the candidate (two gates: plan, then commit). The order follows the dependencies:

1. Requirements and design.
2. A redaction proof of concept, to de-risk the hardest design question first.
3. Tooling with hash-locked dependencies.
4. Pure cryptography, then storage, then the API.
5. Verification, then redaction and retention, then export.
6. Scenario C, then the final documentation.

Each commit lists its quality-gate results in DEVELOPMENT.md and its AI involvement in AI_USAGE.md.

## 2. Requirement-to-implementation mapping
| Assignment requirement | Implementation | Evidence |
|------------------------|----------------|----------|
| Write API with eventType, actorId, resourceType, resourceId, payload, timestamp (documented choice) | `POST /audit/events`; the caller may supply a timestamp (defaults to server time, rejected if more than 5 min in the future); the server assigns `recordedAt` | `tests/api/test_events_api.py`, `tests/ingest`; REQUIREMENTS §3 #1 |
| Append-only: no update or delete operations | No such routes; guard triggers as defense in depth | `test_no_route_updates_or_deletes_records`, trigger tests |
| Query by actorId, resourceType+resourceId, eventType, from/to, any combination, paginated | `GET /audit/events`, filters AND-combined, keyset pagination | `tests/api/test_events_api.py` |
| Hash of own content and of the preceding record, defined genesis | `contentHash`, `recordHash`, `prevHash`, genesis = 64 zeros | `tests/crypto` (known-answer vectors), DESIGN §2 |
| `GET /audit/verify`: intact? first inconsistency and its violation type | `verify/service.py`, statuses VERIFIED / INDETERMINATE / TAMPERED | `tests/verify`, `tests/api/test_verify_api.py` |
| Modify the store directly, then verify again to confirm detection | Raw SQLite tamper tests and `scripts/tamper_demo.py` | DESIGN §10, TESTING §4 |
| B: retention that is archivable without false-positive breaks | Admin `POST /audit/retention/runs` (dry run by default), signed run, archive file, C7/C8 | `tests/lifecycle/test_retention.py` |
| B: structured redaction without breaking the chain; approach, trade-offs and limits documented | Per-leaf salted commitments; signed `SYSTEM_REDACTION`; nothing recomputed | DESIGN §2, §6–6.1, LIMITATIONS 2, 6, 58–66; `tests/lifecycle/test_redaction.py` |
| B: verifiable bulk export by resourceId or actorId | `GET /audit/export`, signed bundle, standalone `tools/verify_bundle.py` | `tests/export`, DESIGN §8.1 |
| C: clarified requirement, ambiguities, assumptions, design, implemented vs scoped out | `docs/SCENARIO_C.md`, `GET /audit/reports/account-access` | `tests/api/test_access_report.py` |
| Core 1–2: requirement understanding, task decomposition | REQUIREMENTS.md, DESIGN.md, the commit plan (AI_USAGE §4) | — |
| Core 3: AI-assisted execution, traceability, quality gates, human sign-off | AI_USAGE.md (sessions, accepted, modified and rejected suggestions, errors); gates for every commit | DEVELOPMENT.md "Quality gate results" |
| Core 4: code, API/schema definitions, tests, docs | FastAPI OpenAPI (`/docs`), STRICT SQL schema, 650 tests | TESTING.md |
| Core 5: risks, failure scenarios, guardrails | LIMITATIONS.md, ARCHITECTURE §5, failure-injection tests | — |
| Deliverables: repository history, ATTESTATION.md, architecture, setup, testing, AI log, summary | README, ARCHITECTURE, TESTING, DEVELOPMENT, AI_USAGE, this document | ATTESTATION.md has personal fields for the candidate to complete |

## 3. Completed features
API-key roles; ingestion with strict validation and limits; filtered keyset queries; a SHA-256 hash
chain with typed-path salted leaf commitments; full-chain verification with safe, value-free reports;
Ed25519 checkpoints and anchored verification; a controlled schema migration with narrowly scoped
triggers; authorized redaction; retention with signed archives; signed export bundles with an
independent offline verifier; the Scenario C account-access report; and the reproducible tamper
demonstration.

## 4. Deliberate scope reductions
- **Single-node SQLite;** no cloud deployment, container setup or metrics.
- **Checkpoints are not stored in the database.** The caller keeps them and passes them in as an
  anchor; there's no external publication or Merkle proofs.
- **One service signing key,** with no rotation, list of trusted keys or HSM.
- **Archived payloads are not exported,** so archived records in a bundle verify as INDETERMINATE. There
  is no restore endpoint and archive files are not encrypted (DESIGN §7.1 lists that as future work).
- **Scenario C:** no regulator role, no auditing of reads made through the service itself, and no
  signed or CSV reports (SCENARIO_C §5).

## 5. Key decisions and trade-offs
| Decision | Why | Cost |
|----------|-----|------|
| Canonical JSON (an RFC 8785 subset: no floats, NFC strings) | The same bytes in any language; the independent verifier reimplements it | Clients must send decimals as strings |
| SHA-256 and domain-separated preimages (`t`, `v` tags) | Standard and fast; hashes of different kinds of data can't be confused | No algorithm agility beyond `hashVersion` |
| Per-leaf salted commitments with typed paths | Redaction without recomputation; equal values can't be linked by their commitments | Paths and array lengths remain visible |
| Ed25519 signatures for authorizations | Appending an event does not authenticate it; a signature does | Key custody on the host |
| VERIFIED / INDETERMINATE / TAMPERED | Never overclaims: evidence that can't be checked is not reported as either outcome | Clients must handle three outcomes |
| Verification stops at the first violation | Simple, clear reports | Later records are reported as UNVERIFIED rather than classified |
| SQLite with `BEGIN IMMEDIATE` and WAL | One writer means a consistent chain head; easy to run | No horizontal write scaling |
| Keyset pagination | Stable under concurrent appends | No random page access |

## 6. Reproducible demonstration
1. Set up: README "Prerequisites and installation" and "Keys and server".
2. Run `scripts/tamper_demo.py`. It writes and queries events, verifies them, edits SQLite directly, and
   shows the change detected. It also shows truncation detected against a signed checkpoint.
3. Run the README example requests: ingest, query, verify, checkpoint, redact, retention, export, and
   the account-access report.
4. Run `tools/verify_bundle.py bundle.json --trusted-key <hex>`. Then edit `bundle.json` and run it
   again; the result is `FAILED` with a specific code.
5. Run `python -m pytest -W error --cov=aip --cov-branch`: 650 tests pass with 96% branch coverage.

## 7. What remains for production readiness
- **Security:** TLS termination, rate limiting, encryption at rest, a KMS or HSM for the signing key
  with rotation and a list of trusted keys, an identity provider instead of static API keys, and
  per-account authorization.
- **Integrity:** checkpoints published periodically to an external, append-only location (for example
  a transparency log or WORM storage), and Merkle proofs for exports.
- **Operations:** backups that respect redaction, encrypted archives with monitored availability,
  orphan-archive cleanup, incremental verification, metrics and alerts.
- **Scale:** a server database (PostgreSQL) with a single-writer queue, and load and soak tests.
- **Compliance:** answers to the Scenario C questions (in particular, whether reads of the audit log
  must be recorded), legal holds, and per-type retention policies.
