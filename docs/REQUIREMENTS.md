# Requirements Analysis

Source: the assignment brief, which is confidential and deliberately not stored in this repository.
Requirements are restated in our own words with section references.

Implementation status (commit 2): no application code exists yet. The acceptance evidence column
describes planned tests, not completed ones.

## 1. Problem statement
Build an append-only audit log service with an HTTP API. Each stored record is hash-linked to its
predecessor so that modification or deletion of past records is detected by a verification endpoint.
Extend it with retention, privacy redaction and verifiable export (Scenario B), and turn an
intentionally vague compliance requirement into a concrete, scoped design (Scenario C).

## 2. Requirements
| ID | Ref | Requirement | Planned acceptance evidence |
|----|-----|-------------|-----------------------------|
| A1 | §5A Write | Accept `eventType`, `actorId`, `resourceType`, `resourceId`, `payload` (object), `timestamp` | API tests: valid → 201; missing or invalid field → 422 |
| A2 | §5A | No update or delete operation exposed | Route inventory test; DB guard triggers reject UPDATE/DELETE (defense in depth only) |
| A3 | §5A Query | Filter by any combination of `actorId`, `resourceType`/`resourceId`, `eventType`, `from`/`to`; paginate | Filter combination tests; pagination completeness test |
| A4 | §5A Chain | Each record stores a hash of its own content and of the preceding record; defined genesis value | Known-answer tests; genesis documented in DESIGN.md |
| A5 | §5A Verify | `GET /audit/verify` walks the full chain; reports intact, or the first inconsistency and its violation type | Tamper matrix tests (DESIGN.md §10) |
| A6 | §5A | Direct modification of the data store is detected through the API | Reproducible test that removes the guard triggers, edits SQLite directly, then calls `/audit/verify` (DESIGN.md §10) |
| B1 | §5B Retention | Records older than a configurable window are archivable; no false-positive breaks for legitimate archives | Legitimate archive → intact; forged archive → violation |
| B2 | §5B Redaction | Sensitive payload fields are redactable without breaking the chain; approach, trade-offs and limits documented | PoC, tests, DESIGN.md §6, LIMITATIONS.md |
| B3 | §5B Export | Export all records for a `resourceId` or `actorId` as a self-contained bundle a recipient can verify | Standalone verifier tests |
| C1 | §5C | Clarified requirement, ambiguities, assumptions, design, implemented vs scoped-out | docs/SCENARIO_C.md and `tests/api/test_access_report.py` (commit 11; the document and the code were committed together, not the document first as planned) |
| D1 | §0.4, §7 | Attestation, architecture, setup, testing approach, AI usage log, final summary | Files present and accurate |

## 3. Ambiguities and proposed decisions
| # | Ambiguity | Proposed decision | Rationale |
|---|-----------|-------------------|-----------|
| 1 | Caller- vs server-assigned timestamp | `timestamp` is optional and caller-supplied (defaults to server time), included in the content hash; more than 5 minutes in the future → 422. The server always assigns `recordedAt`. `from`/`to` filter on `timestamp`; retention uses `recordedAt`; chain order uses `seq`. | Producers know when events happened; retention must not be bypassable by backdating |
| 2 | "Any combination" of filters | All filters AND-combined; `resourceType` and `resourceId` usable independently | Export requires `resourceId` alone |
| 3 | Pagination | Keyset cursor on `seq`; `limit` default 50, max 200 | Stable under concurrent appends; no OFFSET scans |
| 4 | Payload numbers | Integers within ±2^53 only; decimals as strings | Deterministic serialization across languages |
| 5 | What is redactable | Only `payload` leaves; envelope fields are assumed pseudonymous identifiers | The brief places sensitive data in the payload; the envelope drives chain and queries |
| 6 | Archive vs soft-delete | Archive: payload moved to a signed archive file; hash skeleton kept in the database | Keeps the chain verifiable without false positives |
| 7 | Export completeness | Bundle proves integrity and chain membership; completeness is asserted by the signer | Proving it would reveal other records' identifiers |
| 8 | Who may redact or archive | `admin` role only; each action is a signed system event | Separation from writers; authenticated authorization |
| 9 | System event namespace | `eventType` values starting with `SYSTEM_` are reserved; client submissions → 422 | Blocks forged authorization events via the API |

## 4. Out of scope (time budget)
AWS deployment, metrics, container orchestration, migration tooling, multi-instance writers, KMS/HSM key
custody, external anchoring, Merkle proofs, encryption at rest. Consequences are listed in LIMITATIONS.md.
