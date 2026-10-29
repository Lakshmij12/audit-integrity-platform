# ADR-001: SQLite instead of PostgreSQL for the prototype

- **Status:** Accepted (prototype).
- **Recorded:** retrospectively, on 2026-10-28. The decision was made during planning and documented
  in DESIGN.md §3 (commit `03e2d98`), then implemented in commit `243c69e`. This record summarizes it;
  it was not written at the time.

## Context
The chain needs a single, totally ordered sequence of records: each append must read the current head
and write the next record without another writer slipping in between. The brief asks for a working
prototype that reviewers can run locally in a 2–3 day window, validated through the API, including
modifying the data store directly to show that tampering is detected.

## Alternatives
| Option | For | Against |
|--------|-----|---------|
| **SQLite (WAL, `BEGIN IMMEDIATE`)** | No server to install; one file a reviewer can inspect and tamper with; one writer by design, which makes reading the chain head inside the write lock trivial; STRICT tables and triggers | Single node; one writer at a time; no network access control; no encryption at rest without extensions |
| PostgreSQL | Concurrency, replication, row-level security, mature operations | A server to install and configure for every reviewer; serializing appends needs an explicit lock (for example an advisory lock or `SELECT ... FOR UPDATE` on a head row) |
| Append-only file or ledger database | Natural fit for append-only data | Weaker querying and constraints; more custom code; harder to demonstrate direct tampering |

## Decision
Use SQLite in WAL mode with `synchronous=FULL`, `secure_delete=ON`, STRICT tables and explicit
transactions. Every append runs in `BEGIN IMMEDIATE`, which takes the write lock before the head is
read, so two writers can never extend the same head. Access goes through SQLAlchemy Core with
explicit SQL, so the schema stays visible and portable.

## Consequences
- **Positive:** zero-setup runs; tests and the tamper demonstration use real database files;
  `prev_hash` and `record_hash` are UNIQUE, so a fork is also rejected by constraints.
- **Negative:**
  - One writer at a time; a writer that can't get the lock within the busy timeout gets
    `503 store_busy` (LIMITATIONS 14, 31).
  - Retention holds the write lock while writing its archive file (63).
  - No encryption at rest (1).
  - Single host only. Measured on the development machine: about 320–340 appends per second with
    `synchronous=FULL` (PERFORMANCE.md).

## Production evolution
Move to PostgreSQL with append-only tables (no UPDATE or DELETE grants, plus triggers), a
single-writer append path serialized by a lock on the chain head, idempotency keys, encryption at
rest and row-level access control. The hashing and verification design is storage-independent: the
canonical preimages (DESIGN §1–2) don't change. See ARCHITECTURE.md §7 (proposed, not implemented).
