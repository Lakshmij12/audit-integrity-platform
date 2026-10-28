# Scenario C: Auditing Access to Client Account Data

Requirement C1 (docs/REQUIREMENTS.md). The brief gives one sentence from Product, restated here in our
own words: regulators must be able to audit who accessed client account data. The brief says this is
deliberately under-specified. It asks us to show how we clarified it, which ambiguities and
assumptions we identified, the design that follows, and what we implemented versus scoped out.

## 1. Clarified requirement (the statement we worked from)
> An authorized reviewer, acting for a regulator, can request a report of every recorded access to a
> given client account, or of every client-account access by a given actor, optionally narrowed to an
> event type and a time range. For each access the report states who, what kind of access, which
> account and when. It contains no payload values. The report states plainly whether the underlying
> audit records passed integrity verification: for the report as a whole and for each listed event, it
> says VERIFIED, INDETERMINATE (evidence could not be checked), TAMPERED, or UNVERIFIED (after a
> detected break). A tamper-evident copy can be handed over with the existing signed export.

## 2. Ambiguities, and the assumptions we made
| # | Ambiguity | Assumption / decision | Question we would ask Product |
|---|-----------|-----------------------|-------------------------------|
| 1 | What counts as "access": reads only, or reads and changes? | Every recorded event on a client-account resource counts as access; the event type says which kind (e.g. `ACCOUNT_VIEWED`, `ACCOUNT_UPDATED`). The report can narrow to one `eventType`. | Which actions must regulators see? Are failed or denied attempts in scope? |
| 2 | How do we know an event concerns client account data? | Producers log it with `resourceType = CLIENT_ACCOUNT` (configurable: `AIP_ACCOUNT_RESOURCE_TYPE`) and the account number as `resourceId`. The service does not infer this from payloads. | Is there a canonical account identifier, and are accounts reached through other resource types (orders, documents)? |
| 3 | Access recorded where? | Access by the client-facing systems that write to this audit log. Access *through this audit service* (auditors reading events or exports) is not yet recorded (see §5). | Must reads of the audit log itself be audited too? |
| 4 | Who is "the regulator"? | No regulator logs in directly. An internal compliance user with the existing `auditor` (or `admin`) role produces the report and hands it over. The brief defines no regulator role, so none was added. | Does the regulator need direct, scoped access? Per-regulator restrictions? |
| 5 | Report shape: query, document, signed artifact? | A JSON report from an API endpoint (summary plus event list). For a signed, independently verifiable copy, use the existing `GET /audit/export?resourceId=<account>` (Scenario B). | Required format (CSV, PDF)? Must the report itself be signed? |
| 6 | Time range | The half-open range `[from, to)` on the event `timestamp` (when the access happened), consistent with the query API. | Should it be by recording time instead? Which retention period must reports cover? |
| 7 | Payload contents | Excluded: data minimization. Payloads may hold client data, and the regulator's question is who, when and what kind of access. Redacted paths and the archived flag are shown. | Do regulators need the accessed fields (for example, which fields were viewed)? |
| 8 | How trustworthy is the report? | Every report runs the full chain verification and reports its result. Per-event status follows from where verification stopped. | Is an external anchor (a published checkpoint) required for regulatory evidence? |
| 9 | Volume | At most 10,000 events per report (422 asks for a narrower time range). | Expected volumes and response-time needs? |

## 3. Design
- **Endpoint.** `GET /audit/reports/account-access` with `accountId` and/or `actorId` (at least one),
  optional `eventType`, `from` and `to`. Roles: `auditor` and `admin` (the `writer` role gets 403).
  Read-only.
- **Data source.** The existing records via the existing filtered keyset query (`query_records`), with
  `resourceType` fixed to the configured client-account type. No new tables or schema changes.
- **Integrity.** `verify_database` runs with the service's trusted key and archive directory, exactly
  as in `GET /audit/verify`. Overall status: VERIFIED, INDETERMINATE or TAMPERED, plus the
  first-inconsistency seq and violation type. Per event:
  - **Chain VERIFIED:** every event is VERIFIED.
  - **Chain INDETERMINATE:** redacted or archived events are INDETERMINATE, because their
    authorizations or archived content could not be checked. The others are VERIFIED.
  - **Chain TAMPERED at seq k:** events before k are VERIFIED, the event at k is TAMPERED, and events
    after k are UNVERIFIED, because verification stops at the first violation.

  `summary.eventsNotVerified` counts every event that is not VERIFIED.
- **Content.** Per event: `seq`, `eventId`, `eventType`, `actorId`, `accountId`, `timestamp`,
  `recordedAt`, `recordHash` (lets a reviewer match the event to an export or a checkpoint),
  `redactedPaths` and `archived`. The summary gives totals by event type and by actor, the accounts
  involved, and the first and last timestamps.
- **Trade-offs:**
  - A full-chain verification per report is simple and always current, but costs O(chain) time
    (LIMITATIONS 57).
  - Using the existing role avoids inventing a requirement, but gives coarse-grained access
    (LIMITATIONS 74).
  - An unsigned JSON report is quick to produce. The signed export already provides the
    tamper-evident hand-over artifact.

## 4. Implemented (commit 11)
- `src/aip/reports/access.py` (report builder and per-event integrity mapping),
  `src/aip/api/routes_reports.py` (endpoint), schemas, and the `AIP_ACCOUNT_RESOURCE_TYPE` setting.
- `tests/api/test_access_report.py` (11 tests):
  - filtering by account, actor, event type and time range, plus the empty result
  - report correctness: exact summary and event fields, and no payload values in the response
  - redacted and archived events
  - INDETERMINATE when no trusted key is configured
  - per-event TAMPERED and UNVERIFIED after direct database tampering
  - authorization (401, 403, 200 for admin) and 422 errors

## 5. Scoped out, and why
- **Auditing reads of this service itself.** Recording `GET /audit/events`, exports and reports as
  events would turn reads into writes, which affects concurrency, failure handling and the append-only
  design. That needs a Product answer to question 3. Today the JSON access log (request id, role, key
  id, path) records them, but it is not tamper-evident (LIMITATIONS 47, 73).
- **A dedicated regulator role, per-account authorization, and report signing** (questions 4 and 5).
- **CSV or PDF output, scheduled reports, and reports spanning more than 10,000 events** (questions 5
  and 9).
- **Inferring account access from payloads, or from other resource types** (question 2).
