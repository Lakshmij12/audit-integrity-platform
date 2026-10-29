# audit-integrity-platform

A tamper-evident, append-only audit log service: a Python/FastAPI prototype built for an interview
assignment. It records events in a SHA-256 hash chain over SQLite and verifies the whole chain on
demand. It supports authorized redaction and retention without breaking the chain, exports signed
bundles that anyone can verify offline, and produces account-access reports for compliance review.

## Start here
- **Reviewers:** [FINAL_SUMMARY](docs/FINAL_SUMMARY.md) (requirement mapping and decisions), then
  [ARCHITECTURE](docs/ARCHITECTURE.md) (diagrams, threat model, proposed production design).
- **Running it:** the quick start below ("Prerequisites and installation", "Keys and server").
- **Decisions:** [ADR-001 SQLite](docs/adr/ADR-001-sqlite-vs-postgresql.md),
  [ADR-002 hash chain and Ed25519](docs/adr/ADR-002-hash-chain-and-ed25519.md),
  [ADR-003 salted commitments](docs/adr/ADR-003-typed-path-salted-commitments.md).
- **Operations and evidence:** [RUNBOOK](docs/RUNBOOK.md), [PERFORMANCE](docs/PERFORMANCE.md) (measured),
  [TESTING](docs/TESTING.md), [LIMITATIONS](docs/LIMITATIONS.md), [AI_USAGE](docs/AI_USAGE.md).

## Key features
- **Write and query API.** `POST /audit/events` and `GET /audit/events`, with filters on actor,
  resource, event type and time range, and keyset pagination. There is no update or delete endpoint.
- **Hash chain and verification.** Each record stores its content hash and the previous record's hash.
  `GET /audit/verify` walks the chain and reports the first inconsistency and its type, including
  edits made directly in SQLite.
- **Typed-path leaf commitments.** Each payload field is committed separately with its own salt, so a
  field can be redacted without recomputing any hash.
- **Authorized redaction** (admin). The value and salt are removed. A signed `SYSTEM_REDACTION` event
  authorizes the change, and verification rejects any removal that has no valid authorization.
- **Retention and archive** (admin; dry run by default). Old records are moved to a signed archive file,
  and archived records verify without false positives.
- **Ed25519 signed checkpoints** for anchoring to evidence held outside the database.
- **Signed export bundles.** `GET /audit/export` for one `actorId` or `resourceId`.
  `tools/verify_bundle.py` checks a bundle offline. It is separate code that does not import the
  service.
- **Account-access report** (Scenario C): `GET /audit/reports/account-access`, with an overall and a
  per-event integrity status.
- **API-key roles:** `writer`, `auditor`, `admin`. Errors follow RFC 9457, and neither errors nor logs
  include payload values.

## Prerequisites and installation
CPython 3.14 and Git. It was developed and tested on Windows 10 with CPython 3.14.3; Linux is untested
(docs/DEVELOPMENT.md).
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
```
The project is not pip-installed: commands that import `aip` need `src` on the path (`$env:PYTHONPATH =
"src"`, or `--app-dir src` for uvicorn).

## Keys and server
```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m aip.cli new-api-key --role writer     # prints the key once and its AIP_API_KEYS entry
.\.venv\Scripts\python.exe -m aip.cli new-api-key --role auditor
.\.venv\Scripts\python.exe -m aip.cli new-api-key --role admin
.\.venv\Scripts\python.exe -m aip.cli new-signing-key --out keys/signing.pem   # prints the public key (hex)

$env:AIP_API_KEYS = "writer:<sha256hex>,auditor:<sha256hex>,admin:<sha256hex>"   # the printed entries
$env:AIP_SIGNING_KEY_PATH = "keys/signing.pem"   # needed for redaction, retention runs, checkpoints, export
.\.venv\Scripts\python.exe -m uvicorn aip.api.app:create_app --factory --app-dir src
```
Only SHA-256 hashes of API keys are configured; the keys themselves are never stored. `keys/`, `*.pem`,
`data/` and `archives/` are git-ignored. Other settings (all prefixed `AIP_`): `DB_PATH` (default
`data/audit.db`), `ARCHIVE_DIR` (`archives`), `RETENTION_WINDOW_DAYS` (365), `ACCOUNT_RESOURCE_TYPE`
(`CLIENT_ACCOUNT`), `MAX_BODY_BYTES` (131072), `BUSY_TIMEOUT_MS` (5000). Interactive API docs:
`http://127.0.0.1:8000/docs`. Click **Authorize**, paste an API key under `ApiKey`, and every
request sends it as `X-API-Key`; the POST endpoints show their JSON schema and an example body.

## Example requests (PowerShell; all data synthetic)
```powershell
$base = "http://127.0.0.1:8000/audit"
$w = @{ "X-API-Key" = "<writer key>" }; $a = @{ "X-API-Key" = "<auditor key>" }; $adm = @{ "X-API-Key" = "<admin key>" }

# Ingest (timestamp optional: server time if omitted)
$event = '{"eventType":"ACCOUNT_VIEWED","actorId":"advisor-1","resourceType":"CLIENT_ACCOUNT","resourceId":"acct-0001","payload":{"ssn":"900-00-0001","channel":"web"}}'
$e = Invoke-RestMethod -Method Post "$base/events" -Headers $w -ContentType application/json -Body $event

# Query and verify
Invoke-RestMethod "$base/events?resourceId=acct-0001&limit=50" -Headers $a
Invoke-RestMethod "$base/verify" -Headers $a                     # status VERIFIED / INDETERMINATE / TAMPERED
$cp = Invoke-RestMethod "$base/checkpoints/latest" -Headers $a   # signed head; keep it outside the service
Invoke-RestMethod "$base/verify?anchorSeq=$($cp.seq)&anchorHash=$($cp.recordHash)" -Headers $a

# Redact a payload field (admin)
Invoke-RestMethod -Method Post "$base/events/$($e.eventId)/redactions" -Headers $adm -ContentType application/json -Body '{"paths":[["ssn"]],"reason":"client privacy request"}'

# Retention: dry run (default), then archive for real (admin)
Invoke-RestMethod -Method Post "$base/retention/runs" -Headers $adm
Invoke-RestMethod -Method Post "$base/retention/runs" -Headers $adm -ContentType application/json -Body '{"dryRun": false}'

# Signed export and Scenario C report
New-Item -ItemType Directory -Force exports | Out-Null   # exports/ is git-ignored: bundles hold plaintext payloads
Invoke-WebRequest "$base/export?resourceId=acct-0001" -Headers $a -OutFile exports\bundle.json
Invoke-RestMethod "$base/reports/account-access?accountId=acct-0001" -Headers $a
```

## Independent export verification
```powershell
.\.venv\Scripts\python.exe tools\verify_bundle.py exports\bundle.json --trusted-key <public key hex from new-signing-key>
.\.venv\Scripts\python.exe tools\verify_bundle.py exports\bundle.json --trusted-key <hex> --anchor-seq <seq> --anchor-hash <recordHash>
```
The verifier needs only Python 3.14 and `cryptography`; it does not import `aip`. It never trusts the
public key embedded in the bundle. Exit codes: 0 VERIFIED, 3 INDETERMINATE (archived payloads are not
exported), 1 FAILED, 2 usage error.

## Tests and tamper demonstration
```powershell
.\.venv\Scripts\python.exe -m pytest -W error --cov=aip --cov-branch
.\.venv\Scripts\python.exe -m ruff check . ; .\.venv\Scripts\python.exe -m ruff format --check . ; .\.venv\Scripts\python.exe -m mypy
$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe scripts\tamper_demo.py
$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe scripts\benchmark.py --sizes 1000,10000   # optional, a few minutes
```
The demo writes events through the API and verifies them. It then changes a stored value directly in
SQLite and shows the API detecting it, and it shows truncation detected against a signed checkpoint.
Everything runs in a temporary directory.

## Security limitations (summary)
- **No anchor, no protection against a full rewrite.** Without a checkpoint held outside the service,
  someone with write access to the database file can rewrite the chain, or truncate it, without
  detection.
- **Plaintext storage.** Payloads are stored in plaintext; archive files and export bundles are
  plaintext too.
- **No secure deletion.** Redaction does not remove values from backups, copies or earlier exports.
- **Key handling is prototype-grade.** API keys are static. The signing key is an unencrypted file on
  the same host, with no rotation. There is no TLS or rate limiting inside the service.
- **Export completeness is signer-asserted.** A bundle cannot prove that every matching record was
  exported.

The full list is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Documentation
| Document | Content |
|----------|---------|
| [docs/FINAL_SUMMARY.md](docs/FINAL_SUMMARY.md) | Requirement mapping, decisions, demo steps, production gaps |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Diagrams, components, data flow, trust boundaries, threat model, proposed production design |
| [docs/adr/](docs/adr/) | Architecture decision records (recorded retrospectively): SQLite, hash chain and Ed25519, salted commitments |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Manual incident procedures: TAMPERED, INDETERMINATE, archives, busy, unknown commits, key compromise, restore |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Benchmark method, environment and measured results |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | Requirements analysis and ambiguity decisions |
| [docs/DESIGN.md](docs/DESIGN.md) | Detailed design: serialization, hashes, verification, redaction, retention, export |
| [docs/SCENARIO_C.md](docs/SCENARIO_C.md) | Scenario C: clarified requirement, assumptions, design, scope |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy, commands, tamper scenarios |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Setup details, dependency locks, quality-gate results per commit |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Limitations and remaining risks |
| [docs/AI_USAGE.md](docs/AI_USAGE.md) | AI usage log and traceability |
| [ATTESTATION.md](ATTESTATION.md) | Candidate attestation |
