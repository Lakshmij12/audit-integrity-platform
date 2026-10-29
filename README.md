# audit-integrity-platform

A tamper-evident, append-only audit log service: a Python/FastAPI prototype built for an interview
assignment. It records events in a SHA-256 hash chain over SQLite and verifies the whole chain on
demand. It supports authorized redaction and retention without breaking the chain, exports signed
bundles that anyone can verify offline, and produces account-access reports for compliance review.

## Start here
- **Try it:** [Quick start with Docker](#quick-start-with-docker) below. One script builds and starts the API
  and a browser test UI; Docker Desktop is the only thing to install.
- **Reviewers:** [FINAL_SUMMARY](docs/FINAL_SUMMARY.md) (requirement mapping and decisions), then
  [ARCHITECTURE](docs/ARCHITECTURE.md) (diagrams, threat model, proposed production design).
- **Decisions:** [ADR-001 SQLite](docs/adr/ADR-001-sqlite-vs-postgresql.md),
  [ADR-002 hash chain and Ed25519](docs/adr/ADR-002-hash-chain-and-ed25519.md),
  [ADR-003 salted commitments](docs/adr/ADR-003-typed-path-salted-commitments.md).
- **Operations and evidence:** [RUNBOOK](docs/RUNBOOK.md), [PERFORMANCE](docs/PERFORMANCE.md) (measured),
  [TESTING](docs/TESTING.md), [LIMITATIONS](docs/LIMITATIONS.md), [AI_USAGE](docs/AI_USAGE.md).

## Quick start with Docker

### Required tools
| Tool | Needed for | How it gets installed |
|------|-----------|-----------------------|
| **Docker Desktop** (includes Docker Compose v2) | Everything | **Install it yourself:** https://www.docker.com/products/docker-desktop/ |
| Git | Cloning the repository (or download the ZIP from GitHub instead) | Install it yourself if you don't have it |
| Python 3.14 and all locked dependencies | The API | Automatically, inside the `audit-integrity-platform` image |
| nginx | Serving the test UI | Automatically (`nginx:1.27-alpine` image) |
| sqlite-web | Optional database browser | Automatically (`coleifer/sqlite-web` image), only with `-DbAdmin` |
| Python 3.14, pytest, Ruff, mypy | Running the tests | Automatically, in a throwaway `python:3.14-slim` container (`scripts/check.ps1`) |

You do not need Python on your machine. Everything except Docker Desktop is pulled or built by the
scripts below.

### 1. Get the code
```powershell
git clone https://github.com/Lakshmij12/audit-integrity-platform.git
cd audit-integrity-platform
```

### 2. Start everything
Windows (PowerShell):
```powershell
.\scripts\start.ps1
```
macOS or Linux:
```bash
sh scripts/start.sh
```
If PowerShell refuses to run scripts, allow it for this window only:
`Set-ExecutionPolicy -Scope Process Bypass`, then run the script again.

The script:
1. checks that Docker is installed, and on Windows starts Docker Desktop if it isn't running;
2. builds the API image (Python 3.14, hash-checked dependencies from `requirements.lock`);
3. on the first run only, creates three API keys (writer, auditor, admin) in `keys/api-keys.txt`,
   their SHA-256 entries in `keys/aip.env`, and an Ed25519 signing key in the `aip-keys` volume;
4. starts the containers with `docker compose` and waits until the API is healthy;
5. prints the URLs, and the API keys when it has just created them.

| What | URL |
|------|-----|
| Test UI | http://127.0.0.1:8080 |
| API docs (Swagger) | http://127.0.0.1:8000/docs |
| SQLite browser (only with `-DbAdmin` / `--dbadmin`) | http://127.0.0.1:8082 |

`keys/` is git-ignored. The service stores only hashes of the API keys; the keys themselves are in
`keys/api-keys.txt`. Print them again with `.\scripts\start.ps1 -ShowKeys`.

### 3. Test it in the UI
Open http://127.0.0.1:8080 and paste the writer, auditor and admin keys from `keys/api-keys.txt`
into the three boxes at the top (the dots turn green; the browser remembers them). Each action uses
the right key on its own: writes use the writer key, reads the auditor key, redaction and retention
the admin key.

1. **Write → Load 12 sample events** (synthetic data across three actors and four accounts).
2. **Browse → Search**, then click a row to see the full record.
3. **Browse → Redact** on a row, path `ssn`, any reason. The value becomes `null`, a signed
   `SYSTEM_REDACTION` event is appended (so there is one more record), and the chain still verifies.
4. **Verify → Verify now** shows VERIFIED. **Sign checkpoint** saves a signed chain head in the
   browser; **Verify against** checks the chain against it.
5. **Access report** with an account ID (`acct-0001`) or actor ID (`advisor-1`).
6. **Export** a signed bundle for an actor or resource and download it.
7. **Retention** shows what would be archived (dry run by default; records must be older than the
   365-day window).

To see tampering detected, start with `-DbAdmin`, open http://127.0.0.1:8082, and in the **Query**
tab run `DROP TRIGGER payload_leaves_no_update;` then
`UPDATE payload_leaves SET value = '"phone"' WHERE path = '["channel"]' AND seq = 2;`.
**Verify now** then reports TAMPERED with `LEAF_COMMITMENT_MISMATCH` at seq 2, the access report marks
that event TAMPERED, and checkpoints and exports are refused (409). The damage is permanent: a dropped
trigger also stops the API from starting again (`unexpected schema`), so finish with
`.\scripts\start.ps1 -Reset`.

### Everyday commands
| Task | Windows | macOS / Linux |
|------|---------|---------------|
| Start (or rebuild after a code change) | `.\scripts\start.ps1` | `sh scripts/start.sh` |
| Start with the SQLite browser | `.\scripts\start.ps1 -DbAdmin` | `sh scripts/start.sh --dbadmin` |
| Stop (data and keys are kept) | `.\scripts\start.ps1 -Stop` | `sh scripts/start.sh --stop` |
| Delete all audit data and start empty (keys are kept) | `.\scripts\start.ps1 -Reset` | `sh scripts/start.sh --reset` |
| Print the API keys | `.\scripts\start.ps1 -ShowKeys` | `sh scripts/start.sh --show-keys` |
| Run Ruff, mypy, the 669 tests and the tamper demo | `.\scripts\check.ps1` | `sh scripts/check.sh` |
| API logs | `docker logs -f aip` | same |

The containers restart with Docker Desktop. To start over with new keys as well, stop the stack, delete
the `keys/` folder and run `docker volume rm aip-keys`; the next start creates new ones.

### What runs where
| Container | Image | Port (localhost only) | Volumes |
|-----------|-------|-----------------------|---------|
| `aip` | `audit-integrity-platform` (built from `Dockerfile`) | 8000 | `aip-data` → `/app/data` (SQLite), `aip-archives` → `/app/archives`, `aip-keys` → `/app/keys` (signing key) |
| `aip-ui` | `nginx:1.27-alpine` serving `ui/index.html`; proxies `/audit` and `/docs` to `aip` | 8080 | `ui/` mounted read-only, so edits show on refresh |
| `aip-sqlite-web` (optional) | `coleifer/sqlite-web` | 8082 | `aip-data` (the live database) |

`docker-compose.yml` defines the stack; the API reads `AIP_API_KEYS` and `AIP_SIGNING_KEY_PATH` from
`keys/aip.env`. The image runs as a non-root user and serves plain HTTP. Every port is bound to
127.0.0.1; do not expose them. Without the scripts:
`docker compose up -d --build` (add `--profile dbadmin` for the SQLite browser), after creating
`keys/aip.env` as described in [Local Python setup](#local-python-setup-without-docker).

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
- **Browser test UI** (`ui/index.html`): a single static page over the API, for manual testing only.

## Example requests (PowerShell; all data synthetic)
These work against the Docker stack and the local setup alike.
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
The trusted key is the signing public key: the `signing public key (hex)` line in
`keys/api-keys.txt`, or the output of `new-signing-key`.

With Docker (the verifier is in the image):
```powershell
docker cp exports\bundle.json aip:/tmp/bundle.json
docker exec aip python tools/verify_bundle.py /tmp/bundle.json --trusted-key <public key hex>
```
With a local Python setup:
```powershell
.\.venv\Scripts\python.exe tools\verify_bundle.py exports\bundle.json --trusted-key <public key hex>
.\.venv\Scripts\python.exe tools\verify_bundle.py exports\bundle.json --trusted-key <hex> --anchor-seq <seq> --anchor-hash <recordHash>
```
The verifier needs only Python 3.14 and `cryptography`; it does not import `aip`. It never trusts the
public key embedded in the bundle. Exit codes: 0 VERIFIED, 3 INDETERMINATE (archived payloads are not
exported), 1 FAILED, 2 usage error.

## Local Python setup (without Docker)
Only needed to work on the code without containers; `scripts/check.ps1` already runs every check in
Docker. Requires CPython 3.14 and Git. Developed on Windows 10 with CPython 3.14.3; CI runs the same
checks on Ubuntu (docs/DEVELOPMENT.md).
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
```
The project is not pip-installed: commands that import `aip` need `src` on the path (`$env:PYTHONPATH =
"src"`, or `--app-dir src` for uvicorn).

### Keys and server
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
(`CLIENT_ACCOUNT`), `MAX_BODY_BYTES` (131072), `BUSY_TIMEOUT_MS` (5000). In the Swagger UI at
`http://127.0.0.1:8000/docs`, click **Authorize**, paste an API key under `ApiKey`, and every request
sends it as `X-API-Key`; the POST endpoints show their JSON schema and an example body. The test UI
needs the nginx proxy, so use the Docker stack for it.

### Tests and tamper demonstration
```powershell
.\.venv\Scripts\python.exe -m pytest -W error --cov=aip --cov-branch
.\.venv\Scripts\python.exe -m ruff check . ; .\.venv\Scripts\python.exe -m ruff format --check . ; .\.venv\Scripts\python.exe -m mypy
$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe scripts\tamper_demo.py
$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe scripts\benchmark.py --sizes 1000,10000   # optional, a few minutes
```
The demo writes events through the API and verifies them. It then changes a stored value directly in
SQLite and shows the API detecting it, and it shows truncation detected against a signed checkpoint.
Everything runs in a temporary directory.

## Continuous integration
`.github/workflows/ci.yml` runs on every push and pull request to `main`, on Ubuntu with the Python
version from `.python-version`: a hash-checked install of `requirements-dev.lock`, `ruff check`,
`ruff format --check`, strict `mypy`, and `pytest -W error --cov=aip --cov-branch`. A second job
builds the Docker image, starts it, and checks that the API answers and rejects requests without a key.

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
- **The Docker stack is for local testing.** Plain HTTP on localhost; the test UI keeps API keys and
  checkpoints in the browser's local storage; the optional SQLite browser has no login and can edit
  the live database.

The full list is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Documentation
| Document | Content |
|----------|---------|
| [docs/FINAL_SUMMARY.md](docs/FINAL_SUMMARY.md) | Requirement mapping, decisions, demo steps, production gaps |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Diagrams, components, data flow, trust boundaries, threat model, proposed production design |
| [docs/adr/](docs/adr/) | Architecture decision records (recorded retrospectively): SQLite, hash chain and Ed25519, salted commitments |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Manual incident procedures: TAMPERED, INDETERMINATE, archives, busy, unknown commits, key compromise, restore, the Docker stack |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Benchmark method, environment and measured results |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | Requirements analysis and ambiguity decisions |
| [docs/DESIGN.md](docs/DESIGN.md) | Detailed design: serialization, hashes, verification, redaction, retention, export |
| [docs/SCENARIO_C.md](docs/SCENARIO_C.md) | Scenario C: clarified requirement, assumptions, design, scope |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy, commands, tamper scenarios, CI and manual UI testing |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Setup details, Docker, CI, dependency locks, quality-gate results per commit |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Limitations and remaining risks |
| [docs/AI_USAGE.md](docs/AI_USAGE.md) | AI usage log and traceability |
| [ATTESTATION.md](ATTESTATION.md) | Candidate attestation |
