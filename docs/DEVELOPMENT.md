# Development Setup

Status: tooling, the pure cryptographic foundations (`src/aip/crypto/`, commit 5), and SQLite
persistence with append-only ingestion as a service layer (`src/aip/storage/`, `src/aip/ingest/`,
commit 6). The HTTP API, verification endpoint, redaction, retention, archive, export and signing are
not implemented yet.

Target interpreter: CPython 3.14 (developed with 3.14.3 on Windows 10).

Verified on 2026-10-28 (Windows 10, CPython 3.14.3, pip 25.3): both locks resolve in hash-checking
mode, `requirements-dev.lock` installs with `--require-hashes`, `pip check` reports no broken
requirements, and the seven runtime/tooling smoke tests pass with warnings treated as errors (see
"Quality gate results"). This verifies the toolchain only; the audit log service is not implemented.
Linux installation is **unverified** (see "Platform limitations").

## Prerequisites
- CPython 3.14
- Git

## Bootstrap tools vs hash-locked dependencies
| Category | Packages | How installed | Hash-verified |
|----------|----------|---------------|---------------|
| Interpreter and installer | CPython 3.14; pip (25.3 in the development environment) | `python -m venv` | No |
| Lock-generation bootstrap (only needed to regenerate locks) | pip-tools 7.6.2 and its dependencies: build, pyproject_hooks, setuptools, wheel, click, colorama, packaging | `pip install pip-tools==7.6.2` | No |
| Isolated build environment | setuptools from `[build-system]`, used by pip-compile to read project metadata | Automatically during `pip-compile` | No |
| Runtime and development dependencies | Everything listed in `requirements.lock` / `requirements-dev.lock` | `pip install --require-hashes -r ...` | Yes |

**pip is deliberately excluded from both locks** (`--unsafe-package pip`). pip-audit's dependency chain
(`pip-audit` → `pip-api`) requires pip; locking it made installing the dev lock upgrade the installer
itself (to pip 26.2.2 at generation time). Instead, the pip already present in the virtual environment
satisfies that requirement. pip-compile records this with a `# WARNING` block at the end of
`requirements-dev.lock`; hash-checking installation works because pip is installed in every virtual
environment.

## Setup
Install the locked dependencies **before** any bootstrap tool, so that packages shared with pip-tools
(click, colorama, packaging) are installed from the lock with hash verification:
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
```
bash: `.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock`

The project is not installed as a package: pytest and mypy add `src/` to the import path
(see `pyproject.toml`), so the project adds no unlocked packages of its own.

Note on the original development environment: pip-tools was bootstrapped before the dev lock was
installed, so click 8.5.0, colorama 0.4.6 and packaging 26.3 were already present at the locked
versions, and pip did not reinstall them or check them against the lock hashes.

## Regenerating the locks
```powershell
.\.venv\Scripts\python.exe -m pip install pip-tools==7.6.2
.\.venv\Scripts\python.exe -m piptools compile --generate-hashes --unsafe-package pip --strip-extras --output-file requirements.lock pyproject.toml
.\.venv\Scripts\python.exe -m piptools compile --extra dev --generate-hashes --unsafe-package pip --strip-extras --output-file requirements-dev.lock pyproject.toml
```
- Do not add `--allow-unsafe`: it pins every unsafe package and would put pip back into the locks.
- Do not edit hashes by hand.

Check the regenerated locks before installing:
```powershell
.\.venv\Scripts\python.exe -m pip install --dry-run --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --dry-run --require-hashes -r requirements-dev.lock
```

Lock contents as generated on 2026-10-28: `requirements.lock` 20 packages (6 direct, 14 transitive,
400 hashes); `requirements-dev.lock` 61 packages (12 direct, 49 transitive, 1,177 hashes); the runtime
lock is a subset of the dev lock at identical versions; pip is absent from both.

### Test client dependency: `httpx2`, not `httpx`
The dev dependencies pin `httpx2==2.16.0` instead of `httpx`. Starlette 1.10.0 (installed via FastAPI
0.162.0) imports `httpx2` for `starlette.testclient` and falls back to `httpx` with a
`StarletteDeprecationWarning`; with `filterwarnings = ["error"]` that fallback broke test collection.
Starlette and FastAPI both declare `httpx2>=2.0.0` in their own optional dependencies, so installing it
uses the supported path without suppressing any warning. Replacing `httpx` changed only the dev lock:
`httpx` 0.28.1 and `httpcore` 1.0.9 were removed and `httpx2` 2.16.0, `httpcore2` 2.16.0 and
`truststore` 0.10.5 were added; the runtime lock was unchanged.

## Platform limitations
The locks were generated on Windows 10 with CPython 3.14.3.
1. pip-compile resolves for the platform it runs on and emitted no environment markers. `colorama` is a
   Windows-only dependency (via click and pytest) but is pinned unconditionally, so a Linux install
   includes it unnecessarily (pure Python; expected to be harmless). Any Linux-only transitive
   dependency would be missing from the locks; none is known in this set, but this is unverified.
2. Compiled packages carry hashes for many published files (e.g. pydantic-core 137, cffi 100,
   sqlalchemy 72, cryptography 59), which suggests that Linux wheels are covered. **Linux installation
   and hash coverage are unverified** until CI installs the locks on Linux.

## Smoke tests
`tests/test_smoke.py` contains runtime and tooling checks only: interpreter version, imports, Ed25519,
SQLite WAL and `BEGIN IMMEDIATE`, SQLAlchemy, Pydantic strict models and the FastAPI test client.
They do not test the audit log service.

## Cryptographic foundation tests
`tests/crypto/` covers canonical JSON, strict parsing, timestamps, typed-path leaf commitments, payload
roots, redaction stability, content/record hashes and chain link checks (commit 5). These are unit tests
of pure functions; they do not exercise any API or database.

### Known-answer vectors
`tests/crypto/vectors.py` holds 22 vectors. For each one, the preimage bytes are written by hand from the
specification in DESIGN.md §1–2 (not produced by project code), and the SHA-256 digest was computed over
those exact bytes with two external tools that agreed on all 22 (2026-10-28):
- GNU coreutils `sha256sum` 8.32 (Git for Windows), run as `sha256sum -b <file>` with a relative file name;
- PowerShell 5.1 `Get-FileHash -Algorithm SHA256 -LiteralPath <file>`.

Later vectors embed earlier digests (leaf → payload root → content → record 1 → record 2), so they were
computed in that order. The tests then check, for each vector, that the project's function produces the
same bytes or digest. Two vectors are cross-checked against RFC 8785: the §3.2.2 string/literal sample
(expected bytes taken from the §3.2.4 hex dump, with the float `numbers` member removed) and the §3.2.3
sorting sample (without U+FB33, which is not NFC; the full sample is tested as rejected).

To reproduce a digest independently, write the preimage bytes to a file and hash it with either tool.
Note: GNU `sha256sum` prefixes its output with `\` when the file name contains backslashes; use a
relative name (or `--tag`) so the digest is read correctly.

## Storage and ingestion tests
`tests/storage/` and `tests/ingest/` (commit 6) run against real SQLite files in pytest's `tmp_path`
(SQLite 3.50.4 bundled with CPython 3.14.3 on the development machine). They cover the v1 schema,
constraints and guard triggers (tested by bypassing the application with a raw `sqlite3`
connection), `BEGIN IMMEDIATE` locking and lock contention, rollback after a partial insert, a real
COMMIT-time failure (a deferred foreign-key violation), error classification, input validation and
limits, timestamp clamping, restart persistence, full recomputation of every stored record, and
concurrent appends from 8 threads and from 2 spawned processes. COMMIT failures are also simulated at
the driver level (`SQLITE_IOERR`, `SQLITE_FULL`, `SQLITE_BUSY`), including a ROLLBACK that itself
fails, to check error classification and that the connection is discarded. The concurrency and
transaction tests passed 5 out of 5 repeated runs on Windows 10.

## Running the API (commit 7)
The project is not pip-installed, so `src/` must be on the import path: uvicorn takes `--app-dir src`,
and the CLI needs `PYTHONPATH`.
```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m aip.cli new-api-key --role writer    # prints the key once + its entry
.\.venv\Scripts\python.exe -m aip.cli new-api-key --role auditor
$env:AIP_API_KEYS = "writer:<sha256hex>,auditor:<sha256hex>"         # entries printed above
$env:AIP_DB_PATH  = "data/audit.db"                                   # default; data/ is git-ignored
.\.venv\Scripts\python.exe -m uvicorn aip.api.app:create_app --factory --app-dir src
```
Swagger UI is at `http://127.0.0.1:8000/docs`. Clients send the key in `X-API-Key`. Settings:
`AIP_DB_PATH`, `AIP_API_KEYS`, `AIP_BUSY_TIMEOUT_MS` (default 5000), `AIP_MAX_BODY_BYTES`
(default 131072). With no keys configured, every request is rejected.

Endpoints in commit 7: `POST /audit/events` (writer, admin; 201), `GET /audit/events` (auditor, admin;
filters `actorId`, `resourceType`, `resourceId`, `eventType`, `from` inclusive, `to` exclusive; keyset
pagination with `limit` 1–200, default 50, and `cursor` = `nextCursor`), `GET /audit/events/{eventId}`
(auditor, admin). Errors are RFC 9457 `application/problem+json` with a `code`, `requestId` and, for
validation, `issues` (field and rule code only).

Smoke-tested on 2026-10-28 with the commands above against a scratch database: POST 201 with a
`Location` header, filtered GET 200, a writer key on GET 403, `/docs` 200, JSON access log lines without
API keys.

## Verification, signed checkpoints and the tampering demo (commit 8)
```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m aip.cli new-signing-key --out keys/signing.pem   # never overwrites
$env:AIP_SIGNING_KEY_PATH = "keys/signing.pem"   # optional; without it checkpoints return 503
```
`keys/` and `*.pem` are git-ignored; never commit a private key. Endpoints (auditor, admin):
- `GET /audit/verify`: `status` `VERIFIED` / `INDETERMINATE` / `TAMPERED`, `intact` `true` / `null` /
  `false`, `firstInconsistency`, `unverified` counts, `notes`.
- `GET /audit/verify?anchorSeq=<seq>&anchorHash=<recordHash>`: also checks against a saved checkpoint
  (`TRUNCATED`, `ANCHOR_MISMATCH`).
- `GET /audit/checkpoints/latest`: verifies, then signs the head. Returns 409 if the chain has a
  violation, 404 if the log is empty, 503 without a key.

Reproducible tampering demonstration (temporary directory, synthetic data, in-process API client):
```powershell
$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe scripts\tamper_demo.py
```
Part 1 writes five events, queries them, verifies (`VERIFIED`) and then changes one stored payload value
with a raw `sqlite3` connection, after dropping the guard triggers as an attacker with file access would.
Verifying again reports `LEAF_COMMITMENT_MISMATCH` at seq 3 without echoing the value. Part 2 deletes the
newest record: plain verification still passes, and verification against a signed checkpoint taken
earlier reports `TRUNCATED`. Exit code 0 means every step behaved as expected; the script also runs as a
test (`tests/verify/test_tamper_demo.py`).

## Redaction and retention (commit 9)
Both need an admin key and a signing key (`AIP_SIGNING_KEY_PATH`). Settings are
`AIP_RETENTION_WINDOW_DAYS` (default 365) and `AIP_ARCHIVE_DIR` (default `archives`, git-ignored;
archives hold plaintext payloads).
```powershell
$h = @{ "X-API-Key" = "<admin key>" }
$base = "http://127.0.0.1:8000/audit"
$redact = '{"paths": [["ssn"]], "reason": "client privacy request"}'
Invoke-RestMethod -Method Post -Uri "$base/events/<eventId>/redactions" -Headers $h -ContentType application/json -Body $redact
Invoke-RestMethod -Method Post -Uri "$base/retention/runs" -Headers $h    # dry run (default)
Invoke-RestMethod -Method Post -Uri "$base/retention/runs" -Headers $h -ContentType application/json -Body '{"dryRun": false}'
```
`GET /audit/verify` then reports `authorized.redactedLeaves` and `authorized.archivedRecords`. If the
signing key is missing it reports `INDETERMINATE`, and if an archive file has been moved away it reports
`unverified.archivedContentUnavailable`. A database created by commits 6–8 (schema v1) is migrated to v2
the first time it is opened.

## Export and offline verification (commit 10)
```powershell
$h = @{ "X-API-Key" = "<auditor key>" }
Invoke-WebRequest -Uri "http://127.0.0.1:8000/audit/export?actorId=user-0042" -Headers $h -OutFile bundle.json
# The public key printed by `new-signing-key` (or obtained from the operator), never the one in the bundle:
python tools/verify_bundle.py bundle.json --trusted-key <64 hex characters>
python tools/verify_bundle.py bundle.json --trusted-key-file trusted.hex --anchor-seq 42 --anchor-hash <recordHash>
```
The verifier needs only Python 3.14 and `cryptography`; it does not import `aip`. The tests run it in
isolated mode (`python -I`) from a temporary directory without `src` on the path. Exit codes: 0
VERIFIED, 3 INDETERMINATE (archived payloads not included), 1 FAILED, 2 usage error. `tools/` is
included in strict mypy (`pyproject.toml`).

## Account-access report (commit 11, Scenario C)
```powershell
$h = @{ "X-API-Key" = "<auditor key>" }
Invoke-RestMethod -Headers $h -Uri "http://127.0.0.1:8000/audit/reports/account-access?accountId=acct-0001"
Invoke-RestMethod -Headers $h -Uri "http://127.0.0.1:8000/audit/reports/account-access?actorId=advisor-1&from=2026-10-01T00:00:00Z&to=2026-11-01T00:00:00Z"
```
Events must use `resourceType` `CLIENT_ACCOUNT` (or the value of `AIP_ACCOUNT_RESOURCE_TYPE`). See
docs/SCENARIO_C.md.

## Quality gates
```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m pytest
```
Dependency audit (options confirmed against `pip-audit --help` for version 2.10.1: `-r` audits a
requirements file, `--require-hashes` checks each requirement against its hash, `--disable-pip` skips
pip-based resolution and is valid only for hashed files; the default vulnerability service is `pypi`):
```powershell
.\.venv\Scripts\python.exe -m pip_audit -r requirements-dev.lock --require-hashes --disable-pip --progress-spinner off
```
`pip-audit` reports only advisories known to its vulnerability service at the time it runs; a clean
result is not a claim that the dependencies have no vulnerabilities.

### Quality gate results (2026-10-28, Windows 10, CPython 3.14.3)
Commit 4 (tooling only):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `9 files already formatted` |
| `mypy` (strict) | 0 | `Success: no issues found in 2 source files` |
| `pytest -v` | 0 | `7 passed in 1.14s` (runtime/tooling smoke tests only) |
| `pip_audit` (command above, service `pypi`) | 0 | `No known vulnerabilities found` (run at 2026-10-28T09:18-04:00) |

Commit 5 (cryptographic foundations, after review corrections; no dependency changes, so pip-audit
was not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `24 files already formatted` |
| `mypy --warn-unreachable` (strict) | 0 | `Success: no issues found in 17 source files` |
| `pytest` (warnings as errors) | 0 | `259 passed` (7 smoke tests + 252 crypto unit tests) |
| `pytest --cov --cov-branch` (report only) | 0 | `src/aip`: 98% combined statement and branch coverage; 8 uncovered lines are defensive branches made unreachable by earlier validation |

For commit 5, `--warn-unreachable` was passed on the command line; commit 6 sets it in `pyproject.toml`.

Commit 6 (persistence and ingestion; no dependency changes, so pip-audit was not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `mypy` right after adding `warn_unreachable = true` (before new code) | 0 | `Success: no issues found in 17 source files` (no pre-existing findings) |
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `41 files already formatted` |
| `mypy` (strict, `warn_unreachable` from `pyproject.toml`) | 0 | `Success: no issues found in 34 source files` |
| `pytest` (warnings as errors) | 0 | `413 passed` (259 existing + 154 storage/ingestion) |
| `pytest --cov --cov-branch` (report only) | 0 | 96% overall; `storage/errors.py` 100%, `storage/database.py` 90%, `storage/repository.py` 89%. Uncovered: connect failures, an unsupported transaction mode, exceptions raised by a rollback inside a transaction, a COMMIT failure after which SQLite already ended the transaction, an SQLite older than 3.37 and a failure to enable WAL |
| Transaction + concurrency tests, 5 repeated runs | 0 × 5 | `33 passed` each run |

Final figures after the transaction review fixes (unknown-outcome COMMIT errors, rollback failure after a
failed COMMIT); earlier runs in the same commit reported 400 and then 397 tests.

Commit 7 (HTTP API; no dependency changes, so pip-audit was not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `53 files already formatted` |
| `mypy` (strict, `warn_unreachable`) | 0 | `Success: no issues found in 46 source files` |
| `pytest` (warnings as errors) | 0 | `478 passed` (413 existing + 65 API) |
| Live run of the documented uvicorn command | — | see "Running the API" |

Commit 8 (verification, signing, tampering demo; `cryptography` was already locked, so pip-audit was
not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `63 files already formatted` |
| `mypy` (strict, `warn_unreachable`) | 0 | `Success: no issues found in 55 source files` |
| `pytest -W error --cov=aip --cov-branch` | 0 | `533 passed` (478 existing + 55 verification, signing and API); 96% overall; `routes_verify.py` 100%, `verify/service.py` 96%, `crypto/signing.py` 95% |
| `scripts/tamper_demo.py` | 0 | `RESULT: all steps behaved as expected` |

Commit 9 (redaction, retention, schema v2; no dependency changes, so pip-audit was not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `73 files already formatted` |
| `mypy` (strict, `warn_unreachable`) | 0 | `Success: no issues found in 65 source files` |
| `pytest -W error --cov=aip --cov-branch` | 0 | `612 passed` (533 existing, 5 of them updated for the new rules, + 79 lifecycle, migration and API); 96% overall; `lifecycle/service.py` 99%, `lifecycle/archive.py` 96%, `routes_lifecycle.py` 100%, `verify/service.py` 93%, `storage/schema.py` 97% |
| `scripts/tamper_demo.py` | 0 | `RESULT: all steps behaved as expected` |

Commit 10 (export and standalone verifier; no dependency changes, so pip-audit was not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `79 files already formatted` |
| `mypy` (strict, `warn_unreachable`, now including `tools/`) | 0 | `Success: no issues found in 71 source files` |
| `pytest -W error --cov=aip --cov-branch` | 0 | `638 passed` (612 existing + 26 export/verifier, most of them running `tools/verify_bundle.py` as a subprocess); 96% overall; `routes_export.py` 95%, `export/bundle.py` 85% (uncovered: the 10,000-record limit and skipping malformed system events). `tools/` is outside `src/aip`, so coverage does not measure it; the subprocess tests exercise it |
| `scripts/tamper_demo.py` | 0 | `RESULT: all steps behaved as expected` |

Commit 11 (Scenario C account-access report; no dependency changes, so pip-audit was not re-run):

| Gate | Exit code | Output |
|------|-----------|--------|
| `ruff check .` | 0 | `All checks passed!` |
| `ruff format --check .` | 0 | `84 files already formatted` |
| `mypy` (strict, `warn_unreachable`) | 0 | `Success: no issues found in 75 source files` |
| `pytest -W error --cov=aip --cov-branch` | 0 | `649 passed` (638 existing + 11 report); 96% overall; `reports/access.py` 91%, `routes_reports.py` 95% |

`poc/` is excluded from Ruff: it holds the redaction spike exactly as run and recorded in commit 3.
