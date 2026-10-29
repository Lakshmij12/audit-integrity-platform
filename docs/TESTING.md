# Testing

## 1. Strategy
- **Pure cryptography first.** Canonical JSON, hashes, commitments and the payload root are covered by
  known-answer vectors (with digests computed by external tools) and by property and edge-case tests.
- **Integration tests on real SQLite files.** Every storage, ingestion and lifecycle test opens a fresh
  database in a temporary directory; nothing is mocked except failure injection.
- **Tamper tests bypass the application.** A raw `sqlite3` connection drops the guard triggers and edits
  rows, then verification has to find the change from the hashes alone (DESIGN.md §10).
- **API tests** use FastAPI's in-process client for roles, validation, error shapes and full flows.
- **The independent verifier is tested as a black box:** a subprocess in isolated mode (`python -I`),
  run from a temporary directory without `src` on the path.
- **No leaks.** Tests plant marker values (for example `acct-900123456`, `SECRET-VALUE`) and assert they
  never appear in reports, errors, verifier output, or the database files after redaction.
- **Warnings are errors** (`filterwarnings = ["error"]`).

## 2. Commands
With only Docker installed (runs everything below in a `python:3.14-slim` container, on a read-only
copy of the checkout):
```powershell
.\scripts\check.ps1        # macOS/Linux: sh scripts/check.sh
```
With a local virtual environment:
```powershell
.\.venv\Scripts\python.exe -m pytest -W error --cov=aip --cov-branch --cov-report=term-missing
.\.venv\Scripts\python.exe -m pytest tests/export          # independent verifier (subprocess)
.\.venv\Scripts\python.exe -m ruff check . ; .\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy                         # strict, warn_unreachable; src, tests, tools
$env:PYTHONPATH = "src"; .\.venv\Scripts\python.exe scripts\tamper_demo.py
```

## 3. Inventory (669 tests)
| Area | Tests | Covers |
|------|------:|--------|
| `tests/test_smoke.py` | 7 | Runtime and toolchain |
| `tests/test_benchmark_smoke.py` | 1 | `scripts/benchmark.py` still runs end to end (30 records) |
| `tests/crypto` | 268 | Canonical JSON (RFC 8785 subset), timestamps, hashes, typed-path commitments, payload root, chain checks, Ed25519 checkpoints and signed documents, known-answer vectors |
| `tests/storage` | 85 | STRICT schema, constraints, triggers, v1→v2 migration (including a failed migration rolling back), transactions, failed and unknown COMMIT, rollback failures |
| `tests/ingest` | 86 | Validation and limits, append, recordedAt clamping, thread and process concurrency, restart, full recomputation |
| `tests/verify` | 25 | Every violation type, malformed rows, rewrites and truncation with and without anchors, no values in reports, the tamper demo script |
| `tests/lifecycle` | 48 | Redaction (hashes unchanged, value gone from the DB and WAL files, unauthorized or altered or forged authorizations), retention (dry run, archive evidence, missing or altered archive, unauthorized archival, rollback and unknown-COMMIT file handling, restart) |
| `tests/api` | 123 | Auth and roles, OpenAPI security scheme and POST request schemas, events API (including no PUT/PATCH/DELETE route), verify and checkpoints, redaction and retention endpoints, the Scenario C report (including per-event status around redacted and archived records) |
| `tests/export` | 26 | Export endpoint and the standalone verifier: valid, empty, partially redacted and archived bundles, wrong key, attacker re-signing, tampered sections, checks behind the signature, substitution, anchors, malformed input |

Branch coverage of `src/aip`: 96% (DEVELOPMENT.md has the per-commit results). `tools/` and `scripts/`
are outside the coverage source and are exercised by subprocess tests.

## 4. Tampering scenarios (raw SQLite, triggers dropped)
| Change | Expected result |
|--------|-----------------|
| Payload value, envelope field or stored hash of record k | `LEAF_COMMITMENT_MISMATCH` / `CONTENT_HASH_MISMATCH` / `RECORD_HASH_MISMATCH` at k |
| Delete record k, or one of its leaves | `SEQUENCE_GAP` / `PAYLOAD_ROOT_MISMATCH` / `MALFORMED_LEAF` |
| Unparsable path or value, wrong hashVersion or eventId | `MALFORMED_*` / `EVENT_ID_MISMATCH` |
| Null a value and salt without authorization; alter or remove the authorization | `UNAUTHORIZED_REDACTION` |
| Mark a row archived without a run, or outside the run's range or cutoff; restore its leaves | `INVALID_ARCHIVE` |
| Alter an archive file | `ARCHIVE_CONTENT_MISMATCH` |
| Rewrite and recompute every later hash; delete the tail | VERIFIED without an anchor (documented L1 limit); `ANCHOR_MISMATCH` / `TRUNCATED` with one |
| Same changes, then `GET /audit/checkpoints/latest` or `/audit/export` | 409: never signs a chain that fails verification |

## 5. Continuous integration
`.github/workflows/ci.yml` runs on every push and pull request to `main`:
- **`checks`** on `ubuntu-latest` with the Python version from `.python-version`: hash-checked
  install of `requirements-dev.lock`, `ruff check .`, `ruff format --check .`, `mypy`, and
  `pytest -W error --cov=aip --cov-branch`.
- **`docker`**: builds the image, starts it with no keys configured, and checks that
  `/openapi.json` returns 200 and `/audit/events` returns 401.

`pip-audit` is not in CI: its result depends on the advisory database on the day it runs, so it stays
a manual gate (DEVELOPMENT.md "Quality gates").

## 6. Manual testing with the browser UI
`scripts/start.ps1` starts the API with a test UI at http://127.0.0.1:8080 (README "Test it in the
UI"). It is a manual aid, not part of the automated suite. On 2026-10-29 every UI flow was exercised
against a throwaway container with temporary keys: append and sample load, client-side and server
validation errors, paging and filters, redaction (including already-redacted and unknown paths),
verify, checkpoints and anchored verify, the account-access report, export and retention. After a
direct SQLite edit the UI showed TAMPERED with `LEAF_COMMITMENT_MISMATCH`, the report marked the event
TAMPERED and later ones UNVERIFIED, and signing a checkpoint was refused with 409. Results are in
DEVELOPMENT.md.

## 7. Known untested cases
- **macOS.** Windows 10 and 11 were run locally, and Linux (Debian in Docker, Ubuntu in CI); macOS
  was not.
- **Real crash or power loss** during archive writes or COMMIT. Failure paths are simulated by injecting
  exceptions, and the missing directory fsync is documented (LIMITATIONS 61).
- **Load and concurrency performance.** `scripts/benchmark.py` measures single-threaded throughput and
  latency up to 10,000 records (PERFORMANCE.md); there is no load, soak or contention benchmarking, and
  the 10,000-record export and report limits are not exercised.
- **Some defensive branches:** the 10,000-record export and report limits, skipping malformed system
  events during export, and some branches that are unreachable after earlier validation (listed in the
  coverage report).
- **TLS, a reverse proxy and multi-instance deployment** (out of scope). The nginx container in the
  Docker stack is a plain-HTTP proxy for the test UI only.
- **The test UI and start scripts** have no automated tests; they were checked by hand (section 6).
- **The verifier against bundles from other implementations.** It shares the specification, not code,
  with the service; it was tested only on bundles this service produced.
