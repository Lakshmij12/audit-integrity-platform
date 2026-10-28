# Development Setup

Status: tooling and the pure cryptographic foundations (`src/aip/crypto/`, commit 5). The audit log
service itself (API, database, retention, archive, export, signing) is not implemented yet.

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

`--warn-unreachable` is passed on the command line; it is not yet set in `pyproject.toml`.

`poc/` is excluded from Ruff: it holds the redaction spike exactly as run and recorded in commit 3.
