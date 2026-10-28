# AI Usage Log

Records which AI tools were involved, what each contributed, what material each received, and what the
candidate decided. AI recommendations and candidate decisions are recorded separately. This log is the
traceability record; commits do not carry AI co-author trailers.

## 1. Tools
| Tool | Role | Period |
|------|------|--------|
| Claude Code (Anthropic), VS Code extension, model Claude Opus 5.5 | Repository work: inspection, planning and design documents, and in later milestones implementation and tests. Every file change, install and commit is approved by the candidate first. | 2026-10-28 onward |
| OpenAI ChatGPT | Advisory: requirement interpretation, planning advice, prompt drafting and review of Claude Code's output. ChatGPT provided planning and review guidance; no repository implementation or testing is attributed to ChatGPT. | October 2026, including 2026-10-28 |

## 2. Contributions

### Claude Code
- Inspected the repository, Git configuration and GitHub visibility with read-only commands.
- Produced the requirements mapping, architecture, hash-chain/redaction/retention/export design, risk
  analysis, test strategy and milestone plan (plans v1 to v3.1).
- Ran dependency-resolution dry-runs for CPython 3.14 on Windows and Linux (no packages installed).
- Drafted the Step 0 verification commands and checked their output.
- Wrote and staged the commit 1 files and created commit 1 after candidate approval.
- Drafted the commit 2 documents (this file, REQUIREMENTS.md, DESIGN.md, LIMITATIONS.md) and created
  commit 2 after candidate approval.
- Wrote the redaction proof of concept (`poc/redaction_poc.py`), ran it with Python 3.14.3, and
  generated `docs/poc/redaction-poc-output.md` from the captured output; created commit 3 after
  candidate approval.
- Proposed the commit 4 tooling decisions and wrote the hand-written commit 4 files (project
  configuration, `.gitattributes`, smoke tests, development guide).
- Gate B: selected and installed pip-tools 7.6.2, generated both hashed locks with pip-compile,
  identified that the first dev lock would upgrade pip, regenerated the locks without pip after the
  candidate's decision, and installed the dev lock in hash-checking mode.
- Gate C: ran Ruff, mypy, pytest and pip-audit; diagnosed the pytest collection error; investigated
  `httpx2` from installed metadata, PyPI and GitHub (read-only); applied the candidate-approved
  dependency change and re-ran all gates.
- Commit 6: planned and implemented SQLite persistence (`src/aip/storage/`) and append-only ingestion
  (`src/aip/ingest/`) with integration tests, and ran the quality gates.
- Commit 5: reviewed the committed design and PoC, found the JSON Pointer ambiguity in leaf
  commitments, proposed decisions U1–U9, implemented `src/aip/crypto/` and `tests/crypto/`, assembled
  hand-written known-answer preimages (digests computed by external tools), and ran the quality gates.

### ChatGPT (as reported by the candidate)
- Helped interpret and organize the assessment requirements.
- Suggested a technology stack and a phased implementation approach.
- Prepared generic prompts that the candidate used with Claude Code.
- Reviewed Claude Code's architecture and implementation plans.
- Identified concerns involving cryptographic verification, redaction, archive integrity, export
  completeness, confidentiality, GitHub repository visibility and accurate AI-use documentation.
- Reviewed the proposed first commit and recommended keeping the attestation template blank.

ChatGPT's suggestions were advisory and reviewed by the candidate.

## 3. Material shared
| Tool | Material |
|------|----------|
| Claude Code | Assignment brief (PDF); screenshot of the recruiter's instruction email; candidate prompts; terminal output from the Step 0 authentication and identity checks |
| ChatGPT | Assignment brief (PDF) and recruiter instructions/screenshots during earlier discussions; Claude Code's architecture plans, design proposals, documentation drafts, code snippets and implementation updates |

External services contacted by Claude Code's own commands on 2026-10-28: PyPI (package names, via
`pip install --dry-run`) and the GitHub API (this repository's path, via `gh` and one anonymous request).
Claude Code cannot observe what was shared with other tools; the ChatGPT entries are as reported by the
candidate.

## 4. Session log
| # | Date | Activity | AI recommendation | Candidate decision |
|---|------|----------|-------------------|--------------------|
| 1 | 2026-10-28 | Repository inspection; plan v1 before the brief was shared with Claude Code | Claude Code: plan with assumed Scenario A/B/C mappings; asked for the scenario text | Superseded once the brief was shared |
| 2 | 2026-10-28 | Plan v2, from an early prompt that framed the work as an independent portfolio project; this framing was corrected when the actual assignment requirements were reviewed | Claude Code: broad plan including AWS, Docker, metrics and CI | Framing corrected to the assignment; scope cut to the three scenarios and the 2–3 day budget |
| 3 | 2026-10-28 | Brief and recruiter email shared with Claude Code; plan aligned to the brief | Claude Code: requirements mapping and design; flagged that the recruiter email ("make it public") conflicts with the brief (private repository); asked the candidate to confirm identity | Repository kept private |
| 4 | 2026-10-28 | Plan v3 | Claude Code: hash layout, invariants, guarantee levels, redaction PoC design, milestones | Direction approved subject to 12 refinements: focus on the scenarios; one Python version after a compatibility check; SHA-256 chain with documented genesis; PoC before redaction; separate guarantee levels; export completeness; retention evidence; reproducible tamper test; genuine history; confidentiality; accurate AI log; no invented results |
| 5 | 2026-10-28 | Plan v3.1 | Claude Code: revised design text and Milestone 1 file contents | 9 corrections: archive metadata vs content integrity; redaction authentication; accurate AI log; plaintext-storage limitation; validate installation; privacy; identity verification; assignment field names; no fabrication |
| 6 | 2026-10-28 | Milestone 1 review | Claude Code: proposed a Co-Authored-By trailer and a pip-freeze lock file | 10 adjustments: nothing marked approved without explicit approval; attestation as a template; verify the repository before the first commit; record ChatGPT and Claude Code; no Co-Authored-By trailer; lock generated from declared dependencies; document plaintext archives and propose an improvement; tamper demo must not rely on triggers; show status and staged diff before each commit; no install, commit, push or visibility change without approval |
| 7 | 2026-10-28 | Step 0 verification | Claude Code: verification commands; read-only checks | Candidate logged `gh` into the repository owner account, set a repository-local Git identity and confirmed the commit email is verified. Results: owner `Lakshmij12`, visibility `PRIVATE`, anonymous access 404 |
| 8 | 2026-10-28 | Commit 1 (`2641783`) | Claude Code: .gitignore additions, attestation template, commit message | Approved as proposed; attestation details left blank for the candidate to complete |
| 9 | 2026-10-28 | Commit 2 (`03e2d98`) | Claude Code: drafted the four documentation files | Candidate specified the ChatGPT entries and content requirements, requested five edits, then approved; committed as `03e2d98` |
| 10 | 2026-10-28 | Commit 3 prepared: redaction proof of concept | Claude Code: wrote `poc/redaction_poc.py` (14 self-checks, synthetic data), ran it with Python 3.14.3 (exit 0, 14/14 PASS, empty stderr), and generated `docs/poc/redaction-poc-output.md` from the captured stdout | Candidate approved the script plan with two wording corrections (see §5), reviewed the test results, requested final wording checks, and approved staging. Commit 3 not yet approved or created (status when the entry was written; the candidate then approved the commit, created as `dc2c264`) |
| 11 | 2026-10-28 | Commit 4 prepared, Gate A: project configuration | Claude Code: proposed decisions D1–D6 (pip-tools hashed locks; runtime and dev locks; no package install; exclude `poc/` from Ruff; `.gitattributes`; development guide) and execution gates A–E; wrote `.gitattributes`, `.python-version`, `pyproject.toml`, `src/aip/__init__.py`, `tests/test_smoke.py`, `docs/DEVELOPMENT.md` | Candidate approved D1–D6 with seven adjustments (conservative `.gitattributes`; dependency compatibility marked unverified; bootstrap and isolated build dependencies documented as outside the locks; pip-audit command provisional; `poc/` Ruff exclusion documented; smoke tests described as runtime/tooling checks; this log updated) and approved Gate A only. No packages installed, locks generated or tests run yet (status at Gate A; see row 12) |
| 12 | 2026-10-28 | Commit 4, Gate B: dependency locks and installation | Claude Code: dry-run selected pip-tools 7.6.2 (declares `pip>=22.2`, Python 3.14 classifier); installed it into `.venv`; generated both locks with hashes; found that the first dev lock pinned `pip==26.2.2` (required via pip-audit → pip-api), so installing it would upgrade pip 25.3; stopped and proposed options A–C, recommending B; corrected the B command before running it (`--allow-unsafe` would have re-included pip); regenerated; ran hash-mode dry-runs; installed the dev lock | Candidate chose Option B (exclude pip from the locks; keep pip 25.3 as the bootstrap installer) and approved continuing Gate B only. Results: runtime lock 20 packages / 400 hashes; dev lock 60 packages / 1,175 hashes; no environment markers; pip absent from both, with pip-compile's expected WARNING that pip is unpinned; both dry-runs exit 0; install exit 0 with empty stderr; 60/60 lock entries installed at the locked versions; pip still 25.3; `pip check` clean. Smoke tests and quality gates not yet run (status at Gate B; see row 13) |
| 13 | 2026-10-28 | Commit 4, Gate C: quality gates | Claude Code: inspected line endings read-only (`git ls-files --eol`, `git check-attr`; index untouched); ran `ruff check .` (exit 0) and `ruff format --check .` (exit 0); `pytest -v` failed at collection (exit 2): Starlette 1.10.0's test client imports `httpx2` and falls back to `httpx` with a `StarletteDeprecationWarning`, which `filterwarnings = ["error"]` turned into an error; mypy was not launched because of a wrapper mistake (§6) and was re-run separately (exit 0). Investigated `httpx2` without installing it: Starlette 1.10.0 and FastAPI 0.162.0 declare `httpx2>=2.0.0` in their extras; Starlette 1.2.0/1.2.1/1.3.0 and FastAPI 0.143.4 release notes add httpx2 support; PyPI metadata names Tom Christie (author) and Pydantic Services Inc. (maintainer), source `github.com/pydantic/httpx2` (pydantic organization, not a fork). PyPI maintainer accounts were not verified. Proposed Options 1a/1b/2/3, recommending 1a | Candidate chose Option 1a (`httpx2==2.16.0` replacing `httpx==0.28.1`, `filterwarnings` unchanged) and authorized completing Gate C. Results: runtime lock byte-identical; dev lock −`httpx` 0.28.1, −`httpcore` 1.0.9, +`httpx2` 2.16.0, +`httpcore2` 2.16.0, +`truststore` 0.10.5 (61 packages, 1,177 hashes); dry-runs and install exit 0; `httpx`/`httpcore` required only by unselected extras, so uninstalled; pip still 25.3; `pip check` clean; 61/61 lock entries installed. Final gates: ruff check 0, ruff format 0, mypy 0, pytest 7 passed (exit 0), pip-audit options confirmed via `--help`, audit exit 0 "No known vulnerabilities found" (pypi service, 2026-10-28T09:18-04:00). Commit 4 not yet staged or committed (status when the entry was written; the candidate then approved staging and the commit, created as `d591e28`) |
| 14 | 2026-10-28 | Commit 5: cryptographic foundations | Claude Code: reviewed REQUIREMENTS, DESIGN, LIMITATIONS and the commit 3 PoC; found that JSON Pointer leaf paths make `{"a":["x"]}` and `{"a":{"0":"x"}}` hash identically; proposed typed paths and decisions U1–U9 (typed paths, UTF-16 key order, reject non-NFC, ±(2^53−1), `"t"` domain tags, strict timestamps, pure `check_chain` now, `MAX_DEPTH=32`, two-tool digests); implemented six modules and five test modules; verified the RFC 8785 examples against the published RFC text, finding that its sorting sample's key U+FB33 is not NFC | Candidate approved U1–U9 with ten corrections: typed paths with the PoC left unchanged; bind the complete JSON structure (arrays vs numeric keys, empty and nested empty containers, malformed/conflicting paths); validate every hashing input; one precise `MAX_DEPTH` enforced everywhere; strict timestamp validation; explicit `VALID`/`INVALID`/`REDACTED_UNVERIFIED` leaf status; vectors from manually reviewed bytes, confirmed by `sha256sum` and `Get-FileHash`, cross-checked with RFC 8785; chain tests including an undetectable full rewrite; scope limited to pure foundations; accurate docs. Results: 22/22 vectors agree between the two tools; ruff check 0, ruff format 0, mypy 0 (17 files), pytest 244 passed (exit 0), branch coverage 98% (report only). Commit 5 not yet staged or committed (status at implementation; see row 15) |
| 15 | 2026-10-28 | Commit 5: pre-staging security and maintainability review | Claude Code: read-only review of canonical, commitments, hashing, chain, timestamps and vectors; no Critical or High findings. Medium: M1 `TypeIs` made mypy treat invalid-input branches as unreachable (demonstrated with `--warn-unreachable`); M2 vector preimages hand-written by the same author as the implementation; M3 a matching `payload_root` does not verify revealed values. Low: L1 root leaf accepted non-`{}` values; L2 mutable empty-container values; L3 `isinstance` accepted `datetime` subclasses; L4 repeated validation; L5 malformed `prevHash` reported as a link mismatch; L6 no size limits. Recommended Option A | Candidate chose Option A, without the generator script or new dependencies: fix M1 (`TypeGuard`, `--warn-unreachable`), L1 (root leaf must be a revealed `{}`, not redactable), L3 (exact `datetime`), L5 (malformed `prevHash` → `MALFORMED_RECORD`), add the M3 regression test and document it, defer the rest. Results: M1 probe now reveals `str` in the negative branch; pytest 259 passed (252 crypto + 7 smoke); ruff check 0; ruff format 0; mypy `--warn-unreachable` 0 (17 files); branch coverage 98%. Commit 5 not yet staged or committed (status at review; the candidate then approved staging and the commit, created as `7b7e83ef1603e2b3cacee562b8632fbd29868958`) |
| 16 | 2026-10-28 | Commit 6: SQLite persistence and append-only ingestion | Claude Code: planned schema v1 (STRICT tables, CHECK/UNIQUE constraints, guard triggers), `BEGIN IMMEDIATE` appends via SQLAlchemy Core, strict `EventInput`, limits and error classes, and decisions D1–D10; implemented `storage/` and `ingest/` with 141 tests | Candidate approved D1–D10 with eleven requirements: `warn_unreachable` first with a separate mypy run; record the commit 5 hash; explicit DDL, STRICT, Core, `BEGIN IMMEDIATE`; future-timestamp check against the real clock with the recordedAt clamp unable to weaken it; `eventId = "evt_" + recordHash[:32]` validated on read, collision limits documented; v1 triggers kept, redaction to need a migration, no overclaiming for archived records; limits before commitment work; distinguish busy from integrity from unexpected errors, success only after COMMIT, commit-outcome uncertainty documented; thread and process concurrency, restart, malformed input, schema and full-recomputation tests; all gates. Results: mypy after the config change 0 with no findings; SQLite 3.50.4; pytest 400 passed (259 + 141); ruff check 0; ruff format 0; mypy 0 (34 files); coverage 96%; concurrency and transaction tests 5/5 repeated runs. Commit 6 not yet staged or committed (status at implementation; see row 17) |
| 17 | 2026-10-28 | Commit 6: pre-staging transaction review | Claude Code: read-only review of `database.py`, `errors.py` and the transaction tests, with scratch probes (SQLite trace of one append: exactly `BEGIN IMMEDIATE`, head `SELECT`, inserts, one `COMMIT`; errors inside a transaction; rollback failing always and once). No Critical or High findings. Medium M1: unexpected COMMIT failures were reported as "nothing was committed", although SQLite documents that after `SQLITE_IOERR`/`SQLITE_FULL`/`SQLITE_NOMEM` a transaction "may or may not be rolled back automatically". Low: L1 rollback failure after a failed COMMIT untested; L2 cleanup after a failed rollback inside a transaction relies on SQLAlchemy; L3 nested write transactions block themselves; L4 SQLAlchemy logs pool reset failures | Candidate chose Option A: add `StorageCommitUnknownError` for COMMIT failures that are neither busy nor constraint violations, with a message advising a check before retrying; keep busy and integrity classes; correct the `StorageError` documentation and LIMITATIONS 32; add tests for COMMIT I/O, FULL and BUSY failures and for a failing ROLLBACK after a failed COMMIT; record L2–L4 as deferred. Results: pytest 413 passed (259 + 154); ruff check 0; ruff format 0; mypy 0 (34 files); coverage 96% (`errors.py` 100%, `database.py` 90%); transaction and concurrency tests 33 passed in each of 5 runs. Commit 6 not yet staged or committed (status at review; the candidate then approved staging and the commit, created as `243c69e94a79712dd69a0d937b7d48fb2d22d1db`) |
| 18 | 2026-10-28 | Commit 7: HTTP API for writing and querying events | Claude Code: proposed a time-boxed plan for the remaining commits, a two-gate approval process, a cut order and decisions E1–E6; implemented `config.py`, `cli.py`, `api/` (app factory, API-key auth, RFC 9457 errors, routes, schemas), filtered keyset queries in `storage/repository.py`, and 65 API tests; ran a live uvicorn smoke test | Candidate approved the two-gate process, E1–E6 (X-API-Key with SHA-256 hashes and constant-time comparison; `/audit` routes with 201; 128 KiB body limit enforced while reading; keyset pagination, default 50, max 200; RFC 9457 errors without values, unknown COMMIT outcomes distinguishable; documented uvicorn command) and the cut order. Results: pytest 478 passed (413 + 65); ruff check 0; ruff format 0; mypy 0 (46 files); live run POST 201, GET 200, writer GET 403, `/docs` 200, no keys in logs. Commit 7 not yet staged or committed (status at implementation; the candidate then approved the 17 staged files and the commit, created as `0557eb2960bc4ab8b1e0837e8f818c8d9605e370`) |
| 19 | 2026-10-28 | Commit 8: chain verification, Ed25519 checkpoints, tampering demo | Claude Code (a session that closed before staging, then a resumed session that first checked Git state and found commit 7 created and commit 8 unstaged): implemented `verify/service.py`, `api/routes_verify.py`, `crypto/signing.py`, the `new-signing-key` CLI, raw-row repository readers, `scripts/tamper_demo.py` and verification, signing and API tests. The resumed session's review found two gaps and fixed them: redacted/archived content was reported as `intact: true` (now `INDETERMINATE`, `intact: null`), and the checkpoint endpoint signed the stored head without verifying the chain (now verifies first, 409 on a violation) | Candidate approved the commit 8 scope (verification of commitments, roots, content and record hashes, sequence and links; safe first-violation reporting; Ed25519 and key CLI; checkpoints if time allowed; direct-SQLite demo and API test; no overclaiming without a trusted anchor; redaction/archive not misclassified; no values, salts or keys in errors). Results: see DEVELOPMENT.md "Quality gate results", commit 8. Not yet committed (status at implementation; the candidate then approved the 20 staged files and the commit, created as `75f9091843922e3377e96ca50385d3029286d4a6`) |
| 20 | 2026-10-28 | Commit 9: authorized redaction, retention/archival, schema v2 | Claude Code: implemented the v1→v2 trigger migration, `lifecycle/` (signed SYSTEM_REDACTION and SYSTEM_RETENTION_RUN events in the same transaction as the mutation; archive files written durably before COMMIT, deleted on rollback, kept on an unknown COMMIT outcome), verifier checks C6–C8 with signature-checked authorizations, admin-only endpoints (retention dry run by default), redacted/archived read views, and 79 tests; updated 5 existing tests whose expectations the new rules intentionally change (unauthorized blanking and archive marking are now TAMPERED, not INDETERMINATE) | Candidate approved the scope and security requirements: never regenerate commitments or rewrite hashes; unauthorized removal never classified as redaction; no secure-deletion claim; legitimate archives with valid evidence not TAMPERED; documented failure and recovery for archive writes; existing API, signing and verification behaviour kept. Results: see DEVELOPMENT.md, commit 9. Not yet committed (status at implementation; the candidate then approved the 31 staged files and the commit, created as `b3f4ff2484e963cf32e283a849584ab13e1345d5`) |
| 21 | 2026-10-28 | Commit 10: signed export and standalone verifier | Claude Code: implemented `export/bundle.py` (one canonical-JSON bundle: records, authorization events, whole-chain hash skeleton, Ed25519-signed manifest with section digests and `completeness: signer-asserted`), `GET /audit/export` (exactly one of actorId/resourceId, reader roles, verify-before-export), and `tools/verify_bundle.py`, a separate implementation of the published specs that imports nothing from `aip`; 26 tests, most running the verifier as an isolated subprocess (valid, empty, partially redacted, archived, wrong key, attacker re-signing, tampered sections, checks behind the signature, anchors, malformed input, authorization) | Candidate approved the scope: explicit out-of-band key trust (the embedded key is never trusted); a defined result for unavailable archived content (INDETERMINATE); no claim of database completeness without a trusted checkpoint; deterministic, documented format; no redacted plaintext or private keys. Results: see DEVELOPMENT.md, commit 10. Not yet committed |

ChatGPT reviews of Claude Code's plans took place between these sessions (October 2026, including
2026-10-28). The candidate reports that these reviews contributed to identifying several of the concerns
behind the refinements, corrections and adjustments in rows 4–6.

## 5. AI suggestions rejected or modified
| Suggestion | Proposed by | Outcome | Reason |
|------------|-------------|---------|--------|
| HMAC-keyed hash chain | Claude Code (as an alternative) | Rejected in the plan direction approved by the candidate | Export recipients would need the secret |
| Trust a public key embedded in the export bundle | Claude Code (as an alternative) | Rejected | An attacker could re-sign; the key must arrive out of band |
| Offset pagination | Claude Code (as an alternative) | Rejected | Unstable under concurrent appends |
| Merkle tree log | Claude Code (as an alternative) | Deferred | Not justified within the time budget |
| Export only the matching records | Claude Code (early design) | Modified by Claude Code | Added hash skeleton and signed manifest so gaps and reordering are detectable |
| AWS, Docker, metrics in scope | Claude Code (plan v2) | Cut by the candidate | Outside the scenarios and the time budget |
| Treat retained `payloadRoot` as proof of archived content | Claude Code (plan v3) | Modified by candidate correction | Proves metadata consistency only; content needs the signed digest checked against the file |
| Treat a chained redaction event as authorized | Claude Code (plan v3) | Modified by candidate correction | Chaining is not authentication; authorizations are Ed25519-signed |
| AI log claim that no assignment material reached other services | Claude Code (plan v3 draft) | Rejected by candidate correction | Not verifiable by Claude Code, and the material had been shared with ChatGPT |
| DESIGN.md status "approved" | Claude Code (plan v3.1 draft) | Changed to "Proposed" by candidate adjustment | Approval is recorded only when the candidate gives it explicitly |
| Co-Authored-By trailer on commits | Claude Code | Rejected by the candidate | This log provides traceability |
| Lock file from `pip freeze` | Claude Code | Modified by the candidate | Lock must be generated from the declared dependencies |
| Describe removing value and salt in the PoC as deletion | Claude Code (commit 3 plan) | Modified by candidate correction | It is logical redaction from an in-memory structure, not secure deletion |
| Describe per-leaf salts as making equal values in different records "unlinkable" | Claude Code (commit 3 plan) | Modified by candidate correction | Salts only prevent inferring equality by comparing commitments; other fields may still link records |
| `.gitattributes` with a single `* text=auto eol=lf` rule | Claude Code (commit 4 plan) | Modified by candidate adjustment | Conservative rules: `* text=auto`, explicit LF for source/config/docs, binary exceptions |
| pip-tools in the `dev` extra with a version placeholder | Claude Code (commit 4 plan) | Revised by Claude Code to apply candidate adjustment 3; approved by the candidate | pip-tools is a bootstrap tool outside the hashed locks, so it is documented rather than declared |
| Lock pip together with the other dependencies (`--allow-unsafe`) | Claude Code (Gate B, first lock generation) | Rejected by the candidate (Option B) | Installing the dev lock would have upgraded the installer from pip 25.3 to 26.2.2 mid-install |
| Option B command keeping `--allow-unsafe` alongside `--unsafe-package pip` | Claude Code (Gate B options) | Corrected by Claude Code before running | `--allow-unsafe` pins all unsafe packages, which would have re-included pip |
| Suppress the `StarletteDeprecationWarning` with a targeted `filterwarnings` ignore (Option 2) | Claude Code (Gate C options) | Not chosen by the candidate | Would keep a deprecated code path and weaken the strict warning policy |
| Pin an older Starlette/FastAPI (Option 3) | Claude Code (Gate C options) | Not chosen by the candidate | Moves pins backwards against both frameworks' direction |
| `git add --renormalize .` as a line-ending check | Claude Code (commit 4 plan) | Replaced by candidate instruction | It can modify the index; read-only `git ls-files --eol` and `git check-attr` used instead |
| JSON Pointer string paths in leaf commitments (DESIGN §2 and the commit 3 PoC) | Claude Code (plan v3, PoC) | Replaced by typed paths; flaw found by Claude Code during the commit 5 review, fix approved by the candidate (U1) | Array indices and numeric object keys were indistinguishable, so two different payloads had the same contentHash |
| Treat redacted leaves as passing verification | Implicit in the PoC's `mismatched_leaves` (skips redacted leaves) | Replaced by an explicit `REDACTED_UNVERIFIED` status (candidate correction 6) | A redacted leaf cannot be checked against its value; it must not be reported as valid |
| `TypeIs[str]` return types for `is_hex_digest` and `is_canonical_timestamp` | Claude Code (commit 5) | Replaced by `TypeGuard[str]` after the commit 5 review (candidate-approved M1) | A False result does not mean "not a str", so `TypeIs` let mypy skip invalid-input branches |
| Combined `verify_payload` API now | Claude Code (commit 5 review, M3) | Deferred by the candidate to the verification milestone | Regression test and documentation added instead |
| Commit the known-answer generator script | Claude Code (commit 5 review, M2) | Declined by the candidate | Kept to the 19 proposed files; method documented in DEVELOPMENT.md |
| Report every unexpected COMMIT failure as "not committed" | Claude Code (commit 6 implementation) | Replaced after the transaction review (candidate-approved M1) | SQLite does not guarantee a rollback after I/O, full or out-of-memory errors; these now raise `StorageCommitUnknownError` |
| Harden cleanup after a failed rollback inside a transaction; make read transactions read-only; configure logging | Claude Code (commit 6 review, L2–L4) | Deferred by the candidate | Recorded as LIMITATIONS 41–43 |
| Integer limit "absolute value ≤ 2^53" (DESIGN §1) | Claude Code (plan v3) | Corrected to ±(2^53−1) (U4) | 2^53 is outside JavaScript's safe-integer range |
| Report redacted leaves and archived rows as `intact: true` with an unverified count | Claude Code (commit 8, first session) | Replaced by `status: INDETERMINATE`, `intact: null` (candidate requirement: unverifiable states are neither valid nor tampered) | Either state can be faked with file access to hide an edit, so `intact: true` overclaimed |
| Sign the stored head row directly in `GET /audit/checkpoints/latest` | Claude Code (commit 8, first session) | Corrected by Claude Code in the resumed session's review | Would sign a tampered chain and fail with a 500 on a malformed head; now verifies first and returns 409 |
| Append a signed checkpoint inside each redaction/retention transaction (DESIGN §6 step 5, §7 step 3) | Claude Code (plan v3) | Dropped in commit 9 | Checkpoints are held outside the database (commit 8); a stored one would add nothing an attacker with file access could not delete |
| Multi-file export (`records.jsonl`, `skeleton.jsonl`, `manifest.json`) with an embedded signed checkpoint (DESIGN §8) | Claude Code (plan v3) | Simplified in commit 10 | One canonical-JSON document with section digests in the signed manifest gives the same guarantees with less to get wrong; the head is signed in the manifest, and an external checkpoint is passed with `--anchor-*` |
| Store checkpoints in the database and check them as C9 | Claude Code (design §4) | Simplified for the time budget | Checkpoints held in the same database can be deleted with the tail; the caller keeps them and passes an anchor |

## 6. Errors and corrections during AI-assisted work
- Claude Code's first `git commit` attempt for commit 1 failed because PowerShell passed the message as a
  pathspec. Nothing was committed; the commit was retried with a message file.
- A `gh api --jq` filter failed because of PowerShell quoting; it was rerun with a simpler filter.
- The Linux wheel dry-run first failed because only one platform tag was passed; it was rerun with the
  full manylinux tag set.
- The first draft of the PoC output document described the embedded stdout as "byte-for-byte"; the
  assembly step had converted CRLF line endings to LF, so the wording was corrected to state that
  transformation before review.
- During Gate B, `python -m piptools --version` failed because that option does not exist; the version
  was confirmed with `pip-compile --version` instead.
- The Option B description first stated that setuptools would stay locked; setuptools is not in either
  dependency tree, so the statement did not apply and was corrected before regeneration.
- During Gate C, Claude Code's first PowerShell wrapper returned the function's captured output instead
  of the process exit code, so it reported "STOPPING after ruff check failure" although `ruff check .`
  had exited 0 ("All checks passed!"). The exit code was confirmed by re-running Ruff, and the wrapper
  was rewritten to return only the exit code.
- The rewritten wrapper passed an empty argument list to `Start-Process` for mypy, which raised a
  parameter-validation error, so mypy was never launched; the wrapper then continued to pytest instead
  of stopping. mypy was run separately afterwards (exit 0, "Success: no issues found in 2 source files").
  Later Gate C steps called each process directly and checked its exit code.
- During the `httpx2` investigation, `gh api --jq` filters failed again under PowerShell quoting; the same
  read-only queries were re-run through Bash.
- The commit 3 PoC's 14 self-checks did not include an array versus an object with numeric keys, so the
  JSON Pointer ambiguity passed unnoticed until the commit 5 design review.
- During commit 5 vector generation, the first `sha256sum` run passed Windows paths, so GNU `sha256sum`
  prefixed each digest with `\`; the script embedded those strings into later preimages. The run was
  discarded, the script switched to relative file names and rejected any digest that is not 64 hex
  characters, and all vectors were regenerated before PowerShell `Get-FileHash` confirmed 22/22.
- Test files written by Claude Code contained literal non-ASCII characters (including U+2028 LINE
  SEPARATOR) where `\u` escapes had been intended. Ruff (RUF001) flagged some; a scan found 23. They were
  converted to escapes by a script that first checked each one sat inside a plain string literal, and
  the full suite was re-run (244 passed). A first scan missed U+2028 because Python's `splitlines()`
  treats it as a line break.
- First gate run of commit 5: 3 test failures (a malformed `Leaf` commitment raised `HashInputError`
  instead of `LeafError`), 13 Ruff findings (line length, union order, ambiguous Unicode), 4 files to
  reformat, and 5 mypy errors (one in `canonical.py`, where a combined `list`/`dict` branch could not be
  narrowed). All were fixed within the commit 5 files and the gates re-run cleanly.
- Claude Code annotated `is_hex_digest` and `is_canonical_timestamp` with `TypeIs[str]`, which is only
  correct when False means "not a str". mypy therefore treated their negative branches as unreachable
  and did not type-check them; the default strict run did not report this. Found during the review by a
  probe run with `--warn-unreachable`, and fixed by switching to `TypeGuard[str]`.
- Commit 6, real defect found by its own test: after a COMMIT that SQLite rejected (a deferred
  foreign-key violation), SQLite still held the transaction while SQLAlchemy treated it as finished,
  so the connection went back to the pool with an open transaction and the next append failed with
  "cannot start a transaction within a transaction". Fixed by rolling back on the raw driver
  connection when it is still in a transaction and then invalidating the connection.
- Commit 6 test mistakes: a test expected the code `lone_surrogate` for an identifier, but Pydantic
  rejects lone surrogates itself with `string_unicode` (the input was still rejected); and the
  no-leak check on the rendered traceback failed because `traceback.format_exception` prints source
  lines, and the test's own line contained the literal. Walking the exception chain showed no value in
  any exception's `str()`/`repr()`; the test now builds the value at runtime and checks each exception.
- Commit 6 lint and typing: 16 Ruff findings (line length, a quoted annotation, two S608 false positives
  on SQL built from a constant column list, suppressed with a stated reason, test-style rules), 4 files
  to reformat, and one mypy error (a `StoredRecord` built from `*texts`, rewritten with keywords).
- Literal non-ASCII characters appeared again in two test files where `\u` escapes were written; 6
  were converted with the same checked script as in commit 5.
- An unused `Database.check()` method added by Claude Code was found through coverage and removed.
- Commit 7: the first live smoke test failed to generate keys because `python -m aip.cli` cannot import
  `aip` unless `src` is on `PYTHONPATH` (the project is not pip-installed); the documented commands now
  set it. Gate fixes: an exception renamed to `PayloadTooLargeError` (N818), one long line, a `Mapping`
  versus `dict` header type in `problem()`, and a missing test annotation (mypy).
- Commit 8: the Claude Code session closed before staging. The resumed session checked `git log` first
  (commit 7 existed, so it was not recreated), then reviewed the unstaged work: the two gaps in section 5,
  plus a Ruff E501 in a test and one file to reformat after adding `VerifyStatus`.
- Commit 9 test mistakes found by running them: two trigger tests ran statements that matched no rows
  (so no trigger fired); an archive-tampering test replaced a byte pattern that did not occur (canonical
  key order differs); one assertion expected an altered authorization to be reported at the system event
  instead of at the redacted target (the verifier's behaviour was correct); a check that a sensitive value
  was absent from a whole archive file ignored a second, unredacted record. mypy flagged a meaningless
  bytes-in-strings assertion (`comparison-overlap`). All were corrected in the tests; no product code
  changed because of them. Gate fixes: 8 long lines (mostly docstrings), 2 PT018 assertions, untyped JSON in
  `parse_archive` and one dict annotation.
- Commit 10: the first export test run had one error (a test used the `api` fixture, which is defined
  only for `tests/api/`) and one meaningless assertion (`... or True`), both found during review and
  removed. Gate fixes in the verifier: 7 long lines, `pairwise` instead of `zip` (RUF007), and two
  mypy findings (an over-broad `type: ignore` in the canonical validator, comparing possibly-None
  seqs).

## 7. Verification policy
- Every file change, install, commit and push requires candidate approval.
- Test and tool results are recorded only from actual runs.
- ChatGPT's suggestions are advisory; repository implementation is done with Claude Code and reviewed by
  the candidate.
