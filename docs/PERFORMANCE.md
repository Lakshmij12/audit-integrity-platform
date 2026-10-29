# Performance

Measured, not estimated. These are the results of one run of `scripts/benchmark.py` on the
development machine. They show the prototype's scaling behaviour and bottlenecks; they are not a
capacity claim for any other machine or deployment.

## 1. How to reproduce
```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe scripts\benchmark.py --sizes 1000,10000 --json "$env:TEMP\aip-benchmark.json"
```
`--json` is optional. Write it outside the repository (as above), so raw results are never committed
by accident.
- **Data:** synthetic and seeded (`--seed`, default 20261028): 200 accounts, 50 actors, three event
  types, nested payloads (`ssn` is a synthetic `900-00-nnnn` value).
- **Storage:** a temporary directory created and deleted by the script. No development database, key
  or archive is touched, and the service never imports the script.
- **Smoke test:** `tests/test_benchmark_smoke.py` runs it on 30 records, so it keeps working.

## 2. What is measured
| Metric | Method |
|--------|--------|
| Service append | Each `IngestService.append` is timed with `perf_counter_ns` (events already validated). Includes salts and commitments, `BEGIN IMMEDIATE`, hashing, INSERT and a `synchronous=FULL` COMMIT. One thread, sequential. |
| HTTP append, **in-process** | 500 `POST /audit/events` calls through FastAPI's in-process test client on a fresh database: API-key check, body limit, strict validation, routing, append and response. **No network or socket is involved, so this is not network latency.** The workload is the same for every dataset size (500 requests on an empty database), so the two result columns are two runs of one workload, not a scaling result. |
| Full-chain verification | `verify_database` with the trusted key; median of 3 runs. |
| Export | `build_bundle` for one account and one actor; median of 3. Every bundle includes a hash-only skeleton of the **whole** chain. **Bundle building only:** `GET /audit/export` first runs a full-chain verification, which is not included here (see the verification row). |
| Offline bundle verification | `tools/verify_bundle.py` on the account bundle, in a separate process. Includes interpreter start-up. |
| Account-access report | Full verification plus `build_access_report` for one account; median of 3. |
| Percentiles | Python `statistics.quantiles` (inclusive method) over all samples. |

## 3. Environment
| Item | Value |
|------|-------|
| Date | 2026-10-28 21:39 UTC |
| OS | Windows 10 (10.0.19045) |
| CPU | Intel64 Family 6 Model 158 Stepping 9 (GenuineIntel), 8 logical CPUs |
| Python / SQLite | CPython 3.14.3 / SQLite 3.50.4 |
| Code | Commit `34ef21a` plus the working-tree changes present at the time (the OpenAPI declarations and the Scenario C per-event correction), which are part of the same final commit as this document |
| Disk | Not recorded by the script (fsync latency depends heavily on it) |
| Load | Interactive development machine; no other benchmark running |

## 4. Results (single run)
| Metric | N = 1,000 | N = 10,000 |
|---|---|---|
| Service append throughput (events/s) | 337 | 319 |
| Service append latency p50 / p95 / p99 (ms) | 2.70 / 5.66 / 7.25 | 2.67 / 5.89 / 13.80 |
| HTTP append, in-process (events/s; requests) | 113; 500 | 113; 500 |
| HTTP append, in-process p50 / p95 / p99 (ms) | 8.21 / 12.62 / 16.03 | 8.24 / 11.62 / 14.58 |
| Full-chain verification (s, median of 3) | 1.098 | 11.283 |
| Export one account (s; records; bytes) | 0.083; 5; 304,304 | 0.975; 58; 3,059,835 |
| Export one actor (s; records; bytes) | 0.103; 22; 336,641 | 1.053; 221; 3,369,196 |
| Offline bundle verification, account (s, incl. process start) | 0.321 | 1.311 |
| Account-access report incl. verification (s; events) | 1.120; 5 | 11.485; 58 |
| Database file size, main file without WAL (bytes) | 1,802,240 | 17,604,608 |

How to read two rows (the numbers are as measured):
- **HTTP append:** both columns are the same 500-request workload on an empty database (section 2).
- **Export:** `build_bundle` only. A `GET /audit/export` call also pays the full-chain verification.
  Adding the two measured rows gives about 1.2 s at 1,000 records and 12.3 s at 10,000 for the
  account bundle. That is an estimate; the endpoint itself was not timed.

## 5. Observations
- **Append cost doesn't grow with the chain.** Throughput and p50 are about the same at 1,000 and
  10,000 records: each append reads only the head. Median latency is about 2.7 ms, most of it the
  `synchronous=FULL` commit. The p99 rose at 10,000 (13.8 ms), but that's a single run on a busy
  machine, so treat it as noise until repeated.
- **HTTP adds about 5.5 ms per request in-process** (p50 8.2 ms versus 2.7 ms). That covers
  authentication, validation and serialization; real network and TLS costs would come on top.
- **Verification scales linearly**: about 1.1 ms per record, so 10× the records took about 10× the
  time (1.1 s → 11.3 s). It recomputes every commitment and hash and reads each record's leaves.
- **Every verify, checkpoint, export and report call pays that cost**, because each one verifies
  first (LIMITATIONS 57). The account report at 10,000 records took 11.5 s, almost all of it
  verification. (The report row includes the verification; the export rows do not.)
- **Bundle size is dominated by the skeleton.** An account bundle with 58 records was about 3 MB,
  because the skeleton covers all 10,000 records (LIMITATIONS 70).
- **The offline verifier is fast**: 1.3 s at 10,000, including Python start-up.

## 6. Limitations of these measurements
- One run on one Windows machine, with no repetitions across runs and no confidence intervals.
- In-process only: no network, TLS, reverse proxy or real HTTP server (uvicorn) in the loop.
- Single-threaded appends: write contention and `store_busy` behaviour under load were not
  benchmarked (the concurrency tests check correctness, not performance).
- Not measured: retention runs, redaction, very large payloads, chains beyond 10,000 records, memory
  use, or cold-cache disk effects.
- The numbers depend on disk fsync latency and background load, so other machines will differ.

## 7. Implications
For the prototype's scale these numbers are adequate. For production, the full-chain walk on every
verify, export and report is the first bottleneck, and the proposed answer is incremental
verification from the last trusted checkpoint (ARCHITECTURE.md §7, proposed, not implemented).
