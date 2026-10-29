"""Reproducible performance benchmark on disposable synthetic data (docs/PERFORMANCE.md).

Everything runs in a temporary directory that is deleted afterwards; no development database, key
or archive is touched, and nothing here is imported by the service.

For each dataset size N it measures, in one process on this machine:

* service append: ``IngestService.append`` for N events (validation already done, so this is
  salts and commitments, ``BEGIN IMMEDIATE``, hashing, INSERT and a ``synchronous=FULL`` COMMIT);
* HTTP append: ``POST /audit/events`` through FastAPI's in-process test client (API-key check,
  body limit, strict JSON validation, routing, append). In-process: NOT network latency;
* full-chain verification (``verify_database``), median of three runs;
* export of one account and of one actor (``build_bundle``), and offline verification of the
  account bundle with ``tools/verify_bundle.py`` in a separate process;
* the Scenario C account-access report for one account (including its full verification).

Run from the repository root:
    $env:PYTHONPATH = "src"; .\\.venv\\Scripts\\python.exe scripts\\benchmark.py --sizes 1000,10000
Output is a Markdown report on stdout (and JSON with --json). Numbers depend on the machine and
especially on disk fsync latency; record the environment with every result.
"""

import argparse
import json
import os
import platform
import random
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from aip.api import create_app
from aip.api.auth import generate_api_key, hash_api_key
from aip.config import Settings
from aip.crypto.signing import Signer, generate_signing_key, public_key_hex
from aip.crypto.timestamps import format_timestamp
from aip.export import build_bundle
from aip.ingest import IngestService, validate_event
from aip.reports import build_access_report
from aip.storage import DatabaseConfig, open_database
from aip.verify import verify_database

ROOT = Path(__file__).resolve().parents[1]
ACCOUNTS = 200
ACTORS = 50
HTTP_SAMPLE = 500


def _event(rng: random.Random, i: int) -> dict[str, Any]:
    return {
        "eventType": rng.choice(["ACCOUNT_VIEWED", "ACCOUNT_UPDATED", "PERMISSION_GRANTED"]),
        "actorId": f"actor-{rng.randrange(ACTORS):03d}",
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": f"acct-{rng.randrange(ACCOUNTS):04d}",
        "payload": {
            "channel": rng.choice(["web", "branch", "api"]),
            "ssn": f"900-00-{i % 10000:04d}",  # synthetic, never a real identifier
            "fields": ["balance", "address"][: 1 + i % 2],
            "amount": str(rng.randrange(1, 100_000)),
            "meta": {"session": f"s-{i:06d}", "attempt": 1 + i % 3},
        },
    }


def _percentiles(samples_ns: list[int]) -> dict[str, float]:
    ms = sorted(sample / 1e6 for sample in samples_ns)
    cuts = statistics.quantiles(ms, n=100, method="inclusive")
    return {"p50_ms": cuts[49], "p95_ms": cuts[94], "p99_ms": cuts[98], "max_ms": ms[-1]}


def _timed(fn: Callable[[], Any]) -> tuple[float, Any]:
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def _median_seconds(fn: Callable[[], Any], runs: int = 3) -> tuple[float, Any]:
    timings, result = [], None
    for _ in range(runs):
        seconds, result = _timed(fn)
        timings.append(seconds)
    return statistics.median(timings), result


def run_size(size: int, seed: int, workdir: Path) -> dict[str, Any]:
    rng = random.Random(seed)  # noqa: S311 - reproducible synthetic data, not security
    db_path = workdir / f"bench-{size}.db"
    key_path = workdir / f"signing-{size}.pem"
    generate_signing_key(key_path)
    signer = Signer.from_pem_file(key_path)
    trusted = {signer.key_id: signer.public_key}
    events = [validate_event(_event(rng, i)) for i in range(size)]

    database = open_database(DatabaseConfig(db_path))
    try:
        service = IngestService(database)
        samples: list[int] = []
        started = time.perf_counter()
        for event in events:
            t0 = time.perf_counter_ns()
            service.append(event)
            samples.append(time.perf_counter_ns() - t0)
        append_seconds = time.perf_counter() - started

        verify_seconds, report = _median_seconds(
            lambda: verify_database(database, trusted_keys=trusted, archive_dir=workdir)
        )
        if report.status.value != "VERIFIED" or report.records_checked != size:
            raise RuntimeError("benchmark chain did not verify")

        account, actor = "acct-0007", "actor-007"
        now = format_timestamp(datetime.now(UTC))

        def export(**filters: str) -> bytes:
            with database.read_transaction() as conn:
                return build_bundle(
                    conn,
                    signer,
                    actor_id=filters.get("actor_id"),
                    resource_id=filters.get("resource_id"),
                    exported_at=now,
                )

        export_account_seconds, account_bundle = _median_seconds(
            lambda: export(resource_id=account)
        )
        export_actor_seconds, actor_bundle = _median_seconds(lambda: export(actor_id=actor))
        bundle_path = workdir / f"bundle-{size}.json"
        bundle_path.write_bytes(account_bundle)
        offline_seconds, completed = _timed(
            lambda: subprocess.run(  # noqa: S603 - fixed interpreter and script path
                [
                    sys.executable,
                    "-I",
                    str(ROOT / "tools" / "verify_bundle.py"),
                    str(bundle_path),
                    "--trusted-key",
                    public_key_hex(signer.public_key),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        )
        if completed.returncode != 0:
            raise RuntimeError("offline bundle verification failed")

        def report_for_account() -> Any:
            verification = verify_database(database, trusted_keys=trusted, archive_dir=workdir)
            with database.read_transaction() as conn:
                return build_access_report(
                    conn,
                    verification,
                    resource_type="CLIENT_ACCOUNT",
                    account_id=account,
                    actor_id=None,
                    event_type=None,
                    from_ts=None,
                    to_ts=None,
                    generated_at=now,
                )

        report_seconds, access = _median_seconds(report_for_account)
    finally:
        database.close()

    http = _http_append(workdir, size, seed)
    return {
        "records": size,
        "service_append": {
            "total_s": append_seconds,
            "events_per_s": size / append_seconds,
            **_percentiles(samples),
        },
        "http_append_in_process": http,
        "verify_full_chain_s": verify_seconds,
        "export_account": {
            "s": export_account_seconds,
            "records": len(json.loads(account_bundle)["records"]),
            "bytes": len(account_bundle),
        },
        "export_actor": {
            "s": export_actor_seconds,
            "records": len(json.loads(actor_bundle)["records"]),
            "bytes": len(actor_bundle),
        },
        "offline_verify_account_bundle_s": offline_seconds,
        "account_access_report_s": report_seconds,
        "report_events": len(access.events),
        "database_bytes": db_path.stat().st_size,
    }


def _http_append(workdir: Path, size: int, seed: int) -> dict[str, Any]:
    """POST /audit/events through the in-process test client, on a fresh database."""
    rng = random.Random(seed + 1)  # noqa: S311 - reproducible synthetic data
    key = generate_api_key()
    settings = Settings(
        db_path=str(workdir / f"http-{size}.db"),
        api_keys=f"writer:{hash_api_key(key)}",
        archive_dir=str(workdir / "archives"),
    )
    count = min(HTTP_SAMPLE, size)
    samples: list[int] = []
    with TestClient(create_app(settings)) as client:
        started = time.perf_counter()
        for i in range(count):
            body = _event(rng, i)
            t0 = time.perf_counter_ns()
            response = client.post("/audit/events", json=body, headers={"X-API-Key": key})
            samples.append(time.perf_counter_ns() - t0)
            if response.status_code != 201:
                raise RuntimeError(f"HTTP append failed with {response.status_code}")
        total = time.perf_counter() - started
    return {"requests": count, "events_per_s": count / total, **_percentiles(samples)}


def environment() -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        ).stdout.strip()
    except OSError:
        commit = "unknown"
    return {
        "date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        "logical_cpus": os.cpu_count(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "git_commit": commit or "unknown",
        "working_tree": "uncommitted changes present" if _dirty() else "clean",
    }


def _dirty() -> bool:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        ).stdout
    except OSError:
        return False
    return bool(out.strip())


def markdown(env: dict[str, Any], results: list[dict[str, Any]]) -> str:
    lines = ["Environment: " + ", ".join(f"{k}={v}" for k, v in env.items()), ""]
    head = "| Metric | " + " | ".join(f"N = {r['records']:,}" for r in results) + " |"
    lines += [head, "|---|" + "---|" * len(results)]

    def row(label: str, fn: Callable[[dict[str, Any]], str]) -> None:
        lines.append(f"| {label} | " + " | ".join(fn(r) for r in results) + " |")

    row(
        "Service append throughput (events/s)",
        lambda r: f"{r['service_append']['events_per_s']:.0f}",
    )
    row(
        "Service append latency p50 / p95 / p99 (ms)",
        lambda r: "{p50_ms:.2f} / {p95_ms:.2f} / {p99_ms:.2f}".format(**r["service_append"]),
    )
    row(
        "HTTP append, in-process (events/s; requests)",
        lambda r: "{events_per_s:.0f}; {requests}".format(**r["http_append_in_process"]),
    )
    row(
        "HTTP append, in-process p50 / p95 / p99 (ms)",
        lambda r: "{p50_ms:.2f} / {p95_ms:.2f} / {p99_ms:.2f}".format(
            **r["http_append_in_process"]
        ),
    )
    row("Full-chain verification (s, median of 3)", lambda r: f"{r['verify_full_chain_s']:.3f}")
    row(
        "Export one account (s; records; bytes)",
        lambda r: "{s:.3f}; {records}; {bytes:,}".format(**r["export_account"]),
    )
    row(
        "Export one actor (s; records; bytes)",
        lambda r: "{s:.3f}; {records}; {bytes:,}".format(**r["export_actor"]),
    )
    row(
        "Offline bundle verification, account (s, incl. process start)",
        lambda r: f"{r['offline_verify_account_bundle_s']:.3f}",
    )
    row(
        "Account-access report incl. verification (s; events)",
        lambda r: f"{r['account_access_report_s']:.3f}; {r['report_events']}",
    )
    row("Database file size (bytes)", lambda r: f"{r['database_bytes']:,}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--sizes", default="1000,10000", help="comma-separated record counts")
    parser.add_argument("--seed", type=int, default=20261028)
    parser.add_argument("--json", type=Path, help="also write raw results as JSON here")
    args = parser.parse_args(argv)
    sizes = [int(part) for part in args.sizes.split(",") if part.strip()]
    if not sizes or min(sizes) < 1:
        parser.error("--sizes needs positive integers")
    env = environment()
    with tempfile.TemporaryDirectory(prefix="aip-bench-") as tmp:
        results = [run_size(size, args.seed, Path(tmp)) for size in sizes]
    sys.stdout.write(markdown(env, results) + "\n")
    if args.json:
        args.json.write_text(
            json.dumps({"environment": env, "results": results}, indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
