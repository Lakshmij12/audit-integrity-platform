"""Concurrent appends from threads and from separate processes produce one linear chain."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aip.ingest import IngestService
from aip.storage import Database, DatabaseConfig, open_database
from tests.ingest.support import append_worker, make_event, verify_store

THREADS = 8
PER_THREAD = 25
PROCESSES = 2
PER_PROCESS = 25


def test_threads_append_one_linear_chain(db_path: Path) -> None:
    database = open_database(DatabaseConfig(db_path, busy_timeout_ms=30_000))
    try:
        service = IngestService(database)

        def work(worker: int) -> list[int]:
            return [
                service.append(make_event(actorId=f"t{worker}-{i}", payload={"w": worker})).seq
                for i in range(PER_THREAD)
            ]

        with ThreadPoolExecutor(max_workers=THREADS) as pool:
            seqs = [seq for batch in pool.map(work, range(THREADS)) for seq in batch]

        assert sorted(seqs) == list(range(1, THREADS * PER_THREAD + 1))
        assert verify_store(database) == THREADS * PER_THREAD
        _assert_recorded_at_nondecreasing(database)
    finally:
        database.close()


def test_processes_append_one_linear_chain(db_path: Path) -> None:
    open_database(DatabaseConfig(db_path)).close()  # create the schema before workers start
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(target=append_worker, args=(str(db_path), PER_PROCESS, f"p{n}"))
        for n in range(PROCESSES)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=120)
    assert [worker.exitcode for worker in workers] == [0] * PROCESSES

    database = open_database(DatabaseConfig(db_path))
    try:
        assert verify_store(database) == PROCESSES * PER_PROCESS
        _assert_recorded_at_nondecreasing(database)
    finally:
        database.close()


def _assert_recorded_at_nondecreasing(database: Database) -> None:
    from sqlalchemy import text

    with database.read_transaction() as conn:
        values = conn.execute(text("SELECT recorded_at FROM audit_records ORDER BY seq")).scalars()
        recorded = list(values)
    assert recorded == sorted(recorded)
