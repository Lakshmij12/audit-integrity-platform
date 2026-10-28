"""Reproducible direct-database tampering demonstration (runs entirely in a temporary directory).

Part 1 follows the assignment's validation flow through the HTTP API (in-process test client):
write events, query them, verify the chain, modify a stored record directly in SQLite, verify again.
Part 2 shows the limit of hash links: deleting the newest record is invisible to plain verification
but detected against a signed checkpoint saved earlier (a trusted external anchor).

Run from the repository root:
    $env:PYTHONPATH = "src"; .\\.venv\\Scripts\\python.exe scripts\\tamper_demo.py
Exit code 0 means every step behaved as expected. All data is synthetic.
"""

import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from aip.api import create_app
from aip.api.auth import generate_api_key, hash_api_key
from aip.config import Settings
from aip.crypto.signing import generate_signing_key, verify_checkpoint

failures: list[str] = []


def check(label: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)


def show(label: str, value: Any) -> None:
    print(f"  {label}: {json.dumps(value, sort_keys=True)}")


def tamper(db_path: Path, *statements: str) -> None:
    """What an attacker with file access does: bypass the application, drop the guard triggers."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        for trigger in ("audit_records_no_update", "audit_records_no_delete",
                        "payload_leaves_no_update", "payload_leaves_no_delete"):  # fmt: skip
            conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        for statement in statements:
            conn.execute(statement)
    finally:
        conn.close()


def app_for(directory: Path) -> tuple[TestClient, dict[str, str], dict[str, str], Path]:
    writer, auditor = generate_api_key(), generate_api_key()
    key_path = directory / "signing.pem"
    generate_signing_key(key_path)
    db_path = directory / "audit.db"
    settings = Settings(
        db_path=str(db_path),
        api_keys=f"writer:{hash_api_key(writer)},auditor:{hash_api_key(auditor)}",
        signing_key_path=str(key_path),
    )
    client = TestClient(create_app(settings))
    return client, {"X-API-Key": writer}, {"X-API-Key": auditor}, db_path


def event(n: int) -> dict[str, Any]:
    return {
        "eventType": "RECORD_UPDATED",
        "actorId": "user-0042" if n % 2 else "user-0007",
        "resourceType": "CLIENT_ACCOUNT",
        "resourceId": f"acct-{n:04d}",
        "payload": {"field": "email", "amount": str(100 * n), "approved": n % 2 == 0},
    }


def part_one(directory: Path) -> None:
    print("Part 1: modify a stored record directly in SQLite")
    client, writer, auditor, db_path = app_for(directory)
    with client:
        for n in range(1, 6):
            created = client.post("/audit/events", json=event(n), headers=writer)
            check(
                f"POST event {n} -> 201 (seq {created.json().get('seq')})",
                created.status_code == 201,
            )
        query = client.get("/audit/events", params={"actorId": "user-0042"}, headers=auditor)
        check("GET /audit/events?actorId=user-0042 -> 3 events", len(query.json()["items"]) == 3)
        before = client.get("/audit/verify", headers=auditor).json()
        check("GET /audit/verify before tampering -> intact", before["intact"] is True)

        tamper(db_path, "UPDATE payload_leaves SET value = '\"999999\"' "
                        "WHERE seq = 3 AND path = '[\"amount\"]'")  # fmt: skip
        after = client.get("/audit/verify", headers=auditor).json()
        problem = after["firstInconsistency"] or {}
        show("verify after tampering", {"status": after["status"], "firstInconsistency": problem})
        check("verify after tampering -> TAMPERED, not intact",
              (after["status"], after["intact"]) == ("TAMPERED", False))  # fmt: skip
        check("violation LEAF_COMMITMENT_MISMATCH at seq 3, path ['amount']",
              (problem.get("violationType"), problem.get("seq"), problem.get("leafPath"))
              == ("LEAF_COMMITMENT_MISMATCH", 3, ["amount"]))  # fmt: skip
        check("the tampered value is not echoed", "999999" not in json.dumps(after))


def part_two(directory: Path) -> None:
    print("Part 2: delete the newest record (truncation)")
    client, writer, auditor, db_path = app_for(directory)
    with client:
        for n in range(1, 4):
            client.post("/audit/events", json=event(n), headers=writer)
        checkpoint = client.get("/audit/checkpoints/latest", headers=auditor).json()
        public_key = checkpoint.pop("publicKey")
        check("signed checkpoint verifies with the public key",
              verify_checkpoint(checkpoint, public_key))  # fmt: skip
        tamper(db_path, "DELETE FROM payload_leaves WHERE seq = 3",
               "DELETE FROM audit_records WHERE seq = 3")  # fmt: skip
        plain = client.get("/audit/verify", headers=auditor).json()
        check("plain verify after truncation -> intact (hash links cannot see it)",
              plain["intact"] is True)  # fmt: skip
        anchored = client.get(
            "/audit/verify",
            params={"anchorSeq": checkpoint["seq"], "anchorHash": checkpoint["recordHash"]},
            headers=auditor,
        ).json()
        show("verify against the saved checkpoint", anchored["firstInconsistency"])
        violation = (anchored["firstInconsistency"] or {}).get("violationType")
        check("anchored verify -> TRUNCATED", violation == "TRUNCATED")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        part_one(Path(tmp) / "one")
        part_two(Path(tmp) / "two")
    print()
    print("RESULT: all steps behaved as expected" if not failures
          else f"RESULT: {len(failures)} step(s) failed")  # fmt: skip
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
