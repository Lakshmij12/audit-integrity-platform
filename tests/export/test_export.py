"""GET /audit/export and the standalone verifier (tools/verify_bundle.py), run as a subprocess."""

import ast
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aip.api import create_app
from aip.crypto import canonical_json, sha256_hex
from aip.crypto.signing import Signer, generate_signing_key, public_key_hex, sign_document
from tests.api.conftest import auth, make_settings
from tests.ingest.support import FakeClock, event_data, raw_connection

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "tools" / "verify_bundle.py"
SENSITIVE = "acct-" + "900123456"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def key_path(tmp_path: Path) -> Path:
    path = tmp_path / "keys" / "signing.pem"
    generate_signing_key(path)
    return path


@pytest.fixture
def signer(key_path: Path) -> Signer:
    return Signer.from_pem_file(key_path)


@pytest.fixture
def client(tmp_path: Path, key_path: Path, clock: FakeClock) -> Iterator[TestClient]:
    settings = make_settings(
        tmp_path / "audit.db", signing_key_path=str(key_path), retention_window_days=30
    )
    with TestClient(create_app(settings, clock=clock)) as test_client:
        yield test_client


def _write(client: TestClient, actor: str, resource: str, n: int) -> str:
    response = client.post(
        "/audit/events",
        json=event_data(actorId=actor, resourceId=resource, payload={"n": n, "ssn": SENSITIVE}),
        headers=auth("writer"),
    )
    assert response.status_code == 201
    event_id: str = response.json()["eventId"]
    return event_id


def _seed(client: TestClient) -> list[str]:
    return [
        _write(client, "alice", "acct-1", 0),
        _write(client, "bob", "acct-1", 1),
        _write(client, "alice", "acct-2", 2),
        _write(client, "carol", "acct-3", 3),
    ]


def _export(client: TestClient, **params: str) -> bytes:
    response = client.get("/audit/export", params=params, headers=auth("auditor"))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    return response.content


def _run(
    tmp_path: Path, bundle: bytes, key: str, *extra: str, name: str = "bundle.json"
) -> tuple[int, dict[str, Any], str]:
    """Run the verifier in isolated mode (-I), from an unrelated directory, without src/ on the
    path: it must work without the aip package."""
    path = tmp_path / name
    path.write_bytes(bundle)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(  # noqa: S603 - fixed interpreter and script path
        [sys.executable, "-I", str(VERIFIER), str(path), "--trusted-key", key, *extra],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
        timeout=60,
        check=False,
    )
    report = json.loads(result.stdout) if result.stdout.strip() else {}
    return result.returncode, report, result.stdout + result.stderr


def _code(report: dict[str, Any]) -> str | None:
    problem = report.get("problem")
    return None if problem is None else problem["code"]


def _resign(bundle: dict[str, Any], signer: Signer) -> bytes:
    """Recompute digests and re-sign with the trusted key: simulates a faulty signer, to exercise
    the checks behind the signature."""
    manifest = dict(bundle["manifest"])
    for section, digest in (
        ("records", "recordsSha256"),
        ("authorizations", "authorizationsSha256"),
        ("skeleton", "skeletonSha256"),
    ):
        manifest[digest] = sha256_hex(canonical_json(bundle[section]))
    manifest["recordSeqs"] = [record["seq"] for record in bundle["records"]]
    manifest["recordCount"] = len(bundle["records"])
    bundle = {**bundle, "manifest": manifest, "signature": sign_document(signer, manifest)}
    return canonical_json(bundle)


def test_verifier_is_independent_of_the_aip_package() -> None:
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
    modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(name == "aip" or name.startswith("aip.") for name in modules)


def test_valid_actor_export_verifies(client: TestClient, signer: Signer, tmp_path: Path) -> None:
    _seed(client)
    bundle = _export(client, actorId="alice")
    data = json.loads(bundle)
    assert [r["actorId"] for r in data["records"]] == ["alice", "alice"]
    assert data["manifest"]["recordSeqs"] == [1, 3]
    assert data["manifest"]["completeness"] == "signer-asserted"
    assert b"PRIVATE KEY" not in bundle
    code, report, _ = _run(tmp_path, bundle, public_key_hex(signer.public_key))
    assert (code, report["status"], report["recordsChecked"]) == (0, "VERIFIED", 2)
    assert report["filter"] == {"actorId": "alice"}
    assert any("completeness is asserted" in note for note in report["notes"])


def test_bundle_is_deterministic_for_a_fixed_clock(client: TestClient) -> None:
    _seed(client)
    assert _export(client, resourceId="acct-1") == _export(client, resourceId="acct-1")


def test_resource_export_and_empty_export(
    client: TestClient, signer: Signer, tmp_path: Path
) -> None:
    _seed(client)
    key = public_key_hex(signer.public_key)
    code, report, _ = _run(tmp_path, _export(client, resourceId="acct-1"), key)
    assert (code, report["recordsChecked"], report["filter"]) == (0, 2, {"resourceId": "acct-1"})
    empty = _export(client, actorId="nobody")
    assert json.loads(empty)["records"] == []
    code, report, _ = _run(tmp_path, empty, key, name="empty.json")
    assert (code, report["status"], report["recordsChecked"]) == (0, "VERIFIED", 0)


def test_trusted_key_from_a_file(client: TestClient, signer: Signer, tmp_path: Path) -> None:
    _seed(client)
    path = tmp_path / "bundle.json"
    path.write_bytes(_export(client, actorId="bob"))
    key_file = tmp_path / "trusted.hex"
    key_file.write_text(public_key_hex(signer.public_key) + "\n", encoding="utf-8")
    result = subprocess.run(  # noqa: S603 - fixed interpreter and script path
        [sys.executable, "-I", str(VERIFIER), str(path), "--trusted-key-file", str(key_file)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_partially_redacted_export_verifies_without_plaintext(
    client: TestClient, signer: Signer, tmp_path: Path
) -> None:
    ids = _seed(client)
    redaction = client.post(
        f"/audit/events/{ids[0]}/redactions",
        json={"paths": [["ssn"]], "reason": "privacy"},
        headers=auth("admin"),
    )
    assert redaction.status_code == 201
    bundle = _export(client, actorId="alice")
    data = json.loads(bundle)
    assert len(data["authorizations"]) == 1
    assert data["records"][0]["leaves"][1] == {
        "path": ["ssn"],
        "commitment": data["records"][0]["leaves"][1]["commitment"],
        "salt": None,
        "value": None,
    }
    assert bundle.count(SENSITIVE.encode()) == 1  # only the unredacted alice record (seq 3)
    code, report, output = _run(tmp_path, bundle, public_key_hex(signer.public_key))
    assert (code, report["redactedLeavesAuthorized"]) == (0, 1)
    assert SENSITIVE not in output

    # dropping the authorization (and re-signing) leaves an unauthorized redaction
    data["authorizations"] = []
    code, report, _ = _run(tmp_path, _resign(data, signer), public_key_hex(signer.public_key))
    assert (code, _code(report)) == (1, "UNAUTHORIZED_REDACTION")


def test_archived_records_are_indeterminate(
    client: TestClient, signer: Signer, tmp_path: Path, clock: FakeClock
) -> None:
    _seed(client)
    clock.advance(days=31)
    _write(client, "alice", "acct-9", 9)
    run = client.post("/audit/retention/runs", json={"dryRun": False}, headers=auth("admin"))
    assert run.status_code == 201
    bundle = _export(client, actorId="alice")
    data = json.loads(bundle)
    assert [r["leaves"] is None for r in data["records"]] == [True, True, False]
    assert [r["eventType"] for r in data["authorizations"]] == ["SYSTEM_RETENTION_RUN"]
    code, report, _ = _run(tmp_path, bundle, public_key_hex(signer.public_key))
    assert (code, report["status"]) == (3, "INDETERMINATE")
    assert (report["archivedRecords"], report["archivedContentUnavailable"]) == (2, 2)
    assert report["problem"] is None


def test_wrong_trusted_key_and_attacker_resigning_fail(
    client: TestClient, signer: Signer, tmp_path: Path
) -> None:
    _seed(client)
    bundle = _export(client, actorId="alice")
    generate_signing_key(tmp_path / "attacker.pem")
    attacker = Signer.from_pem_file(tmp_path / "attacker.pem")
    code, report, _ = _run(tmp_path, bundle, public_key_hex(attacker.public_key))
    assert (code, _code(report)) == (1, "UNTRUSTED_KEY")

    # An attacker re-signs an altered bundle with their own key and embeds their public key.
    data = json.loads(bundle)
    data["records"][0]["actorId"] = "mallory"
    data["manifest"]["keyId"] = attacker.key_id
    data["signerPublicKey"] = public_key_hex(attacker.public_key)
    forged = _resign(data, attacker)
    code, report, _ = _run(tmp_path, forged, public_key_hex(signer.public_key))
    assert (code, _code(report)) == (1, "UNTRUSTED_KEY")


def _mutate_records(data: dict[str, Any]) -> None:
    data["records"][0]["leaves"][0]["value"] = 99


def _drop_record(data: dict[str, Any]) -> None:
    data["records"].pop()


def _reorder(data: dict[str, Any]) -> None:
    data["records"].reverse()


def _change_filter(data: dict[str, Any]) -> None:
    data["manifest"]["filter"] = {"actorId": "bob"}


def _skeleton_edit(data: dict[str, Any]) -> None:
    data["skeleton"][1]["recordedAt"] = "2020-01-01T00:00:00.000000Z"


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (_mutate_records, "MANIFEST_DIGEST_MISMATCH"),
        (_drop_record, "MANIFEST_DIGEST_MISMATCH"),
        (_reorder, "MANIFEST_DIGEST_MISMATCH"),
        (_skeleton_edit, "MANIFEST_DIGEST_MISMATCH"),
        (_change_filter, "SIGNATURE_INVALID"),
    ],
)
def test_tampered_bundles_fail(
    client: TestClient, signer: Signer, tmp_path: Path, mutate: Any, code: str
) -> None:
    _seed(client)
    data = json.loads(_export(client, actorId="alice"))
    mutate(data)
    status, report, output = _run(
        tmp_path, json.dumps(data).encode(), public_key_hex(signer.public_key)
    )
    assert (status, report["status"], _code(report)) == (1, "FAILED", code)
    assert SENSITIVE not in output


def _substitute(data: dict[str, Any], other: dict[str, Any]) -> None:
    data["records"][0] = other["records"][0]  # a genuine record from another export


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (_mutate_records, "LEAF_COMMITMENT_MISMATCH"),
        (_reorder, "RECORD_SET_MISMATCH"),
        (_skeleton_edit, "RECORD_HASH_MISMATCH"),
        ("substitute", "FILTER_MISMATCH"),
    ],
)
def test_checks_behind_the_signature(
    client: TestClient, signer: Signer, tmp_path: Path, mutate: Any, code: str
) -> None:
    """Even if the signer were faulty (bundle re-signed with the trusted key), record-level
    alterations, reordering, skeleton edits and substituted records are still detected."""
    _seed(client)
    data = json.loads(_export(client, actorId="alice"))
    if mutate == "substitute":
        _substitute(data, json.loads(_export(client, actorId="bob")))
        resigned = _resign(data, signer)
    elif mutate is _reorder:
        _reorder(data)
        manifest_seqs = sorted(r["seq"] for r in data["records"])
        resigned_data = json.loads(_resign(data, signer))
        resigned_data["manifest"]["recordSeqs"] = manifest_seqs
        resigned_data["signature"] = sign_document(signer, resigned_data["manifest"])
        resigned = canonical_json(resigned_data)
    else:
        mutate(data)
        resigned = _resign(data, signer)
    status, report, _ = _run(tmp_path, resigned, public_key_hex(signer.public_key))
    assert (status, _code(report)) == (1, code)


def test_record_substituted_into_another_chain_position(
    client: TestClient, signer: Signer, tmp_path: Path
) -> None:
    _seed(client)
    data = json.loads(_export(client, actorId="alice"))
    data["records"][1]["seq"] = 2  # claims to sit where bob's record is
    status, report, _ = _run(tmp_path, _resign(data, signer), public_key_hex(signer.public_key))
    assert (status, _code(report)) == (1, "RECORD_NOT_IN_CHAIN")


def test_anchor_checks(client: TestClient, signer: Signer, tmp_path: Path) -> None:
    _seed(client)
    checkpoint = client.get("/audit/checkpoints/latest", headers=auth("auditor")).json()
    bundle = _export(client, actorId="alice")
    key = public_key_hex(signer.public_key)
    ok = _run(tmp_path, bundle, key, "--anchor-seq", "4", "--anchor-hash", checkpoint["recordHash"])
    assert (ok[0], ok[1]["anchorMatched"]) == (0, True)
    bad = _run(tmp_path, bundle, key, "--anchor-seq", "4", "--anchor-hash", "0" * 64)
    assert (bad[0], _code(bad[1])) == (1, "ANCHOR_MISMATCH")
    beyond = _run(tmp_path, bundle, key, "--anchor-seq", "9", "--anchor-hash", "0" * 64)
    assert (beyond[0], _code(beyond[1])) == (1, "TRUNCATED")


@pytest.mark.parametrize(
    ("content", "args", "expected"),
    [
        (b"not json", (), 1),
        (b'{"a":1,"a":2}', (), 1),
        (b'{"x":1.5}', (), 1),
        (b"{}", ("--anchor-seq", "1"), 2),
    ],
)
def test_malformed_input_and_usage(
    signer: Signer, tmp_path: Path, content: bytes, args: tuple[str, ...], expected: int
) -> None:
    code, report, _ = _run(tmp_path, content, public_key_hex(signer.public_key), *args)
    assert code == expected
    if expected == 1:
        assert _code(report) == "MALFORMED_BUNDLE"


def test_bad_trusted_key_is_a_usage_error(tmp_path: Path) -> None:
    code, _, output = _run(tmp_path, b"{}", "not-a-key")
    assert code == 2
    assert "not-a-key" not in output


def test_export_authorization_and_filters(client: TestClient, tmp_path: Path) -> None:
    _seed(client)
    assert client.get("/audit/export", params={"actorId": "alice"}).status_code == 401
    writer = client.get("/audit/export", params={"actorId": "alice"}, headers=auth("writer"))
    assert writer.status_code == 403
    admin = client.get("/audit/export", params={"actorId": "alice"}, headers=auth("admin"))
    assert admin.status_code == 200
    for params in ({}, {"actorId": "alice", "resourceId": "acct-1"}, {"actorId": ""}):
        response = client.get("/audit/export", params=params, headers=auth("auditor"))
        assert response.status_code == 422


def test_export_needs_a_key_and_an_intact_chain(client: TestClient, tmp_path: Path) -> None:
    settings = make_settings(tmp_path / "unsigned" / "audit.db")
    with TestClient(create_app(settings, clock=FakeClock())) as api:
        unsigned = api.get("/audit/export", params={"actorId": "x"}, headers=auth("auditor"))
    assert unsigned.status_code == 503
    _seed(client)
    conn = raw_connection(tmp_path / "audit.db")
    try:
        conn.execute("DROP TRIGGER audit_records_no_update")
        conn.execute("UPDATE audit_records SET actor_id = 'alice' WHERE seq = 2")
    finally:
        conn.close()
    refused = client.get("/audit/export", params={"actorId": "alice"}, headers=auth("auditor"))
    assert refused.status_code == 409
