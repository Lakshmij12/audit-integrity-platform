"""Runtime and tooling smoke checks.

These verify that the pinned interpreter and third-party dependencies import and behave as
expected on this machine. They do not test the audit log service, which is not implemented yet.
"""

import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import create_engine, text

import aip


def test_interpreter_is_python_314() -> None:
    assert sys.version_info[:2] == (3, 14)


def test_package_imports() -> None:
    assert aip.__version__ == "0.1.0"


def test_ed25519_sign_and_verify() -> None:
    key = Ed25519PrivateKey.generate()
    signature = key.sign(b"checkpoint")
    key.public_key().verify(signature, b"checkpoint")
    with pytest.raises(InvalidSignature):
        key.public_key().verify(signature, b"tampered")


def test_sqlite_wal_and_begin_immediate(tmp_path: Path) -> None:
    with closing(sqlite3.connect(tmp_path / "smoke.db", isolation_level=None)) as conn:
        assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.execute("COMMIT")


def test_sqlalchemy_sqlite_engine(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sa.db'}")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar_one() == 1
    engine.dispose()


class _StrictProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_type: str


def test_pydantic_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _StrictProbe.model_validate({"event_type": "X", "unexpected": 1})


def test_fastapi_test_client() -> None:
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    with TestClient(app) as client:
        response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
