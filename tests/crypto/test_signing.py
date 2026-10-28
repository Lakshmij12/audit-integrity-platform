"""Ed25519 signing keys and signed checkpoints."""

from pathlib import Path
from typing import Any

import pytest

from aip.cli import main as cli_main
from aip.crypto.signing import (
    Signer,
    SigningKeyError,
    generate_signing_key,
    key_id_for,
    public_key_hex,
    sign_checkpoint,
    verify_checkpoint,
)

HEAD = "ab" * 32
SIGNED_AT = "2026-10-28T12:00:00.000000Z"


@pytest.fixture
def signer(tmp_path: Path) -> Signer:
    generate_signing_key(tmp_path / "key.pem")
    return Signer.from_pem_file(tmp_path / "key.pem")


def _checkpoint(signer: Signer) -> dict[str, Any]:
    cp = sign_checkpoint(signer, seq=7, record_hash=HEAD, signed_at=SIGNED_AT)
    return {
        "seq": cp.seq,
        "recordHash": cp.record_hash,
        "signedAt": cp.signed_at,
        "keyId": cp.key_id,
        "signature": cp.signature,
    }


def test_signed_checkpoint_verifies(signer: Signer) -> None:
    checkpoint = _checkpoint(signer)
    assert len(checkpoint["signature"]) == 128
    assert checkpoint["keyId"] == key_id_for(signer.public_key)
    assert verify_checkpoint(checkpoint, public_key_hex(signer.public_key))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("seq", 8),
        ("recordHash", "cd" * 32),
        ("signedAt", "2026-10-28T12:00:00.000001Z"),
        ("signature", "00" * 64),
        ("signature", "zz"),
        ("signature", None),
        ("keyId", "0" * 16),
        ("seq", "7"),
    ],
)
def test_altered_checkpoints_fail(signer: Signer, field: str, value: object) -> None:
    checkpoint = _checkpoint(signer)
    checkpoint[field] = value
    assert not verify_checkpoint(checkpoint, public_key_hex(signer.public_key))


def test_wrong_or_malformed_public_key_fails(signer: Signer, tmp_path: Path) -> None:
    other = generate_signing_key(tmp_path / "other.pem")
    checkpoint = _checkpoint(signer)
    assert not verify_checkpoint(checkpoint, public_key_hex(other))
    assert not verify_checkpoint(checkpoint, "not-hex")
    assert not verify_checkpoint(checkpoint, "00" * 31)
    del checkpoint["signature"]
    assert not verify_checkpoint(checkpoint, public_key_hex(signer.public_key))


def test_key_file_is_never_overwritten(tmp_path: Path) -> None:
    generate_signing_key(tmp_path / "key.pem")
    with pytest.raises(FileExistsError):
        generate_signing_key(tmp_path / "key.pem")


@pytest.mark.parametrize("content", [b"", b"not a pem", b"-----BEGIN PRIVATE KEY-----\nAAAA\n"])
def test_unusable_key_files_are_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.pem"
    path.write_bytes(content)
    with pytest.raises(SigningKeyError):
        Signer.from_pem_file(path)
    with pytest.raises(SigningKeyError):
        Signer.from_pem_file(tmp_path / "missing.pem")


def test_signer_repr_hides_key_material(signer: Signer, tmp_path: Path) -> None:
    pem = (tmp_path / "key.pem").read_text()
    body = "".join(line for line in pem.splitlines() if "-----" not in line)
    assert body not in repr(signer)
    assert repr(signer) == f"Signer(key_id={signer.key_id!r})"


def test_cli_new_signing_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "keys" / "signing.pem"
    assert cli_main(["new-signing-key", "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    signer = Signer.from_pem_file(out)
    assert public_key_hex(signer.public_key) in printed
    assert signer.key_id in printed
    assert "PRIVATE" not in printed
    assert cli_main(["new-signing-key", "--out", str(out)]) == 1  # refuses to overwrite
