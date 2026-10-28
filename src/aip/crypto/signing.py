"""Ed25519 signing of checkpoints (and, in later commits, authorizations and export manifests).

A checkpoint commits to the chain head:

    checkpointMessage = canon({"t": "aip.checkpoint", "v": 1, "seq", "recordHash", "signedAt",
                               "keyId"})
    signature         = Ed25519(privateKey, checkpointMessage)        (64 bytes, lowercase hex)
    keyId             = first 16 hex characters of SHA-256(raw 32-byte public key)

A signature proves the holder of the private key produced the checkpoint. It anchors the chain only
if the verifier keeps the checkpoint (or the public key and checkpoint) somewhere an attacker with
database access cannot change. The private key never leaves the signer and is never logged.
"""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from aip.crypto.canonical import canonical_json
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import require_hex_digest
from aip.crypto.timestamps import require_canonical_timestamp

CHECKPOINT_TAG: Final = "aip.checkpoint"
CHECKPOINT_VERSION: Final = 1


class SigningKeyError(CryptoInputError):
    """A signing key file is missing, unreadable or not an unencrypted Ed25519 PEM key."""


def key_id_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def public_key_hex(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def generate_signing_key(path: Path) -> Ed25519PublicKey:
    """Create a new Ed25519 private key as unencrypted PKCS#8 PEM. Refuses to overwrite a file."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)  # owner-only on POSIX; Windows applies its own ACLs
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    return key.public_key()


class Signer:
    """Holds one Ed25519 private key loaded from a PEM file."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id_for(self.public_key)

    @classmethod
    def from_pem_file(cls, path: Path) -> Signer:
        try:
            key = load_pem_private_key(path.read_bytes(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise SigningKeyError("cannot load the signing key file") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningKeyError("the signing key is not an Ed25519 key")
        return cls(key)

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def __repr__(self) -> str:  # never show key material
        return f"Signer(key_id={self.key_id!r})"


def checkpoint_message(*, seq: int, record_hash: str, signed_at: str, key_id: str) -> bytes:
    if type(seq) is not int or seq < 1:
        raise CryptoInputError("checkpoint seq must be an int >= 1")
    if type(key_id) is not str or len(key_id) != 16:
        raise CryptoInputError("checkpoint keyId must be 16 hex characters")
    return canonical_json(
        {
            "t": CHECKPOINT_TAG,
            "v": CHECKPOINT_VERSION,
            "seq": seq,
            "recordHash": require_hex_digest(record_hash, "recordHash"),
            "signedAt": require_canonical_timestamp(signed_at, "signedAt"),
            "keyId": key_id,
        }
    )


@dataclass(frozen=True, slots=True)
class Checkpoint:
    seq: int
    record_hash: str
    signed_at: str
    key_id: str
    signature: str


def sign_checkpoint(signer: Signer, *, seq: int, record_hash: str, signed_at: str) -> Checkpoint:
    message = checkpoint_message(
        seq=seq, record_hash=record_hash, signed_at=signed_at, key_id=signer.key_id
    )
    return Checkpoint(seq, record_hash, signed_at, signer.key_id, signer.sign(message))


def sign_document(signer: Signer, document: dict[str, Any]) -> str:
    """Sign ``canon(document)``. Documents carry their own ``t`` (type tag), ``v`` and ``keyId``,
    so a signature for one document type can never be replayed as another."""
    if document.get("keyId") != signer.key_id or type(document.get("t")) is not str:
        raise CryptoInputError("a signed document needs a type tag and the signer's keyId")
    return signer.sign(canonical_json(document))


def verify_document(document: object, signature: object, public_key: Ed25519PublicKey) -> bool:
    """True only if ``signature`` is a valid Ed25519 signature of ``canon(document)``."""
    try:
        if type(document) is not dict or type(signature) is not str:
            return False
        public_key.verify(bytes.fromhex(signature), canonical_json(document))
    except InvalidSignature, ValueError, CryptoInputError:
        return False
    return True


def verify_checkpoint(checkpoint: dict[str, Any], public_key_raw_hex: str) -> bool:
    """True only if the checkpoint is well-formed and signed by the given public key."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_raw_hex))
        if checkpoint.get("keyId") != key_id_for(public_key):
            return False
        message = checkpoint_message(
            seq=checkpoint["seq"],
            record_hash=checkpoint["recordHash"],
            signed_at=checkpoint["signedAt"],
            key_id=checkpoint["keyId"],
        )
        signature = checkpoint["signature"]
        if type(signature) is not str:
            return False
        public_key.verify(bytes.fromhex(signature), message)
    except InvalidSignature, ValueError, KeyError, TypeError, CryptoInputError:
        return False
    return True
