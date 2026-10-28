"""Archive files written by retention runs (DESIGN.md section 7).

``<archive_dir>/<runId>.json`` holds canonical JSON::

    {"t": "aip.archive", "v": 1, "runId": "run_<32 hex>",
     "records": [{"seq", "eventId", "recordHash", "payloadRoot",
                  "leaves": [{"path": [...], "commitment", "salt": hex | null, "value": ...}]}]}

The file is plaintext: it holds the archived payload values and salts (LIMITATIONS.md). Its SHA-256
is signed in the retention authorization, so any change to the file is detectable; whether the file
still exists is reported separately (verification reports it as unavailable, not as tampering).
"""

import os
import re
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from aip.crypto.canonical import canonical_json, parse_strict_json
from aip.crypto.commitments import Leaf
from aip.crypto.errors import CryptoInputError
from aip.crypto.hashing import sha256_hex
from aip.storage.repository import StoredRecord

ARCHIVE_TAG: Final = "aip.archive"
ARCHIVE_VERSION: Final = 1
_RUN_ID = re.compile(r"run_[0-9a-f]{32}", re.ASCII)


class ArchiveError(ValueError):
    """An archive file is malformed or does not match what the retention run signed."""


def new_run_id() -> str:
    return "run_" + secrets.token_hex(16)


def is_run_id(value: object) -> bool:
    return type(value) is str and _RUN_ID.fullmatch(value) is not None


def archive_file_name(run_id: str) -> str:
    if not is_run_id(run_id):
        raise ArchiveError("invalid runId")
    return f"{run_id}.json"


def build_archive(run_id: str, records: Sequence[tuple[StoredRecord, Sequence[Leaf]]]) -> bytes:
    return canonical_json(
        {
            "t": ARCHIVE_TAG,
            "v": ARCHIVE_VERSION,
            "runId": run_id,
            "records": [
                {
                    "seq": record.seq,
                    "eventId": record.event_id,
                    "recordHash": record.record_hash,
                    "payloadRoot": record.payload_root,
                    "leaves": [
                        {
                            "path": list(leaf.path),
                            "commitment": leaf.commitment,
                            "salt": None if leaf.salt is None else leaf.salt.hex(),
                            "value": leaf.value,
                        }
                        for leaf in leaves
                    ],
                }
                for record, leaves in records
            ],
        }
    )


def write_archive(path: Path, data: bytes) -> str:
    """Write ``data`` durably and return its SHA-256. Never overwrites an existing file.

    Writes ``<name>.tmp`` (exclusive create, owner-only on POSIX), fsyncs it, then renames it into
    place, so a crash leaves either no file or a complete one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(path.name)
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return sha256_hex(data)


def parse_archive(data: bytes, run_id: str) -> dict[int, list[Leaf]]:
    """The leaves of each archived seq. Raises ArchiveError if the file is not a valid archive."""
    try:
        document: Any = parse_strict_json(data.decode("utf-8"))  # shape checked below
        if (
            type(document) is not dict
            or document.get("t") != ARCHIVE_TAG
            or document.get("v") != ARCHIVE_VERSION
            or document.get("runId") != run_id
            or type(document.get("records")) is not list
        ):
            raise ArchiveError("not an archive of this run")
        result: dict[int, list[Leaf]] = {}
        for entry in document["records"]:
            seq = entry["seq"]
            if type(seq) is not int or seq in result or type(entry["leaves"]) is not list:
                raise ArchiveError("malformed archive record")
            leaves = []
            for item in entry["leaves"]:
                salt = item["salt"]
                path = item["path"]
                if type(path) is not list or (salt is not None and type(salt) is not str):
                    raise ArchiveError("malformed archive leaf")
                leaves.append(
                    Leaf(
                        tuple(path),
                        item["commitment"],
                        None if salt is None else bytes.fromhex(salt),
                        item["value"],
                    )
                )
            result[seq] = leaves
    except (UnicodeDecodeError, CryptoInputError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("malformed archive file") from exc
    return result
