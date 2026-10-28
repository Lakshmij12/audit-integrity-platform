"""Command-line helpers.

    python -m aip.cli new-api-key --role writer

prints a new random key once (give it to the client) and the ``role:sha256hex`` entry to add to
``AIP_API_KEYS``. The key itself is never stored by the service.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from aip.api.auth import ROLES, generate_api_key, hash_api_key
from aip.crypto.signing import generate_signing_key, key_id_for, public_key_hex


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aip.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    new_key = commands.add_parser("new-api-key", help="generate an API key for a role")
    new_key.add_argument("--role", required=True, choices=sorted(ROLES))
    signing = commands.add_parser("new-signing-key", help="create an Ed25519 signing key file")
    signing.add_argument(
        "--out", required=True, type=Path, help="PEM file to create (not overwritten)"
    )
    args = parser.parse_args(argv)
    if args.command == "new-api-key":
        key = generate_api_key()
        sys.stdout.write(f"api key (shown once): {key}\n")
        sys.stdout.write(f"AIP_API_KEYS entry:  {args.role}:{hash_api_key(key)}\n")
    elif args.command == "new-signing-key":
        try:
            public_key = generate_signing_key(args.out)
        except FileExistsError:
            sys.stderr.write("refusing to overwrite an existing key file\n")
            return 1
        sys.stdout.write(f"private key written: {args.out}\n")
        sys.stdout.write(f"public key (hex):    {public_key_hex(public_key)}\n")
        sys.stdout.write(f"key id:              {key_id_for(public_key)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
