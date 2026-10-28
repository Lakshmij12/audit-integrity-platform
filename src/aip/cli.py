"""Command-line helpers.

    python -m aip.cli new-api-key --role writer

prints a new random key once (give it to the client) and the ``role:sha256hex`` entry to add to
``AIP_API_KEYS``. The key itself is never stored by the service.
"""

import argparse
import sys
from collections.abc import Sequence

from aip.api.auth import ROLES, generate_api_key, hash_api_key


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aip.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    new_key = commands.add_parser("new-api-key", help="generate an API key for a role")
    new_key.add_argument("--role", required=True, choices=sorted(ROLES))
    args = parser.parse_args(argv)
    if args.command == "new-api-key":
        key = generate_api_key()
        sys.stdout.write(f"api key (shown once): {key}\n")
        sys.stdout.write(f"AIP_API_KEYS entry:  {args.role}:{hash_api_key(key)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
