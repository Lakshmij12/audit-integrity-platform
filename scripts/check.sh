#!/usr/bin/env sh
# Runs the quality gates (Ruff, mypy, pytest with coverage) and the tamper demo in a Python 3.14
# container (scripts/check.ps1 on Windows). Only Docker is required; the checkout is mounted read-only.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker is not installed." >&2; exit 1; }
# The pip cache volume makes later runs faster; it holds only downloaded packages.
exec docker run --rm -v "$root:/src:ro" -v aip-pip-cache:/root/.cache/pip python:3.14-slim sh /src/scripts/checks.sh
