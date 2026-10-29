#!/usr/bin/env sh
# Quality gates and the tamper demo, run inside a python:3.14-slim container so that only Docker
# is needed. Called by scripts/check.ps1 and scripts/check.sh with the repository mounted
# read-only at /src; it works on a copy so the host checkout is never written to.
set -eu

mkdir /work
tar -C /src --exclude=./.venv --exclude=./.git --exclude=./keys --exclude=./data \
  --exclude=./archives --exclude=./exports -cf - . | tar -C /work -xf -
cd /work

echo "==> Installing requirements-dev.lock (hash-checked)"
python -m pip install -q --root-user-action=ignore --disable-pip-version-check \
  --require-hashes -r requirements-dev.lock

echo "==> ruff check";  python -m ruff check .
echo "==> ruff format"; python -m ruff format --check .
echo "==> mypy";        python -m mypy
echo "==> pytest";      python -m pytest -W error --cov=aip --cov-branch -q
echo "==> tamper demo"; PYTHONPATH=src python scripts/tamper_demo.py

echo
echo "All checks passed."
