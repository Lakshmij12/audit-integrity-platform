"""The tampering demonstration script runs end to end and reports every step as expected."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_tamper_demo_script() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT)}
    result = subprocess.run(  # noqa: S603 - fixed interpreter and script path
        [sys.executable, str(ROOT / "scripts" / "tamper_demo.py")],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: all steps behaved as expected" in result.stdout
    assert "[FAIL]" not in result.stdout
    assert "LEAF_COMMITMENT_MISMATCH" in result.stdout
    assert "TRUNCATED" in result.stdout
