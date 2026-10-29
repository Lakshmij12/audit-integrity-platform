"""The benchmark script (scripts/benchmark.py) still runs end to end on a tiny dataset."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_benchmark_runs_on_a_tiny_dataset(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    out = tmp_path / "results.json"
    result = subprocess.run(  # noqa: S603 - fixed interpreter and script path
        [
            sys.executable,
            str(ROOT / "scripts" / "benchmark.py"),
            "--sizes",
            "30",
            "--json",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "| Service append throughput (events/s) |" in result.stdout
    assert "HTTP append, in-process" in result.stdout
    assert out.exists()
    assert "900-00-" not in result.stdout  # synthetic payload values are never printed
