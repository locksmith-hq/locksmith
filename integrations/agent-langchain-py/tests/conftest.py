import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

KIT = Path(__file__).resolve().parents[3] / "tests" / "kit"


@pytest.fixture
def mock_gateway():
    """Start the mock gateway with the given args; returns the base URL. Stopped at teardown."""
    procs = []

    def start(*args: str) -> str:
        p = subprocess.Popen(
            [sys.executable, "-I", str(KIT / "mock_gateway.py"), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        procs.append(p)
        return f"http://127.0.0.1:{p.stdout.readline().strip().split('=')[1]}"

    yield start
    for p in procs:
        p.kill()
        p.wait()


@pytest.fixture
def scan_transcript(tmp_path):
    """Runs tests/kit/oracle.py over a transcript and a canary file; fails on any hit."""

    def scan(entries: list, canary: str) -> None:
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text("".join(json.dumps(e, default=str) + "\n" for e in entries))
        keep = os.environ.get("ADVERSARIAL_ARTIFACT_DIR")
        if keep:  # tests/adversarial/cases/F2.sh scans these with the oracle too
            with open(Path(keep) / f"{Path(__file__).resolve().parents[1].name}.jsonl", "a") as fh:
                fh.write(transcript.read_text())
        canaries = tmp_path / "canaries"
        canaries.write_text(canary + "\n")
        res = subprocess.run(
            [
                sys.executable,
                "-I",
                str(KIT / "oracle.py"),
                "scan",
                "--canary-file",
                str(canaries),
                "--transcript",
                str(transcript),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stdout

    return scan
