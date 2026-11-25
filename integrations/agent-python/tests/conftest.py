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
        line = p.stdout.readline()
        return f"http://127.0.0.1:{line.strip().split('=')[1]}"

    yield start
    for p in procs:
        p.kill()
        p.wait()
