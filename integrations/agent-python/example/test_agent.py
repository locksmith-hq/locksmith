"""The client alone: list grants, relay one GET, write a JSONL transcript.

Uses the mock gateway unless LOCKSMITH_GATEWAY_URL is set (then the live stack, as
`just agent-smoke python` runs it).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from locksmith_agent import AgentClient

MOCK = Path(__file__).resolve().parents[3] / "tests" / "kit" / "mock_gateway.py"


def test_lists_grants_and_relays_one_get():
    mock = None
    url = os.environ.get("LOCKSMITH_GATEWAY_URL")
    if not url:
        mock = subprocess.Popen(
            [sys.executable, "-I", str(MOCK)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        url = f"http://127.0.0.1:{mock.stdout.readline().strip().split('=')[1]}"
    transcript = os.environ.get("LOCKSMITH_TRANSCRIPT")
    if transcript:
        Path(transcript).write_text("")

    def log(entry: dict) -> None:
        if transcript:
            with open(transcript, "a") as f:
                f.write(json.dumps(entry) + "\n")

    try:
        with AgentClient(
            gateway_url=url,
            enrollment_secret=os.environ.get("LOCKSMITH_ENROLLMENT_SECRET", "example-enrollment-secret"),
        ) as client:
            grants = client.list_grants()
            log({"step": "list_grants", "grants": grants})
            assert grants
            target = os.environ.get("LOCKSMITH_SMOKE_URL", "http://127.0.0.1:9/v1/ping")
            res = client.relay(secret_id=grants[0]["secret_id"], version=1, method="GET", url=target)
            log({"step": "relay", "url": target, "status": res["status"]})
            assert res["status"] == 200
    finally:
        if mock:
            mock.kill()
            mock.wait()
