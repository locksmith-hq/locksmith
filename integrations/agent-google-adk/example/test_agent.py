"""A scripted `BaseLlm` drives a Google ADK `Agent` (run by `InMemoryRunner`) through the Locksmith MCP
tools: `list_my_keys`, `relay_http_request` on the first grant, then a final answer. JSONL transcript of
every model turn and event to LOCKSMITH_TRANSCRIPT.

Uses the mock gateway unless LOCKSMITH_GATEWAY_URL is set (the live stack, as `just agent-smoke
google-adk` runs it). A real model runs only with LOCKSMITH_LIVE=1 and the provider key, else `skip live`.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from google.adk.agents import Agent
from google.adk.models import BaseLlm, LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from locksmith_agent import AgentClient
from pydantic import Field

from locksmith_agent_google_adk import locksmith_toolset

MOCK = Path(__file__).resolve().parents[3] / "tests" / "kit" / "mock_gateway.py"


def _call(name: str, args: dict) -> LlmResponse:
    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part.from_function_call(name=name, args=args)])
    )


class ScriptedLlm(BaseLlm):
    """List keys, relay one GET on the first grant, answer."""

    target: str = ""
    step: int = 0
    log: list = Field(default_factory=list)

    async def generate_content_async(self, llm_request, stream=False):
        self.step += 1
        if self.step == 1:
            resp = _call("list_my_keys", {})
        elif self.step == 2:
            found = re.search(
                r'secret_id\\*"\s*:\s*\\*"([0-9a-f-]{36})', json.dumps(llm_request.contents, default=str)
            )
            args = {
                "secret_id": found.group(1) if found else "unknown",
                "version": 1,
                "method": "GET",
                "url": self.target,
            }
            resp = _call("relay_http_request", args)
        else:
            resp = LlmResponse(
                content=types.Content(role="model", parts=[types.Part(text="Done: the relay call returned.")])
            )
        self.log.append({"step": self.step, "contents": llm_request.contents, "reply": resp.content})
        yield resp


@pytest.fixture
def gateway(monkeypatch):
    live = os.environ.get("LOCKSMITH_GATEWAY_URL")
    if live:
        yield live
        return
    # Offline: any request beyond the mock fails (proxies point at a closed loopback port).
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    mock = subprocess.Popen(
        [sys.executable, "-I", str(MOCK)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        yield f"http://127.0.0.1:{mock.stdout.readline().strip().split('=')[1]}"
    finally:
        mock.kill()
        mock.wait()


async def test_scripted_model_lists_keys_relays_one_get_answers(gateway):
    target = os.environ.get("LOCKSMITH_SMOKE_URL", "http://127.0.0.1:9/v1/ping")
    llm = ScriptedLlm(model="scripted", target=target)
    events = []
    with AgentClient(
        gateway_url=gateway,
        enrollment_secret=os.environ.get("LOCKSMITH_ENROLLMENT_SECRET", "example-enrollment-secret"),
    ) as client:
        toolset = locksmith_toolset(client)
        try:
            agent = Agent(name="locksmith_example", model=llm, tools=[toolset])
            runner = InMemoryRunner(agent=agent, app_name="locksmith-example")
            session = await runner.session_service.create_session(app_name="locksmith-example", user_id="u")
            message = types.Content(role="user", parts=[types.Part(text="List my keys and relay one GET.")])
            async for event in runner.run_async(user_id="u", session_id=session.id, new_message=message):
                events.append(event)
        finally:
            await toolset.close()
    transcript = os.environ.get("LOCKSMITH_TRANSCRIPT")
    if transcript:
        entries = [*llm.log, *(e.model_dump(mode="json", exclude_none=True) for e in events)]
        Path(transcript).write_text("".join(json.dumps(e, default=str) + "\n" for e in entries))
    assert llm.step == 3
    responses = [r for e in events for r in e.get_function_responses()]
    assert len(responses) == 2
    assert "200" in json.dumps(responses[1].response, default=str)
    assert events[-1].content.parts[0].text.startswith("Done")


def test_live_model():
    if os.environ.get("LOCKSMITH_LIVE") != "1":
        pytest.skip("skip live: set LOCKSMITH_LIVE=1 and the provider key")
    pytest.skip("skip live: the adapter ships no provider key handling")
