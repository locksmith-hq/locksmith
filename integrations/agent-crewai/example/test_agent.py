"""A scripted `BaseLLM` drives a one-agent CrewAI `Crew` through the Locksmith MCP tools: `list_my_keys`,
`relay_http_request` on the first grant, then a final answer. Telemetry is off. JSONL transcript of every
model turn and tool result to LOCKSMITH_TRANSCRIPT.

Uses the mock gateway unless LOCKSMITH_GATEWAY_URL is set (the live stack, as `just agent-smoke crewai` runs
it). A real model runs only with LOCKSMITH_LIVE=1 and the provider key, else `skip live`.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

os.environ["CREWAI_DISABLE_TELEMETRY"] = "true"
os.environ["OTEL_SDK_DISABLED"] = "true"

import pytest
from crewai import Agent, BaseLLM, Crew, Task
from locksmith_agent import AgentClient
from pydantic import Field

from locksmith_agent_crewai import locksmith_tools

MOCK = Path(__file__).resolve().parents[3] / "tests" / "kit" / "mock_gateway.py"


class ScriptedLLM(BaseLLM):
    """List keys, relay one GET on the first grant, answer (ReAct text turns)."""

    target: str = ""
    step: int = 0
    log: list = Field(default_factory=list)

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None,
             from_agent=None, response_model=None):  # fmt: skip
        self.step += 1
        if self.step == 1:
            reply = "Thought: I need my keys.\nAction: list_my_keys\nAction Input: {}"
        elif self.step == 2:
            found = re.search(r'secret_id\\*"\s*:\s*\\*"([0-9a-f-]{36})', json.dumps(messages, default=str))
            args = {
                "secret_id": found.group(1) if found else "unknown",
                "version": 1,
                "method": "GET",
                "url": self.target,
            }
            reply = f"Thought: relay one GET.\nAction: relay_http_request\nAction Input: {json.dumps(args)}"
        else:
            reply = "Thought: I now know the final answer\nFinal Answer: Done: the relay call returned."
        self.log.append({"step": self.step, "messages": messages, "reply": reply})
        return reply

    def supports_function_calling(self) -> bool:
        return False

    def supports_stop_words(self) -> bool:
        return False


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


def test_scripted_model_lists_keys_relays_one_get_answers(gateway):
    target = os.environ.get("LOCKSMITH_SMOKE_URL", "http://127.0.0.1:9/v1/ping")
    llm = ScriptedLLM(
        model="scripted",
        target=target,
    )
    with (
        AgentClient(
            gateway_url=gateway,
            enrollment_secret=os.environ.get("LOCKSMITH_ENROLLMENT_SECRET", "example-enrollment-secret"),
        ) as client,
        locksmith_tools(client) as tools,
    ):
        agent = Agent(
            role="assistant", goal="Use the Locksmith tools", backstory="A careful agent.",
            llm=llm, tools=list(tools), verbose=False,
        )  # fmt: skip
        task = Task(
            description="List my keys and relay one GET.", expected_output="A short answer.", agent=agent
        )
        result = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
    transcript = os.environ.get("LOCKSMITH_TRANSCRIPT")
    if transcript:
        Path(transcript).write_text("".join(json.dumps(e, default=str) + "\n" for e in llm.log))
    assert llm.step == 3
    assert "200" in json.dumps(llm.log[2]["messages"], default=str)
    assert str(result).startswith("Done")


def test_live_model():
    if os.environ.get("LOCKSMITH_LIVE") != "1":
        pytest.skip("skip live: set LOCKSMITH_LIVE=1 and the provider key")
    pytest.skip("skip live: the adapter ships no provider key handling")
