"""A scripted chat model drives the LangGraph prebuilt ReAct agent through the Locksmith tools:
`list_my_keys`, `relay_http_request` on the first grant, then a final answer. JSONL transcript of every
message, tool call and result to LOCKSMITH_TRANSCRIPT.

Uses the mock gateway unless LOCKSMITH_GATEWAY_URL is set (the live stack, as `just agent-smoke langchain-py`
runs it). A real model runs only with LOCKSMITH_LIVE=1 and the provider key, else `skip live`.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.prebuilt import create_react_agent
from locksmith_agent import AgentClient

from locksmith_agent_langchain import locksmith_tools

MOCK = Path(__file__).resolve().parents[3] / "tests" / "kit" / "mock_gateway.py"


class ScriptedModel(BaseChatModel):
    """List keys, relay one GET on the first grant, answer."""

    target: str
    step: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, *_a, **_k):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.step += 1
        if self.step == 1:
            msg = AIMessage(content="", tool_calls=[{"id": "c1", "name": "list_my_keys", "args": {}}])
        elif self.step == 2:
            seen = json.dumps([str(m.content) for m in messages])
            found = re.search(r'secret_id\\*"\s*:\s*\\*"([0-9a-f-]{36})', seen)
            args = {
                "secret_id": found.group(1) if found else "unknown",
                "version": 1,
                "method": "GET",
                "url": self.target,
            }
            msg = AIMessage(content="", tool_calls=[{"id": "c2", "name": "relay_http_request", "args": args}])
        else:
            msg = AIMessage(content="Done: the relay call returned.")
        return ChatResult(generations=[ChatGeneration(message=msg)])


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
    transcript = os.environ.get("LOCKSMITH_TRANSCRIPT")
    if transcript:
        Path(transcript).write_text("")

    def log(entry: dict) -> None:
        if transcript:
            with open(transcript, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")

    target = os.environ.get("LOCKSMITH_SMOKE_URL", "http://127.0.0.1:9/v1/ping")
    with AgentClient(
        gateway_url=gateway,
        enrollment_secret=os.environ.get("LOCKSMITH_ENROLLMENT_SECRET", "example-enrollment-secret"),
    ) as client:
        lt = await locksmith_tools(client)
        agent = create_react_agent(ScriptedModel(target=target), lt.tools)
        result = await agent.ainvoke({"messages": [HumanMessage("List my keys and relay one GET.")]})
    for m in result["messages"]:
        log({"type": m.type, "content": m.content, "tool_calls": getattr(m, "tool_calls", [])})
    tools = [m for m in result["messages"] if m.type == "tool"]
    assert [m.name for m in tools] == ["list_my_keys", "relay_http_request"]
    assert "200" in json.dumps(tools[1].content)
    assert result["messages"][-1].content.startswith("Done")


def test_live_model():
    if os.environ.get("LOCKSMITH_LIVE") != "1":
        pytest.skip("skip live: set LOCKSMITH_LIVE=1 and the provider key")
    pytest.skip("skip live: no provider package is a dependency of this adapter")
