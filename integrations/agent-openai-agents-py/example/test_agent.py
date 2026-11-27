"""A scripted `Model` drives an OpenAI Agents SDK `Agent` (run by `Runner`) through the Locksmith MCP tools:
`list_my_keys`, `relay_http_request` on the first grant, then a final answer. Tracing is disabled. JSONL
transcript of every run item to LOCKSMITH_TRANSCRIPT.

Uses the mock gateway unless LOCKSMITH_GATEWAY_URL is set (the live stack, as `just agent-smoke
openai-agents-py` runs it). A real model runs only with LOCKSMITH_LIVE=1 and the provider key, else `skip live`.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from agents import Agent, Model, ModelResponse, RunConfig, Runner, Usage
from agents.items import TResponseOutputItem
from locksmith_agent import AgentClient
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from locksmith_agent_openai_agents import locksmith_mcp_server

MOCK = Path(__file__).resolve().parents[3] / "tests" / "kit" / "mock_gateway.py"


def _call(call_id: str, name: str, args: dict) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        type="function_call", call_id=call_id, name=name, arguments=json.dumps(args), id=f"fc_{call_id}"
    )


class ScriptedModel(Model):
    """List keys, relay one GET on the first grant, answer."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.step = 0

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs,
                           tracing, **_kw) -> ModelResponse:  # fmt: skip
        self.step += 1
        output: list[TResponseOutputItem]
        if self.step == 1:
            output = [_call("c1", "list_my_keys", {})]
        elif self.step == 2:
            found = re.search(r'secret_id\\*"\s*:\s*\\*"([0-9a-f-]{36})', json.dumps(input, default=str))
            args = {
                "secret_id": found.group(1) if found else "unknown",
                "version": 1,
                "method": "GET",
                "url": self.target,
            }
            output = [_call("c2", "relay_http_request", args)]
        else:
            output = [
                ResponseOutputMessage(
                    id="m1",
                    type="message",
                    role="assistant",
                    status="completed",
                    content=[
                        ResponseOutputText(
                            type="output_text", text="Done: the relay call returned.", annotations=[]
                        )
                    ],
                )
            ]
        return ModelResponse(output=output, usage=Usage(), response_id=None)

    def stream_response(self, *_a, **_k):
        raise NotImplementedError("the scripted model does not stream")


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
        async with locksmith_mcp_server(client) as server:
            agent = Agent(name="locksmith-example", model=ScriptedModel(target), mcp_servers=[server])
            result = await Runner.run(
                agent, "List my keys and relay one GET.", run_config=RunConfig(tracing_disabled=True)
            )
    for item in result.new_items:
        log({"type": item.type, "item": item.to_input_item()})
    outputs = [i for i in result.new_items if i.type == "tool_call_output_item"]
    assert len(outputs) == 2
    assert "200" in json.dumps(outputs[1].output, default=str)
    assert str(result.final_output).startswith("Done")


def test_live_model():
    if os.environ.get("LOCKSMITH_LIVE") != "1":
        pytest.skip("skip live: set LOCKSMITH_LIVE=1 and the provider key")
    pytest.skip("skip live: the adapter ships no provider key handling")
