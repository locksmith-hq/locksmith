import json
import os
import secrets
from types import SimpleNamespace

import pytest
from locksmith_agent import AgentClient, AgentError

from locksmith_agent_google_adk import adapter, locksmith_toolset

ENROL = os.environ.get("ADVERSARIAL_CANARY") or secrets.token_urlsafe(32)
RELAY = {
    "secret_id": "00000000-0000-4000-8000-000000000001",
    "version": 1,
    "method": "GET",
    "url": "http://127.0.0.1:9/v1/ping",
}


async def _call(tools, name: str, args: dict) -> str:
    named = {t.name: t for t in tools}
    return json.dumps(await named[name].run_async(args=args, tool_context=None), default=str)


async def test_unsafe_tool_list_is_reduced_to_three(mock_gateway, scan_transcript):
    with AgentClient(gateway_url=mock_gateway("--tools", "unsafe"), enrollment_secret=ENROL) as client:
        toolset = locksmith_toolset(client)
        try:
            tools = await toolset.get_tools()
            names = sorted(t.name for t in tools)
            assert names == ["explain_block", "list_my_keys", "relay_http_request"]
            keys = await _call(tools, "list_my_keys", {})
            out = await _call(tools, "relay_http_request", RELAY)
        finally:
            await toolset.close()
        scan_transcript([{"names": names}, keys, out], ENROL)


async def test_value_shaped_schema_raises_unsafe_tool(monkeypatch):
    bad = SimpleNamespace(
        name="relay_http_request",
        raw_mcp_tool=SimpleNamespace(
            inputSchema={"type": "object", "properties": {"secret_value": {"type": "string"}}}
        ),
    )

    async def fake_get_tools(self, *_a, **_k):
        return [bad]

    monkeypatch.setattr(adapter.McpToolset, "get_tools", fake_get_tools)
    with AgentClient(gateway_url="http://127.0.0.1:1", enrollment_secret=ENROL) as client:
        toolset = locksmith_toolset(client)
        with pytest.raises(AgentError) as e:
            await toolset.get_tools()
        assert e.value.slug == "unsafe_tool"
