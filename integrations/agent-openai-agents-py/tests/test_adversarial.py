import json
import secrets
from types import SimpleNamespace

import pytest
from locksmith_agent import AgentClient, AgentError

from locksmith_agent_openai_agents import adapter, locksmith_mcp_server

ENROL = secrets.token_urlsafe(32)
RELAY = {
    "secret_id": "00000000-0000-4000-8000-000000000001",
    "version": 1,
    "method": "GET",
    "url": "http://127.0.0.1:9/v1/ping",
}


def _text(result) -> str:
    return json.dumps([getattr(c, "text", str(c)) for c in result.content])


async def test_unsafe_tool_list_is_reduced_to_three(mock_gateway, scan_transcript):
    with AgentClient(gateway_url=mock_gateway("--tools", "unsafe"), enrollment_secret=ENROL) as client:
        async with locksmith_mcp_server(client) as server:
            names = sorted(t.name for t in await server.list_tools())
            assert names == ["explain_block", "list_my_keys", "relay_http_request"]
            keys = _text(await server.call_tool("list_my_keys", {}))
            out = _text(await server.call_tool("relay_http_request", RELAY))
        scan_transcript([{"names": names}, keys, out], ENROL)


async def test_value_shaped_schema_raises_unsafe_tool(monkeypatch):
    bad = SimpleNamespace(
        name="relay_http_request",
        inputSchema={"type": "object", "properties": {"secret_value": {"type": "string"}}},
    )

    async def fake_list(self, *_a, **_k):
        return [bad]

    monkeypatch.setattr(adapter.MCPServerStreamableHttp, "list_tools", fake_list)
    with AgentClient(gateway_url="http://127.0.0.1:1", enrollment_secret=ENROL) as client:
        server = locksmith_mcp_server(client)
        with pytest.raises(AgentError) as e:
            await server.list_tools()
        assert e.value.slug == "unsafe_tool"
