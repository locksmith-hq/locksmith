import asyncio
import json

from locksmith_agent import AgentClient

from locksmith_agent_openai_agents import locksmith_mcp_server

SECRET_ID = "00000000-0000-4000-8000-000000000001"
RELAY = {"secret_id": SECRET_ID, "version": 1, "method": "GET", "url": "http://127.0.0.1:9/v1/ping"}


def _text(result) -> str:
    return json.dumps([getattr(c, "text", str(c)) for c in result.content])


async def test_exposes_exactly_the_allowed_tools(mock_gateway):
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client:
        async with locksmith_mcp_server(client) as server:
            tools = await server.list_tools()
            assert sorted(t.name for t in tools) == ["explain_block", "list_my_keys", "relay_http_request"]


async def test_relay_reaches_the_mock_with_the_token(mock_gateway):
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client:
        async with locksmith_mcp_server(client) as server:
            assert "secret_id" in _text(await server.call_tool("list_my_keys", {}))
            assert "200" in _text(await server.call_tool("relay_http_request", RELAY))


async def test_uses_a_renewed_token_after_expiry(mock_gateway):
    with AgentClient(
        gateway_url=mock_gateway("--token-ttl", "2"), enrollment_secret="canary-enrol"
    ) as client:
        async with locksmith_mcp_server(client) as server:
            await asyncio.sleep(2.5)
            assert "secret_id" in _text(await server.call_tool("list_my_keys", {}))
