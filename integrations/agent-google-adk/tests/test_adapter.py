import asyncio
import json

from locksmith_agent import AgentClient

from locksmith_agent_google_adk import locksmith_toolset

SECRET_ID = "00000000-0000-4000-8000-000000000001"
RELAY = {"secret_id": SECRET_ID, "version": 1, "method": "GET", "url": "http://127.0.0.1:9/v1/ping"}


async def _call(tools, name: str, args: dict) -> str:
    named = {t.name: t for t in tools}
    return json.dumps(await named[name].run_async(args=args, tool_context=None), default=str)


async def test_exposes_exactly_the_allowed_tools(mock_gateway):
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client:
        toolset = locksmith_toolset(client)
        try:
            tools = await toolset.get_tools()
            assert sorted(t.name for t in tools) == ["explain_block", "list_my_keys", "relay_http_request"]
        finally:
            await toolset.close()


async def test_relay_reaches_the_mock_with_the_token(mock_gateway):
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client:
        toolset = locksmith_toolset(client)
        try:
            tools = await toolset.get_tools()
            assert "secret_id" in await _call(tools, "list_my_keys", {})
            assert "200" in await _call(tools, "relay_http_request", RELAY)
        finally:
            await toolset.close()


async def test_uses_a_renewed_token_after_expiry(mock_gateway):
    with AgentClient(
        gateway_url=mock_gateway("--token-ttl", "2"), enrollment_secret="canary-enrol"
    ) as client:
        toolset = locksmith_toolset(client)
        try:
            tools = await toolset.get_tools()
            await asyncio.sleep(2.5)
            assert "secret_id" in await _call(tools, "list_my_keys", {})
        finally:
            await toolset.close()
