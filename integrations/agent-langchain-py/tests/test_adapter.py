import asyncio
import json

from locksmith_agent import AgentClient

from locksmith_agent_langchain import locksmith_tools

SECRET_ID = "00000000-0000-4000-8000-000000000001"
RELAY = {"secret_id": SECRET_ID, "version": 1, "method": "GET", "url": "http://127.0.0.1:9/v1/ping"}


async def test_exposes_exactly_the_allowed_tools(mock_gateway):
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client:
        lt = await locksmith_tools(client)
        assert sorted(t.name for t in lt.tools) == ["explain_block", "list_my_keys", "relay_http_request"]
        assert lt.dropped == ["issue_short_lived_credential"]


async def test_relay_reaches_the_mock_with_the_token(mock_gateway):
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client:
        lt = await locksmith_tools(client)
        by = {t.name: t for t in lt.tools}
        assert "secret_id" in json.dumps(await by["list_my_keys"].ainvoke({}))
        out = await by["relay_http_request"].ainvoke(RELAY)
        assert "200" in json.dumps(out)


async def test_uses_a_renewed_token_after_expiry(mock_gateway):
    with AgentClient(
        gateway_url=mock_gateway("--token-ttl", "2"), enrollment_secret="canary-enrol"
    ) as client:
        lt = await locksmith_tools(client)
        await asyncio.sleep(2.5)
        out = await {t.name: t for t in lt.tools}["list_my_keys"].ainvoke({})
        assert "secret_id" in json.dumps(out)
