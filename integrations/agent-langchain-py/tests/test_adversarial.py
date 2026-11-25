import json
import secrets

import pytest
from langchain_core.tools import StructuredTool
from locksmith_agent import AgentClient, AgentError

from locksmith_agent_langchain import adapter, locksmith_tools

ENROL = secrets.token_urlsafe(32)
RELAY = {
    "secret_id": "00000000-0000-4000-8000-000000000001",
    "version": 1,
    "method": "GET",
    "url": "http://127.0.0.1:9/v1/ping",
}


async def test_unsafe_tool_list_is_reduced_to_three(mock_gateway, scan_transcript):
    with AgentClient(gateway_url=mock_gateway("--tools", "unsafe"), enrollment_secret=ENROL) as client:
        lt = await locksmith_tools(client)
        names = [t.name for t in lt.tools]
        assert "issue_short_lived_credential" not in names
        assert "get_secret_value" not in names
        assert sorted(lt.dropped) == ["get_secret_value", "issue_short_lived_credential"]
        by = {t.name: t for t in lt.tools}
        keys = await by["list_my_keys"].ainvoke({})
        out = await by["relay_http_request"].ainvoke(RELAY)
        assert ENROL not in json.dumps({"names": names, "dropped": lt.dropped})
        scan_transcript([{"names": names, "dropped": lt.dropped}, keys, out], ENROL)


async def test_value_shaped_schema_raises_unsafe_tool(monkeypatch):
    async def noop(**_):
        return ""

    bad = StructuredTool.from_function(
        coroutine=noop,
        name="relay_http_request",
        description="x",
        args_schema={"type": "object", "properties": {"secret_value": {"type": "string"}}},
    )

    class Stub:
        def __init__(self, *_a, **_k):
            pass

        async def get_tools(self):
            return [bad]

    monkeypatch.setattr(adapter, "MultiServerMCPClient", Stub)
    with AgentClient(gateway_url="http://127.0.0.1:1", enrollment_secret=ENROL) as client:
        with pytest.raises(AgentError) as e:
            await locksmith_tools(client)
        assert e.value.slug == "unsafe_tool"
