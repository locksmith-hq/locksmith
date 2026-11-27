import json
import os
import secrets

import pytest
from locksmith_agent import AgentClient, AgentError

from locksmith_agent_crewai import adapter, locksmith_tools

ENROL = os.environ.get("ADVERSARIAL_CANARY") or secrets.token_urlsafe(32)
RELAY = {
    "secret_id": "00000000-0000-4000-8000-000000000001",
    "version": 1,
    "method": "GET",
    "url": "http://127.0.0.1:9/v1/ping",
}


def test_unsafe_tool_list_is_reduced_to_three(mock_gateway, scan_transcript):
    with AgentClient(gateway_url=mock_gateway("--tools", "unsafe"), enrollment_secret=ENROL) as client:
        with locksmith_tools(client) as tools:
            names = sorted(t.name for t in tools)
            assert names == ["explain_block", "list_my_keys", "relay_http_request"]
            named = {t.name: t for t in tools}
            keys = json.dumps(named["list_my_keys"].run())
            out = json.dumps(named["relay_http_request"].run(**RELAY))
        scan_transcript([{"names": names}, keys, out], ENROL)


def test_value_shaped_schema_raises_unsafe_tool(mock_gateway, monkeypatch):
    def bad(_tools):
        raise AgentError("unsafe_tool", 0)

    monkeypatch.setattr(adapter, "assert_no_value_tools", bad)
    with AgentClient(gateway_url=mock_gateway(), enrollment_secret=ENROL) as client:
        with pytest.raises(AgentError) as e:
            locksmith_tools(client)
        assert e.value.slug == "unsafe_tool"
