import json
import time

from locksmith_agent import AgentClient

from locksmith_agent_crewai import locksmith_tools

SECRET_ID = "00000000-0000-4000-8000-000000000001"
RELAY = {"secret_id": SECRET_ID, "version": 1, "method": "GET", "url": "http://127.0.0.1:9/v1/ping"}


def _by_name(tools) -> dict:
    return {t.name: t for t in tools}


def test_exposes_exactly_the_allowed_tools(mock_gateway):
    with (
        AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client,
        locksmith_tools(client) as tools,
    ):
        assert sorted(t.name for t in tools) == ["explain_block", "list_my_keys", "relay_http_request"]


def test_relay_reaches_the_mock_with_the_token(mock_gateway):
    with (
        AgentClient(gateway_url=mock_gateway(), enrollment_secret="canary-enrol") as client,
        locksmith_tools(client) as tools,
    ):
        named = _by_name(tools)
        assert "secret_id" in json.dumps(named["list_my_keys"].run())
        assert "200" in json.dumps(named["relay_http_request"].run(**RELAY))


def test_uses_a_renewed_token_after_expiry(mock_gateway):
    with (
        AgentClient(gateway_url=mock_gateway("--token-ttl", "2"), enrollment_secret="canary-enrol") as client,
        locksmith_tools(client) as tools,
    ):
        time.sleep(2.5)
        assert "secret_id" in json.dumps(_by_name(tools)["list_my_keys"].run())
