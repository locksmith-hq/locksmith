import copy
import json
import logging
import pickle
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from locksmith_agent import ALLOWED_TOOLS, AgentClient, AgentError, assert_no_value_tools, pick_allowed_tools
from locksmith_agent.tools import _FORBIDDEN

KIT = Path(__file__).resolve().parents[3] / "tests" / "kit"
ENROLL = "canary-enroll-secret"
ERRORS = json.loads((KIT / "agent-contract" / "errors.json").read_text())


def test_forbidden_words_equal_the_contract_file():
    contract = json.loads((KIT / "agent-contract" / "forbidden-words.json").read_text())
    assert sorted(_FORBIDDEN) == sorted(contract)


def test_grants_and_relay_round_trip(mock_gateway):
    url = mock_gateway()
    with AgentClient(gateway_url=url, enrollment_secret=ENROLL) as c:
        grants = c.list_grants()
        assert grants[0]["secret_name"] == "stripe-test"
        r = c.relay(
            secret_id=grants[0]["secret_id"], version=1, method="GET", url="http://127.0.0.1:9/v1/ping"
        )
        assert r["status"] == 200
        assert c.mcp_url == url + "/mcp"


def test_enrolment_secret_from_the_environment(mock_gateway, monkeypatch):
    url = mock_gateway()
    monkeypatch.setenv("LOCKSMITH_GATEWAY_URL", url)
    monkeypatch.setenv("LOCKSMITH_ENROLLMENT_SECRET", ENROLL)
    with AgentClient() as c:
        assert len(c.list_grants()) == 1


def test_token_function(mock_gateway):
    url = mock_gateway()
    minted = AgentClient(gateway_url=url, enrollment_secret=ENROLL).bearer_token()
    with AgentClient(gateway_url=url, token=lambda: minted) as c:
        assert len(c.list_grants()) == 1


def test_renews_inside_the_margin_and_reuses_outside_it(mock_gateway):
    # A 2 s TTL is inside the 60 s margin, so every call mints a fresh token.
    url = mock_gateway("--token-ttl", "2")
    with AgentClient(gateway_url=url, enrollment_secret=ENROLL) as c:
        a = c.bearer_token()
        time.sleep(1.1)
        b = c.bearer_token()
        assert a != b
        assert len(c.list_grants()) == 1
    # With a long TTL the cached token is reused.
    url = mock_gateway("--token-ttl", "900")
    with AgentClient(gateway_url=url, enrollment_secret=ENROLL) as c:
        first = c.bearer_token()
        assert c.bearer_token() == first
        forced = c.bearer_token(renew=True)  # force mints again; the new one is then cached
        assert forced != first and c.bearer_token() == forced


def test_renews_once_after_a_401(mock_gateway):
    url = mock_gateway()
    seen = []

    class Spy(httpx.HTTPTransport):
        revoked = False

        def handle_request(self, request):
            res = super().handle_request(request)
            seen.append((request.url.path, res.status_code))
            return res

    c = AgentClient(gateway_url=url, enrollment_secret=ENROLL, transport=Spy())
    first = c.bearer_token()
    # Another client mints a newer token, which invalidates the first one at the mock.
    AgentClient(gateway_url=url, enrollment_secret=ENROLL).bearer_token()
    assert len(c.list_grants()) == 1
    assert c.bearer_token() != first
    assert seen.count(("/v1/grants", 401)) == 1
    assert seen[-1] == ("/v1/grants", 200)


@pytest.mark.parametrize("err", ERRORS, ids=[e["slug"] for e in ERRORS])
def test_every_gateway_slug(mock_gateway, err):
    url = mock_gateway("--fail", err["slug"])
    c = AgentClient(gateway_url=url, token="canary-agent-token")
    with pytest.raises(AgentError) as ei:
        c.list_grants()
    assert (ei.value.slug, ei.value.status, str(ei.value)) == (err["slug"], err["status"], err["slug"])
    assert "canary-" not in repr(ei.value) + str(ei.value)


def test_gives_up_after_a_second_401(mock_gateway):
    url = mock_gateway("--fail", "unauthenticated")
    with pytest.raises(AgentError) as ei:
        AgentClient(gateway_url=url, enrollment_secret=ENROLL).list_grants()
    assert (ei.value.slug, ei.value.status) == ("unauthenticated", 401)


def test_bad_config_and_transport():
    for kw in ({"gateway_url": "not a url", "token": "x"}, {"gateway_url": "http://127.0.0.1:1"}):
        with pytest.raises(AgentError) as ei:
            AgentClient(**kw)
        assert ei.value.slug == "bad_config"
    with pytest.raises(AgentError) as ei:
        AgentClient(gateway_url="http://127.0.0.1:1", token="x").list_grants()
    assert (ei.value.slug, ei.value.status) == ("transport", 0)


def test_foreign_origin_is_refused_and_gets_no_token(mock_gateway):
    url = mock_gateway()
    c = AgentClient(gateway_url=url, token="canary-agent-token")
    reached = []
    with httpx.Client(
        auth=c.auth, transport=httpx.MockTransport(lambda r: reached.append(r) or httpx.Response(200))
    ) as h:
        with pytest.raises(AgentError) as ei:
            h.get("http://example.invalid/x")
        assert ei.value.slug == "foreign_origin"
        assert reached == []
        assert h.get(url + "/v1/grants").status_code == 200  # gateway origin carries the token
        assert reached[0].headers["authorization"] == "Bearer canary-agent-token"


def test_unsafe_tool_list_is_reduced_to_three(mock_gateway):
    url = mock_gateway("--tools", "unsafe")
    with AgentClient(gateway_url=url, enrollment_secret=ENROLL) as c:
        res = httpx.post(  # tools/list as an adapter would
            c.mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, auth=c.auth
        )
    tools = res.json()["result"]["tools"]
    kept, dropped = pick_allowed_tools(tools)
    assert sorted(t["name"] for t in kept) == sorted(ALLOWED_TOOLS)
    assert "issue_short_lived_credential" in dropped and "get_secret_value" in dropped
    assert_no_value_tools(kept)
    unsafe = next(t for t in tools if t["name"] == "get_secret_value")
    with pytest.raises(AgentError) as ei:
        assert_no_value_tools([unsafe])
    assert ei.value.slug == "unsafe_tool"


def test_value_shaped_schemas_are_caught_everywhere():
    for schema in (
        {"properties": {"secretValue": {"type": "string"}}},
        {"properties": {"a": {"items": {"properties": {"api_key": {}}}}}},
        {"anyOf": [{"properties": {"token": {}}}]},
        {"$defs": {"x": {"properties": {"value": {}}}}},
    ):
        with pytest.raises(AgentError):
            assert_no_value_tools([{"name": "t", "inputSchema": schema}])
    assert_no_value_tools([{"name": "t", "outputSchema": {"properties": {"valid": {}}}}])


def test_secrets_never_print_pickle_or_copy(mock_gateway, caplog):
    url = mock_gateway()
    enroll = secrets.token_urlsafe(32)
    caplog.set_level(logging.DEBUG)
    c = AgentClient(gateway_url=url, enrollment_secret=enroll)
    tok = c.bearer_token()
    seen = " ".join(
        [repr(c), str(c), repr(vars(c)), repr(c.auth), caplog.text, repr(c._enrollment), repr(c._current)]
    )
    assert enroll not in seen and tok not in seen
    for holder in (c._enrollment, c._current):
        with pytest.raises(TypeError):
            pickle.dumps(holder)
        with pytest.raises(TypeError):
            copy.copy(holder)
        with pytest.raises(TypeError):
            copy.deepcopy(holder)
        assert (
            str(holder) == "Secret(<redacted>)"
            and f"{holder}" == "<redacted>"
            and f"{holder:>20}" == "<redacted>"
        )


def test_transcript_holds_no_canary(mock_gateway, tmp_path):
    url = mock_gateway()
    enroll = secrets.token_urlsafe(32)
    tok = secrets.token_urlsafe(32)
    c = AgentClient(gateway_url=url, enrollment_secret=enroll)
    grants = c.list_grants()
    r = c.relay(secret_id=grants[0]["secret_id"], version=1, method="GET", url="http://127.0.0.1:9/x")
    bad = AgentClient(gateway_url=url, token=tok)
    with httpx.Client(auth=bad.auth) as h, pytest.raises(AgentError) as ei:
        h.get("http://example.invalid/x")
    lines = [
        json.dumps({"result": grants}),
        json.dumps({"result": r}),
        json.dumps({"error": repr(ei.value), "s": str(ei.value)}),
    ]
    (tmp_path / "t.jsonl").write_text("\n".join(lines) + "\n")
    (tmp_path / "canaries").write_text(f"{enroll}\n{tok}\n")
    scan = subprocess.run(
        [
            sys.executable,
            "-I",
            str(KIT / "oracle.py"),
            "scan",
            "--canary-file",
            str(tmp_path / "canaries"),
            "--transcript",
            str(tmp_path / "t.jsonl"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert scan.returncode == 0, scan.stdout + scan.stderr
