# locksmith-agent-google-adk

Locksmith MCP toolset for Google ADK agents. `locksmith_toolset(client)` returns an ADK `McpToolset` on the
gateway's Agent MCP endpoint (Streamable HTTP) limited to `list_my_keys`, `relay_http_request` and
`explain_block`. The agent never holds a secret value: the gateway relays the call.

## Install

```sh
uv add locksmith-agent-google-adk   # needs Python 3.11 or newer; google-adk and mcp pinned exactly
```

## Quick start

```python
from google.adk.agents import Agent
from locksmith_agent import AgentClient
from locksmith_agent_google_adk import locksmith_toolset

with AgentClient() as client:  # LOCKSMITH_GATEWAY_URL and LOCKSMITH_ENROLLMENT_SECRET
    toolset = locksmith_toolset(client)
    agent = Agent(name="assistant", model="gemini-2.5-flash", tools=[toolset])
    # run it with a Runner, then: await toolset.close()
```

## Why the tools are filtered

A gateway may list tools that hand a value back (for example `get_secret_value`). The toolset keeps only
`ALLOWED_TOOLS`, and `assert_no_value_tools` raises `AgentError("unsafe_tool")` if a kept tool has a
value-shaped input property. ADK's connection `headers` are static, so the token does not go there: the
connection params carry an `httpx_client_factory` whose client uses `client.auth` on every request, so the
token renews and never sits in a header. `mcp` stays on 1.x because 2.x moves to `httpx2`.

## Smoke test

With `just up` and `just api` running: `just agent-smoke google-adk`.
