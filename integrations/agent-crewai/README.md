# locksmith-agent-crewai

Locksmith MCP tools for CrewAI agents. `locksmith_tools(client)` opens a CrewAI `MCPServerAdapter` on the
gateway's Agent MCP endpoint (Streamable HTTP) limited to `list_my_keys`, `relay_http_request` and
`explain_block`. The agent never holds a secret value: the gateway relays the call.

## Install

```sh
uv add locksmith-agent-crewai   # needs Python 3.11 or newer; crewai and crewai-tools[mcp] pinned exactly
```

## Quick start

```python
from crewai import Agent, Crew, Task
from locksmith_agent import AgentClient
from locksmith_agent_crewai import locksmith_tools

with AgentClient() as client:  # LOCKSMITH_GATEWAY_URL and LOCKSMITH_ENROLLMENT_SECRET
    with locksmith_tools(client) as tools:
        agent = Agent(role="assistant", goal="List my keys", backstory="Careful.", tools=list(tools))
        task = Task(description="List my keys.", expected_output="The key names.", agent=agent)
        Crew(agents=[agent], tasks=[task]).kickoff()
```

## Why the tools are filtered

A gateway may list tools that hand a value back (for example `get_secret_value`). The adapter keeps only
`ALLOWED_TOOLS`, and `assert_no_value_tools` raises `AgentError("unsafe_tool")` if a kept tool has a
value-shaped input property. The token comes from `client.auth` on every request, so it renews and never sits
in a static header. Turn CrewAI telemetry off for agents that handle Locksmith results
(`CREWAI_DISABLE_TELEMETRY=true`, `OTEL_SDK_DISABLED=true`).

## Smoke test

With `just up` and `just api` running: `just agent-smoke crewai`.
