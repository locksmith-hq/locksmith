# locksmith-agent-openai-agents

Locksmith MCP server for OpenAI Agents SDK agents. `locksmith_mcp_server(client)` returns an
`MCPServerStreamableHttp` on the gateway's Agent MCP endpoint with a static tool filter, so the agent sees only
`list_my_keys`, `relay_http_request` and `explain_block`. The agent never holds a secret value: the gateway
relays the call.

## Install

```sh
uv add locksmith-agent-openai-agents   # needs Python 3.11 or newer; pins mcp 1.x (httpx auth)
```

## Quick start

```python
from agents import Agent, Runner
from locksmith_agent import AgentClient
from locksmith_agent_openai_agents import locksmith_mcp_server

with AgentClient() as client:  # LOCKSMITH_GATEWAY_URL and LOCKSMITH_ENROLLMENT_SECRET
    async with locksmith_mcp_server(client) as server:
        agent = Agent(name="assistant", mcp_servers=[server])
        await Runner.run(agent, "List my keys.")
```

## Why the tools are filtered

A gateway may list tools that hand a value back (for example `get_secret_value`). The static filter drops
everything outside `ALLOWED_TOOLS`, and `assert_no_value_tools` raises `AgentError("unsafe_tool")` if a kept
tool has a value-shaped input or output property. Tracing exports prompts and tool output to OpenAI by
default; turn it off for agents that handle Locksmith results (`RunConfig(tracing_disabled=True)`).

## Smoke test

With `just up` and `just api` running: `just agent-smoke openai-agents-py`.
