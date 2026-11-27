# locksmith-agent-langchain

Locksmith tools for LangChain and LangGraph agents. The adapter loads the Locksmith Agent MCP tools with
`langchain-mcp-adapters` over Streamable HTTP and returns only `list_my_keys`, `relay_http_request` and
`explain_block`. The agent never holds a secret value: the gateway relays the call.

## Install

```sh
uv add locksmith-agent-langchain   # needs Python 3.11 or newer (langchain-core)
```

## Quick start

```python
from langgraph.prebuilt import create_react_agent
from locksmith_agent import AgentClient
from locksmith_agent_langchain import locksmith_tools

with AgentClient() as client:  # LOCKSMITH_GATEWAY_URL and LOCKSMITH_ENROLLMENT_SECRET
    lt = await locksmith_tools(client)
    agent = create_react_agent(model, lt.tools)
```

## Why the tools are filtered

A gateway may list tools that hand a value back (for example `get_secret_value`). `pick_allowed_tools` drops
everything outside the allowed three and `assert_no_value_tools` raises `AgentError("unsafe_tool")` if a kept
tool has a value-shaped input or output property. The names of dropped tools are in `lt.dropped`.

## Smoke test

With `just up` and `just api` running: `just agent-smoke langchain-py`.
