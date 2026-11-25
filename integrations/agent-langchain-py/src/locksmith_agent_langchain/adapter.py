"""Loads the Agent MCP tools with `MultiServerMCPClient` over Streamable HTTP.

The token comes from `client.auth`, an `httpx.Auth` that asks the client for the token on every request
(so it renews) and refuses any other origin. The adapter holds no security logic: it filters the tool list
with `pick_allowed_tools` and re-checks the result with `assert_no_value_tools`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient
from locksmith_agent import AgentClient, assert_no_value_tools, pick_allowed_tools


@dataclass(frozen=True)
class LocksmithTools:
    """`tools`: `list_my_keys`, `relay_http_request` and `explain_block` only. `dropped`: names left out."""

    tools: list[BaseTool]
    dropped: list[str] = field(default_factory=list)


def _described(tool: BaseTool) -> dict[str, Any]:
    schema = tool.args_schema
    return {"name": tool.name, "inputSchema": schema if isinstance(schema, dict) else None}


async def locksmith_tools(client: AgentClient) -> LocksmithTools:
    mcp = MultiServerMCPClient(
        {
            "locksmith": {
                "transport": "streamable_http",
                "url": client.mcp_url,
                "auth": client.auth,
            }
        }
    )
    every = await mcp.get_tools()
    kept, dropped = pick_allowed_tools(_described(t) for t in every)
    names = {k["name"] for k in kept}
    tools = [t for t in every if t.name in names]
    assert_no_value_tools(_described(t) for t in tools)
    return LocksmithTools(tools=tools, dropped=dropped)
