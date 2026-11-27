"""An `MCPServerStreamableHttp` on the gateway's Agent MCP endpoint, limited to the allowed tools.

The token comes from `client.auth`, an `httpx.Auth` that asks the client for the token on every request
(so it renews) and refuses any other origin. The adapter holds no security logic: the static tool filter
is `ALLOWED_TOOLS`, and `assert_no_value_tools` re-checks what the gateway lists once the server is
connected.
"""

from __future__ import annotations

from typing import Any

from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter
from locksmith_agent import ALLOWED_TOOLS, AgentClient, assert_no_value_tools


class _CheckedServer(MCPServerStreamableHttp):
    """Re-checks the filtered tool list on every listing; raises `AgentError("unsafe_tool")`."""

    async def list_tools(self, *args: Any, **kwargs: Any):
        tools = await super().list_tools(*args, **kwargs)
        assert_no_value_tools({"name": t.name, "inputSchema": t.inputSchema} for t in tools)
        return tools


def locksmith_mcp_server(client: AgentClient) -> MCPServerStreamableHttp:
    """Use it as `async with locksmith_mcp_server(client) as server: Agent(..., mcp_servers=[server])`."""
    return _CheckedServer(
        params={"url": client.mcp_url, "auth": client.auth},
        name="locksmith",
        cache_tools_list=False,
        tool_filter=create_static_tool_filter(allowed_tool_names=list(ALLOWED_TOOLS)),
    )
