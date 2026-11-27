"""A Google ADK `McpToolset` on the gateway's Agent MCP endpoint, limited to the allowed tools.

`StreamableHTTPConnectionParams.headers` is static, so the token does not go there. The connection params
take an `httpx_client_factory`, and the one here builds the MCP HTTP client with `client.auth` (an
`httpx.Auth` that asks the client for the token on every request, so it renews, and refuses any other
origin). The tool filter is `ALLOWED_TOOLS`, and `assert_no_value_tools` re-checks what the gateway lists.
"""

from __future__ import annotations

from typing import Any

import httpx
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from locksmith_agent import ALLOWED_TOOLS, AgentClient, assert_no_value_tools
from mcp.shared._httpx_utils import create_mcp_http_client


class _CheckedToolset(McpToolset):
    """Re-checks the filtered tool list on every listing; raises `AgentError("unsafe_tool")`."""

    async def get_tools(self, *args: Any, **kwargs: Any):
        tools = await super().get_tools(*args, **kwargs)
        assert_no_value_tools({"name": t.name, "inputSchema": t.raw_mcp_tool.inputSchema} for t in tools)
        return tools


def _client_factory(gateway_auth: httpx.Auth):
    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        # ADK passes `auth=None`; the gateway auth always applies.
        return create_mcp_http_client(headers=headers, timeout=timeout, auth=auth or gateway_auth)

    return factory


def locksmith_toolset(client: AgentClient) -> McpToolset:
    """Use it as `Agent(..., tools=[locksmith_toolset(client)])`, and `await toolset.close()` when done."""
    return _CheckedToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=client.mcp_url, httpx_client_factory=_client_factory(client.auth)
        ),
        tool_filter=list(ALLOWED_TOOLS),
    )
