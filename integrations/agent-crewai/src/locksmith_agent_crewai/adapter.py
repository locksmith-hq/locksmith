"""CrewAI tools on the gateway's Agent MCP endpoint, limited to the allowed tools.

`MCPServerAdapter` hands its parameters to the MCP Streamable HTTP client, so `client.auth` (an `httpx.Auth`
that asks the client for the token on every request, so it renews, and refuses any other origin) is passed as
`auth` and no token sits in a static header. The tool filter is `ALLOWED_TOOLS`, and `assert_no_value_tools`
re-checks the kept tools' schemas.
"""

from __future__ import annotations

from typing import Any

import httpx
from crewai_tools import MCPServerAdapter
from locksmith_agent import ALLOWED_TOOLS, AgentClient, assert_no_value_tools


class _SharedAuth(httpx.Auth):
    """Delegates to `client.auth`; copies share the client, because `MCPServerAdapter` deep-copies its
    parameters and a `Secret` refuses to be copied."""

    def __init__(self, inner: httpx.Auth) -> None:
        self._inner = inner

    def __repr__(self) -> str:
        return "SharedAuth(<redacted>)"

    def __deepcopy__(self, memo: dict[int, Any]) -> _SharedAuth:
        return self

    def auth_flow(self, request):
        return self._inner.auth_flow(request)

    def async_auth_flow(self, request):
        return self._inner.async_auth_flow(request)


def _drop_none_args(tool: Any) -> None:
    """CrewAI fills every optional schema field with `None`; the gateway rejects unknown or null
    arguments, so the call keeps only the fields that carry a value."""
    run = tool._run

    def _run(**kwargs: Any) -> Any:
        return run(**{k: v for k, v in kwargs.items() if v is not None})

    object.__setattr__(tool, "_run", _run)


def locksmith_tools(client: AgentClient) -> MCPServerAdapter:
    """Use it as `with locksmith_tools(client) as tools: Agent(..., tools=tools)`; raises
    `AgentError("unsafe_tool")` if a kept tool has a value-shaped schema."""
    adapter = MCPServerAdapter(
        {"url": client.mcp_url, "transport": "streamable-http", "auth": _SharedAuth(client.auth)},
        *ALLOWED_TOOLS,
    )
    try:
        for tool in adapter.tools:
            _drop_none_args(tool)
        assert_no_value_tools(
            {"name": t.name, "inputSchema": t.args_schema.model_json_schema()} for t in adapter.tools
        )
    except BaseException:
        adapter.stop()
        raise
    return adapter
