"""Contract types of the Locksmith agent client. No value or key material appears here."""

from __future__ import annotations

from typing import Any, TypedDict

# Gateway error slugs (tests/kit/agent-contract/errors.json; one per gateway status code).
GATEWAY_SLUGS = (
    "bad_request",
    "unauthenticated",
    "denied",
    "denied_address",
    "no_grant",
    "not_found",
    "audit_failed",
    "internal",
    "grants_unavailable",
    "response_withheld",
    "secret_unavailable",
    "secret_unusable",
    "upstream_error",
    "upstream_unreachable",
    "audit_unavailable",
    "unavailable",
    "upstream_timeout",
    "invalid_request",
    "duration_too_short",
    "binding_ambiguous",
    "not_bound",
    "vend_disabled",
    "service_denied",
    "sts_error",
    "sts_unreachable",
    "redaction_failed",
    "token_unavailable",
    "upstream_unauthorized",
    "upstream_redirect",
    "too_many_credentials",
    "settings_unavailable",
)
CLIENT_SLUGS = ("unauthorized", "bad_config", "foreign_origin", "transport", "unsafe_tool")

# The only Agent MCP tools an adapter exposes.
ALLOWED_TOOLS = ("list_my_keys", "relay_http_request", "explain_block")


class AgentError(Exception):
    """A fixed slug and an HTTP status (0 when no response arrived); never server or transport text."""

    def __init__(self, slug: str, status: int = 0) -> None:
        super().__init__(slug)
        self.slug = slug
        self.status = status

    def __repr__(self) -> str:
        return f"AgentError(slug={self.slug!r}, status={self.status})"


class Grant(TypedDict):
    """One grant of GET /v1/grants: ids and names, never a value."""

    secret_id: str
    secret_name: str
    mode: str
    expires_at: str | None
    allowed_origin: str


RelayResponse = dict[str, Any]
