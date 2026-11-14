# Proposal: M10 MCP Server

## Why

Agents work best when they can discover what credentials exist and ask for new ones in their native
tool interface. Without that, they guess env var names or ask the user to paste keys into chat,
which is the leak we are preventing. v5 Phase 4 specifies the MCP server. v6 adds request-to-human
flows so the agent can ask, and a human supplies the value outside the model's context.

## What Changes

- `locksmith-mcp` stdio server (attested daemon client). Tools:
  - `locksmith_list_keys`: names, environments, types, opaque-token availability. Never values.
  - `locksmith_request_secret`: the agent asks for a secret it needs (name, purpose, provider). The
    human gets a native prompt (desktop notification or terminal) to paste the value or connect it to
    a provider, and the agent gets only "created" or "declined".
  - `locksmith_rotate_secret`: starts a rotation that the human completes (paste new value), or a
    provider-API rotation when a connector supports it.
  - `locksmith_issue_token`: an opaque `lsk_` token for a key and host (M6).
  - `locksmith_status`: session, scopes, expiry, what is delegated.
  - `locksmith_explain_block`: given a blocked action id, explains why and the supported path.
- MCP resources: `locksmith://project/binding`, the read-only `.locksmith.toml` view.
- Plugin wiring: `integrations/claude-code` adds the MCP server config, and Cursor and Codex
  snippets.

## Usable outcome

An agent setting up a Stripe integration calls `locksmith_request_secret("STRIPE_KEY")`. The
developer pastes the key into a native prompt, and the agent continues using
`smith run`/`lsk_` without ever seeing the value.

## Capabilities

### New Capabilities
- `mcp-server`: Agent-facing tool interface for discovery and human-approved secret creation.

### Modified Capabilities

## Out of scope

- Remote (HTTP/SSE) MCP transport. stdio only.

## Impact

New crate `locksmith-mcp` using the `rmcp` crate. A native prompt helper (`ls-platform::prompt`,
using osascript/zenity or the desktop app when it is running).
