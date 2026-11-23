# Windsurf (Devin Desktop)

`hooks.json` is the legacy Windsurf hook file (generated from `crates/smith-cli/src/agents.rs`).
Format notes and sources are in `docs/research/agent-plugin-formats.md`.

**Protection: unknown, not protected.** Windsurf is now Devin Desktop, whose current hook file is
`.devin/hooks.v1.json` (Claude-style `PreToolUse`), not the `.windsurf/hooks.json` shape in this
directory. Until a recorded payload confirms the format, `smith hook windsurf` has no handler,
`smith init` does not write this file and `smith doctor` reports Windsurf as "unknown, not
protected". Do not rely on this file for protection.

Use today: the MCP server only (detection, no prevention). Windsurf keeps MCP servers outside the
repo (`~/.codeium/windsurf/mcp_config.json`, or `.devin/mcp_config.json` for Devin Desktop);
`smith init` prints the step instead of editing home-directory files. Entry:
`{"mcpServers":{"locksmith":{"command":"locksmith-mcp","args":[]}}}`.

Gaps, stated honestly:
- Hooks do not load in Restricted Mode.
- Workspace path, schema, payload and stderr handling of this legacy shape are unconfirmed.
