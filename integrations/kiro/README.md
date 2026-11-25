# Kiro

`hooks/locksmith.json` is a Kiro `PreToolUse` command hook and `settings/mcp.json` the MCP entry
(both generated from `crates/smith-cli/src/agents.rs`; `smith init` writes `.kiro/hooks/locksmith.json`,
keeps every other hook in the file, and merges the `locksmith` server into `.kiro/settings/mcp.json`).

**Protection: unknown, not protected by a preventing hook.** Kiro documents a blocking project
`PreToolUse` hook: a command that exits non-zero blocks the tool call and its stderr goes to the
agent. `smith hook kiro PreToolUse` exits 2 with the reason on stderr to deny, and the wrapper does
the same when `smith` is missing. `smith doctor` still labels it unknown because the stdin payload
is documented only for MCP tools and `read_file`, not recorded from a running Kiro
(`crates/ls-hooks/tests/fixtures/kiro/SOURCE.md`).

What is checked: `read_file` (`tool_input.path`) of `.env`-style files. Any other tool name,
including MCP tools, passes as unknown; a payload that does not fit the documented shape is blocked.

Install: run `smith init --yes` in the repository. `smith init` does not edit the user-level
`~/.kiro/settings/mcp.json` or `~/.kiro/hooks/`.

Gaps, stated honestly:
- Built-in shell and write tool names and input keys are not in the docs we read, so shell
  commands are not inspected yet.
- The hook file has no timeout key (its unit is not documented): a hung hook is Kiro's to handle.
- Hooks apply in the IDE and the CLI, not in Kiro Web or Mobile.
- No remote Hub MCP entry (`smith doctor` prints `hub.mcp: unsupported`).
