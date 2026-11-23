# Cline

`PreToolUse` is the hook script (generated from `crates/smith-cli/src/agents.rs`; `smith init`
installs it as `.clinerules/hooks/PreToolUse`, executable, and never overwrites a hook someone else
wrote). Format notes and sources are in `docs/research/agent-plugin-formats.md`.

**Protection: prevention (blocking hook), unconfirmed against a live agent.** Cline runs the script
before each tool call and `smith hook cline PreToolUse` answers `{"cancel":true,"errorMessage":...}`
to block. The script always exits 0 with JSON, so it does not depend on Cline's undocumented
exit-code handling.

What is blocked: shell commands that read secrets or dump the environment, and reads and writes of
`.env`-style files. Ambiguous commands are denied with a message to run them manually. Both the
VS Code extension payload and the SDK/CLI runner payload are parsed.

Install: run `smith init --yes` in the repository, turn on "Enable Hooks" in Cline, then add the MCP
server by hand: Cline keeps MCP servers in the user-level `cline_mcp_settings.json` (Cline MCP
Servers panel), which `smith init` does not edit. Entry: `{"mcpServers":{"locksmith":{"command":"locksmith-mcp","args":[]}}}`.

Gaps, stated honestly:
- Hooks are not supported on Windows in the VS Code extension and need "Enable Hooks" on.
- The `command` and `path` parameter keys and Cline's exit-code semantics are doc-derived; the
  fixtures are not recordings (`crates/ls-hooks/tests/fixtures/cline/SOURCE.md`).
- A hook timeout or crash can let the tool run; only a missing `smith` is made visible and
  blocking by the script.
