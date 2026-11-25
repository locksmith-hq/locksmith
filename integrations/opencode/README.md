# OpenCode

`plugins/locksmith.js` is the guardrail plugin and `opencode.json` the MCP entry (both generated
from `crates/smith-cli/src/agents.rs`; `smith init` writes `.opencode/plugins/locksmith.js` and merges
the `locksmith` server into `opencode.json` (or into `opencode.jsonc` when that is the project's only
config), and never overwrites a plugin file someone else wrote).

**Protection: unknown, not protected by a preventing hook.** The plugin's `tool.execute.before`
pipes `{tool, args}` to `smith hook opencode tool.execute.before` and throws, which blocks the tool
call, on a deny, a non-zero exit, a timeout or a missing `smith`. `smith doctor` still labels it
unknown because the payload is read from OpenCode's docs, not recorded from a running agent
(`crates/ls-hooks/tests/fixtures/opencode/SOURCE.md`), and because a repo's own config can switch a
project plugin off.

What is checked: `bash` commands (secret reads, environment dumps) and `read` of `.env`-style files.
Any other tool name passes as unknown, and an unexpected shape of a known tool is blocked.

Install: run `smith init --yes` in the repository. `smith init` does not edit the user-level
`~/.config/opencode/opencode.json`.

Gaps, stated honestly:
- The plugin targets the V1 plugin API (`export const Locksmith = async () => ({ "tool.execute.before": ... })`),
  while the MCP entry uses the V2 shape (`mcp.servers.locksmith`). V2's deny mechanism for
  `execute.before` is not documented, so under V2 the plugin may not load or may not block; verify
  with `smith doctor` and a test read of `.env`.
- Plugins load from `.opencode/plugins/` (plural). A plugin can be disabled from config.
- `write`, `edit`, `grep`, `glob` and other tools are not checked: their argument keys are not in
  the docs we read.
- No remote Hub MCP entry (`smith doctor` prints `hub.mcp: unsupported`).
