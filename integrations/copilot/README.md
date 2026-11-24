# GitHub Copilot (VS Code agent mode and CLI)

`hooks/locksmith.json` is the hook file (installed as `.github/hooks/locksmith.json`) and
`mcp.json` the VS Code MCP entry (installed as `.vscode/mcp.json`). Both are generated from
`crates/smith-cli/src/agents.rs`; `smith init` merges them.

**Protection: prevention (blocking hook), with a fail-open timeout.** The `preToolUse` hook calls
`smith hook copilot preToolUse`; a denial blocks the tool call.

What is blocked: shell commands that read secrets or dump the environment, and reads and edits of
`.env`-style files. Ambiguous commands are denied with a message to run them manually.

Install: run `smith init --yes` in the repository.

Gaps, stated honestly:
- Copilot lets the tool call proceed when a hook times out (fail-open). `smith doctor` checks that
  the timeout stays at 10 s (`hooks.copilot.timeout`).
- The Copilot CLI reads MCP from `.mcp.json` or `.github/mcp.json`, not `.vscode/mcp.json`; copy the
  entry there for the CLI. The `toolArgs.command` key is doc-derived and unconfirmed.
- Only the `bash` hook command is generated; Windows (`powershell`) hosts are not covered yet.
