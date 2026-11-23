# Gemini CLI

`settings.json` is the hook and MCP snippet (generated from `crates/smith-cli/src/agents.rs`;
`smith init` merges it into `.gemini/settings.json`). Format notes and sources are in
`docs/research/agent-plugin-formats.md`.

**Protection: prevention (blocking hook).** `BeforeTool` and `BeforeAgent` hooks call
`smith hook gemini-cli <event>`; a denial exits 2 with the reason on stderr.

What is blocked: shell commands that read secrets or dump the environment, reads and writes of
`.env`-style files, and prompts that paste secret values. Ambiguous commands (`eval`, base64 into
`sh`) are denied with a message to run them manually.

Install: run `smith init --yes` in the repository, then open `gemini` there and trust the folder.

Gaps, stated honestly:
- Gemini loads project hooks and stdio MCP servers only in a trusted folder; in an untrusted one the
  hook does not run and the MCP server shows as Disconnected. `smith doctor` warns about this
  (`hooks.gemini_cli.trust`).
- A hook crash or timeout can let the tool run; only a missing `smith` is made visible and blocking
  by the wrapper (exit 2).
- The trust-file format `smith doctor` reads is doc-derived and unconfirmed.
