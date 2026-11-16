# integrations/

Thin agent, IDE and CI plugins. They call `smith hook` or `locksmith-mcp` and contain no security logic.

Language rule: TypeScript/JavaScript only, managed with npm. Decisions about secrets, policy or licensing belong in Rust, not here.

Hook config files here (`claude-code/hooks/hooks.json`, `cursor/hooks.json`, `codex/config.toml`, plus the MCP snippets `claude-code/.mcp.json`, `cursor/mcp.json`)
are generated from `crates/smith-cli/src/agents.rs`; a unit test fails on drift. Regenerate with
`UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents`.

## Claude Code plugin

`integrations/claude-code` is a Claude Code plugin (`.claude-plugin/plugin.json`, hooks, `.mcp.json`, `skills/`, `commands/`), listed by the marketplace at `.claude-plugin/marketplace.json` in the repo root. Install with `/plugin marketplace add <repo>` then `/plugin install locksmith@locksmith`; validate with `claude plugin validate .`. `plugin.json` `version` must equal the workspace version (checked by `cargo test -p smith-cli`). Skills and commands are hand-written; only hooks and `.mcp.json` are generated.
