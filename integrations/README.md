# integrations/

Thin agent, IDE and CI plugins. They call `smith hook` or `locksmith-mcp` and contain no security logic.

Language rule: TypeScript/JavaScript only, managed with npm. Decisions about secrets, policy or licensing belong in Rust, not here.

Hook config files here (`claude-code/hooks/hooks.json`, `cursor/hooks.json`, `codex/config.toml`, plus the MCP snippets `claude-code/.mcp.json`, `cursor/mcp.json`)
are generated from `crates/smith-cli/src/agents.rs`; a unit test fails on drift. Regenerate with
`UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents`.
