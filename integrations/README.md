# integrations/

Thin agent, IDE and CI plugins. They call `smith hook` or `locksmith-mcp` and contain no security logic.

Language rule: TypeScript/JavaScript only, managed with npm. Decisions about secrets, policy or licensing belong in Rust, not here.

Hook config files here (`claude-code/hooks/hooks.json`, `cursor/hooks.json`, `codex/config.toml`, plus the MCP snippets `claude-code/.mcp.json`, `cursor/mcp.json`)
are generated from `crates/smith-cli/src/agents.rs`; a unit test fails on drift. Regenerate with
`UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents`.

## Agent policy (human-owned)

`locksmith_start_session` grants an agent a session without the passphrase only inside
`agent-policy.toml` in the Locksmith config dir (outside any git work tree, owned by you, not
group/other-writable; read at unlock). For those sessions `smith run` injects only the `inject`
keys; every other key is relay-only (http token), and the relay sends a key only to the hosts listed
for it here, never to hosts from `.locksmith.toml`:

```toml
max_ttl_secs = 3600
scopes = ["run", "http"]
[relay]
allow_private = ["10.0.0.12:443"]    # exact ip:port of an internal HTTPS upstream (the relay speaks TLS)
[projects.default]
envs = ["development"]
inject = ["DATABASE_URL"]            # optional; default: nothing injectable
[projects.default.http.LANGFUSE_SECRET_KEY]
hosts = ["us.cloud.langfuse.com"]
```

Limits: the relay redacts the exact value and its standard encodings in responses; an approved host
that reflects the key in another form is out of scope, so choose hosts with care. Keys in `inject`
reach a process the agent controls, which can print them transformed: inject only what a trusted
command needs.

## Claude Code plugin

`integrations/claude-code` is a Claude Code plugin (`.claude-plugin/plugin.json`, hooks, `.mcp.json`, `skills/`, `commands/`), listed by the marketplace at `.claude-plugin/marketplace.json` in the repo root. Install with `/plugin marketplace add <repo>` then `/plugin install locksmith@locksmith`; validate with `claude plugin validate .`. `plugin.json` `version` must equal the workspace version (checked by `cargo test -p smith-cli`). Skills and commands are hand-written; only hooks and `.mcp.json` are generated.

Test commands for each integration: [docs/testing.md](../docs/testing.md).
