# integrations/

Thin agent, IDE and CI plugins. They call `smith hook` or `locksmith-mcp` and contain no security logic.

Language rule: TypeScript/JavaScript only, managed with npm. Decisions about secrets, policy or licensing belong in Rust, not here.

Hook config files here (`claude-code/hooks/hooks.json`, `cursor/hooks.json`, `codex/config.toml`, plus the MCP snippets `claude-code/.mcp.json`, `cursor/mcp.json`, `generic-mcp/mcp.json`, and the Gemini CLI, Copilot, Windsurf and Cline files listed below)
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

## Supported agents

`smith init --yes` detects the agents in a repository and merges the hook and MCP entries for each.
The protection label is what `smith doctor` prints: **prevention** means a blocking pre-tool hook
denies secret reads and environment dumps; **none** means only the MCP server is wired and nothing
blocks the agent's own shell.

| Agent | Directory | Install | Protection |
|---|---|---|---|
| Claude Code | `claude-code` | `/plugin marketplace add <repo>` then `/plugin install locksmith@locksmith`, or `smith init` | prevention |
| Cursor | `cursor` | `smith init` (`.cursor/hooks.json`, `.cursor/mcp.json`) | prevention |
| Codex | `codex` | `smith init` (`.codex/config.toml`) | prevention |
| Gemini CLI | `gemini-cli` | `smith init`, then trust the folder in `gemini` | prevention (needs a trusted folder) |
| Copilot (VS Code agent mode, CLI) | `copilot` | `smith init` (`.github/hooks/locksmith.json`, `.vscode/mcp.json`) | prevention, with a fail-open timeout |
| Cline | `cline` | `smith init` (`.clinerules/hooks/PreToolUse`; add the MCP server by hand in Cline's MCP Servers panel) | prevention, unconfirmed against a live agent |
| Windsurf (Devin Desktop) | `windsurf` | generated only; no hook handler yet | unknown, not protected |
| Any other MCP client | `generic-mcp` | merge `mcp.json` by hand | none |

Each directory's README states what is blocked and the known gaps. Regenerate every generated file
with `UPDATE_INTEGRATIONS=1 cargo test -p smith-cli --bin smith agents`.

Test commands for each integration: [docs/testing.md](../docs/testing.md).
