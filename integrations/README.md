# integrations/

Thin agent, IDE and CI plugins. They call `smith hook` or `locksmith-mcp` and contain no security logic.

Language rule: TypeScript/JavaScript only, managed with npm. Decisions about secrets, policy or licensing belong in Rust, not here. Framework adapters (`agent-*`) are npm packages whose tools come from the gateway; they hold no security logic and only filter the tool list.

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

## Agent framework adapters

npm packages that give an agent built on a framework the Locksmith gateway tools (`list_my_keys`, `relay_http_request`, `explain_block`). All are relay only: no tool returns a value. Each README has the quick start; run the smoke test with `just agent-smoke <name>`.

| Framework | Directory | Install |
|---|---|---|
| Vercel AI SDK | `agent-vercel-ai` | `npm i @locksmith/agent @locksmith/agent-vercel-ai` |
| OpenAI Agents SDK (JS) | `agent-openai-agents` | `npm i @locksmith/agent @locksmith/agent-openai-agents` |
| LangChain.js / LangGraph.js | `agent-langchain` | `npm i @locksmith/agent @locksmith/agent-langchain` |

Relay only: no tool returns a value.

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

## Agent frameworks

Spike for `p5-framework-adapters` task 1.1. Checked 2026-11-24 from the npm and PyPI registries and the published package type declarations (docs sites are not reachable from agent runs). Anything not read from a source is marked **unverified**. The Python, CrewAI and ADK rows feed `p6-python-adapters` and later changes, not P5 (which adapts only the three TypeScript frameworks); their behaviour columns stay **unverified** until a `needs-research` answer or that change reads the wheels.

| Framework | Package, version, released, licence | Streamable HTTP MCP client | Per-request auth hook | Tool name filter | Scripted test model |
|---|---|---|---|---|---|
| Vercel AI SDK | `ai` 7.0.181 (2026-11-23, Apache-2.0) with `@ai-sdk/mcp` 2.0.104 (2026-11-23, Apache-2.0); source: https://registry.npmjs.org/ai and https://registry.npmjs.org/@ai-sdk/mcp, tarball `dist/index.d.ts` | yes (`type: "http"` transport) | custom `fetch` (`MCPTransportConfig.fetch`), static `headers` and `authProvider` (OAuth provider interface) | none on the client: filter the returned tool record | `MockLanguageModelV3` / `MockLanguageModelV4` from `ai/test` |
| OpenAI Agents SDK (JS) | `@openai/agents` 0.22.0 (2026-11-12, MIT); source: https://registry.npmjs.org/@openai/agents-core, `dist/mcp.d.ts` | yes (`MCPServerStreamableHttp`) | `fetch`, `requestInit` and `authProvider` options | `toolFilter` (static allow list or callback) | implement the `Model` interface (`dist/model.d.ts`) |
| LangChain.js / LangGraph.js | `@langchain/mcp-adapters` 2.0.3 (2026-11-11, MIT), `@langchain/langgraph` 1.7.5 (2026-11-17, MIT), `@langchain/core` 1.5.1 (2026-11-24, MIT); source: https://registry.npmjs.org/@langchain/mcp-adapters, `dist/types.d.ts` | yes (`MultiServerMCPClient`, `http` transport) | static `headers` and `authProvider`; no per-request `fetch` seen (**unverified** at runtime) | none in the adapter: filter the returned tools | fake chat models in `@langchain/core` (**unverified**) |
| OpenAI Agents SDK (Python) | `openai-agents` 0.26.0 (2026-11-24, MIT); source: https://pypi.org/pypi/openai-agents/json | **unverified** | **unverified** | **unverified** | **unverified** |
| LangChain / LangGraph (Python) | `langchain-mcp-adapters` 0.3.2 (2026-08-06, MIT), `langgraph` 1.2.24 (2026-11-20, MIT); source: https://pypi.org/pypi/langchain-mcp-adapters/json, https://pypi.org/pypi/langgraph/json | **unverified** | **unverified** (`httpx.Auth` expected) | **unverified** | **unverified** |
| CrewAI | `crewai` 1.15.45 (2026-11-24, licence **unverified**: PyPI metadata empty); source: https://pypi.org/pypi/crewai/json | **unverified** | **unverified** | **unverified** | **unverified** |
| Google ADK | `@google/adk` 2.5.0 (2026-11-12, Apache-2.0, npm); `google-adk` 2.15.0 (2026-11-20, Apache-2.0 by PyPI classifier); source: https://pypi.org/pypi/google-adk/json, https://registry.npmjs.org/@google/adk | **unverified** | **unverified** | **unverified** | **unverified** |

Underlying `@modelcontextprotocol/sdk` 1.32.2 (2026-10-23, MIT): `StreamableHTTPClientTransport` takes `requestInit`, a custom `fetch` and an `authProvider`, so a per-request token is possible wherever a framework exposes `fetch` or lets us pass a transport. Open for task 5.1: the LangChain adapter needs a token that renews, which its option list does not show directly.
