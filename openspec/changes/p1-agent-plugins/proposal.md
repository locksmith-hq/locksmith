# Proposal: P1 Agent Framework Plugins and Extensions (parallel track)

## Why

Locksmith only works if it is wired into the tools developers actually use. M4 and M10 built the
engine (`smith hook`, `locksmith-mcp`) and minimal manifests. This track packages, publishes and
maintains first-class integrations for each agent framework, IDE and CI system. Each one is thin
and lives in `integrations/`, and all of them are tested against the same adversarial suite.

## What Changes

| Integration | Package | Contents |
|---|---|---|
| Claude Code | plugin in a Locksmith marketplace repo (`integrations/claude-code`) | hooks (PreToolUse, UserPromptSubmit, SessionStart status), MCP server config, `/locksmith` slash commands, a skill that teaches the agent the supported paths |
| Cursor | `integrations/cursor` | hooks.json, MCP config, a project rule file |
| OpenAI Codex | `integrations/codex` | config.toml hooks/approval policy snippet, MCP config, AGENTS.md section |
| Grok Build | `integrations/grok-build` | its hook/MCP equivalents (verified against current docs when built) |
| OpenHands | `integrations/openhands` | a microagent plus runtime setup action that starts `smith session` in the sandbox |
| Gemini CLI | `integrations/gemini-cli` | extension manifest with MCP config and context file |
| VS Code (+ Cursor/Windsurf forks) | `integrations/vscode` (TS) | status bar (lock/session), "Run with Locksmith" tasks, approvals notifications, `.locksmith.toml` schema |
| GitHub Action | `integrations/github-action` | installs `smith`, unlocks from OIDC-fetched team vault access, runs steps with redaction |
| Devcontainer feature | `integrations/devcontainer-feature` | installs `smith` and forwards the host daemon socket into the container |

- `smith integrations ls|install|update|doctor` detects installed agents and installs or updates the
  matching integrations. `smith init` calls it.
- A compatibility matrix (`integrations/compat.toml`): integration version ↔ minimum `smith`
  version ↔ agent version range. It is checked by doctor and CI.
- A contract test kit: golden hook payloads per agent version, and a weekly job that installs the
  latest agent releases and runs the A6 and A7 suites to catch upstream schema changes early.

## Usable outcome

`smith integrations install` sets up every agent a developer uses in one step. Marketplace listings
let new users discover Locksmith from inside their agent.

## Capabilities

### New Capabilities
- `agent-integrations`: Installation, compatibility and behaviour of per-agent and per-IDE integrations.

### Modified Capabilities

## Out of scope

- JetBrains plugin (backlog). Agents without hooks or MCP get session plus run guidance only.

## Impact

`integrations/*` (npm workspaces for the TS ones), `crates/ls-hooks` adapters per agent, the docs
guides (W2). Starts after M4. Claude Code, Cursor and Codex come first, then the rest after M10.
