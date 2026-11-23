# Proposal: P3 agent plugins

## Why

Locksmith ships thin plugins for Claude Code, Codex and Cursor only. Teams on Gemini CLI, GitHub Copilot, Windsurf or Cline cannot get the guardrail hook or the `locksmith` MCP server without hand-editing configs, and any other MCP client has no documented setup. The local pieces (`locksmith-mcp`, `smith hook`) already exist, so wider reach costs little now and the roadmap lists it as a standalone row (P3, needs nothing).

## What Changes

- Extend `crates/smith-cli/src/agents.rs` (the single source of truth) with Gemini CLI, GitHub Copilot (VS Code agent mode and Copilot CLI), Windsurf and Cline: id, hook events, config and MCP paths, detection, idempotent merge, and the fail-closed wrapper.
- Add `smith hook <agent> <event>` payload parsing and reply shapes for each new agent, reusing the existing `ls_hooks` decision code.
- Add `integrations/gemini-cli`, `integrations/copilot`, `integrations/windsurf`, `integrations/cline` and `integrations/generic-mcp`. Hook and MCP config files are generated and covered by the existing drift test (`UPDATE_INTEGRATIONS=1`); only READMEs and instruction files are hand-written.
- `smith init` and `smith doctor` learn the four new agents.
- Each integration gets a live or recorded smoke test and a `just test <name>` recipe; `docs/testing.md` gains one row each.
- A generic MCP setup guide for any other MCP client (stdio `locksmith-mcp`, no hook).
- Where an agent has no pre-tool hook, its README and `smith doctor` say so and label the protection as detection or none, never prevention.

Out of scope: publishing to any marketplace or extension registry, the remote Agent MCP (that is P4), SDKs, new gateway or policy behavior, any web or desktop surface (these plugins have no console UI), and agents beyond the four named.

Depends on: none.

## Capabilities

### New Capabilities
- `agent-plugins`: how Locksmith wires its guardrail hook and MCP server into supported coding agents, generated from one source, with honest protection labels and a smoke test per agent.

### Modified Capabilities

## Impact

- Code: `crates/smith-cli/src/{agents,hook_cmd,init_cmd,doctor_m4}.rs`, new `integrations/*` directories, `justfile` (`test` recipe case), `docs/testing.md`, `integrations/README.md`.
- No new runtime dependency expected; plugin code stays TypeScript-free config and docs (licence Apache-2.0).
- No change to secrets handling: hooks only deny or allow, and no plugin file ever contains a secret value.
