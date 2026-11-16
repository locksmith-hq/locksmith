# Locksmith monorepo

Credential broker for AI coding agents. Agents perform authenticated operations without holding the credential.

## Build and test

- `just ci`: fmt, lint, test-rust, test-web, tree-check (run before every push)
- `just fmt` / `just lint` / `just test-rust` / `just test-web` / `just tree-check`
- `just dev <app>`: build one app, e.g. `just dev web`
- `npm run build`, `npm test`, `npm run lint`: run across all npm workspaces
- `cargo test --workspace`: run one Rust crate with `cargo test -p <crate>`

## Layout

- `crates/`: Rust core libraries and binaries (smith-cli, locksmithd, locksmith-mcp)
- `services/`: Rust axum backend services
- `apps/`: web, docs, desktop (npm workspaces, except desktop which is Tauri/Rust)
- `packages/`: shared TypeScript (tsconfig, eslint-config, ui)
- `integrations/`: thin agent/IDE/CI plugins that call `smith hook` or `locksmith-mcp`
- `infra/`: OpenTofu IaC
- `tests/`: cross-component end-to-end tests (`tests/e2e/`)
- `docs/`: product and planning docs
- `scripts/tree-check.sh`: enforces where Rust and package.json may live

## Security rules

- Never print, log or serialize a plaintext secret.
- Secrets only in secrecy/zeroize types with no Debug/Display/Clone.
- Never block unlock or export because of licensing or update failures.
- Rust for anything touching secrets.
- npm only. Never pnpm or yarn.

## Working principles

- Roadmap: `docs/roadmap.md`. Rules every change follows: `openspec/config.yaml` (evidence, OSS-first, local test per change).
- Research before building: `docs/research/` (Infisical, OSS building blocks). Reuse a maintained OSS package before writing one.
- Local first: `just up` stack + MCP servers in `.mcp.json` give agents the DB, logs and traces.
- Scheduled runs work in the `../locksmith-worker` worktree, log to `.agent-runs.md` (gitignored, repo root), commit only to `change/<id>` branches, never push.

## OpenSpec workflow

- `openspec list`: see active changes
- `/opsx:apply <id>`: implement a change
- `/opsx:archive <id>`: archive a finished change

## Delegating to subagents

Pick the subagent model by how hard and how critical the task is:

- **Opus 5.5** (`model: opus`): hard or critical work. Anything touching secrets, crypto, the vault,
  the daemon's authorization or audit paths, relays and forwarders, adversarial gates, protocol
  implementations, and cross-cutting design or merge decisions.
- **Sonnet 5.5** (`model: sonnet`): medium-hard work. Feature code outside the secret paths, CLI
  commands, doctor checks, integration tests, CI fixes, and non-trivial refactors.
- **Haiku 5.5** (`model: haiku`): easy-medium work. Searches and code exploration, docs and
  OpenSpec text edits, catalog/config data, formatting and lint fixes, and simple mechanical changes.

When unsure, go one tier up. Split a mixed task so each part runs on the right tier.
