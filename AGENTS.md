# Locksmith monorepo

Locksmith is an open-source secrets platform and credential gateway for AI coding agents. Agents perform authenticated operations without ever holding the credential.

## Build and test
- `just ci` runs fmt, lint, test-rust, test-web, tree-check and task-guard. Run it before every push.
- Other recipes: `just up` / `just down` (local stack), `just dev <app>`, and `cargo test -p <crate>` for a single crate.
- npm workspaces only. Never use pnpm or yarn. After changing a `package.json`, run `npm i` in that package's directory.

## Layout
| Path | Contents |
|---|---|
| `crates/` | Rust libraries and binaries |
| `services/` | axum backends |
| `apps/` | web, docs, desktop (Tauri) |
| `packages/` | shared TypeScript |
| `integrations/` | thin agent plugins |
| `infra/` | compose, helm, OpenTofu |
| `tests/` | e2e and adversarial tests |
| `scripts/` | tooling |

`scripts/tree-check.sh` enforces this layout.

## CI policy (GitHub Actions)
The repo is public, so Actions minutes are free. Every PR runs:
- `ci`: hygiene (tree-check, task guard, public-check, gitleaks), Rust (fmt, clippy, cargo-deny, tests), web (lint, build, tests) and desktop (fmt, clippy, tests, api-types);
- `ci-platforms`: macOS tests and a Windows check;
- `adversarial`: the scripted adversarial cases (live cases run nightly and on main).

CI jobs call the same `just` recipes as `just ci`. Still run `just ci` before every push.

## Security rules
- Never print, log or serialize a plaintext secret.
- Secrets live only in `secrecy`/`zeroize` types, with no Debug, Display or Clone.
- Agents never receive secret values. Use relay, delegation, or short-lived scoped credentials.
- Never block unlock or export because of licensing, billing or update failures.
- Use Rust for anything that touches secrets.

## How we work
- **Plan:** `docs/roadmap.md` and `openspec/changes/<id>/`. The rules for every change are in `openspec/config.yaml`.
- **Evidence and reuse:** base decisions on evidence, not guesses (`docs/research/`). Reuse a maintained OSS package before writing one.
- **Local first:** `just up` plus the MCP servers in `.mcp.json` give agents access to the database, logs and traces.
- **Progress:** each change has an append-only `progress.md`. Read it and `git log` before starting work.
- **Tasks:** only tick tasks after they are verified. Never rewrite task text on an agent branch; `scripts/check-task-edits.sh` enforces this.
- **Cloud and scheduled agents:** see `docs/cloud-dev.md` and `docs/agents/`.
