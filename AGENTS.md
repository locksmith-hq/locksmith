# Locksmith monorepo

Locksmith is an open-source secrets platform and credential gateway for AI coding agents. Agents perform authenticated operations without ever holding the credential.

## Build and test
- `just ci` runs fmt, lint, test-rust, test-web, tree-check and task-guard. Never run it locally: the PR's required checks run it.
- Before every push run `just quick` (fmt and lint of your branch's committed changes) plus the tests you touched (`cargo test -p <crate>`).
- Other recipes: `just up` / `just down` (local stack), `just dev <app>`, and `cargo test -p <crate>` for a single crate.
- npm workspaces only. Never use pnpm or yarn. After changing a `package.json`, run `npm i` in that package's directory. `turbo.json` runs the JavaScript tasks (`npm run lint|build|test` call `turbo run`); TypeScript is checked with oxlint, oxfmt and knip.

## Layout
| Path | Contents |
|---|---|
| `crates/` | Rust libraries and binaries |
| `ee/` | source-available enterprise layer (Rust), see LICENSING.md |
| `services/` | axum backends |
| `apps/` | web, docs, desktop (Tauri), and `api` (the NestJS API, from change `b1-nestjs-api`) |
| `packages/` | shared TypeScript |
| `integrations/` | thin agent plugins |
| `infra/` | compose, helm (AWS and OpenTofu live in the private `locksmith-cloud` repo) |
| `tests/` | e2e and adversarial tests |
| `scripts/` | tooling |

`scripts/tree-check.sh` enforces this layout.

## CI policy (GitHub Actions)
The repo is public, so Actions minutes are free. Every PR runs:
- `ci`: hygiene (tree-check, task guard, public-check, gitleaks), Rust (fmt, clippy, cargo-deny, tests), web (lint, build, tests) and desktop (fmt, clippy, tests, api-types);
- `ci-platforms`: macOS tests and a Windows check;
- `adversarial`: the scripted adversarial cases (live cases run nightly and on main).

CI jobs call the same `just` recipes as `just ci`, so run `just quick` locally and let CI run the full suite.

## Security rules
- Never print, log or serialize a plaintext secret.
- Secrets live only in `secrecy`/`zeroize` types, with no Debug, Display or Clone.
- Agents never receive secret values. Use relay, delegation, or short-lived scoped credentials.
- Never block unlock or export because of licensing, billing or update failures.
- Use Rust for anything that touches plaintext secrets, keys or proxies. The NestJS API never receives plaintext secrets or key bytes; it calls the Rust core.
- Any test that needs an AWS API (STS, S3, DynamoDB, SQS, Cognito, KMS...) runs against Floci (https://github.com/floci-io/floci, `floci` in compose, `localhost:4566`), never real AWS, moto or LocalStack. Humans, workers, the lead and the PM all follow this.

## How we work
- **Plan:** `docs/roadmap.md` and `openspec/changes/<id>/`. The rules for every change are in `openspec/config.yaml`.
- **Evidence and reuse:** base decisions on evidence, not guesses (`docs/research/`). Reuse a maintained OSS package before writing one.
- **Local first:** `just up` plus the MCP servers in `.mcp.json` give agents access to the database, logs and traces.
- **Progress:** each change has an append-only `progress.md`. Read it and `git log` before starting work.
- **Tasks:** only tick tasks after they are verified. Never rewrite task text on an agent branch; `scripts/check-task-edits.sh` enforces this.
- **Cloud and scheduled agents:** see `docs/cloud-dev.md` and `docs/agents/`.
