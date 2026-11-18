## Context
Observed on main (2026-11-18): 30 component directories; the only test recipes are aggregate (`just test-rust`, `just test-web`, `just desktop-test`, `just test-e2e`, `tests/adversarial/run.sh`, `tests/kit/leak_scan_test.sh`). Directory names differ from Cargo package names (`services/control-plane` is `ls-control-plane`, `services/gateway` is `ls-gateway`, `tests/e2e` is `ls-e2e`). Only `apps/desktop` has a `test` script among the app/package `package.json` files found by a quick grep; `apps/web` runs tests through the root `npm test`. `scripts/tree-check.sh` already runs in `just ci` and in CI.

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| One table in `docs/testing.md` is the source of truth, checked by a script | A README per component (30 files, drifts); a TOML manifest (a second format agents must learn) | A single index is what agents read first; the check stops drift. Precedent: `tree-check.sh` enforces layout the same way |
| `just test <name>` resolves Rust dirs with `cargo metadata --no-deps` | A hand-kept dir-to-package map | `cargo metadata` is the documented way to read package names and manifest paths: https://doc.rust-lang.org/cargo/commands/cargo-metadata.html |
| npm dirs run `npm test --workspace <dir>` | Per-package scripts called directly | npm workspaces docs: https://docs.npmjs.com/cli/v10/using-npm/workspaces (AGENTS.md: npm workspaces only) |
| `just` recipe with a positional argument | A new CLI tool | `just` recipe parameters: https://just.systems/man/en/recipe-parameters.html; the justfile already uses `set positional-arguments` |
| The coverage check runs inside `just tree-check` | A new CI job | AGENTS.md CI policy: no new jobs; tree-check is seconds-long hygiene and already in CI |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `just` | CC0-1.0 | already used | existing | task runner | not AGPL |
| `cargo-nextest` | MIT/Apache-2.0 | already used | existing | Rust test runner | not AGPL |
| `jq` | MIT | already used by scripts | existing | read `cargo metadata` JSON | not AGPL |
Built in-house: a shell script of about 60 lines and one `just` recipe; nothing on crates.io or npm maps monorepo directories to mixed Rust and npm test commands, and the existing tools already do the work.

## How an agent debugs this
`bash scripts/test-recipes-check.sh` prints each missing or stale row. `just test <name>` echoes the command it runs before running it. `cargo metadata --no-deps --format-version 1 | jq '.packages[].manifest_path'` shows the dir-to-package mapping. No DB tables, logs or traces are involved.

## Risks
- Components with no tests of their own (`packages/tsconfig`, `packages/eslint-config`, the `integrations/*` folders) could be papered over with "covered by". Mitigation: the row must name the covering component and why; real tests for integrations come with P3.
