# Proposal: M0 Foundation

## Why

Nothing exists yet. Every later milestone needs a few things in place first: a Rust workspace, CI on
macOS and Linux, a signed release pipeline, a way to get new builds onto tester machines, and a
diagnostics entry point. If these come late, each milestone ships something nobody can install, and
bug reports arrive without context. v5 has no release, update or diagnostics story at all (see
docs/v6-review.md §4).

## What Changes

- The full product monorepo skeleton (design D1): Cargo workspace (`crates/`, `services/`), npm
  workspaces (`apps/`, `packages/`, `integrations/`), `infra/`, `tests/`, and a root `justfile` so
  `just ci` builds, lints and tests every component in one command.
- Rust tooling: `rust-toolchain.toml`, `cargo-deny`, `clippy -D warnings`, `rustfmt`.
- TypeScript tooling: shared `packages/tsconfig` and `packages/eslint-config`, Prettier, Vitest.
  Placeholder `apps/web`, `apps/docs`, `apps/desktop` and `packages/ui` packages build to "hello"
  output so CI covers them from day one.
- Path-filtered CI so a docs-only change does not run the Rust matrix, and the reverse.
- `smith` CLI skeleton: `--version`, `--json` global flag, consistent exit codes, shell completions.
- `smith doctor`: a check registry with human and JSON output. M0 ships the platform, toolchain,
  config-dir permissions and update-reachability checks. Every later milestone registers its own.
- Release pipeline: `cargo-dist` builds macOS (universal) and Linux (x86_64/arm64 musl) archives,
  `.sha256`, minisign signatures, Homebrew tap formula. Published to GitHub Releases.
- `smith self update` (basic): fetches the latest release manifest, verifies the minisign signature
  and SHA-256, and atomically replaces the binary. M12 replaces the transport with TUF.
- `tests/adversarial` harness skeleton (runner, secret-leak oracle, CI job) with no attacks yet.
- Repo hygiene: `CLAUDE.md`/`AGENTS.md` for agent contributors, `SECURITY.md`, CODEOWNERS,
  branch protection, GitHub secret scanning and push protection.

## Usable outcome

An internal tester runs `curl -fsSL <install.sh> | sh` (or `brew install`). The tester gets `smith`,
runs `smith doctor`, and receives new builds with `smith self update`.

## Capabilities

### New Capabilities
- `cli-core`: CLI surface conventions: version, global flags, exit codes, JSON output, completions.
- `diagnostics`: `smith doctor` check registry and its output contract.
- `update-delivery`: Verified self-update of the installed binaries.

### Modified Capabilities

## Out of scope

- Any secret storage (M1).
- TUF, channels, staged rollout (M12).
- Windows builds (M16). The workspace must compile on Windows in CI (`cargo check`) from M0.

## Impact

New repo content only: root `Cargo.toml`, `package.json`, `justfile`, every top-level directory
from design D1, `.github/workflows/*`, `dist-workspace.toml`. External: a GitHub Releases-based install for testers who are repo
collaborators (private repo), and a public `homebrew-tap` repo.
