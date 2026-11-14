# Design: M0 Foundation

## Context

Greenfield. The project context in openspec/config.yaml fixes Rust for all secret-touching code and
npm-only TypeScript for the desktop UI.

## Goals / Non-Goals

**Goals:** an installable, updatable, diagnosable `smith` on day 5, and a layout that later
milestones fill in without restructuring.
**Non-Goals:** feature work, Windows release artifacts, public distribution.

## Decisions

### D1. Monorepo layout (whole product)
```
Cargo.toml            # Rust workspace: crates/*, services/*, apps/desktop/src-tauri
package.json          # npm workspaces: apps/*, packages/*, integrations/*
justfile              # single entry point: just ci | just dev <app> | just release
rust-toolchain.toml   .nvmrc   deny.toml   .editorconfig

crates/               # Rust, security-relevant
  smith-cli/  locksmithd/  locksmith-mcp/                 # binaries
  ls-core/ ls-crypto/ ls-vault/ ls-redact/ ls-ipc/ ls-broker/
  ls-proxy/ ls-platform/ ls-diag/ ls-update/ ls-license/ ls-hooks/
services/             # Rust (axum)
  license-server/  sync-server/
apps/
  web/                # Astro: landing, pricing, changelog, account portal (React islands)
  docs/               # Astro Starlight: public docs, CLI reference generated from clap
  desktop/            # Tauri v2: src-tauri/ (Rust, depends on crates/*) + ui/ (React 19, Vite)
packages/
  ui/                 # design tokens + React components shared by web, docs, desktop
  tsconfig/  eslint-config/
  api-types/          # TS types generated from Rust (ts-rs) for license/sync/daemon APIs
integrations/
  claude-code/        # Claude Code plugin: hooks.json, skills, MCP config, marketplace.json
  cursor/  codex/  grok-build/  openhands/  gemini-cli/
  vscode/             # VS Code extension (TS): status bar, approvals, run-with-locksmith
  github-action/      # use Locksmith in CI runners
  devcontainer-feature/
infra/                # OpenTofu: Cloudflare (Pages, R2, DNS), Fly.io/ECS for services
tests/  adversarial/  e2e/
docs/                 # internal: v6-review, roadmap, product, ADRs
```
Rules:
- Only `crates/`, `services/` and `apps/desktop/src-tauri` contain Rust.
- Plugins never contain security logic. They are manifests that call `smith hook <agent> <event>`
  (stdin JSON in, decision JSON out) or launch `locksmith-mcp`. One Rust implementation is tested
  once and serves every agent framework.
- `packages/ui` is the one design system. Web, docs and desktop must import it, not fork it.
- Versioning: Rust binaries, desktop and plugins share one product version (`vX.Y.Z` tags).
  Web and docs deploy continuously from `main`.
- Code owners: `crates/ls-crypto`, `ls-ipc`, `ls-broker`, `ls-update` and `ls-license` require a
  security reviewer.

### D1b. Task runner and CI
`just` recipes wrap cargo and npm (`just ci`, `just test-rust`, `just test-web`, `just dev web`).
CI uses `dorny/paths-filter` to run only the affected jobs: rust, web, docs, desktop or
integrations. `just ci` locally runs everything. Turborepo and Nx were rejected because npm
workspaces plus path-filtered CI cover this repo size without another tool to learn.

### D2. CLI framework
`clap` derive with `clap_complete`. Exit codes: 0 ok, 1 generic failure, 2 usage, 3 blocked by
policy, 4 locked or auth required, 5 not found, 10+ reserved. `--json` makes every command print
exactly one JSON document on stdout. Human text goes to stderr in JSON mode.

### D3. Doctor registry
A `Check` trait with `id` (dotted, stable, e.g. `platform.memlock`), `run() -> Outcome {status: ok|warn|fail|skip, summary, remediation?, fixable: bool}`.
Checks register through `inventory` so later crates add checks without editing a central list.
The JSON schema is versioned (`doctor.v1`) and snapshot-tested.

### D4. Release and basic self-update
A hand-written `release.yml` publishes raw `smith-<triple>` binaries to GitHub Releases, plus a minisign signature over `manifest.json`
(`{version, targets: {triple: {url, sha256}}}`). The minisign public key is compiled into `smith`.
The update path is: download to a temp file in the same directory, verify SHA-256, `rename()` over
the running binary (safe on Unix), then re-exec `smith --version` as a smoke test. Downloading from
a private repo requires `GH_TOKEN`. That is fine for internal testers, and M12 moves distribution to
a public CDN.

As built: `Source::GitHub` resolves assets through the GitHub API with `GH_TOKEN`. It follows the storage redirect *without* the token. `Source::Http` serves any mirror (`LOCKSMITH_UPDATE_URL`). The new binary is smoke-tested (`--version`) *before* the rename, so a broken build never replaces a working one. cargo-dist was dropped for M0: its installers and Homebrew tap assume public downloads, which a private repo cannot serve. It is reconsidered in M12.

Alternative rejected: `axoupdater`. It is convenient, but it trusts the GitHub release without our
own signature, and we would replace it in M12 anyway.

### D5. Adversarial harness
`tests/adversarial/run.sh <case>` runs inside a throwaway `$HOME`. The oracle plants canary secrets
(random 32-byte, base64url) and greps every captured artifact (stdout/stderr, transcript JSONL,
`git log -p`, shell history, files under the work tree) for the canary in all redactor encodings.
Live-agent mode (`--agent claude`) runs `claude -p` with the attack prompt. It runs nightly and only
when `ANTHROPIC_API_KEY` is present in CI secrets.

## Risks / Trade-offs

- Private repo releases need auth → internal testers only until M12. Accepted.
- minisign key custody: the key is held in GitHub Actions secrets for now and moves to KMS-backed TUF
  roles in M12.
