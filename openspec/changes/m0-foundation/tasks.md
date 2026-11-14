# Tasks

## 1. Workspace and tooling

- [ ] 1.1 Create the Cargo workspace (`Cargo.toml`, `rust-toolchain.toml` pinned stable, edition 2024, `[workspace.lints]` denying `unsafe_code` except in `ls-platform`) with empty crates from design D1. Verify: `cargo check --workspace` passes.
- [ ] 1.1a Create the npm workspaces root (`package.json` with `workspaces: [apps/*, packages/*, integrations/*]`, `.nvmrc`), `packages/tsconfig`, `packages/eslint-config`, and placeholder `apps/web`, `apps/docs`, `packages/ui` with a build script each. Verify: `npm i && npm run build --workspaces --if-present` passes.
- [ ] 1.1b Create the remaining top-level dirs from design D1 (`services/`, `integrations/`, `infra/`, `tests/e2e/`) with a README stating each dir's purpose and language rule. Verify: `just tree-check` (a script asserting no `.rs` outside the allowed dirs and no `package.json` inside `crates/`) passes.
- [ ] 1.1c Add the root `justfile` (`ci`, `fmt`, `lint`, `test-rust`, `test-web`, `dev <app>`). Verify: `just ci` runs green locally on macOS and Linux.
- [ ] 1.2 Add `deny.toml` (license allowlist, ban `openssl` in favor of `rustls`, deny yanked and advisories) and `rustfmt.toml`. Verify: `cargo deny check` and `cargo fmt --check` pass.
- [ ] 1.3 Write `CLAUDE.md` and `AGENTS.md` (build/test commands, the security rules from openspec/config.yaml, the OpenSpec workflow) plus `SECURITY.md` and `CODEOWNERS`. Verify: files exist and `CLAUDE.md` commands run as written.

## 2. CI

- [ ] 2.1 GitHub Actions `ci.yml` with `dorny/paths-filter`. Rust job: fmt, clippy `-D warnings`, test on `macos-14` and `ubuntu-24.04` (x86_64 + arm64), `cargo check` on `windows-2022`, `cargo deny`. Web job: lint, typecheck, Vitest, build for `apps/*` and `packages/*`. Verify: a docs-only PR runs only the web job, and a crate PR runs only Rust.
- [ ] 2.2 Enable branch protection on `main` (required CI, 1 review), GitHub secret scanning and push protection. Verify: a direct push to `main` is rejected.

## 3. CLI core

- [ ] 3.1 Implement `smith` with clap: `--version`, global `--json`, exit-code enum (spec cli-core), `completions`. Verify: `cargo test -p smith-cli` covers the version JSON shape, the unknown-flag exit code 2, and the zsh completion output.
- [ ] 3.2 Add `ls-core` config paths (XDG on Linux, `~/Library/Application Support/Locksmith` on macOS) with 0700 creation. Verify: unit test asserts the directory mode.

## 4. Doctor

- [ ] 4.1 Implement the `ls-diag` check registry (`inventory`), the human renderer and the `doctor.v1` JSON plus its published JSON schema in `docs/schemas/doctor.v1.json`. Verify: snapshot test with `insta`, and schema validation test.
- [ ] 4.2 Add the foundation checks `platform.supported`, `fs.config_dir_perms`, `binary.signature`, `update.reachable`. Verify: a test sets the dir to 0755 and asserts fail plus remediation text.

## 5. Release and self-update

- [ ] 5.1 Configure `cargo-dist` (macOS universal, Linux gnu+musl x86_64/arm64, shell installer, Homebrew tap) and a `release.yml` triggered by `v*` tags. Verify: tag `v0.0.1-alpha.1` produces a GitHub Release with archives and checksums.
- [ ] 5.2 Generate a minisign keypair, store the secret key in Actions secrets, sign `manifest.json` in `release.yml`, embed the public key in `ls-update`. Verify: `minisign -V` on the release manifest succeeds.
- [ ] 5.3 Implement `smith self update [--check]` with the hash plus signature check and atomic rename. Verify: integration test against a local HTTP fixture covers the valid, tampered-hash, bad-signature and interrupted-download cases.

## 6. Adversarial harness skeleton

- [ ] 6.1 Create `tests/adversarial/` with `run.sh`, the canary generator and the leak oracle (plain, base64 at 3 offsets, base64url, hex, percent, JSON-escaped). Verify: the oracle self-test detects a canary planted in each encoding.
- [ ] 6.2 Add the `adversarial.yml` nightly workflow (scripted mode always, live-agent mode when `ANTHROPIC_API_KEY` is set). Verify: a manual dispatch runs green with zero cases.

## 7. Milestone acceptance

- [ ] 7.1 Fresh-machine test: install from the release on a clean macOS VM and an Ubuntu container, run `smith doctor`, publish `v0.0.1-alpha.2`, run `smith self update`. Verify: the recorded transcript is attached to the milestone PR.
