# Contributing to Locksmith

Thanks for helping. Locksmith is a secrets platform, so every change is reviewed as if it could leak a secret. This guide explains how to contribute and the rules a pull request must meet before it can be merged.

## Ways to contribute
- **Report a bug:** open a [bug report](https://github.com/locksmith-hq/locksmith/issues/new?template=bug.yml).
- **Suggest a feature:** open a [feature request](https://github.com/locksmith-hq/locksmith/issues/new?template=feature.yml). Describe the problem first, then your idea.
- **Fix something:** comment on an issue before you start, so nobody duplicates work. Issues labelled `good first issue` are a good start.
- **Improve the docs:** typo and clarity fixes are always welcome as small pull requests.
- **Report a vulnerability:** never in public. Follow [SECURITY.md](SECURITY.md).

## Development setup
You need Rust (the version in `rust-toolchain.toml`), Node 22, [`just`](https://github.com/casey/just) and Docker.

```sh
git clone https://github.com/<you>/locksmith && cd locksmith
npm ci
just ci      # fmt, lint, Rust and web tests, layout check, task guard
just up      # optional: local stack (Postgres, telemetry, mocks)
```

- Use npm workspaces only; never pnpm or yarn. After changing a `package.json`, run `npm i` in that package's directory and commit the lockfile.
- `cargo test -p <crate>` runs one crate's tests. `just dev <app>` runs one app.
- The layout (`crates/`, `services/`, `apps/`, `packages/`, `integrations/`, `infra/`, `tests/`, `scripts/`) is described in [AGENTS.md](AGENTS.md) and enforced by `scripts/tree-check.sh`.

## Pull request workflow
1. Fork the repository and create a branch from `main`.
2. Keep the change small and focused: one fix or feature per pull request. Larger features start as an OpenSpec change in `openspec/changes/<id>/` (proposal, design, tasks); open an issue first to agree the plan.
3. Add or update tests for any behaviour change.
4. Run `just ci`. It must pass locally; CI runs only lint and hygiene checks, so reviewers rely on your local run.
5. Write clear commit messages: a short imperative subject line (`ls-proxy: reject unsigned S3 requests`), then the why in the body.
6. Open the pull request, fill in the template, and link the issue (`Fixes #123`).

## Review and merge
- Every pull request from outside the core team needs an approving review from a code owner (`.github/CODEOWNERS`) and green checks. Nothing from a fork is merged automatically.
- A first-time contributor's workflow runs wait until a maintainer approves them.
- A new push after approval may need a fresh review. Reply to every review comment before asking for another look.
- Maintainers may close pull requests that are stale, out of scope, or that ignore this guide. That is not personal; you can reopen with the issues addressed.

## What will not be merged
These rules protect users who trust Locksmith with their credentials. A pull request that breaks one is closed, and deliberate attempts lead to a ban (see the [Code of Conduct](CODE_OF_CONDUCT.md)).
- Obfuscated, minified or generated code without its source and generator, and committed binaries or archives.
- New dependencies without a reason, a maintained upstream, and a compatible licence. Typosquatted or brand-new packages are rejected.
- Changes to `.github/`, CI, release, signing, install or update scripts unless an issue asked for them first. These are reviewed by the owner only.
- Network calls, telemetry, or files written outside the documented paths that the pull request does not state clearly.
- Weakening a test, check, lint rule or security control to make a change pass.
- Unrelated changes hidden in a large diff (formatting sweeps mixed with logic, mass renames).

## Security rules for code
- Never print, log or serialise a plaintext secret.
- Secrets live only in `secrecy`/`zeroize` types, with no `Debug`, `Display` or `Clone`.
- Agents never receive secret values. Use relay, delegation or short-lived scoped credentials.
- Code that touches secrets is written in Rust.
- Never block unlock or export because of licensing, billing or update failures.
- Never commit real credentials, even expired ones. Test fixtures use obviously fake values; `gitleaks` runs in CI.

## AI-assisted contributions
You may use AI tools. You are the author: you must understand, test and be able to explain every line you submit. Say in the pull request which parts were AI-generated. Unreviewed bulk output is closed.

## Licensing of contributions
Contributions are licensed under the licence of the component they change: AGPL-3.0-only for `services/` and `apps/web`, Apache-2.0 elsewhere. See [README.md](README.md#licences). Reuse a maintained open-source package before writing one, and state its licence. AGPL code must not enter Apache-2.0 components.

## Getting help
Ask in the issue you are working on, or open a new issue with your question.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
