# Contributing

Thanks for helping. Locksmith handles secrets, so a few rules are strict.

## Setup
- Rust (see `rust-toolchain.toml`), Node 22, `just`, Docker.
- npm workspaces only; do not use pnpm or yarn. After changing a `package.json`, run `npm i` in that package's directory.

## Before you open a pull request
- Run `just ci` (fmt, lint, Rust and web tests, layout check, task guard). It must pass locally.
- Keep changes small and focused. Larger features start as an OpenSpec change in `openspec/changes/<id>/` (proposal, design, tasks).
- Reuse a maintained open-source package before writing one, and say which licence it carries. AGPL code must not enter Apache-2.0 components.

## Security rules for code
- Never print, log or serialise a plaintext secret.
- Secrets live only in `secrecy`/`zeroize` types, with no `Debug`, `Display` or `Clone`.
- Agents never receive secret values. Use relay, delegation or short-lived scoped credentials.
- Code that touches secrets is written in Rust.
- Never block unlock or export because of licensing, billing or update failures.

## Licensing of contributions
Contributions are licensed under the licence of the component they change: AGPL-3.0-only for `services/` and `apps/web`, Apache-2.0 elsewhere. See [README.md](README.md#licences).

## Reporting vulnerabilities
Do not open public issues for security problems; follow [SECURITY.md](SECURITY.md).

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
