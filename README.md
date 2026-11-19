# Locksmith

Locksmith is an open-source secrets platform and credential gateway for AI coding agents. Agents perform authenticated operations (Git, HTTP APIs, databases, AWS) without ever holding the real credential.

Instead of handing a key to an agent, Locksmith keeps it in an encrypted local vault and acts on the agent's behalf: it signs, relays or injects the credential for a session you started, and you can revoke that session at once.

## Security promise

- Agents never receive secret values. They get relay access, delegation or short-lived scoped credentials (`lsk_` tokens).
- Every protection is labelled honestly:
  - **Prevention**: the secret never reaches the agent (relays, signing, injection).
  - **Containment**: a leaked token is scoped, short-lived and revocable.
  - **Detection**: redaction and the tamper-evident audit ledger show what happened afterwards.
- Unlock and export are never blocked because of licensing, billing or update failures.
- Secrets live only in `secrecy`/`zeroize` types in Rust, and are never printed, logged or serialised.

Locksmith is pre-release software. Do not rely on it to protect production credentials yet. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Quick start

You need Rust (see `rust-toolchain.toml`), Node 22, [just](https://github.com/casey/just) and Docker.

```sh
git clone https://github.com/locksmith-hq/locksmith
cd locksmith
just up     # start the local stack
just ci     # fmt, lint, tests, layout and task checks
just down   # stop the stack
```

The local daemon is `locksmithd`, the CLI is `smith`, and the desktop app is a Tauri client of the same daemon. macOS and Linux are supported today.

## Layout

| Path | Contents |
|---|---|
| `crates/` | Rust libraries and binaries |
| `services/` | axum backends |
| `apps/` | web, docs, desktop (Tauri) |
| `packages/` | shared TypeScript |
| `integrations/` | thin agent plugins |
| `infra/` | compose, helm, OpenTofu |
| `tests/` | end-to-end and adversarial tests |
| `scripts/` | tooling |

Plans and decisions: [docs/roadmap.md](docs/roadmap.md) and `openspec/changes/`. Product notes: [PRODUCT.md](PRODUCT.md).

## Licences

- Server components (`services/`, `apps/web`) are licensed under AGPL-3.0-only: see [LICENSE](LICENSE).
- SDKs, CLI, crates, plugins, schemas, desktop and docs are licensed under Apache-2.0: see [LICENSE-APACHE](LICENSE-APACHE).
- Vendored third-party data is listed in [THIRD_PARTY.md](THIRD_PARTY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
