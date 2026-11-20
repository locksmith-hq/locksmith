# Proposal: P2 packaging

## Why

Today a self-hoster must read `infra/compose/compose.yaml` (a dev stack with fixed dev-only tokens, OpenBao in dev mode and no service images) and build the workspace from source. The release workflow publishes `smith` binaries with a minisign-signed manifest, but it points at the old private repository, has no container images, SBOM or provenance, and `scripts/install.sh` needs an authenticated `gh`. The product promise, never hold users' secrets hostage, includes being able to run and verify Locksmith without us. Roadmap row P2 needs no other change, so it can run in parallel.

## What Changes

- Add container images for `locksmith-api` (control plane) and `locksmith-gateway`, built for linux/amd64 and linux/arm64, non-root and minimal.
- Add a self-host compose bundle under `infra/compose/selfhost/`: Postgres 18, OpenBao (production mode, single node), control plane, gateway, optional TLS reverse proxy and optional demo OIDC issuer. One command brings it up; first run generates random secrets into a root-only `.env`, never committed and never printed.
- Add a Helm chart `infra/helm/locksmith` (control plane, gateway, config, migrations job) that takes the Postgres DSN, OIDC settings and key-provider settings as references to existing Kubernetes Secrets, never values. Tested on a local `kind` cluster.
- Extend the release pipeline: keep the minisign manifest that `smith` self-update verifies, and add keyless cosign signatures (Sigstore, GitHub OIDC identity) for archives, manifest and images, a CycloneDX SBOM and a GitHub build provenance attestation. Add `scripts/verify-release.sh` so anyone can check a release with public tools.
- Move the release source, `scripts/install.sh` and `smith` self-update from the private `tomer555/locksmith` repo to the public `locksmith-hq/locksmith`; the installer no longer needs `gh`.
- Installers for macOS and Linux: the verifying `install.sh` (no `gh` needed) and a Homebrew tap formula generated from the signed manifest. No new `smith` subcommand is added for self-hosting.
- A dry-run mode for the release workflow so everything above is tested without publishing a release.

Usable outcome: on a clean macOS or Linux host with Docker, one command starts a working Locksmith (API, gateway, database, key provider); on a Kubernetes cluster, one `helm install` does the same; and `curl -fsSL <url> | sh` installs a `smith` whose signature, checksum and provenance can be verified with `cosign`, `minisign` and `gh attestation verify`.

Out of scope: Windows installers, MSI, winget or Scoop (macOS and Linux only; owner decision 2026-11-19 and decision X1-1); `.deb`/`.rpm` packages; desktop app installers and notarization; cloud (AWS) deployment, which is P1; an upgrade controller or Kubernetes operator; high-availability Postgres or multi-node OpenBao; cargo-dist adoption (rejected in design); publishing to a Helm repository other than GitHub Pages or OCI on `ghcr.io`; any web console or desktop surface (packaging has none); changes to secrets handling or gateway behaviour.

Depends on: none.

## Capabilities

### New Capabilities
- `self-host-packaging`: container images, the compose bundle and the Helm chart that run Locksmith on the user's own infrastructure with generated secrets and honest security labels.
- `signed-releases`: how a release is built, signed (minisign and cosign), described (SBOM, provenance) and verified, without any signing key in the repository.
- `smith-installers`: how `smith` gets onto a macOS or Linux machine and verifies itself.

### Modified Capabilities

## Impact

- Code and files: new `services/*/Dockerfile` (or `infra/docker/`), `infra/compose/selfhost/`, `infra/helm/locksmith/`, `scripts/{verify-release,selfhost-smoke,helm-test}*.sh`, `scripts/install.sh`, `scripts/make-manifest.sh`, `crates/ls-update` (source constant only), `justfile`, `docs/testing.md`, `apps/docs` install pages.
- `.github/workflows/release.yml` and any new workflow are protected paths (`scripts/check-task-edits.sh` trust root): those tasks are lead PRs the owner merges.
- New CI tools (cosign, helm, kind, kubeconform, syft) are pinned in `scripts/ci-tools.sh`; no new runtime dependency in any Rust crate.
- Signing material: the `MINISIGN_SECRET_KEY` Actions secret already exists and is referenced by name only; cosign is keyless, so there is no new key. No plaintext secret appears in any image, chart, compose file or log.
