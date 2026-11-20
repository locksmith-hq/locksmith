# Design: P2 packaging

## Context

Observed in the repo:
- `.github/workflows/release.yml` builds `smith` for four triples (macOS arm64/x86_64, Linux arm64/x86_64), runs `scripts/make-manifest.sh`, signs `manifest.json` with minisign using the `MINISIGN_SECRET_KEY` Actions secret, verifies against `crates/ls-update/update-pubkey.txt` and creates the release. It publishes no image, SBOM or provenance.
- `crates/ls-update` verifies the minisign manifest and SHA-256 and has `DEFAULT_SOURCE = github://tomer555/locksmith`; `scripts/install.sh` also targets the private `tomer555/locksmith` and requires `gh`.
- No Dockerfile exists. `infra/compose/compose.yaml` is the dev stack (`postgres:18.7`, OpenBao in dev mode with fixed `dev-only-*` tokens, wiremock, LGTM, optional Keycloak and Mailpit). Services are `services/control-plane` (`locksmith-api`) and `services/gateway` (`locksmith-gateway`).
- `infra/` has `compose/` only; Helm and OpenTofu directories are planned by the layout.

Assumed, to be confirmed by task 1.1 and recorded in `docs/research/packaging.md`: exact tool versions and release dates (this plan was written offline, so none are cited as fact), how the web console bundle is served, which environment variables the two services read, and whether the gateway can use a key provider other than OpenBao transit. No later task starts before 1.1 and 1.2 pass.

## Decisions and evidence

| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | Keep the minisign-signed `manifest.json` as the trust root for `smith` and self-update; add cosign keyless signatures, SBOM and attestations on top | Replace minisign with cosign only (breaks shipped `smith` self-update and offline verification with a single embedded key) | `crates/ls-update/src/lib.rs`, `release.yml` today; Sigstore keyless uses short-lived certs bound to the workflow identity, so no stored key (cosign docs, URL recorded in 1.1) |
| 2 | Extend the existing `release.yml` instead of adopting cargo-dist | cargo-dist: it would regenerate the release workflow and its own manifest, replacing a working pipeline whose manifest format `ls-update` consumes. Task 1.1 re-checks that it cannot emit our manifest layout and records the result | Existing `release.yml` and `make-manifest.sh`; cargo-dist docs (URL in 1.1) |
| 3 | Build images with `docker buildx` from small multi-stage Dockerfiles, distroless or Alpine-class base, non-root user, multi-arch, pushed to `ghcr.io/locksmith-hq` | Nix or ko-style builders (new toolchain for a Rust workspace that `cargo build --locked` already builds); Docker Hub (rate limits, extra account) | `docs/cloud-dev.md` notes ghcr.io is blocked inside the cloud agent sandbox, so images are built locally with `docker build` and pushed only by the release workflow |
| 4 | Self-host compose is a separate file, `infra/compose/selfhost/compose.yaml`, not the dev file | Reusing the dev compose (dev-only tokens, dev-mode OpenBao, wiremock, LGTM) | `infra/compose/compose.yaml` contents |
| 5 | First-run script generates secrets with `openssl rand` (or `/dev/urandom`) into `.env`, mode 0600; compose reads it; values are never echoed | Fixed defaults in `.env.example` (A0-14 dev tokens must not reach self-hosters); prompting the user | Security rules in `AGENTS.md` |
| 6 | Bundled OpenBao in production mode, single node, file storage, one-key init, unseal key kept in a separate root-only volume; labelled containment, with an external OpenBao or KMS-compatible URL option | Dev-mode OpenBao (in memory, loses keys); mandatory external KMS (kills one-command); Vault (BSL, rejected by project rules) | A0-10, A0-14; owner confirms the default in the Gate task |
| 7 | Helm chart reads Postgres DSN, OIDC and key-provider credentials from existing Secret names (`existingSecret` style); a `values.schema.json` rejects literal secret fields; Postgres is not bundled | Bitnami Postgres subchart (image and licensing churn, and mixes a stateful DB into the chart); literal values with a warning | Project rule: no plaintext secret on any path; A0-1 (Postgres is operator-provided, version 18) |
| 8 | Helm tested on a local kind cluster, plus `helm lint` and `kubeconform` on rendered manifests; Postgres for the test comes from a plain pod in the test script | Testing only with `helm template` (does not prove pods start) | Local first rule: everything runs on a laptop before any cloud |
| 9 | TLS via an optional Caddy profile (automatic certificates) and OIDC via any issuer; Keycloak demo profile reuses the existing realm file and is labelled not for production | Building our own proxy; bundling Keycloak as default | A0-15 (generic OIDC only); existing `infra/compose/keycloak/` |
| 10 | Releases are cut by the owner; a `dry_run` workflow input exercises build, sign (test identity) and verify with no publish | Testing only by tagging for real | Owner gate on the first real tag; private/public flip pending in `docs/going-public.md` |
| 11 | Homebrew formula generated from the signed manifest by a script and published to a tap repository by the owner | Writing formula by hand (drifts from the manifest); a Linux package manager (deb/rpm) now | Roadmap row says `smith` installers; macOS and Linux only (owner decision 2026-11-19) |
| 12 | Repository slug becomes `locksmith-hq/locksmith` everywhere (workflow, `install.sh`, `ls-update`) in this change | Keeping the private slug (installer would fail for the public) | AGENTS.md and `openspec/config.yaml` name the canonical repo |

## OSS used

Versions and last-release dates are pinned in task 1.1 from the registries (they could not be fetched when this plan was written, so none are claimed here).

| Package | Licence | Version | Last release date | Why | AGPL check |
|---|---|---|---|---|---|
| cosign (Sigstore) | Apache-2.0 | pin in 1.1 | record in 1.1 | Keyless signing and verification of assets and images | CI tool only, not linked |
| minisign | ISC | already in use (`ls-update` uses `minisign-verify` 0.2 and `minisign` 0.7) | n/a | Existing manifest trust root | Not AGPL |
| actions/attest-build-provenance | MIT | pin in 1.1 | record in 1.1 | GitHub build provenance attestation | Workflow step only |
| syft or cargo-cyclonedx | Apache-2.0 | pin in 1.1 (one is chosen) | record in 1.1 | CycloneDX SBOM for binaries and images | CI tool only |
| Helm | Apache-2.0 | pin in 1.1 | record in 1.1 | Chart packaging and lint | CI tool only |
| kind | Apache-2.0 | pin in 1.1 | record in 1.1 | Local Kubernetes for the chart test | Test tool only |
| kubeconform | Apache-2.0 | pin in 1.1 | record in 1.1 | Schema validation of rendered manifests | Test tool only |
| Caddy | Apache-2.0 | image tag pinned in 1.1 | record in 1.1 | Optional TLS reverse proxy with automatic certificates | Container image; not linked |
| OpenBao | MPL-2.0 | `2.7.2` as in dev compose; production pin in 1.1 | record in 1.1 | Key provider (already chosen, A0-14) | MPL, not AGPL |
| docker buildx / BuildKit | Apache-2.0 | host or CI | n/a | Multi-arch builds | Tool only |

AGPL: the server components (control plane, gateway) are AGPL-3.0 and shipped in images; the images carry the licence text and a source link. `smith` stays Apache-2.0 and no AGPL code enters it.

Built in-house, after searching first: `scripts/verify-release.sh` (a thin wrapper that calls minisign, cosign and `sha256sum`, because no single tool checks our manifest layout), `scripts/gen-formula.sh` (about 30 lines templating the manifest into a formula; Homebrew has no manifest-driven generator that preserves our signature flow), and the first-run secret generator (a few lines of shell over `openssl rand`). cargo-dist was searched first and rejected for the reason in decision 2.

## Layout and flow

```
tag vX.Y.Z (or dry_run) -> build 4 triples -> archives + manifest.json
   -> minisign sign manifest -> cosign sign (archives, manifest, images) -> SBOM -> attest
   -> buildx multi-arch images -> verify-release.sh -> publish (not in dry run)
```

- `infra/compose/selfhost/`: `compose.yaml`, `.env.example` (variable names, no values), `bootstrap.sh` (generate secrets, init OpenBao once, refuse dev-only values), optional profiles `tls` (Caddy) and `demo-oidc` (Keycloak).
- `infra/helm/locksmith/`: `Chart.yaml`, `values.yaml`, `values.schema.json`, templates for the two Deployments, Services, migration Job, optional Ingress and a NetworkPolicy.
- Dockerfiles live in `infra/docker/` (one per service) so `services/` keeps only Rust.
- `justfile` recipes: `selfhost-up`, `selfhost-smoke`, `helm-test`, `release-dry-run`, `release-verify`, `installer-test`. Each has a `docs/testing.md` row where the layout check requires one.

## Risks

- A self-hosted bundled key provider is weaker than a managed KMS: labelled containment, with the external option documented, and the owner confirms the default (Gate task).
- The first real release needs the owner: repo public, tag cut, tap repository created. Until then everything is proven by dry run.
- Cosign keyless needs the Actions OIDC token and a public Rekor/Fulcio; the dry run uses a test identity and the verify script documents the offline limit. The minisign check still works with no network.
- The OpenBao init key in a volume next to data can be read by anyone with the host's root; that is the documented containment boundary, not prevention.
- Image-size and build time on four targets: builds run in parallel per triple, and the dry run builds one triple on a branch.

## How an agent debugs this

- `just selfhost-up` then `docker compose -f infra/compose/selfhost/compose.yaml ps` and `logs <service>` (no secret values appear in logs; the leak scan checks that). `just selfhost-smoke` runs the end-to-end request.
- `just helm-test` creates a kind cluster, installs the chart and prints pod status and events on failure; `kubectl logs` for the two services.
- `just release-dry-run` then `just release-verify <dir>` for signature, hash, SBOM and provenance results, one line per asset.
- Existing MCP servers in `.mcp.json` (Postgres, Grafana/LGTM via `just up`) still apply for the dev stack; the self-host bundle exposes the same OTLP variables so traces can go to a local LGTM when it is running. Tables touched: the control plane's migrated schema only; this change adds none.
- `just leak-scan` over images, logs and release directories; `smith --version` reports version and channel; `smith update --check` exercises self-update.
