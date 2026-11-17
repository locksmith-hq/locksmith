# OSS building blocks (2026-11-16)

Every pick below was checked against the GitHub and crates.io APIs on 2026-11-16 for licence, latest release and activity. Each change's design.md re-checks the version it adopts.

## Selections

The rule throughout: build in-house only what touches plaintext. Everything else comes from these packages.

| Area | Pick | Licence | Version (date) | Runner-up / rejected |
|---|---|---|---|---|
| AEAD | RustCrypto `chacha20poly1305` / `aes-gcm` | Apache/MIT | 0.11.x (2026-08) | `ring` rejected: releases stale since 2025-03, no FIPS |
| FIPS path | `aws-lc-rs` (+ `aws-lc-fips-sys`) | Apache/ISC | 1.19.0 (2026-10-28) | only FIPS-validated Rust option |
| Seal to public key | `hpke` | MIT/Apache (verify) | 0.15.1 (2026-10-28) | `age` 0.12.1 for export/backup files |
| Secret memory | `zeroize` + `secrecy` | Apache/MIT | 1.9.1 / 0.10.3 (2024-10, stable) | n/a |
| KMS (local) | OpenBao transit | MPL-2.0 | 2.7.2 (2026-10-26) | **LocalStack: public repo archived, EULA**. Rejected |
| KMS (cloud) | `aws-sdk-kms` | Apache-2.0 | 1.131.0 (2026-11-10) | behind a `KeyProvider` trait |
| Human auth | `openidconnect` + `webauthn-rs` | MIT / MPL-2.0 | 4.1.0 / 0.6.2 (2026-10-31) | Bundled IdP rejected. Speak generic OIDC: Cognito in our cloud, Keycloak (Apache) locally, document Keycloak and Zitadel (AGPL) for self-hosters. Supabase Auth considered and dropped on 2026-11-17 (owner chose AWS) |
| Workload identity | GitHub/K8s OIDC JWT verification | n/a | n/a | SPIRE 1.16 (Apache) later |
| Authz | `cedar-policy` in-process | Apache-2.0 | 4.14.1 (2026-11-02) | regorus (Rego is harder to author). OpenFGA, SpiceDB and OPA are out-of-process services |
| DB + migrations | `sqlx` (repo moved to transact-rs) | Apache/MIT | 0.9.0 (2026-05-21) | SeaORM, Diesel (ORM not needed) |
| Jobs | `SELECT … FOR UPDATE SKIP LOCKED` first, then `apalis` (Postgres) | MIT | 1.2.0 (2026-11-14) | pgmq needs an extension. sqlxmq is stale |
| HTTP | `hyper` 1.x + `axum` | MIT | 1.12.0 | n/a |
| MITM / injection proxy | `hudsucker` (or keep `ls-proxy`, decided in S3 spike) | Apache-2.0 | 0.25.0 (2026-07-15) | `rama` is pre-1.0 and churns. `pingora` is a reverse proxy, not MITM |
| Postgres relay | `pgwire` | Apache-2.0 | 0.42.3 (2026-11-13) | n/a |
| Audit | in-house SHA-256 hash chain + signed checkpoints | n/a | n/a | Tessera (Go) as the upgrade path. Rekor is too heavy |
| Log export | Vector sidecar | MPL-2.0 | 0.62.0 | n/a |
| OpenAPI | `utoipa` | Apache/MIT | 6.0.0 (2026-09-22) | aide |
| SDK gen | hey-api (TS), OpenAPI Generator (others), progenitor (Rust) | MIT / Apache / MPL | 2026 | Fern and Speakeasy hosted services are paid |
| Secret scanning | betterleaks or gitleaks (CLI) | MIT | 1.10.1 (2026-11-12) / 8.30.1 | trufflehog is AGPL: allowed only as a separate process |
| Telemetry | `opentelemetry` crates | Apache-2.0 | 0.33.1 | pin, because it is pre-1.0 |
| Local obs stack | `grafana/otel-lgtm` | Apache-2.0 image (Loki and Grafana inside are AGPL; fine as dev containers) | 0.41.0 (2026-11-13) | Jaeger |
| Tests | nextest, insta, proptest, cargo-fuzz, testcontainers, wiremock, Playwright, oha | Apache/MIT | 2026 | k6 is AGPL: allowed only as a CLI |

## MCP servers for agents (local stack)

| Need | Server | Licence | Read-only mode |
|---|---|---|---|
| Postgres | crystaldba/postgres-mcp, with googleapis/mcp-toolbox as the fallback | MIT / Apache | `--access-mode=restricted` / read-only tools |
| Logs, traces, metrics | grafana/mcp-grafana | Apache-2.0 | `--disable-write` |
| Browser e2e | microsoft/playwright-mcp | Apache-2.0 | n/a |
| GitHub | github/github-mcp-server | MIT | `--read-only` |
| Kubernetes (phase 4) | containers/kubernetes-mcp-server | Apache-2.0 | `--read-only` |
| AWS (phase 4) | managed AWS MCP Server (GA 2026-05), awslabs/mcp as fallback | AWS service / Apache-2.0 | read-only role, writes via MCP denied (A0 decision 18) |

Dogfooding: these MCP servers take DB URLs and tokens from env. Once S4 lands, route them through Locksmith.

## Prior art

Ideas only; no copying of non-permissive code.

- **OpenBao (MPL):** reuse for KMS.
- **Vault:** BSL. Do not embed.
- **Infisical:** see [infisical.md](infisical.md). Never copy `ee/`.
- **Phase:** custom licence. Its pitch is "keep secrets from AI agents".
- **SOPS (MPL):** export format.
- **1Password and Bitwarden:** possible provider backends.

## Not verified

- the exact licence texts of aws-lc-rs, regorus, Phase and agent-vault
- the `hpke` crate licence
- read-only flags for the Docker, AWS and LocalStack MCP servers
