# Design: F0 dev harness

## Stack (infra/compose/compose.yaml)
| Service | Image | Port (localhost only) | Purpose |
|---|---|---|---|
| postgres | `postgres:18` | 5432 | the only datastore |
| lgtm | `grafana/otel-lgtm` | 3000 Grafana, 4317/4318 OTLP | logs, traces, metrics in one container |
| openbao | `openbao/openbao` on Docker Hub (dev mode; ghcr.io returned 403 in the Claude cloud sandbox on 2026-11-16, lesson L2, transit enabled) | 8200 | stand-in KMS for gateway keys (S2) |
| upstream | `wiremock/wiremock` | 8089 | mock third-party API that records what it received |

All ports bind `127.0.0.1`. Dev credentials live in `infra/compose/.env.example`. They are dev-only and never real.

## Decisions and evidence
| Decision | Alternatives rejected | Evidence |
|---|---|---|
| `grafana/otel-lgtm` single container | Separate Jaeger + Loki + Prometheus (more moving parts) | Apache-2.0, v0.41.0 released 2026-11-13, https://github.com/grafana/docker-otel-lgtm |
| Grafana MCP for logs and traces | One MCP per backend | `grafana/mcp-grafana` Apache-2.0, v2.3.0 2026-11-10, covers Loki, Prometheus, Tempo: https://github.com/grafana/mcp-grafana |
| Postgres MCP `crystaldba/postgres-mcp` in `--access-mode=restricted` | Official reference server (archived) | MIT; last release v0.3.0 2025-05, repo active 2026-08. **Watch item:** release cadence is slow; re-check in S1 and swap if it stalls. https://github.com/crystaldba/postgres-mcp |
| OpenBao transit as local KMS | LocalStack KMS | LocalStack's public repo is **archived** (verified 2026-11-16, `archived: true`) and has no OSS licence assertion. OpenBao is MPL-2.0, v2.7.2 2026-10-26: https://github.com/openbao/openbao |
| WireMock as mock upstream | Hand-written mock server | MIT image, request journal is queryable over `/__admin/requests`, so tests can assert what the upstream received. https://github.com/wiremock/wiremock-docker |
| Docker Compose v2 | Tilt, k3d | Simplest thing that runs on macOS and Linux. Helm arrives in P2. |

## OSS used
| Package | Licence | Version | Last release | AGPL check |
|---|---|---|---|---|
| grafana/otel-lgtm | Apache-2.0 | 0.41.0 | 2026-11-13 | dev-only, not shipped |
| grafana/mcp-grafana | Apache-2.0 | 2.3.0 | 2026-11-10 | dev-only |
| crystaldba/postgres-mcp | MIT | 0.3.0 | 2025-05-16 | dev-only |
| openbao/openbao | MPL-2.0 | 2.7.2 | 2026-10-26 | dev-only here; MPL is fine for server use |
| wiremock/wiremock | MIT/Apache-2.0 | 3.13.x | 2026-03 | dev-only |

Pin image tags by version, never `latest`.

## Nothing built in-house except glue
- The `just` recipes.
- `scripts/harness-check.sh`, a curl- and psql-based health and MCP smoke check.

## How an agent debugs this
- **DB:** the `postgres` MCP tools, or `just psql -c '...'`.
- **Logs:** the `grafana` MCP `query_loki_logs`, or `just logs <svc>`.
- **Traces:** the `grafana` MCP Tempo search.
- **Metrics:** the `grafana` MCP PromQL.
- **Upstream:** the requests the upstream received are at `curl localhost:8089/__admin/requests`.
- **Whole stack:** `just harness-check` prints one PASS/FAIL line per service.

## Platforms
macOS (Docker Desktop or OrbStack) and Linux. Windows: later (phase 6).
