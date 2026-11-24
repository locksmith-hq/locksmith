# Dev harness

Local stack that makes the system observable to agents. Start it with `just up`; stop with `just down`; wipe with `just reset`.

## What runs (all ports bind 127.0.0.1)

| Service | Image | Port | Purpose |
|---|---|---|---|
| postgres | `postgres:18.7` | 5432 | the only datastore |
| lgtm | `grafana/otel-lgtm:0.41.0` | 3000 Grafana, 4317 OTLP gRPC, 4318 OTLP HTTP | logs (Loki), traces (Tempo), metrics (Prometheus) |
| openbao | `openbao/openbao:2.7.2` (dev mode) | 8200 | stand-in KMS (transit engine) |
| upstream | `wiremock/wiremock:3.13.2` | 8089 | mock third-party API that records requests |
| floci | `floci/floci:2.5.0` | 4566 | local AWS (STS, IAM, S3 and more) for every AWS-API test (`AWS_ENDPOINT_URL_STS=http://localhost:4566`) |
| keycloak (profile `auth`) | `keycloak/keycloak:26.0.8` (`start-dev`) | 8180 | local OIDC issuer, realm `locksmith` imported from `infra/compose/keycloak/locksmith-realm.json` (clients `locksmith-web`, `locksmith-desktop`, `smith-cli`; users `alice@locksmith.test` verified, `bob@locksmith.test` unverified; Google and GitHub stubs with placeholder client ids) |
| mailpit (profile `auth`) | `axllent/mailpit:v1.21.8` | 8025 UI and API, 1025 SMTP | catches Keycloak verification and reset mails |

`just up` starts everything including the `auth` profile; `just up-lite` skips Keycloak and mailpit. `just api` trusts the Keycloak realm (`LOCKSMITH_OIDC_*` in `.env.example`; audience `locksmith-api`). `just auth-e2e` (needs `just up` and `just api`) runs sign-up, verification, auth code + PKCE sign-in, reset and API calls; Google and GitHub are tested only up to the `kc_idp_hint` redirect to the provider (no mock IdP).

Dev credentials are in `infra/compose/.env.example`. They are dev-only and never real.

## MCP servers (`.mcp.json`)

Both run through `docker run -i --rm --network host`, so the stack must be up first.

| Question | Tool |
|---|---|
| What tables and rows are in the DB? | `postgres` MCP (`crystaldba/postgres-mcp:0.3.0`, `--access-mode=restricted`, read-only): `list_schemas`, `list_objects`, `execute_sql` |
| What did a service log? | `grafana` MCP (`grafana/mcp-grafana:2.3.0`, `--disable-write`): `query_loki_logs`, `list_loki_label_names` |
| What did a request trace through? | `grafana` MCP Tempo tools |
| Metrics | `grafana` MCP PromQL tools |
| What did the upstream receive? | `curl localhost:8089/__admin/requests` |

Grafana in `otel-lgtm` allows anonymous access on localhost, so the grafana MCP needs no service-account token. If a later change turns auth on, add `GRAFANA_SERVICE_ACCOUNT_TOKEN` to the `grafana` entry.

The postgres DSN uses `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB` from your shell, defaulting to the dev values.

## Troubleshooting

- **Docker daemon down:** `sudo service docker start`, or `dockerd &` in a sandbox.
- **ghcr.io blocked (403):** the compose file uses Docker Hub images. Override with `OPENBAO_IMAGE`.
- **grafana MCP hangs or prints an SSE banner:** the image defaults to SSE; `.mcp.json` passes `-t stdio`.
- **Loki labels empty:** nothing has logged yet. Send an OTLP log to `127.0.0.1:4318`.
- **`just ps` shows unhealthy:** `just logs <svc>`.

## Troubleshooting: MCP servers on macOS
`.mcp.json` runs the MCP containers with `--network host` so they can reach `127.0.0.1`. On Docker Desktop this needs host networking enabled (Settings, Resources, Network, 4.34 or later). Without it, point `DATABASE_URI` and `GRAFANA_URL` at `host.docker.internal` instead.

## Control-plane API (`just api`)
`just up` first, then `just api` (dev auth on, binds 127.0.0.1:8080, exports traces and logs to the LGTM container over OTLP HTTP).

- API proxy (B5): `just up` also starts `api-proxy` on `127.0.0.1:8088` (`LOCKSMITH_PROXY_PORT`). It sends each path to the Rust control plane (8080, `just api`) or the NestJS API (8081, `just api-nest`) by the owner in `apps/api/route-table.json`; every route is `rust` today. Check with `curl -si localhost:8088/healthz | grep -i x-locksmith-upstream`. Point the web dev server at it with `LOCKSMITH_API_URL=http://127.0.0.1:8088 npm run dev --workspace apps/web`, and the desktop control-plane URL setting at the same address.
- Create a project: `curl -H 'X-Locksmith-Dev-Org: <uuid>' -H 'content-type: application/json' -d '{"name":"demo"}' localhost:8080/v1/projects`
- List: `curl -H 'X-Locksmith-Dev-Org: <uuid>' localhost:8080/v1/projects`; contract: `curl localhost:8080/openapi.json`; readiness: `curl localhost:8080/readyz`.
- Traces: Grafana datasource proxy, e.g. `curl -s 'localhost:3000/api/datasources/proxy/uid/tempo/api/search?tags=service.name%3Dlocksmith-api'` (or the `grafana` MCP). Logs: Loki `{service_name="locksmith-api"}`.
- Leak check after tests that use a canary: `just leak-scan`.

Per-component test commands: [testing.md](testing.md).
