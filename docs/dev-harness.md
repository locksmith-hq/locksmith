# Dev harness

Local stack that makes the system observable to agents. Start it with `just up`; stop with `just down`; wipe with `just reset`.

## What runs (all ports bind 127.0.0.1)

| Service | Image | Port | Purpose |
|---|---|---|---|
| postgres | `postgres:18` | 5432 | the only datastore |
| lgtm | `grafana/otel-lgtm:0.41.0` | 3000 Grafana, 4317 OTLP gRPC, 4318 OTLP HTTP | logs (Loki), traces (Tempo), metrics (Prometheus) |
| openbao | `openbao/openbao:2.7.2` (dev mode) | 8200 | stand-in KMS (transit engine) |
| upstream | `wiremock/wiremock:3.13.2` | 8089 | mock third-party API that records requests |

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
