# Tasks: F0 dev harness

## 1. Compose stack
- [x] 1.1 Add `infra/compose/compose.yaml` with postgres, lgtm, openbao (dev mode, transit enabled by an init command), and wiremock. Pin the versions from design.md, add healthchecks, and bind all ports to 127.0.0.1.
- [x] 1.2 Add `infra/compose/.env.example` with dev-only values. Gitignore `.env`.
- [x] 1.3 Add `just up`, `down`, `reset` (down -v), `logs svc`, `psql`, `ps` recipes.
- [x] 1.4 Verify: `just up && just ps` shows all four healthy.

## 2. Agent visibility
- [x] 2.1 Add `.mcp.json` with the `postgres` MCP (restricted/read-only, DSN from `.env`) and the `grafana` MCP with `--disable-write` (pointing at http://127.0.0.1:3000, service-account token created by the compose init). If postgres-mcp fails, fall back to googleapis/mcp-toolbox with read-only tools. Run both via docker or `uvx`/binary. Pin versions.
- [x] 2.2 Add `docs/dev-harness.md`: what runs, ports, which MCP tool answers which question, and troubleshooting.
- [x] 2.3 Add `scripts/mcp-check.sh`. It starts each server in `.mcp.json` through the MCP Inspector CLI (`npx -y @modelcontextprotocol/inspector --cli ... --method tools/list`; check the exact flags with `--help`) and makes one read call per server: the postgres MCP lists schemas or tables, and the grafana MCP lists Loki labels. Add a `just mcp-check` recipe. Verify: `just up && just mcp-check` exits 0. (The interactive `/mcp` command cannot be used by cloud agents.)

## 3. Harness check
- [x] 3.1 `scripts/harness-check.sh`. It checks each healthcheck, that no port binds 0.0.0.0, that an OTLP log (via `curl` to 4318) can be found in Loki, that the OpenBao transit can encrypt and decrypt a test string, and that the WireMock journal records a request. It prints one PASS/FAIL line per check.
- [x] 3.2 Add the `just harness-check` recipe. It runs in the agent VM (free compute), not in GitHub Actions: there is no harness CI job, because Actions minutes are reserved for build and test.
- [x] 3.3 Verify: `just reset && just up && just harness-check` exits 0, and stopping lgtm makes it exit non-zero.

## 4. Local verification
- [x] 4.1 `just up && just harness-check && just ci`
