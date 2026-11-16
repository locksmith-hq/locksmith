# Progress: f0-dev-harness

Append-only session log for this change. Each scheduled or human session adds one entry at the end
before its final commit, and every session reads the last entries plus `git log` before starting.
Format:

## <UTC date time> <worker|review|human>
- Task: <id> - <done|failed|blocked|ci-fix>
- Verified: <command> -> <result>
- Notes for next session: <what to know, what to try next, traps found>


## 2026-11-16 19:55 worker
- Task: 1.1-1.4 - done
- Verified: `OPENBAO_IMAGE=openbao/openbao:2.7.2 just up && just ps` -> all four healthy, transit mounted, all host ports 127.0.0.1; sonnet evaluator PASS
- Notes for next session: ghcr.io is blocked in the cloud sandbox (403), so locally export OPENBAO_IMAGE=openbao/openbao:2.7.2 (Docker Hub); default stays ghcr per design. Docker daemon must be started with `dockerd &` (service start fails). Baseline `just ci` in the VM: smith-cli test `same_user_cannot_read_daemon_memory` fails because the VM runs as root (bypasses non-dumpable); environmental, not fixed. test-web needs `npm ci` first. Transit is enabled by the openbao healthcheck (idempotent). Next: group 2 (.mcp.json, docs/dev-harness.md).

## 2026-11-16 20:20 worker
- Task: 2.1, 2.2 - done; 2.3 left unticked
- Verified: drove both MCP servers over stdio with JSON-RPC against `just up`: postgres `list_schemas` returned the schemas; grafana `list_loki_label_names` returned `[]` (no logs yet) from mcp-grafana 2.3.0. 2.3 needs `/mcp` in a live Claude Code session, which a headless run cannot do.
- Notes for next session: mcp-grafana image defaults to SSE, so `.mcp.json` passes `-t stdio`. otel-lgtm allows anonymous Grafana access, so no service-account token is needed. Compose default OPENBAO_IMAGE moved to Docker Hub (L2). Next: 3.1 harness-check.sh, 3.2 CI job, 3.3.

## 2026-11-16 20:54 worker
- Task: 2.3, 3.1, 3.2, 3.3, 4.1 - done
- Verified: `just reset && just up && just harness-check` -> 8 PASS; stopping lgtm -> exit 1; `just mcp-check` -> postgres and grafana PASS; `just ci` -> exit 0
- Notes for next session: Loki is not published on the host, so harness-check queries it through Grafana's datasource proxy (:3000). MCP Inspector 0.17 takes `--config/--server`, not a command line, so mcp-check writes a temp config with ${VAR:-default} expanded. All F0 tasks ticked; no independent evaluator run on this branch (merge review covers it).
