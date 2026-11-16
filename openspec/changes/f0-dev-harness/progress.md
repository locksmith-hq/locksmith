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
