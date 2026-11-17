# Progress: s3-gateway-http

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-17 17:38 worker
- Task: none - planning
- Verified: `openspec validate s3-gateway-http --strict` -> valid
- Notes for next session: S3 is [opus] work. Design decision 1 reuses ls-redact and the ls-proxy network guard as libraries; check they are public APIs first. Bindings live in gateway config until T2.

## 2026-11-17 19:00 worker
- Task: 1.1, 1.2 - done
- Verified: `cargo nextest run -p ls-control-plane` -> 55 passed; clippy -D warnings and fmt clean; evaluator (opus) PASS
- Notes for next session: internal route reads org from `X-Locksmith-Org` header sent with the bearer token `LOCKSMITH_GATEWAY_SERVICE_TOKEN` (>=32 bytes). Task 3 gateway must send both; its bindings config must carry the org id. Compose/.env wiring of the token is left for 4.1. Next: task 2 (gateway skeleton).

## 2026-11-17 19:16 worker
- Task: 2.1, 2.2 - done
- Verified: `cargo nextest run -p ls-gateway -p ls-control-plane` -> 62 passed; clippy -D warnings clean; `just ci` green
- Notes for next session: `services/gateway` (ls-gateway) has config (env + bindings TOML with org_id), health/ready, and reuses `ls-control-plane` as a library for telemetry, `Database` and readiness. `gateway_audit` is migration 0004 in the control-plane migrator (the gateway never migrates; it connects as locksmith_app, INSERT/SELECT only). Gap: telemetry SERVICE_NAME is still "locksmith-api"; make it a parameter before the relay span lands in 3.3. Next: task 3 [opus] (decrypt, egress rules, relay, redaction).
