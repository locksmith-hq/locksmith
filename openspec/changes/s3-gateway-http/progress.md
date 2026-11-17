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

## 2026-11-17 19:52 worker
- Task: 3.1, 3.2, 3.3, 3.4 - done
- Verified: `cargo nextest run -p ls-gateway` -> 33 passed (incl. testcontainers `audit_pg`); `cargo nextest run -p ls-control-plane` green after the migration-list update; `cargo clippy -p ls-gateway --all-targets -- -D warnings` clean; `cargo fmt --check` clean; tree-check and task guard OK. `just ci` not run in this session.
- Notes for next session: modules `decrypt` (ControlPlane material client, `Unwrapper` over any `KeyWrapper`, `DekCache` 60 s / 1000, sweeper), `egress` (exact origin match, ls-proxy `is_private`/`is_metadata`, all resolved addrs must pass, reqwest pinned via `resolve_to_addrs`, `Policy::none`, `no_proxy`), `relay` (`POST /v1/relay` JSON envelope in/out, response `{status, headers, body|body_base64}`, fixed error slugs), `audit` (`PgAudit`, `MemoryAudit`). Added migration 0005 (`gateway_audit.version`, `caller`; nullable) and `telemetry::Options.service_name` (gateway = `locksmith-gateway`). Fail-closed choices: non-identity `content-encoding` or body over 10 MiB -> 502; secrets shorter than 8 bytes (ls-redact plain-only) are refused; audit write failure after an upstream call withholds the response (500). For 4.x: gateway env needs `LOCKSMITH_CONTROL_PLANE_URL`, service/caller tokens, `OPENBAO_GATEWAY_TOKEN`, bindings TOML with `allow_private_hosts = true` for the mock upstream.
