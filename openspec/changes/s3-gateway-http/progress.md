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

## 2026-11-17 UTC worker (review follow-ups)
- Task: 3.1-3.4 - done (independent opus review PASS; `just ci` green)
- Verified: `just ci` -> exit 0
- Notes for next session: review follow-ups, none blocking. (1) MEDIUM: gateway connects as `locksmith_app`, which is too broad for design decision 2; add a `locksmith_gateway` role with INSERT on `gateway_audit` and EXECUTE on `current_org_id()` only, wire it in 4.1. (2) LOW: egress guard misses NAT64 64:ff9b::/96, 6to4, IPv4-compatible and fec0::/10 ranges; extend `egress.rs` canonicalisation. (3) LOW: ls-redact URL form matches one percent-encoding only (not encodeURIComponent `!*'()`, `+` for space, mixed-case hex). (4) LOW: 401/400 attempts are not audited; spec says every attempt. Task 4.x and 5.x remain.

## 2026-11-17 20:17 UTC worker
- Task: 4.1, 4.2, 4.3, 5.1 - done
- Verified: `just up` + `just api`, `just relay-smoke` -> 1 passed; `just leak-scan` -> clean; `tests/kit/leak_scan_test.sh` -> all PASS (planted canaries detected); `just ci` -> green
- Notes for next session: change is complete; the four review follow-ups in the previous entry (locksmith_gateway role, extra egress ranges, URL-encoding forms, auditing 401/400) are still open and belong in a follow-up change. `just gateway` needs LOCKSMITH_GATEWAY_BINDINGS; relay-smoke starts its own gateway from target/debug.
