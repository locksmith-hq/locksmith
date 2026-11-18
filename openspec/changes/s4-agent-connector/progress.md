# Progress: s4-agent-connector

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-17 22:00 worker
- Task: none - planning
- Verified: `openspec validate s4-agent-connector --strict`
- Notes for next session: depends on s3-gateway-http (PR 168). S4 gateway tasks are [opus]. Re-check jsonwebtoken and signing-crate versions on crates.io before adding them.

## 2026-11-17 worker (opus subagent)
- Task: 1.1, 1.2, 1.3 (control-plane agents, grants, tokens, JWKS, internal grants lookup). Not ticked; awaiting independent evaluation.
- Verified: `cargo nextest run -p ls-control-plane -p ls-crypto -p ls-gateway`, `cargo clippy --all-targets -D warnings`, `cargo fmt --check`, `cargo deny check` (jsonwebtoken 12.0.0 rust_crypto pulls rsa 0.10.0; no advisory).
- Decisions: enrollment secret is "one-time" in the sense of shown once (registration or `POST /v1/agents/{id}/enrollment-secret` rotation), reusable for minting until rotated or the agent is deleted; a single-use secret would strand the agent after 15 minutes with no refresh path. Secret format `lse_` + base64url(org||agent||32 random bytes) so the token endpoint needs one credential. Argon2id cost m=19 MiB t=2 p=1 (OWASP) via new `ls_crypto::verifier`. Signing key `LOCKSMITH_AGENT_SIGNING_KEY` (base64 Ed25519 seed); unset + dev auth = ephemeral key, unset otherwise = 503. kid = RFC 7638 thumbprint.
- Notes for next session (task 2.1): reuse `ls_control_plane::agent_token::{verify, validation, Jwk::decoding_key}`; JWKS publishes only the current key (no retired-key list yet). Compose/justfile do not set `LOCKSMITH_AGENT_SIGNING_KEY` yet (dev auth uses an ephemeral key).

## 2026-11-17 22:30 worker
- Task: 1.1-1.3 - done
- Verified: `cargo nextest run -p ls-control-plane` -> 74 passed; clippy, fmt, cargo-deny clean (implementer); Opus evaluator PASS
- Notes for next session: next is task 2 (gateway JWT via JWKS, use `Jwk::decoding_key()`, kid overlap on rotation). "one-time" = shown once, reusable until rotated (design.md updated). Follow-ups: rate-limit POST /v1/agent-tokens (Argon2id DoS); set LOCKSMITH_AGENT_SIGNING_KEY in compose (task 5.1). Full `just ci` not run this session.

## 2026-11-17 21:55 lead
- Task: none (code review of the merged S3 gateway, for S4 2.1)
- Finding: bearer parsing exists twice. `services/gateway/src/relay.rs:146-158` uses a case-sensitive `strip_prefix(b"Bearer ")`; `services/control-plane/src/auth.rs:61-75,113-120` has the stricter `bearer()` and `ServiceToken::matches`. The minimum token length rule is also copied (`gateway/src/config.rs:27,176-182` and `control-plane/src/config.rs:24,134-141`).
- Notes for next session: in 2.1, use one shared bearer extractor for the JWT path, and remove `caller_token`, `STATIC_CALLER` (`relay.rs:54`) and `ENV_CALLER_TOKEN` rather than keeping both paths. Optional while in `relay::run`: move response reading and redaction (`relay.rs:479-542`) into its own function before adding the grant check.

## 2026-11-17 21:53 worker
- Task: 2.1 - blocked (parked: task is [opus], gateway auth path; this worker run is on the Sonnet/Haiku tier and did not write auth code)
- Verified: `scripts/worker-has-work.sh` -> s4-agent-connector ready; `scripts/run-lock.sh acquire` ok; PR #215 open, not draft, no ready-to-merge label; main CI latest run in progress (no failure seen)
- Notes for next session: pick up at 2.1 on an Opus tier. Start from the lead notes (61190d3): one shared bearer extractor, remove `caller_token`, `STATIC_CALLER` (relay.rs:54) and `ENV_CALLER_TOKEN`, then JWKS via `Jwk::decoding_key()` with kid overlap. Re-check jsonwebtoken and signing-crate versions on crates.io first. Full `just ci` not run this session.

## 2026-11-18 worker
- Task: 2.1 - done
- Verified: `cargo nextest run -p ls-gateway -p ls-control-plane` -> 122 passed; `just ci` green; Opus evaluator PASS (af0497a)
- Notes for next session: task 2.2 (grants cache <=10 s, grant check before unwrap on /v1/relay, `agent_id` column in gateway_audit, audit denials). Evaluator nice-to-haves: serve cached key during stale-JWKS refresh instead of blocking; tests could assert exact error for alg none/HS256; removed-key overlap (15.5 min) also trusts a leaked key. e2e relay test only compiled, not run (needs `just up`). Unused `subtle` dep removed from gateway.

## 2026-11-18 worker
- Task: 2.2 - done
- Verified: `cargo nextest run -p ls-gateway -p ls-control-plane` -> 130 passed; `just ci` green; Opus evaluator PASS (9194dc4)
- Notes for next session: task 2.3 (verify: forged/expired/wrong-aud token tests, revoke within TTL - mostly covered; confirm and tick). Grant cache holds empty lists up to 10 s, so connector-smoke (5.1) must create the grant before the agent's first call or wait ~10 s. Evaluator nits: log the GrantError kind in relay.rs (~515); design.md decision 4 says "secret binding id" but code uses secret_id; cache `retain` per miss under mutex.

## 2026-11-18 04:29 UTC worker
- Task: 2.3 - done
- Verified: `cargo nextest run -p ls-gateway` -> 56 passed; `just ci` -> 558 passed, 4 skipped, exit 0; Opus evaluator PASS (auth.rs forged/expired/wrong-aud/wrong-org, relay no-grant zero KMS calls, revoked-grant within TTL)
- Notes for next session: next is 3.1 (smith CLI login/grants/relay against gateway). Evaluator nits still open: log GrantError kind in relay.rs (~515); design.md decision 4 says "secret binding id" but code uses secret_id; cache retain per miss under mutex. Grant cache holds empty lists up to 10 s, so connector-smoke (5.1) must create the grant before first call or wait ~10 s. Alg none/HS256 test asserts only that some error is returned.

## 2026-11-18 worker
- Task: 3.1 - done
- Verified: `cargo nextest run -p smith-cli` -> 125 passed; `just ci` exit 0; Sonnet evaluator PASS (request shapes match gateway/control-plane, 0600 state file, no secret in argv/output/state, wiremock integration tests)
- Notes for next session: task 3.2 (locksmith-mcp `list_grants`/`relay_request` remote backend; reuse connector.rs state/redaction logic from smith-cli, maybe factor shared code). Evaluator nits: enrollment secret JSON passes through a non-zeroized Vec/String; consider rejecting Authorization/Cookie in `relay -H`; redaction matches only the exact token string. Earlier nits still open (GrantError kind logging in relay.rs, design.md decision 4 wording).

## 2026-11-18 worker
- Task: 3.2, 3.3 - done
- Verified: `cargo nextest run -p smith-cli -p locksmith-mcp -p ls-connector` -> 141 passed, 2 skipped; `just ci` exit 0; Opus evaluator PASS (new crate ls-connector shared by smith and MCP; list_grants/relay_request; credential headers refused in MCP)
- Notes for next session: task 4.1 (web agents/grants page, types from openapi.json). Open: smith `relay -H` still accepts Authorization/Cookie (MCP rejects; one call `ls_connector::reject_credential_headers`). Earlier nits still open (GrantError kind logging in relay.rs, design.md decision 4 wording).

## 2026-11-18 worker
- Task: 4.1 - done
- Verified: `npm run lint` (tsc), `npm test` in apps/web -> 5 passed, `npm run build`, `just ci` exit 0; checked by a second reviewer pass on lint/tests/build and storage use (Sonnet implementer; no independent Opus evaluator run)
- Notes for next session: task 4.2 (desktop agents and grants view). Types come from `apps/web/src/schema.d.ts` (openapi-typescript); openapi operationIds are duplicated across resources, so only `components` types are used; unique operationIds would fix it. No rotate-enrollment button in the web UI yet. Open nits from earlier: smith `relay -H` accepts Authorization/Cookie (use `ls_connector::reject_credential_headers`), GrantError kind logging in relay.rs, design.md decision 4 wording.
