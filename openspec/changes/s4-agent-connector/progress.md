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
