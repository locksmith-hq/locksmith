# Tasks: S3 gateway HTTP relay

## 1. Control-plane material endpoint [opus]
- [x] 1.1 Add `GET /internal/v1/secrets/{id}/versions/{n}/material` returning ciphertext, wrapped DEK and key id only, behind a service token (constant-time compare); org-scoped through the S1 tenant helper. Update `openapi.json` (internal tag).
- [x] 1.2 Verify: `cargo nextest run -p ls-control-plane` covers no token → 401, cross-org → 404, and no plaintext field in the schema.

## 2. Gateway service skeleton [sonnet]
- [x] 2.1 Create `services/gateway` (axum, OTel, health), config with bindings TOML, caller token, OpenBao gateway token; migration `gateway_audit` (append-only, RLS).
- [x] 2.2 Verify: `cargo nextest run -p ls-gateway -E 'test(config)'` and `cargo clippy -p ls-gateway --all-targets -- -D warnings`.

## 3. Decrypt, inject, redact [opus]
- [ ] 3.1 Fetch material, unwrap with `OpenBaoTransit`, `open_version`, DEK cache with TTL and zeroize on evict. No Debug/Display/Clone on secret types.
- [ ] 3.2 Egress rules: host allowlist, private/loopback/link-local refusal, pinned connection, no redirect following.
- [ ] 3.3 `POST /v1/relay`: inject by template, call upstream, redact headers and body with `ls-redact` (fail closed on unscannable encodings), write the audit row.
- [ ] 3.4 Verify: `cargo nextest run -p ls-gateway` including echoed secret in plain/base64/URL/hex, disallowed host makes no decrypt call, redirect not followed, failure paths leak nothing.

## 4. Compose and e2e [sonnet]
- [ ] 4.1 Compose entries and `just gateway`, `just relay-smoke`; OpenBao gateway token wiring from S2.
- [ ] 4.2 e2e: write a canary secret through the control plane, relay to the mock upstream, assert the upstream saw it, the caller did not, and `just leak-scan` is clean over Postgres, Loki, Tempo and the transcript; a planted canary is still detected.
- [ ] 4.3 Verify: `just up && just relay-smoke && just leak-scan`.

## 5. Local verification
- [ ] 5.1 `just up`, the S3 smoke test (`just relay-smoke`), then `just ci`.
