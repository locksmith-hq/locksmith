# Tasks: S2 envelope crypto

## 1. Envelope library [opus]
- [ ] 1.1 Create `crates/ls-envelope`: promote the A0-7 header codec from `a0-spikes`, add `seal_version`/`open_version` over `ls-crypto` AEAD with AAD `org_id ‖ secret_id ‖ version ‖ purpose`. Secret types have no Debug, Display or Clone.
- [ ] 1.2 Known-answer vectors (committed) and proptests for tamper, wrong binding and nonce uniqueness.
- [ ] 1.3 Verify: `cargo nextest run -p ls-envelope` and `cargo clippy -p ls-envelope --all-targets -- -D warnings`.

## 2. KMS wrapping [opus]
- [ ] 2.1 `KeyWrapper` trait and an OpenBao transit implementation (`wrap`, `unwrap`), storing the wrapped DEK in the `dek-wrap` header format.
- [ ] 2.2 Compose: enable transit and create the `gateway` key idempotently; policies and tokens for the control plane (encrypt only) and a gateway test token (decrypt).
- [ ] 2.3 Tests against OpenBao: wrap/unwrap with the gateway token; unwrap with the control-plane token is denied.
- [ ] 2.4 Verify: `just up && cargo nextest run -p ls-envelope -E 'test(kms)'`.

## 3. Versions API [opus]
- [ ] 3.1 Migration `secret_versions` (design decision 6): composite FK, RLS, append-only grants.
- [ ] 3.2 `POST /v1/.../secrets/{id}/versions` accepts a value into `SecretBytes`, seals, wraps, stores, zeroizes; returns version metadata only. `version_count` becomes real; `GET` lists metadata only.
- [ ] 3.3 Update `openapi.json` snapshot; no DTO derives Debug for the value.
- [ ] 3.4 Verify: `cargo nextest run -p ls-control-plane` covering cross-org `404`, no value in responses, and value-field misuse.

## 4. Leak verification [sonnet]
- [ ] 4.1 e2e test: write a canary value, then run `just leak-scan` over Postgres, Loki and Tempo; assert clean. A planted canary in a log must still be detected.
- [ ] 4.2 Verify: `just test-e2e && just leak-scan`.

## 5. Local verification
- [ ] 5.1 `just up`, the S2 smoke test (write a value, gateway token decrypts, control-plane token cannot), then `just ci`.
