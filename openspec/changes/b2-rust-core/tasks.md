# Tasks: B2 Rust core service

## 1. Contract [sonnet]
- [x] 1.1 `services/core/openapi.json` (internal only) for exactly the OC-9 G1 operations: audit append, checkpoint sign, agent-token mint and verify, workload-token mint and verify, DEK wrap and unwrap; bodies carry ids, ciphertext, tokens and verdicts, never plaintext or key bytes. Derive the shapes from `services/control-plane/src` (`audit.rs`, `checkpoint.rs`, `agent_token.rs`, `workload.rs`, `kms.rs`).
- [x] 1.2 `packages/core-client`: TypeScript client generated from it the same way as `packages/control-plane-client`, plus fixture responses for every operation that dependents (B1 task 5.4) use as mocks.
- [x] 1.3 Verify: `npx turbo run build test --filter=@locksmith/core-client` and a drift test that fails when `openapi.json` and the generated client differ.

## 2. Service skeleton [sonnet]
- [ ] 2.1 `services/core` (package `ls-core-service`): axum, `/healthz` and `/readyz`, OTel and config like `services/control-plane`, listens on an internal address; caller authentication (choose a service token from config or mTLS, record it in design.md decision 5) with a test that an unauthenticated request gets 401.
- [ ] 2.2 [haiku] `scripts/tree-check.sh` and `docs/testing.md` entries; `just test ls-core-service` runs its tests.
- [ ] 2.3 Verify: `cargo nextest run -p ls-core-service`.

## 3. Operations (moved, no behaviour change) [sonnet]
- [ ] 3.1 Audit append and checkpoint signing endpoints, reusing `ls_audit` and the control plane's `audit.rs`/`checkpoint.rs` logic (move shared code into a library crate; the control plane keeps calling it in-process).
- [ ] 3.2 Agent-token and workload-token mint and verify endpoints from `agent_token.rs` and `workload.rs`, same token formats and claims.
- [ ] 3.3 DEK wrap and unwrap through KMS from `kms.rs` (OpenBao transit locally); no key bytes in any response, log or trace.
- [ ] 3.4 Contract tests: for every path in `services/core/openapi.json` a success case, an unauthenticated 401 and a bad-input 400; responses match the fixtures from 1.2.
- [ ] 3.5 Verify: `cargo nextest run -p ls-core-service -p ls-control-plane` (control plane unchanged) and `just leak-scan` after the suite with canary inputs.

## 4. Local stack [sonnet]
- [ ] 4.1 Compose service `core` in `infra/compose` on the internal network only; `just up` starts it.
- [ ] 4.2 `just core-check`: health, one audit append, one token mint and verify, and one wrap and unwrap round trip against the running stack.
- [ ] 4.3 Verify: `just up && just core-check`.

## 5. Local verification
- [ ] 5.1 `just up`, `just core-check`, `just apps-build`, then `just quick`.
