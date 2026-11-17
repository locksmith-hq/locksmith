# Progress: S2 envelope crypto

## 2026-11-17 10:37 worker
- Task: planning (proposal, specs, design, tasks) - done
- Verified: openspec validate s2-envelope-crypto -> valid
- Notes for next session: depends on S1 (PR #106, parked on rescue #108). Record exact crate versions in design.md OSS table when implementing.

## 2026-11-17 worker (tasks 1.1, 1.2)
- Task: 1.1 `crates/ls-envelope` (header codec promoted from `a0-spikes`, `seal_version`/`open_version`, `DataKey`/`SealedVersion` without Debug/Display/Clone) - implemented; 1.2 committed KAT vectors (`vectors/v1.json`, generated independently with pyca/cryptography; vector 1 equals the A0-7 spike KAT) and proptests - implemented. Tasks not ticked.
- Verified: `cargo nextest run -p ls-envelope` 20/20 pass; `cargo clippy -p ls-envelope --all-targets -- -D warnings` clean; `cargo fmt --check` clean; tree-check OK.
- Not run: `cargo deny check` (not installed), gitleaks (not run locally; `vectors/v1.json` holds fixed hex test keys).
- Notes for next session: `a0-spikes` still has its own copy of the header code; the payload header `key_id` is a random per-DEK id, and the `dek-wrap` key_id for task 2.1 is the transit key name plus version.

## 2026-11-17 worker (tasks 1.1-1.3 ticked)
- Verified: `just ci` green (exit 0); ls-envelope 20/20; independent Opus evaluator PASS. KAT key material for vector 4 changed to low-entropy values (avoids gitleaks generic-api-key); vectors regenerated with pyca/cryptography.
- Next: task 2.1 (KeyWrapper + OpenBao transit; needs `just up`). Sections 2-5 untouched.

## 2026-11-17 14:55 worker
- Task: 2.1 - done (`KeyWrapper` trait + OpenBao transit client in `crates/ls-envelope`; wrapped DEK is an 80-byte `dek-wrap` blob; key_id = name padded to 12 bytes + u32 version; AAD bound; `vaultrs` rejected, rationale in design.md)
- Verified: `just ci` -> green; ls-envelope 34/34; independent Opus evaluator PASS
- Notes for next session: reqwest `rustls-no-provider` in ls-envelope unifies workspace-wide, so any process building a reqwest client needs a rustls provider installed (control-plane telemetry init now installs ring). Per-request token HeaderValue copy is not zeroized (minor). `KeyWrapper` is not dyn-compatible; use generics. Next: 2.2 (compose transit key + policies/tokens), 2.3 live tests (needs `just up`).

## 2026-11-17 worker
- Task: 2.2 - done (`infra/compose/openbao-init.sh` run as the openbao healthcheck: transit, `gateway` key, `control-plane` encrypt-only and `gateway` decrypt-only policies, fixed dev-only tokens; idempotent, re-applies after a restart)
- Verified: live OpenBao: gateway token decrypts, control-plane token encrypt 200 / decrypt 403; re-run idempotent; `just up` + `just harness-check` 8/8; `just ci` green; independent Opus evaluator PASS
- Notes for next session: tokens are `OPENBAO_CONTROL_PLANE_TOKEN` / `OPENBAO_GATEWAY_TOKEN` (defaults `dev-only-control-plane` / `dev-only-gateway`). Next: 2.3 live tests (wrap/unwrap with gateway token; control-plane unwrap denied), 2.4.

## 2026-11-17 15:16 worker
- Task: 2.3, 2.4 - done (`crates/ls-envelope/tests/kms_live.rs`: live OpenBao tests; control-plane token wraps, gateway token unwraps, reverse directions denied, wrong binding rejected)
- Verified: `LS_REQUIRE_KMS=1 cargo nextest run -p ls-envelope -E 'test(kms)'` -> 7/7 pass; `just ci` green; independent Opus evaluator PASS
- Notes for next session: tests skip when OpenBao is unreachable unless `LS_REQUIRE_KMS=1` (use it when verifying). Next: section 3 (secret_versions migration, versions API in ls-control-plane).

## 2026-11-17 worker (tasks 3.1-3.4)
- Task: 3.1 migration `0003_secret_versions.sql` (PK `(org_id, secret_id, version)`, composite FK to new `secrets (org_id, id)` unique key with ON DELETE CASCADE, FORCE RLS `tenant_isolation`, app role SELECT/INSERT only); 3.2 `POST`/`GET .../secrets/{id}/versions` (`SecretJson` extractor reads the value into `SecretBytes` and wipes the body buffer; seal with `ls-envelope`, wrap via `kms::DekWrapper` (object-safe adapter over `KeyWrapper`), store, drop plaintext and DEK; metadata-only responses; real `version_count`); 3.3 `openapi.json` regenerated, `NewSecretVersion.value` is the only value field (writeOnly password string), compile-time probes for no Debug/Clone/Serialize; 3.4 tests in `tests/versions.rs` and `tests/tenancy.rs`. Tasks not ticked.
- Verified: `LS_REQUIRE_KMS=1 cargo nextest run -p ls-control-plane` -> 48/48 (incl. live OpenBao: control-plane token wraps but cannot unwrap, gateway token unwraps and the value opens); `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt --check` clean.
- Notes for next session: KMS is optional config (`OPENBAO_ADDR`, `OPENBAO_CONTROL_PLANE_TOKEN`, `OPENBAO_TRANSIT_KEY`=gateway, `OPENBAO_TRANSIT_KEY_VERSION`=1); unset -> version writes 503. The KMS call runs inside the tenant transaction holding a `FOR UPDATE` lock on the secret row (consecutive version numbers). `GET versions` is not paginated yet. Deleting a secret cascades to its versions. Not run: `just ci`, independent evaluator. Next: section 4 (leak scan).
