# Progress: d4-workload-identity

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-20 planner
- Task: none - planning
- Verified: `openspec validate d4-workload-identity --strict` -> valid, `bash scripts/tree-check.sh`
- Notes for next session: `x-depends_on` is empty because t1-human-auth is archived on main; no Contract group (no roadmap row needs D4). Reuse `auth/jwks.rs` `JwksCache` per stored issuer and the existing `AgentTokenSigner::mint`; resolve the `[verify]` item (jti cache crate) at task 4.1.

## 2026-11-20 worker (C)
- Task: 1.1, 1.2 - done (migration 0012 registered in `migrate.rs`, tenancy test updated; `workload.rs` validation, matcher, `lsw_` handle with 11 unit tests)
- Verified: `cargo nextest run -p ls-control-plane workload` 11 passed; `--test tenancy` 9 passed; `just ci` -> exit 0
- Notes for next session: 1.3 handlers (POST/GET/DELETE /v1/workload-identities, audit codes) and 1.4 api-types next. New migrations must also be listed in `src/migrate.rs` and the tenancy test (version list, table list, policy count).

## 2026-11-20 worker (C), second run
- Task: 1.3, 1.4, 1.5 - done (`api/workload_identities.rs`: POST/GET list/GET/DELETE under human auth and `with_org`; `workload_identity.created`/`.deleted` audit events; OpenAPI and `control-plane-client` types regenerated; `tests/workload_identities.rs`)
- Verified: `cargo nextest run -p ls-control-plane -p ls-audit workload tenant_lint openapi audit` 19 passed; `just ci` exit 0
- Notes for next session: validation errors are `400` (the repo's `Kind::Validation`), not `422` as task 1.5 text says; unpinned and bare-`*` policies are refused. Audit target type is `workload` (the ledger CHECK allows `[a-z]+` only, no underscore). Response field is `pattern`, not `value` (the OpenAPI guard bans response fields named `value`). Next: 2.1 per-issuer JwksCache registry.

## 2026-11-20 20:55 worker
- Task: ci-fix (macos check red on PR #530) - done
- Verified: just quick -> ok; nextest list --profile portable excludes workload_identities
- Notes for next session: new Postgres-backed test binaries must be added to .config/nextest.toml portable filter. Tasks 2.x onward still open.

## 2026-11-20 worker (C), third run
- Task: 2.1, 2.2, 2.3, 2.4 - done (`auth/issuers.rs` per-issuer registry with address-guarded resolver; `auth/external.rs` `verify_external`; matcher tests; `tests/workload_verify.rs` 20 wiremock cases; `JwksCache::with_client` added so the guarded client is injected)
- Verified: `cargo nextest run -p ls-control-plane workload` 41 passed; `just quick` ok; Opus evaluator PASS (after adding resolver rebinding tests)
- Notes for next session: registry/verifier/config not yet in `AppState` - wire in 3.1; create-time private-issuer 422 should call `IssuerRegistry::check_issuer_host`. Dev flag `LOCKSMITH_WORKLOAD_ALLOW_PRIVATE_ISSUERS` also allows http. Nits: `address_allowed` duplicates gateway egress.rs; `ls-proxy` dep is heavy. Tasks 3.x onward open.

## 2026-11-21 worker (C), fourth run
- Task: 3.1, 3.2, 3.3 - done (`api/workload_tokens.rs` POST /v1/workload-tokens with `ExternalToken` SecretString, `exchange_workload_token` span, `workload_identity.exchanged`/`.denied` audit events, 300s throttled `last_used_at`; verifier wired into AppState and main; create-time private-issuer refusal; OpenAPI and client types regenerated; `tests/workload_exchange.rs`)
- Verified: `cargo nextest run -p ls-control-plane workload` 45 passed; `just quick` ok; Sonnet evaluator PASS
- Notes for next session: ledger attrs allow only ids/codes/hosts, so policy-named claim values are on the tracing event, not the ledger; create-time private issuer is 400 not 422; Authorization-header form of the exchange not implemented. Next: 4.1 jti replay cache and rate limits (resolve the `[verify]` OSS item first), then 4.2.

## 2026-11-21 worker (C), fifth run
- Task: 4.1 - done (`auth/abuse.rs`: moka-backed jti replay cache keyed by sha256(issuer,jti), fixed-window per-policy (60/min) and per-source (30/min) limits, env-configurable; replay and rate limits return the same single 401; replay writes `workload_identity.denied` code `replay`; `[verify]` resolved in design.md: moka 0.12.16)
- Verified: `cargo nextest run -p ls-control-plane workload` 54 passed; clippy and fmt clean; `just quick` ok; Sonnet evaluator PASS
- Notes for next session: source limit uses the peer address (behind a proxy all callers share a bucket; forwarded headers not trusted); rate-limit refusals are not ledgered by design. Test `workload_abuse_a_policy_mismatch_does_not_burn_the_jti` never retries the jti: strengthen in 4.2/4.3. Next: 4.2 adversarial cases, 4.3, then 5.x.

## 2026-11-21 worker (C), sixth run
- Task: 4.2 - done (11 `workload_abuse` tests in `tests/workload_exchange.rs`: forged iss no outbound call, jku/x5u ignored, wrong audience, concurrent jti replay, other-org handle, canary absent from logs/ledger/tables; `tests/adversarial/cases/D4.sh` + README; strengthened the jti-not-burned test)
- Verified: `cargo nextest run -p ls-control-plane workload_abuse` 14 passed; `run.sh all` 9 passed, 0 failed, 1 skipped (A2, no aws CLI); `just quick` ok; Sonnet evaluator PASS
- Notes for next session: 4.3 left unticked: `just leak-scan` needs the live stack and a canary (`just up`, `just canary new`), not run on this VM. Evaluator nits: the embedded-`jwk` case only fails on signature mismatch (sign with attacker key plus embedded jwk to test it properly); `futures_join` helper could be `futures::join_all`. Next: run leak-scan, tick 4.3, then 5.x.

## 2026-11-21 04:10 worker
- Task: ci-fix (adversarial check red on PR #530, case D4 cargo exit 101) - blocked
- Verified: `cargo nextest run -p ls-control-plane workload_abuse` x5 -> 14 passed each; `bash tests/adversarial/run.sh D4` -> PASS (oracle clean). Could not reproduce the CI failure; job logs only show "case exit 101", cargo-test.log artifact not downloadable from the VM and rerun-failed-jobs is 403.
- Notes for next session: this push re-triggers CI. If D4 is red again, suspect testcontainers/postgres startup timing under CI load (tests take ~15s each cold); get the cargo-test.log via a CI step that tails it on failure. 4.3 still open (needs `just up` for leak-scan), then 5.x.

## 2026-11-21 worker (C), seventh run
- Task: ci-fix (adversarial D4 still red on PR #530) - diagnostics only
- Change: `D4.sh` now prints the last 80 lines of cargo-test.log to stderr when cargo fails, so the next CI log shows the real failure. Not reproducible locally; job logs not downloadable from the VM.
- Notes for next session: read the adversarial job log after this push; 4.3 and 5.x still open.

## 2026-11-21 worker (C), eighth run
- Task: ci-fix (adversarial D4 still red on PR #530) - diagnostics only
- Change: `D4.sh` also emits the cargo log tail as a `::error::` annotation on failure; the job log blob host is blocked by the VM proxy but annotations are readable via `check-runs/<id>/annotations`.
- Notes for next session: after this push, read the annotation of the adversarial check run to see the real D4 failure. 4.3 and 5.x still open.

## 2026-11-21 worker (C), eighth run (cont.)
- Root cause of the red adversarial D4: CI has no nextest, so `cargo test` runs the tests as threads of one process; the `exchange_workload_token` span callsite was first hit by a test with no subscriber and cached as disabled, so the capture test saw no span. Reproduced locally with `cargo test`; nextest (one process per test) hid it.
- Fix: `capture_logs` rebuilds the callsite interest cache, and `D4.sh` runs `cargo test ... -- --test-threads=1`. Verified 2x `cargo test -p ls-control-plane --test workload_exchange workload_abuse -- --test-threads=1`: 11 passed. The `::error::` annotation helper stays.

## 2026-11-21 worker (C), ninth run
- Tasks: 5.1-5.4 done (`smith login --workload`, doctor `workload.login`, github-action, tests). Sonnet implementer, Sonnet evaluator PASS. Verified: `cargo nextest run -p smith-cli workload` 9 passed, tree-check OK, just quick ok.
- 4.3 still open: workload_abuse (14 passed) and `run.sh D4` pass, but `just leak-scan` needs the compose stack (`just up`); do it with 7.2.
- Last CI: only `macos` red on b484d4d (nextest exit 100, log blob blocked by the proxy, annotations show no test name; all portable tests pass on Linux, 323/323). Rerun needs Actions write; the new push reruns it.
- Evaluator notes: action checks sha256 only (not minisign), install.sh repo slug differs from action's; cosmetic spaces in GitHub error text.
- Remaining: 4.3, 6.x (web/desktop page), 7.x.

## 2026-11-21 09:20 worker
- Task: d4 - ci-fix (hygiene gitleaks flagged example UUID in integrations/github-action/README.md)
- Verified: gitleaks git . -> only the p4-branch leak remains (not in this branch); just quick -> ok
- Notes for next session: remaining checks on PR #530 not yet re-observed; check CI after push.
