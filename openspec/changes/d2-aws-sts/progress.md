# Progress: d2-aws-sts

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-19 worker
- Task: none - planning
- Verified: `openspec validate d2-aws-sts --strict`, `bash scripts/tree-check.sh`, `bash scripts/check-task-edits.sh`
- Notes for next session: local M7 already has `ls-proxy::aws::sts` (`assume_role`, `contained`, `revoke_older_sessions`) with mock-server tests; D2 adds the hosted gateway route `/v1/aws/credentials`, `smith aws credential-process`, and moto in compose (not present yet). Roadmap `Needs` is `-`, so `x-depends_on` is empty and there is no Contract group. Verify at apply: moto image version, whether moto enforces session policies (task 1.2), awscli availability on the VM.

## 2026-11-19 worker C
- Task: 1.1 - done (moto 5.1.20 in compose with healthcheck on 127.0.0.1:5000, `harness-check` and docs/dev-harness.md list it)
- Verified: `docker compose up -d --wait moto` healthy; `curl -fsS localhost:5000/moto-api/` ok; `just ci`
- Notes for next session: 1.2 is an [opus] spike (AssumeRole against moto, record which session-policy checks moto enforces); 1.3 follows it. Then group 2 (binding shape, session policy renderer) is independent Rust work. No `.env.example` exists, so no entry added (MOTO_IMAGE override is in compose).

## 2026-11-19 22:21 worker
- Task: 1.2, 1.3 - done (moto spike in tests/e2e/tests/aws_sts_moto.rs; findings and decision 6 in design.md)
- Verified: `E2E_REQUIRE_MOTO=1 cargo nextest run -p ls-e2e --test aws_sts_moto` -> 2 passed; `just ci` -> green; Opus evaluator PASS
- Notes for next session: moto ignores session policies and does not validate their shape or 2048 limit, so task 2.2's renderer must check both itself and tests assert the policy moto recorded (data.json) not moto enforcement. Emit compact JSON (moto IAM mode fails signature on spaces). New moto test binaries must join the nextest `moto` group in .config/nextest.toml. Next: group 2 (binding shape, renderer, sonnet), then 3 (gateway route, opus).

## 2026-11-20 worker
- Task: 2.2, 2.3 - done (2.1 partial: gateway `[[aws_binding]]` shape and fixture done; control-plane grant types do not carry the allow-list yet, so 2.1 stays unticked)
- Verified: `cargo nextest run -p ls-gateway aws_policy` -> 8 passed (incl. proptest never-widens); `just ci` -> exit 0. No independent evaluator run (self-checked).
- Notes for next session: `services/gateway/src/aws_policy.rs` has `AwsBinding`, `AwsGrantScope`, `render_session_policy`, `clamp_duration`; finish 2.1 by adding the scope to control-plane grant types and the internal grants API, then group 3 (opus). Other changes p1 (7.1 left, 1.2/4.3 gated), d1 (4.2 onward) and d3 (no branch yet) were not touched this run.

## 2026-11-20 worker
- Task: 2.1 - blocked
- Verified: merged origin/main into the branch (conflicts in infra/compose/compose.yaml and docs/dev-harness.md resolved by keeping both moto and keycloak/mailpit); compose YAML parses -> ok
- Notes for next session: 2.1 needs a `delegate` GrantMode plus a scope column in the control-plane `agent_grants` table, the internal grants API and OpenAPI types. That `delegate` mode belongs to d1-git-delegation and is not on main yet, so building it here would collide with d1's migration. Start 2.1 after d1 lands delegate in control-plane, or agree the shared migration with d1. Group 3 depends on 2.1.

## 2026-11-20 worker
- Task: ci-fix (PR #480 conflicts with main: aws_bindings + git_bindings) - done
- Verified: just ci -> exit 0 after merging origin/main (kept both fields in config.rs, relay.rs, git_fixture_tests.rs)
- Notes for next session: task 2.1 still blocked on d1 `delegate` GrantMode (see earlier entry).

## 2026-11-20 worker
- Task: 2.1 - done (migration 0012: `delegate` grant mode + `scope` jsonb; `GrantScope` validated on grant create; scope served on the internal grants lookup; openapi.json regenerated; control-plane tests added/updated)
- Verified: `cargo nextest run -p ls-control-plane` -> 133 passed; `just ci` -> exit 0
- Notes for next session: group 3 next (opus). Gateway `Grant` in `services/gateway/src/grants.rs` still ignores `scope`; add `scope: Option<AwsGrantScope>` there in 3.1 (it has no deny_unknown_fields, so nothing breaks meanwhile). New embedded migrations must also be listed in `services/control-plane/src/migrate.rs` and tenancy.rs expects the version list.

## 2026-11-20 worker (event: CI red on #480)
- Task: ci-fix - done. Only failure was `ls-control-plane::human_auth auth_garbage_kids_cannot_turn_requests_into_a_fetch_storm` (1 of 779); passes locally in isolation and in full `just ci` after merging origin/main, so treated as a flake (not caused by 2.1).
- Verified: `just ci` -> exit 0 on the merged branch.
- Notes for next session: group 3 (opus) is next; if the fetch-storm test flakes again, log it on the harness-backlog issue.

## 2026-11-20 worker
- Task: 3.1-3.4 gateway `POST /v1/aws/credentials` - done (commit 4fa7337)
- Verified: `cargo nextest run -p ls-gateway aws` 19/19 incl. real moto success test; `just ci` green; independent Opus evaluator PASS.
- Notes for next session: ledger has no free-form attr, so events target the binding's secret id (role ARN not stored; see design.md). Minor: aws.rs:182 classifies sts_unreachable by error text; a typed error from `assume_role` would be sturdier. Next: tasks 4 (smith aws credential-process), 5, 6, 7.

## 2026-11-20 worker (C)
- Task: 4.1-4.3 smith aws credential-process|setup|teardown + doctor `aws.vend` - done
- Verified: `cargo nextest run -p smith-cli aws` 17 passed; `just ci` -> exit 0; independent evaluator PASS (static review).
- Notes for next session: tasks 5, 6, 7 remain. Minor: `smith aws setup --profile B` after A replaces A's managed block (one block only); config write is not atomic. MCP help text unchanged (no AWS MCP tool, by design).

## 2026-11-20 worker (events)
- Task: 6.1, 6.2 - done (gateway case G9 with STS stub: agent policy ignored, duration clamp/reject, STS error echo, base credential absent)
- Verified (evaluator PASS, sonnet, static): `run.sh gateway` 8 passed; run_test.sh, `just leak-scan`, `just audit-verify`, fmt, tree-check, task-guard ok; `just ci` test-rust 804/805, only ls-ipc `foreign_peer_is_closed_without_handling_a_request` failed (needs non-root; VM runs as root), later steps not run
- Notes for next session: 5.1 (bindings page) needs the console pages from t3-console-mvp (not on main yet); do it after t3 merges. 7.x remain. Evaluator not run separately (static review only).

## 2026-11-20 worker (events, wake: needs-rescue #509 closed)
- Task: 7.1 - done (`just aws-smoke`, `tests/e2e/tests/aws_smoke.rs`: real `aws` CLI through `smith aws credential-process` against moto; asserts identity, expiry capped by grant, no key in agent HOME)
- Verified: `just up`, `just aws-smoke` -> 1 passed (run twice, real aws CLI v1 1.46.3 via pip); `just ci` -> exit 0 (aws-CLI-dependent tests skip on the VM without `aws`; with pip aws v1 installed, ls-proxy `aws_cli_through_the_relay` fails "You must specify a region" - pre-existing M7 test, not touched here; log on harness-backlog). Sonnet implemented, self-verified; no separate evaluator.
- Notes for next session: remaining 5.1/5.2 (needs t3-console-mvp bindings page on main), then 7.2 (`just apps-build`, `just ci`, record the P1 real-AWS session-policy check). `just leak-scan` needs a canary file from the stack tests; not run.

## 2026-11-20 worker (C)
- Task: none - parked (merged origin/main into the branch; no code change)
- Verified: merge clean, tree clean. Open tasks 5.1/5.2 need the bindings page from t3-console-mvp (28 tasks open there, nothing on main or its branch); 7.2 needs `just apps-build` after 5.x and a real AWS account for the P1 session-policy check.
- Notes for next session: take 5.x after t3 lands a bindings page; do 7.2 last.

## 2026-11-21 merge (origin/main into the branch)
- Task: none - merged origin/main (m1-remote-mcp). Renumbered this change's migration `0012_grant_delegate.sql` to `0013_grant_delegate.sql` (main's `0012_mcp.sql` keeps 12) and the AWS adversarial case `G9` to `G11` (main's agent MCP case is `G9`, hub MCP `G10`). Kept both sides' audit kinds (`aws.credentials.*`, `credential.issued`), attrs, gateway config and relay options.

## 2026-11-21 worker C
- Task: CI fix (hygiene and web red on 377446cf: `just` recipe `aws-smoke` defined twice once main's P1 recipe (`aws-smoke`, real-AWS session smoke) merged) - done
- Verified: `just --list` parses with both recipes; `just quick` -> see push
- Notes for next session: D2's local moto smoke is now `just aws-vend-smoke` (P1 owns `just aws-smoke`). tasks.md 7.1/7.2 text still says `just aws-smoke` and cannot be edited; read it as `aws-vend-smoke`.

## 2026-11-21 worker (alfie)
- Task: none - resolved PR #480 conflicts (merged origin/main: D4 workload identities took migration 0013, so this change's migration is now `0014_grant_delegate.sql`; kept both justfile recipes and both e2e dev-dependency sets; Cargo.lock regenerated from main's).
- Verified: `cargo check --workspace --tests`, `just quick`, `cargo test -p ls-control-plane --lib`.
- Notes for next session: 19 tasks still unticked; take them in order. Also took no action on #489 (another worker holds t3-console-mvp).

## 2026-11-21 worker C
- Task: CI fix (rust red on 42ddd897: `tenancy.rs` still expected 13 migrations after d2's migration was renumbered to 0014 behind d4's 0013) - done
- Verified: `cargo nextest run -p ls-control-plane --test tenancy --test tenant_lint` -> 13 passed (needs dockerd: start it by hand on a fresh VM); `just quick`
- Notes for next session: any new main migration shifts d2's number again; bump the two counts in `services/control-plane/tests/tenancy.rs` (lines 91, 101). Lead's follow-up still open: wrap `0014_grant_delegate.sql` DDL in `SET LOCAL ROLE locksmith_owner`.

## 2026-11-21 worker (josie)
- Task: none - parked (merged origin/main clean, no migration clash; PR #480 checks were green on f40036d)
- Verified: `just quick`, `cargo check -p ls-control-plane --tests` -> ok
- Notes for next session: only 5.1/5.2 and 7.2 remain; 5.1 needs a live bindings page in apps/web, which does not exist (only the `mockup/` frame; t3-console-mvp #489 is review-failed). Do 5.x after t3 lands, 7.2 last.
