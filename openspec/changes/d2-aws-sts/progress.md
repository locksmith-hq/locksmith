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
