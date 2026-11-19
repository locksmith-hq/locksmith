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
