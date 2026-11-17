# Progress: a0-data-and-cloud-foundations

Append-only session log for this change. Each scheduled or human session adds one entry at the end
before its final commit, and every session reads the last entries plus `git log` before starting.
Format:

## <UTC date time> <worker|review|human>
- Task: <id> - <done|failed|blocked|ci-fix>
- Verified: <command> -> <result>
- Notes for next session: <what to know, what to try next, traps found>


## 2026-11-17 human (planning session)
- Task: design revision - done
- Verified: scripts/check-agent-docs.sh, scripts/tree-check.sh, scripts/check-task-edits.sh -> OK (docs-only change, no code)
- Notes for next session: owner chose AWS over Supabase. Added design decisions 14–18: local parity (moto, Keycloak, OpenBao, postgres:18), Cognito for users, a $5/month `dev` cost model with base and session stacks, budget guardrails, and Claude's AWS access (OpenTofu PRs + read-only AWS MCP). Task 1.1 now covers decisions 1–18. Several prices are tagged [verify] for P1.

## 2026-11-17 human (planning session)
- Task: design revision - done
- Verified: scripts/check-agent-docs.sh, scripts/tree-check.sh -> OK
- Notes for next session: owner revised decision 18. Claude may create AWS resources through the MCP, but each mutating call needs owner approval after a change brief (what, cost, blast radius, security, rollback), enforced by a PreToolUse hook. Guardrail services (IAM, Organizations, SCPs, Budgets, Identity Center) stay OpenTofu-only. MCP-created resources are tagged and imported or destroyed. P1 must build the hook. `.claude/settings.json` is owner-only, so the owner wires it.

## 2026-11-17 human (planning session)
- Task: 1.1 open questions - answered (task not ticked: the owner has not yet signed off decisions 1–18)
- Verified: scripts/check-agent-docs.sh -> OK
- Notes for next session: first region us-east-1. EU residency not at launch (assumed); an EU cell is added on demand.

## 2026-11-17 human (planning session)
- Task: 1.1 - done (owner replied "approved" on #37)
- Verified: scripts/check-agent-docs.sh, scripts/check-task-edits.sh -> OK
- Notes for next session: A0 decisions 1–18 approved, and EU residency is confirmed not needed at launch. Folded in the PR #35 review fixes: a separate Object Lock checkpoint bucket in dev, and `iam:PassRole` allowed through MCP for the session-stack roles only. Next: task group 2 (spikes).

## 2026-11-17 03:58 worker
- Task: 2.1-2.5 - done (Opus implementer, independent Opus evaluator PASS)
- Verified: just ci -> green; cargo nextest run -p a0-spikes -> 31 passed; just leak-scan -> clean; just psql -c 'select uuidv7()' -> v7 UUID on PostgreSQL 18.7
- Notes for next session: crate is at crates/a0-spikes, not tests/spikes/a0 (tree-check.sh forbids Rust there; guard scripts are protected). Findings for 3.1: pin is postgres:18.7; sqlx umbrella crate conflicts with rusqlite (libsqlite3-sys), so use sqlx-core + sqlx-postgres 0.9.0; the RLS policy needs NULLIF(current_setting('app.org_id', true), '') because the setting stays '' after a local set_config commits. just psql was fixed to pass quoted args. Task 3.2 edits openspec/config.yaml, which is protected on agent branches: needs an owner session. rls tests are excluded from just ci (need just up); run them via cargo nextest run -p a0-spikes. Docker Hub returned 429; images came from mirror.gcr.io.
