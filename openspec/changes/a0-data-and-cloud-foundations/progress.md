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
