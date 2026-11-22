# Progress: t2-policy-engine

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-22 pm (walt)
- Task: none - planning (needs-work #597: ready queue empty).
- Verified: `openspec validate t2-policy-engine --strict`, `bash scripts/tree-check.sh`.
- Notes for next session: groups 1-2 need only the T6 contract (ticked). Groups 3-5 need T6 groups 2-3 (memberships, `OrgBinding` role), ticked on `claude/change-t6-org-members` (#605); stack on that branch until it merges. Migration number: take the next free one at apply.
