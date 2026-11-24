# Progress: t2-policy-engine

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-22 pm (walt)
- Task: none - planning (needs-work #597: ready queue empty).
- Verified: `openspec validate t2-policy-engine --strict`, `bash scripts/tree-check.sh`.
- Notes for next session: groups 1-2 need only the T6 contract (ticked). Groups 3-5 need T6 groups 2-3 (memberships, `OrgBinding` role), ticked on `claude/change-t6-org-members` (#605); stack on that branch until it merges. Migration number: take the next free one at apply.

## 2026-11-23 pm (nick-fury)
- Task: none - planning. Retargeted the plan to NestJS after merge-review FAIL on a9f0fcd (OC-9 G1 and G2): Cedar runs in `apps/api` through `@cedar-policy/cedar-wasm` 4.15.0 (Apache-2.0, npm 2026-11-16) instead of a Rust `ls-policy` crate; routes, guard and check endpoint are NestJS; migrations stay with the Rust `migrate` binary (b1 2.3); ledger events go through the core client (b1 5.4). Dropped the plan to stack on the old Rust t6 branch. Answered the review note on human `inject` in design.md (no grant row; role policy on `User`).
- Verified: `openspec validate t2-policy-engine --strict`, `bash scripts/tree-check.sh`.
- Notes for next session: blocked until `b1-nestjs-api` and `t6-org-members:contract` land (x-depends_on).

## 2026-11-24 (PM, planning)
- Needs narrowed to `t6-org-members:contract, b1-nestjs-api:contract` (rule: a row lists only what its first group needs). Group 1 (types and fixtures in `packages/control-plane-client`) builds against B1's frozen `openapi.json`; task 1.3's drift check and group 2 need B1's `apps/api` skeleton (B1 group 2, #674) on main: if it is not there yet, stop after 1.2 and stack nothing.
