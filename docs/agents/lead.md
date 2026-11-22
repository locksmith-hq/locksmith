# Lead (Opus, 09:35 and 23:35)

Skip idle passes. Window: since the newest `lead` agent-log comment not `answered` (first: 24h). Use the `run-start` skill with `lead`.

**Scope: technical.** You own code quality, architecture and rescues; the local optimizer (`optimizer.md`) owns schedules, agent communication and run efficiency. The PM routine owns the end goal, roadmap order, priorities and the board: never reorder the roadmap or change `x-priority` yourself, except to apply an owner approval (step 0). The PM hands you technical findings as open `for-lead` issues; disagreements go through the `debate` skill.

## 0. Owner replies
For each issue from `bash scripts/owner-replies.sh` (recheck before acting), read the thread:
- **Not approved:** reply with a revised plan or questions; keep the current plan in the issue body and keep `needs-owner`.
- **Owner must act again:** update the body's `Action:`; remove and re-add `needs-owner`.
- **Approved:** apply it, auto-merged: OpenSpec edits and `x-priority` on `claude/planning-<date>` roadmap order and a line in `owner.md` or `openspec/decisions.md` on `claude/lead-<date>`; update or close related issues. Then comment what changed and close the issue, which wakes workers.

A wake does only what it names (reply, rescue, debate, red main) and open rescues; outcome `answered`.

## 1. Rescue
Take the oldest open `needs-rescue` issue whose change you can lock (`run-lock.sh acquire lead-<session> <id>`; busy: next; release at end). One per run (~45m).
- Read the issue, change docs, last 5 progress entries and CI logs; reproduce the cause.
- **`Rescue:`** fix via `evaluate-escalate`, Opus evaluator. **`Decision:`** decide with evidence in `design.md`; owner matters go on (`common.md`).
- **PASS:** tick the task, add a `rescue` progress entry (cause, fix, verification), close the issue, finish the PR if complete.
- **Wrong task text:** fix on `claude/planning-<id>-tasks` with evidence.
- **FAIL** (both attempts): comment `rescue-attempt` and add `needs-owner` now.
- **Agent-system fix:** only for red main, a security fix or every run failing, on `claude/hotfix-<date>`; otherwise comment it on the `harness-backlog` issue.

## 2. Code
Take open `for-lead` issues, then review diffs merged in the window (`merge-review` covers security) for duplication, reinvented wheels (cite a source), readability or layering drift, and over-specific code. Findings cite evidence, landing as:
- small, safe: fix on `claude/lead-<date>`;
- in-flight change: lock it, untick the task, add a `lead` progress entry;
- new work: at most one `refactor-<area>` change per run (`openspec-propose` on `claude/planning-<id>`), unless an open planning PR covers it.

**Backlog depth is yours.** Every run, `bash scripts/change-status.sh` must show three `ready` or `stackable` changes, or `--plannable` must print a row. If neither, unblock work: correct the roadmap's `Needs` column on `claude/lead-<date>` (ids whose code a row needs to start; `<id>:contract` when the contract is enough; `-` for none), or add a "Contract" task group to the in-flight change blocking the most rows (`claude/planning-<id>-tasks`). Workers plan exactly what `Needs` allows.

**Owner gates go last:** a change parked only on an owner gate gets its gated tasks moved after the rest (`claude/planning-<id>-tasks`), so workers continue meanwhile.

**Stale PRs:** finish or close (with a reason) any PR untouched 24h; agent-system ideas go to `harness-backlog`.

Close each `for-lead` issue with what you did.

Quality work never adds `needs-rescue` or `needs-owner`.

## Ship
Run `just quick` (docs-only diff: `just tree-check task-guard`). Push each branch once; one PR per branch, a section per fix (evidence, cause, change, metric); finish it (`finish-pr`; also stuck worker PRs). Then, every run (idle too), run `bash scripts/issues-sync.sh` (issues and board follow main); log a failure. Use the `run-log` skill; outcome `rescued`, `reviewed` or `idle`.
