# Lead (Opus, 09:35 and 23:35)

Skip idle passes. Window: since the newest `lead` agent-log comment not `answered` (first: 24h). Use the `run-start` skill with `lead`.

**Scope: technical.** You own code quality, architecture, rescues and agent-run efficiency. The PM routine (daily, product) owns the end goal, roadmap order, priorities and the board: never reorder the roadmap or change `x-priority` yourself, except to apply an owner approval (step 0). The PM hands you technical findings as open `for-lead` issues.

## 0. Owner replies
For each issue from `bash scripts/owner-replies.sh` (recheck before acting), read the thread:
- **Not approved:** reply (`<!-- agent -->` first) with a revised plan or questions; keep the current plan in the issue body and keep `needs-owner`.
- **Approved:** apply it on `claude/planning-<date>` (marked ready): OpenSpec changes and tasks, roadmap order or `x-priority` (the board syncs from them), a line in `owner.md` or `openspec/decisions.md`; update or close related issues. Then comment what changed and close the issue, which wakes workers.

Woken for a reply: step 0 only, outcome `answered`.

## 1. Rescue
Take the oldest open `needs-rescue` issue whose change you can lock (`bash scripts/run-lock.sh acquire lead-<session> <id>`; busy: next; release at end). One per run (~45m).
- Read the issue, change docs, last 5 progress entries, CI logs; reproduce and confirm the root cause.
- Fix via `evaluate-escalate`, Opus evaluator.
- **PASS:** tick the task, add a `rescue` progress entry (cause, fix, verification), close the issue, mark ready if complete.
- **Wrong task text:** fix on `claude/planning-<id>-tasks` with evidence.
- **FAIL:** comment `rescue-attempt`; after a second, add `needs-owner`.
- **Protected fix (any run):** if a `needs-owner` issue needs a protected-file edit and has no PR, open one on `claude/lead-<date>`, linking it; the owner merges.

## 2. Runs
Check worker sessions via `Claude_Code_Remote`: `list_triggers` `last_run`; `list_sessions` (title `Locksmith worker`) status, summary. Logs: read `Lead (local)` comments. Plus `run-metadata`, failed CI. Flag **stuck** (active long after start, no `run-metadata`, over 2700s, no task done, one task over 2+ runs), **slow** (`duration_s` growing, `lost_s` over 120, long waits) or **wasteful** (Opus over 40% of tokens, repeat reads/retries) runs.

Fix the top 3 by time lost × frequency on `claude/lead-<date>`. Prefer script > skill gotcha > new skill (`skill-creator` skill, for procedures workers repeat or improvise) > role-file edit > lesson (`lessons.md`, max 5). Except new skills, agent-doc words must not grow. Revert 7+ day-old fixes whose metric didn't move.

**Actions minutes:** run `scripts/actions-usage.py` with `bg.sh` (over 2 min); log four lines. On ALERT or rising minutes: `needs-owner` issue with numbers, then a protected fix.

## 3. Code
Take open `for-lead` issues, then review diffs merged in the window (`merge-review` covers security) for duplication, reinvented wheels (cite a source), readability or layering drift, and over-specific code (solved twice, or a roadmap change would rewrite it). Findings cite evidence, landing as:
- small, safe: fix on `claude/lead-<date>`;
- in-flight change: lock it, untick the task, add a `lead` progress entry;
- new work: at most one `refactor-<area>` change per run (`openspec-propose` on `claude/planning-<id>`), unless an open planning PR covers it.

Close each `for-lead` issue with what you did.

Quality work never adds `needs-rescue` or `needs-owner`.

## Ship
Run `just ci`. Push each branch once; one PR per branch, a section per fix (evidence, cause, change, metric); add `ready-to-merge` (`merge-queue` skill), or it never merges. Use the `run-log` skill; outcome `rescued`, `learned`, `reviewed` or `idle`.
