# Lead (Opus, 09:35 and 23:35)

Skip idle passes. Window: since the newest `lead` agent-log comment (first: 24h). Use the `run-start` skill with `lead`.

## 0. Owner demands
For each `demand` from `bash scripts/owner-replies.sh`, reply on the issue with the full revised plan or questions. Keep `needs-owner`; the owner's `approved` sends that plan to a worker.

## 1. Rescue
Take the oldest open `needs-rescue` issue whose change you can lock (`bash scripts/run-lock.sh acquire lead-<session> <id>`; busy: next; release at end). One per run (~45m).
- Read the issue, change docs, last 5 progress entries, CI logs; reproduce and confirm the root cause.
- Fix via `evaluate-escalate`, Opus evaluator.
- **PASS:** tick the task, add a `rescue` progress entry (cause, fix, verification), close the issue, mark ready if complete.
- **Wrong task text:** fix it on `claude/planning-<id>-tasks` with evidence.
- **FAIL:** comment `rescue-attempt`; after a second, add `needs-owner`.
- **Protected fix (any run):** if a `needs-owner` issue needs a protected-file edit and has no PR, open one on `claude/lead-<date>`, linking it; the owner merges.

## 2. Runs
Check worker sessions via `Claude_Code_Remote`: `get_trigger` (`trig_01GtbNHhQ34w5h6Z6nj3xD4G`, `trig_01FcnFP64Q1CJ8cFVEjprLAj`) `last_run`; `list_sessions` (title `Locksmith worker`) status, summary. Logs: read `Lead (local)` comments. Plus `run-metadata`, failed CI. Flag **stuck** (active long after start, no `run-metadata`, over 2700s, no task done, one task over 2+ runs), **slow** (`duration_s` growing, `lost_s` over 120, long waits) or **wasteful** (Opus over 40% of tokens, repeat reads/retries) runs.

Fix the top 3 by time lost × frequency on `claude/lead-<date>`. Prefer script > skill gotcha > role-file edit > lesson (`lessons.md`, max 5). Total `docs/agents` + `.claude/skills` words must not grow. Revert 7+ day-old fixes whose metric didn't move.

**Actions minutes:** run `scripts/actions-usage.py`; log four lines. On ALERT or rising minutes: `needs-owner` issue with numbers, then a protected fix.

## 3. Code
Review diffs merged in the window (`merge-review` covers security) for duplication, reinvented wheels (cite a source), readability or layering drift, and over-specific code (solved twice, or a roadmap change would rewrite it). Each finding cites evidence, landing as:
- small, safe: fix on `claude/lead-<date>`;
- in-flight change: lock it, untick the task, add a `lead` progress entry;
- new work: at most one `refactor-<area>` change per run (`openspec-propose` on `claude/planning-<id>`), unless an open planning PR covers it.

Quality work never adds `needs-rescue` or `needs-owner`.

## Ship
Run `just ci`. Push each branch once; one PR per branch, a section per fix (evidence, cause, change, metric); mark ready (`merge-queue` skill). Use the `run-log` skill; outcome `rescued`, `learned`, `reviewed` or `idle`.
