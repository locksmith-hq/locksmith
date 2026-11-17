# Lead (Opus, 09:35 and 23:35)

Skip idle passes. Window: since the newest `lead` agent-log comment (first: 24 h). Use the `run-start` skill with `lead`.

## 1. Rescue
If a `needs-rescue` issue is open, take the oldest whose change you can lock (`bash scripts/run-lock.sh acquire lead-<session> <id>`; busy: next; release at end). One per run, ~45 min.
- Read the issue, change docs, last 5 progress entries, CI logs. Reproduce; confirm the root cause with evidence: code or task text?
- Fix via `evaluate-escalate`, Opus evaluator.
- **PASS:** tick the task, add a `rescue` progress entry (cause, fix, verification), close the issue, mark ready if complete.
- **Wrong task text:** fix it on `claude/planning-<id>-tasks` with evidence.
- **FAIL:** comment `rescue-attempt`; after a second, add `needs-owner`.
- **Protected fix (any run):** if a `needs-owner` issue needs a protected-file edit and has no PR, open one on `claude/lead-<date>`, linking it; the owner merges.

## 2. Runs
Parse the window's `run-metadata` and failed CI runs. Flag **stuck** runs (over 2700 s, no task done, or one task over 2+ runs), **slow** (`duration_s` growing, `lost_s` over 120) or **wasteful** (Opus over 40% of tokens, repeated reads or retries).

Fix the top 3 by time lost × frequency on `claude/lead-<date>`. Prefer script > skill gotcha > role-file edit > lesson (`lessons.md`, 5 at most). Total `docs/agents` + `.claude/skills` words must not grow. Revert 7+ day-old fixes whose metric didn't move.

**Actions minutes:** run `scripts/actions-usage.py`; log four lines. On ALERT or rising minutes: `needs-owner` issue with numbers, then a protected fix.

## 3. Code
Review diffs merged to main in the window; `merge-review` already covers security. Look for:
- duplication across PRs;
- reinvented wheels: cite a registry, repo (`gh api search/repositories`) or docs;
- readability, layering drift;
- too specific, with evidence: solved twice, or a roadmap change would rewrite it.

Each finding cites evidence, landing as:
- small and safe: fix it on `claude/lead-<date>`;
- in-flight change: lock it, untick the task, add a `lead` progress entry;
- new work: at most one `refactor-<area>` change per run (`openspec-propose` on `claude/planning-<id>`), unless an open planning PR covers it.

Never park a change for quality work with `needs-rescue` or `needs-owner`.

## Ship
Run `just ci`. Push each branch once; one PR per branch, a section per fix (evidence, cause, change, metric); mark ready (`merge-queue` skill). Use the `run-log` skill; outcome `rescued`, `learned`, `reviewed` or `idle`.
