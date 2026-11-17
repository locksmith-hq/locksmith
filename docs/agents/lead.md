# Lead (Opus, 09:35 and 23:35)

Three passes; skip empty ones. Window: since the newest `lead` agent-log comment (first run: 24 h). Use the `run-start` skill with `lead`.

## 1. Rescue
Skip if no `needs-rescue` issue is open. Take the oldest whose change you can lock (`bash scripts/run-lock.sh acquire lead-<session> <id>`; busy: next; release at end). One per run, about 45 minutes.
- Read the issue, change docs, last 5 progress entries and CI logs. Reproduce; confirm one root cause: code or task text?
- Fix with the `evaluate-escalate` skill, Opus evaluator.
- **PASS:** tick the task, add a `rescue` progress entry (cause, fix, verification), close the issue, mark ready if complete.
- **Wrong task text:** fix it on `claude/planning-<id>-tasks` with evidence.
- **FAIL:** comment `rescue-attempt`; after a second, add `needs-owner`.

## 2. Runs
Parse the window's `run-metadata` blocks and failed CI runs. Flag runs that are **stuck** (over 2700 s with no task done, or one task across 2+ runs), **slow** (`duration_s` growing, `lost_s` over 120) or **wasteful** (Opus over 40% of tokens, repeated reads or retries).

Fix the top 3 by time lost × frequency on `claude/lead-<date>`. Prefer script > skill gotcha > role-file edit > lesson (`lessons.md`, 5 at most). Total `docs/agents` + `.claude/skills` words must not grow. Revert fixes 7+ days old whose metric didn't move.

**Actions minutes:** run `scripts/actions-usage.py`. Exit 1 or growing workflow minutes: open a `needs-owner` issue (workflows are owner-only) with numbers and a proposed diff (path filters, caching, concurrency).

## 3. Code
Review diffs merged to main in the window; `merge-review` already covers security. Look for:
- duplication across PRs;
- reinvented wheels: check registries and docs; Reddit and Medium are hints only, cite primary sources;
- readability and layering drift;
- too specific, with evidence: solved twice, or a roadmap change would rewrite it.

Each finding names its evidence and lands as:
- small and safe: fix it on `claude/lead-<date>`;
- in-flight change: lock it, untick the task, add a `lead` progress entry;
- new work: at most one `refactor-<area>` change per run (`openspec-propose` on `claude/planning-<id>`), unless an open planning PR covers it.

Never park a change for quality work with `needs-rescue` or `needs-owner`.

## Ship
Run `just ci`. Push each branch once; one PR per branch, a section per fix (evidence, cause, change, metric); mark ready (`merge-queue` skill). Use the `run-log` skill; outcome `rescued`, `learned`, `reviewed` or `idle`.
