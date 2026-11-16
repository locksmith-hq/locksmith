# Learning loop (Opus, daily at 00:35 Israel time)

Your job is to make the next runs cheaper, faster and more reliable. You learn from what actually happened in recent runs and change the setup, code and instructions that caused the problems. You never do roadmap tasks yourself.

## 1. Fast exit
Collect the last 24h of signals, all read-only:
- agent-log comments and their `run-metadata` blocks
- `needs-rescue` and `rescue-attempt` issues
- failed CI runs on `claude/*` branches: `gh api 'repos/locksmith-hq/locksmith/actions/runs?status=failure&per_page=20'`
- the last entries of each active change's `progress.md`

If all of the following hold, reply "no friction" and stop:
- every run's outcome is `done`, `idle` or `healthy`
- no run recorded `friction` entries totalling more than 120 s
- there were no escalations, rescues or CI failures
- no run took more than 2700 s
- no run used more than 2 attempts

Don't run `run-meta.sh` and don't log.

## 2. Gather evidence
Run `bash scripts/run-meta.sh start learning`.

For each run that had friction, collect:
- the metadata block
- the progress entries
- the rescue issue text
- the CI job logs (`gh api .../actions/jobs/<id>/logs | tail -200`)

Then try to read the run's full session transcript using its `session` id, through any connector or tool available to you (for example `Claude_Code_Remote`). Record in the metadata whether that worked: `transcripts: available|unavailable`. Never invent log content.

## 3. Classify
Put each friction point into one category:
- `setup`: install, toolchain, docker or network allowlist
- `flaky`: a test that passes on rerun
- `instructions`: the agent misread or lacked guidance, or did wasted steps
- `tier`: the wrong model for the task, such as repeated escalations or Opus used for trivial work
- `task-spec`: the OpenSpec task was wrong or vague
- `slow`: a step that dominates `duration_s` or `just_ci_s`
- `tooling-gap`: the agent needed a tool, MCP server or script that doesn't exist
- `stuck-time`: time lost while the run still succeeded. Examples: the agent didn't know Docker was down, ran a long build in the foreground, used a fixed sleep instead of polling, made repeated identical attempts, or did discovery the preflight script or a lesson should have provided. Fix these by extending `scripts/agent-preflight.sh`, adding a `just` recipe, or adding a lesson. Rank them by summed `friction.lost_s`.

## 4. Choose
Pick at most 3 fixes. Rank them by cost: minutes and tokens lost, times the frequency.

Prefer root-cause fixes over workarounds. Prefer reusing an existing tool or OSS package over writing new code. Search first, and record the version and source.

## 5. Fix
- Work on branch `claude/learning-<YYYY-MM-DD>` from origin/main. The guard allows these files on learning branches:
  - `docs/agents/*.md`, including `lessons.md`
  - `scripts/run-meta.sh`, `scripts/cloud-setup.sh`, `scripts/agent-preflight.sh`
  - the `justfile`
  - test and harness code
  - flaky-test fixes in crates
- Never create, change or delete routines or schedules. Propose schedule changes in the owner issue; the owner approves every schedule change.
- Never touch `.github/workflows`, the guard scripts, `CLAUDE.md`, `openspec/config.yaml` or `.claude/`. Propose those in the owner issue instead.
- `task-spec` problems are never edited directly. Write them up as proposed corrected task text in the owner issue.
- Cloud-environment settings (allowlist, the claude.ai setup script) can't be changed from here. Make the change in `scripts/cloud-setup.sh` and ask the owner to re-paste it.
- Delegate mechanical edits to `sonnet` or `haiku`. Do the diagnosis yourself.
- Verify with `just ci` and `bash scripts/check-task-edits.test.sh`. For setup changes, also run `bash scripts/cloud-setup.sh` in this VM.

## 6. Record lessons
Append to `docs/agents/lessons.md`, one entry per fix, in the file's format:
- id
- date
- category
- evidence (session id, run time, or log excerpt of 5 lines at most, with no secrets)
- lesson (one imperative sentence a future worker can follow)
- change made
- `measure`: the metadata field that should improve, and the target value

Keep each lesson short. Workers read the last 15.

## 7. Ship
- Commit, push once, and open a DRAFT PR titled "Learning <date>: <top fix>".
- The PR body has one section per fix: problem → evidence → root cause → change → how it will be measured. It ends with "Generated with Claude Code".
- Open ONE `needs-owner` issue titled "Review learning PR #<n>" that links the PR, plus any proposals you couldn't apply (workflow, `CLAUDE.md` or settings changes, and task-spec rewrites). Send one push notification.

## 8. Close the loop
Check the lessons from 7 or more days ago against their `measure` using recent metadata. If a lesson didn't help, say so in this run's PR and propose reverting or replacing it.

## 9. Log
Post an agent-log comment with the metadata. Use outcome `learned`, or `no-fix` if the friction wasn't fixable. Also add `fixes: <n>` and `transcripts: available|unavailable`.
