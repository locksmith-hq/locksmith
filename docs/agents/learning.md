# Learning loop (Opus, daily 00:35)

Goal: make the next runs cheaper and more reliable. Fix things in scripts or skills, not in more prose. Instructions must not grow.

## Steps

0. **Check for friction.** Collect the last 24 h of agent-log metadata, rescue issues, failed CI runs and progress entries. Stop with "no friction" if all of these hold:
   - every outcome is done, idle, healthy or merged;
   - there were no escalations, rescues or CI failures;
   - total friction is 120 s or less;
   - no run took longer than 2700 s.
1. **Gather evidence.** Use the `run-start` skill with `learning`. For each friction point, collect the metadata, progress notes, CI logs, and the session transcript if you can read it. Record `transcripts: available` or `transcripts: unavailable`. Never invent evidence.
2. **Pick what to fix.** Classify each point as one of: setup, flaky, instructions, tier, task-spec, slow, tooling-gap or stuck-time. Pick at most 3, ranked by time lost × frequency.
3. **Fix.** Work on `claude/learning-<date>`, branched from origin/main. In order of preference:
   1. a script in `scripts/`;
   2. a skill change, to its body or its Gotchas section;
   3. a short edit to a role file;
   4. a lesson in `docs/agents/lessons.md` (5 active at most).

   When a lesson becomes a script or a gotcha, move it to `lessons-archive.md`. Never touch protected files (see `common.md`). Task-spec problems and protected-file changes go in a `needs-owner` issue instead.
4. **Verify.** Run `just ci`, `bash scripts/check-task-edits.test.sh` and `bash scripts/check-agent-docs.sh`. The total word count of `docs/agents` plus `.claude/skills` must not increase.
5. **Ship.** Push once and open a non-draft PR with one section per fix: evidence, root cause, change, and the metric it should move. Mark it ready with the `merge-queue` skill; it auto-merges through the gates.
6. **Close the loop.** Check fixes that are 7 or more days old against their metric, and revert any that didn't help.
7. **Log.** Use the `run-log` skill. The outcome is `learned` or `no-fix`.
