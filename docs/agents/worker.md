# Worker (Sonnet; several run at once, each on its own change)

Each run unblocks finished work, then takes tasks for about 40 minutes, across as many changes as fit; a quick PR fix is never the whole run.

0. **Start.**
   - Run `bash scripts/worker-has-work.sh`. If it prints `idle` and you were not woken by an owner tag, run `bash scripts/request-work.sh` and stop.
   - Use the `run-start` skill with `worker`.
   - Use the `finish-pr` skill: red main first, then unblock your own PRs.
   - Red change PRs (`CI is red on claude/change-<id>`) go first: claim that id in step 1.
1. **Claim a change:** `bash scripts/run-lock.sh claim worker-<session> $(bash scripts/change-status.sh --ready)` prints the id you hold; `owned` ones are skipped. None: step 6.
   - Read its last 3 `progress.md` entries and `git log --oneline -10` on its branch.
2. **CI first.** Failing checks or conflicts on the change's PR are the first task (read failures as in `finish-pr`).
3. **Branch.** If `origin/claude/change-<id>` exists and its PR is yours or the owner account's, use it and merge main in (`run-start` step 3); else release and take the next id. Otherwise branch from `origin/main`. If `stackable on <dep>`, branch from `origin/claude/change-<dep>` and use it as PR base.
4. **Baseline:** main's CI checks (`gh run list -b main -L 3`), not a local `just ci`. If red, fix it first.
5. **Tasks.** Work in order with the `evaluate-escalate` skill, committing after each. A task over 30 minutes: commit a verified slice and log the rest in `progress.md`. When the change is done, or **parked** (`needs-rescue`; open one at once when a task needs a key, host or tool the VM lacks), finish it (step 7), then go back to step 1 for the next change while time remains.
6. **Plan ahead** (also after step 5): if `worker-has-work.sh` printed `plan the next one (<id>)`, write that change; the roadmap's `Needs` column, not your judgement, says it can start. Lock one: `run-lock.sh claim worker-<session> <id> $(bash scripts/change-status.sh --plannable)`. Use the `openspec-propose` skill on `claude/planning-<id>`, set `x-depends_on` to its unarchived `Needs`, then open a PR and finish it (`finish-pr`). Nothing to plan: `request-work.sh`.
7. **Finish each change** before leaving it:
   - `run-log` step 1 (`progress.md`) only.
   - Push the branch once and open a non-draft PR if none exists.
   - Every task ticked: finish the PR (`finish-pr`).
   - Always release the lock, even after a failure: `bash scripts/run-lock.sh release worker-<session> <id>`.
8. **End the run:** `run-log` steps 2–3, once.
