# Worker (Sonnet; several run at once, each on its own change)

Each run unblocks finished work, then takes several tasks (each up to 30 minutes of work) for about 40 minutes, across as many changes and PRs as fit.

0. **Start.**
   - Run `bash scripts/worker-has-work.sh`. If it prints `idle` and you were not woken by an owner tag, stop and post nothing.
   - Use the `run-start` skill with `worker`.
   - Use the `finish-pr` skill: red main first, then unblock your own PRs.
   - Red change PRs (`CI is red on claude/change-<id>`) go first: claim that id in step 1.
1. **Claim a change.** For each id from `bash scripts/change-status.sh --ready`, in order, run `bash scripts/run-lock.sh acquire worker-<session> <id>`. Take the first. If none, go to step 6.
   - Read its last 3 `progress.md` entries and `git log --oneline -10` on its branch.
2. **CI first.** Failing checks or conflicts on the change's PR are the first task (logs: `gh api .../actions/jobs/<id>/logs | tail -200`).
3. **Branch.** If `origin/claude/change-<id>` exists and its PR is yours, use it and merge main in (`run-start` step 3); else release and take the next id. Otherwise branch from `origin/main`. If `stackable on <dep>`, branch from `origin/claude/change-<dep>` and use it as PR base.
4. **Baseline** (skip if `run-start` merged nothing and the last progress entry shows `just ci` green): run `bash scripts/bg.sh start ci 1800 -- just ci` and start task one; poll with `bg.sh wait ci`, never looped (no `sleep`). If red, fix it first.
5. **Tasks.** Work in order with the `evaluate-escalate` skill, committing after each. A task over 30 minutes: commit a verified slice and log the rest in `progress.md`. When the change is done, or **parked** (`needs-rescue`; open one at once when a task needs a key, host or tool the VM lacks), finish it (step 7), then go back to step 1 for the next change while time remains.
6. **Plan ahead** (also after step 5): if `worker-has-work.sh` printed `plan the next one (<id>)`, write that change; the roadmap's `Needs` column, not your judgement, says it can start. Lock its id first (`run-lock.sh acquire worker-<session> <id>`; busy: the next id from `change-status.sh --plannable`). Use the `openspec-propose` skill on `claude/planning-<id>`, set `x-depends_on` to its unarchived `Needs`, then open a PR and finish it (`finish-pr`).
7. **Finish each change** before leaving it:
   - Use the `run-log` skill.
   - Push the branch once and open a non-draft PR if none exists.
   - Every task ticked: finish the PR (`finish-pr`).
   - Always release the lock, even after a failure: `bash scripts/run-lock.sh release worker-<session> <id>`.

Each author resolves conflicts on their own PR.
