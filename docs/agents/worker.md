# Worker (Sonnet; several run at once, each on its own change)

Each run merges finished work, then works on changes for about 40 minutes. A blocked change is parked, not a reason to stop.

0. **Start.**
   - Run `bash scripts/worker-has-work.sh`. If it prints `idle`, stop and post nothing.
   - Use the `run-start` skill with `worker`.
   - **Owner approvals.** Apply each `approval` from `scripts/owner-replies.sh` (others are the lead's); record standing ones in `owner.md` or `openspec/decisions.md` (ready PR); close the issue.
   - Use the `merge-queue` skill: mark planning PRs ready, then main CI, merge queue.
1. **Claim a change.** For each id from `bash scripts/change-status.sh --ready`, in order, run `bash scripts/run-lock.sh acquire worker-<session> <id>`. Take the first. If none, go to step 6.
   - Read its last 3 `progress.md` entries and `git log --oneline -10` on its branch.
2. **CI first.** Failing checks or conflicts on the change's PR are the first task (logs: `gh api .../actions/jobs/<id>/logs | tail -200`).
3. **Branch.** If `origin/claude/change-<id>` exists, use it and merge main in (`run-start` step 3). Otherwise branch from `origin/main`. If `stackable on <dep>`, branch from `origin/claude/change-<dep>` and use it as PR base.
4. **Baseline** (skip if `run-start` merged nothing and the last progress entry shows `just ci` green): run `just ci` in the background (`long-commands` skill) and start the first task meanwhile. Check it before your first commit; if red, fixing it is the task.
5. **Tasks.** Work in order with the `evaluate-escalate` skill, committing after each. **Park** the change when a task needs a rescue, needs the owner (see `common.md`), or fails twice: finish it (step 7), then go back to step 1 for the next change.
6. **Plan ahead.** If `worker-has-work.sh` asked for planning and no `claude/planning-*` PR is open, write the next roadmap change whose prerequisites are archived or in review. Lock its id first (`run-lock.sh acquire worker-<session> <id>`; busy: plan the next one). Use the `openspec-propose` skill on `claude/planning-<id>`, set `x-depends_on: [..]`, then open a PR marked ready.
7. **Finish each change** before leaving it:
   - Use the `run-log` skill.
   - Push the branch once and open a non-draft PR if none exists.
   - If every task is ticked, archive the change and mark the PR ready (the `merge-queue` skill).
   - Always release the lock, even after a failure: `bash scripts/run-lock.sh release worker-<session> <id>`.

Other workers' PRs may touch the same files; the merge queue resolves conflicts.
