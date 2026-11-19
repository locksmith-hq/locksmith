# Worker (Sonnet; several run at once, each on its own change)

Each run unblocks finished work, then works on changes for about 40 minutes. A blocked change is parked, not a reason to stop.

0. **Start.**
   - Run `bash scripts/worker-has-work.sh`. If it prints `idle`, stop and post nothing.
   - Use the `run-start` skill with `worker`.
   - Use the `merge-queue` skill: mark planning PRs ready, then main CI, then unblock ready PRs (merge-on-green merges them).
   - Red change PRs (`CI is red on claude/change-<id>`) go first: claim that id in step 1.
1. **Claim a change.** For each id from `bash scripts/change-status.sh --ready`, in order, run `bash scripts/run-lock.sh acquire worker-<session> <id>`. Take the first. If none, go to step 6.
   - Read its last 3 `progress.md` entries and `git log --oneline -10` on its branch.
2. **CI first.** Failing checks or conflicts on the change's PR are the first task (logs: `gh api .../actions/jobs/<id>/logs | tail -200`).
3. **Branch.** If `origin/claude/change-<id>` exists, use it and merge main in (`run-start` step 3). Otherwise branch from `origin/main`. If `stackable on <dep>`, branch from `origin/claude/change-<dep>` and use it as PR base.
4. **Baseline** (skip if `run-start` merged nothing and the last progress entry shows `just ci` green): run `bash scripts/bg.sh start ci 1800 -- just ci` and start task one; poll with `bg.sh wait ci`, never looped (no `sleep`). If red, fix it first.
5. **Tasks.** Work in order with the `evaluate-escalate` skill, committing after each. **Park** the change when it needs the lead (`needs-rescue`, see `common.md`): finish it (step 7), then go back to step 1 for the next change.
6. **Plan ahead** (also after step 5): if `worker-has-work.sh` printed `plan the next one`, write the next roadmap change whose prerequisites are archived or in review. Lock its id first (`run-lock.sh acquire worker-<session> <id>`; busy: plan the next one). Use the `openspec-propose` skill on `claude/planning-<id>`, set `x-depends_on: [..]`, then open a PR marked ready.
7. **Finish each change** before leaving it:
   - Use the `run-log` skill.
   - Push the branch once and open a non-draft PR if none exists.
   - If every task is ticked, archive the change and mark the PR ready (the `merge-queue` skill).
   - Always release the lock, even after a failure: `bash scripts/run-lock.sh release worker-<session> <id>`.

Other workers' PRs may touch the same files; the merge queue resolves conflicts.
