# Worker (Sonnet; several run at once, each on its own change)

Each run merges finished work, then works on changes until about 40 minutes have passed. A blocked change is parked, not a reason to stop.

0. **Start.**
   - Run `bash scripts/worker-has-work.sh`. If it prints `idle`, stop and post nothing.
   - Use the `run-start` skill with `worker`.
   - **Owner replies.** Apply each answered `needs-owner` decision. Add the standing ones to `docs/agents/owner.md` (or `openspec/decisions.md`) in a small PR marked ready. Then close the issue.
   - Use the `merge-queue` skill: main CI first, then the merge queue.
1. **Claim a change.** For each id from `bash scripts/change-status.sh --ready`, in order, run `bash scripts/run-lock.sh acquire worker-<session> <id>`. Take the first one you get. If none, go to step 6.
   - Read its `progress.md` (last 3 entries) and `git log --oneline -10` on `origin/claude/change-<id>`.
2. **CI first.** If the change's PR has failing checks or conflicts, fixing them is the first task. Logs: `gh api .../actions/jobs/<id>/logs | tail -200`.
3. **Branch.** If `origin/claude/change-<id>` exists, use it and merge main in (`run-start` step 3). Otherwise branch from `origin/main`. If the status was `stackable on <dep>`, branch from `origin/claude/change-<dep>` and use that as the PR base.
4. **Baseline.** Run `just ci`, plus `just up && just harness-check` when the stack is needed. If either is red, fixing it is the task.
5. **Tasks.** Work in order with the `evaluate-escalate` skill, committing after each. **Park** the change when a task needs a rescue, needs the owner (see `common.md`), or fails twice: finish it (step 7), then go back to step 1 for the next change.
6. **Plan ahead.** If `worker-has-work.sh` asked for planning and no `claude/planning-*` PR is open, write the next roadmap change whose prerequisites are archived or in review. Use the `openspec-propose` skill on `claude/planning-<id>`, set `x-depends_on: [..]` in its `.openspec.yaml`, then open a PR and mark it ready.
7. **Finish each change** before leaving it:
   - Use the `run-log` skill.
   - Push the branch once and open a non-draft PR if none exists.
   - If every task is ticked, archive the change and mark the PR ready (the `merge-queue` skill).
   - Release the lock: `bash scripts/run-lock.sh release worker-<session> <id>`. Always release it, even after a failure.

Other workers may hold other changes and open PRs that touch the same files. Conflicts are normal; the merge queue resolves them.
