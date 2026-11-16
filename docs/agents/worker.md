# Worker (Sonnet, every 2h off-peak)

Each run merges finished work, then does tasks until the first failure or about 40 minutes, then pushes once and logs.

0. **Start.**
   - Run `bash scripts/worker-has-work.sh`. If it prints `idle`, stop and post nothing.
   - Run `bash scripts/run-lock.sh acquire worker-<session>`. If it reports busy, stop. Release the lock at the end of the run, even if the run failed.
   - Use the `run-start` skill with `worker`.
   - **Owner replies.** For each `needs-owner` issue the owner answered, apply the decision. Add the standing ones to `docs/agents/owner.md` in a small PR marked ready. Then close the issue with a comment.
   - Use the `merge-queue` skill: fix main CI first, work the merge queue, then archive merged changes.
1. **Pick the change.** Read `docs/roadmap.md` and run `openspec list`. The active change is the first one in roadmap order with unchecked tasks.
   - Read its `progress.md` (last 3 entries) and `git log --oneline -10` on `origin/claude/change-<id>`.
   - Skip any task that has an open `needs-rescue` issue.
   - If the next task is an owner gate, raise an owner decision.
2. **CI first.** If the change's PR has failing checks, fixing them is the first task. Get the logs with `gh api .../actions/jobs/<id>/logs | tail -200`.
3. **Branch.**
   - If `origin/claude/change-<id>` exists, use it. `run-start` brings it up to date.
   - Otherwise, check the proposal's "Depends on":
     - Dependency merged: branch from `origin/main`.
     - Dependency's PR fully ticked and green: branch from that PR's branch, and use it as the PR base.
     - Anything else: raise an owner decision.
4. **Baseline.** Run `just ci`. Once the stack exists, also run `just up && just harness-check`. If either is red, fixing it is the task.
5. **Tasks.** Work through them in order with the `evaluate-escalate` skill. Stop at the first rescue, at an owner gate, or after about 40 minutes.
6. **Finish.**
   - Use the `run-log` skill.
   - Commit and push once. Open a non-draft PR if none exists.
   - If every task is ticked, mark the PR ready with the `merge-queue` skill.
