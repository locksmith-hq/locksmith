# Worker (Sonnet orchestrator, 3x daily)

Each run first works the merge queue (`docs/agents/merge.md`). Then it takes tasks one at a time through implement → evaluate → escalate if needed. It keeps going to the next task while each one passes, stops at the first failure or after about 40 minutes of work, then commits, pushes once, logs and stops. This follows Anthropic's [harness for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) and the evaluator-optimizer pattern.

## Steps
0. **Merge queue and main health.**
   - Read `docs/agents/merge.md` from origin/main and follow it.
   - If the latest `ci` run on main failed, fixing main is this run's first task: open `claude/fix-main-<date>`, use the evaluate-then-escalate loop, and mark the PR ready.
   - If a merged change is not archived yet, archiving it is the next task.
1. **Orient.**
   - Run `bash scripts/run-meta.sh start worker`, then `git fetch -q origin && git checkout -q --detach origin/main`.
   - Read `docs/roadmap.md` and run `openspec list`. If openspec is missing, `npm i -g @fission-ai/openspec`.
   - The active change is the first change in roadmap order that has unchecked tasks.
   - If `origin/claude/change-<id>` exists, read its ticks, the last 3 progress entries, and `git log --oneline -10`.
   - Read the open `needs-rescue` issues. Skip any task that has one. If no other task is independent of it, log `waiting: rescue` and stop.
   - If the next task is an owner gate, raise an owner decision.
2. **Check CI first.** If the change has an open PR, read the check-runs for its head SHA. If any failed, fixing it is this run's task:
   - Read the job log: `gh api .../actions/jobs/<id>/logs | tail -200`.
   - Reproduce the failure locally.
   - Fix it through the loop below.
3. **Branch.**
   - If `origin/claude/change-<id>` exists, check it out.
   - Otherwise, read the proposal's "Depends on":
     - If the dependency is merged, branch from `origin/main`.
     - If the dependency's PR has every task ticked and green checks, branch from `origin/claude/change-<dep>` and use that branch as the PR base.
     - Otherwise, raise an owner decision ("merge <dep> to unblock <id>").
4. **Baseline.**
   - Run `just ci` (time it for `just_ci_s`). Once F0's stack exists on the branch, also run `just up && just harness-check`.
   - If the baseline is red, fixing it is this run's task.
   - If `just` is missing: `apt-get install -y just || cargo install just`.
   - If Docker is down: `sudo service docker start`.
5. **Run tasks one at a time, in order, through the evaluate-then-escalate loop.** Continue to the next task while each one passes and total work time is under about 40 minutes. Stop at the first task that goes to rescue, at an owner gate, or when time runs out. For each task:
   1. **Attempt 1.** The implementer subagent works on the task's tier. Give it:
      - the exact task text, design excerpt, files and verification command;
      - the rules: reuse OSS from `docs/research/oss-building-blocks.md`, check real versions, never print secrets.
   2. **Verify yourself.** Run the verification command and `just ci`. If `just ci` fails once, rerun it once, because there is a known flaky test.
   3. **Evaluate.** A separate subagent, never the implementer, reviews the work. It runs on `sonnet`, or on `opus` for `[opus]` tasks. Give it:
      - the task, spec excerpt and `git diff`;
      - the verification output;
      - the CLAUDE.md security rules.

      It answers PASS or FAIL with reasons, checking for:
      - real completion rather than stubs;
      - tests that test the real behaviour;
      - no possible secret leak;
      - no reinvented OSS;
      - real package versions.
   4. **Both PASS:** the task is done.
   5. **Otherwise, attempt 2 goes one tier up** (haiku → sonnet → opus). Give the new implementer the evaluator's reasons, the failing output and the attempt-1 diff. Then verify and evaluate again.
   6. **Attempt 2 also fails:**
      - Commit `WIP:` if the code builds; otherwise `git stash`.
      - Write a progress entry.
      - Open a `needs-rescue` issue titled "Rescue: <change> <task>" (or comment on an existing one) containing: the branch, the tiers used, the evaluator's reasons, failing output (60 lines max), your diagnosis, and the metadata. Do **not** notify the owner. The Opus rescue routine picks it up.
6. **Record.** On a pass, tick the task, append the progress entry, and commit.
7. **Push once.**
   - Run `git push -u origin claude/change-<id>`.
   - If no PR exists, open a DRAFT PR via REST.
   - Before pushing, check the PR state with `gh api repos/locksmith-hq/locksmith/pulls?head=locksmith-hq:claude/change-<id>&state=all`. Never push to a branch whose PR is merged or closed; start a new branch from origin/main instead.
   - When every task is ticked, mark the PR ready as described in `merge.md` (the `ready-to-merge` label plus a merge summary). Do not raise an owner decision for it: the merge queue handles it.
8. **Log.** Post the agent-log comment with the metadata.
