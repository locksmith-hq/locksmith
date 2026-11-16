---
name: merge-queue
description: Autonomously merge finished Locksmith PRs (label ready-to-merge) through deterministic gates plus an independent Opus review, then archive, and fix red main first. Also how to mark a PR ready. Worker step 0.
---

# Merge queue (only the worker merges)

## Mark a PR ready (any agent)
When the last task is ticked and verified, or an archive, learning or research PR is complete:
1. Make sure the PR is not a draft. Always create PRs with `-F draft=false`.
2. Add the `ready-to-merge` label.
3. Comment a summary: what changed (3 lines), how it was verified, and the risks. Every merge is a merge commit, so it can be undone with `git revert -m 1 <sha>`.

Never mark a PR ready while a `needs-rescue` issue is open for that change.

## Main first
If the latest `ci` run on main failed, fixing it comes first. Open `claude/fix-main-<date>`, use the `evaluate-escalate` skill, and mark the PR ready.

## Merge
Take candidates oldest first, at most 2 per run, and stop at the first failure.
1. Run `bash scripts/merge-gate.sh <pr>`. It checks six gates: the work is complete, the guard passes, the branch is up to date, CI is green, no protected files changed, and the latest Claude review verdict is PASS for the head SHA. That review comes from the `claude-review` workflow, which runs in GitHub Actions when the `ready-to-merge` label is added and on every push to a labelled PR.
   - **Gate 3 fails:** merge `origin/main` into the branch, run `just ci`, push once, and retry next run. The push re-triggers the review.
   - **Gate 6 has no verdict yet:** leave the PR for the next run.
   - **Gate 6 FAIL:** fix the review's findings with the `evaluate-escalate` skill, then push once. The push triggers a new review.
   - **Any other failure:** comment the reason on the PR. If the failure is about protected files, also open a `needs-owner` issue.
2. **Merge on GATE PASS,** pinned to the reviewed SHA:
   `gh api -X PUT repos/locksmith-hq/locksmith/pulls/<pr>/merge -f merge_method=merge -f sha=<sha>`
3. **After merging,** if the PR finished an OpenSpec change, use the `archive-change` skill.
