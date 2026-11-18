---
name: merge-queue
description: Mark Locksmith PRs ready-to-merge (with the archive inside), fix red main first, and unblock ready PRs the merge gate rejects (review findings, conflicts). The merge-on-green workflow does the merging. Worker step 0.
---

# Merge queue (only the merge-on-green workflow merges)

## Mark a PR ready (any agent)
When the last task is ticked and verified, or an archive, lead or research PR is complete:
0. If this PR ticks a change's last task, archive the change in this same PR first: `archive-change` steps 2–4 on this branch.
1. Make sure the PR is not a draft. Always create PRs with `-F draft=false`.
2. Add the `ready-to-merge` label.
3. Comment a summary: what changed (3 lines), how it was verified, and the risks. Every merge is a merge commit, so it can be undone with `git revert -m 1 <sha>`.

Never mark a PR ready while a `needs-rescue` issue is open for that change.

## Main first
If the latest `ci` run on main failed, fixing it comes first. Open `claude/fix-main-<date>`, use the `evaluate-escalate` skill, and mark the PR ready.

## Unblock ready PRs
Take candidates oldest first, at most 4 per run. A failed candidate does not stop the others.
1. Run `bash scripts/merge-gate.sh <pr>`. It checks six gates:
   - the change is complete;
   - the task-edit guard passes;
   - the PR is mergeable (GitHub reports no conflicts; being behind main is fine);
   - CI is green;
   - no protected files changed;
   - Claude's review passed (from the `claude-review` workflow, which runs on the `ready-to-merge` label and on pushes). A PASS still counts when the PR's own diff is unchanged since the review, for example after merging main in.

   If a gate fails:
   - **Gate 6, review still running:** move on; don't wait. merge-on-green merges it when the review passes; a `review-failed` label wakes the event worker to fix it.
   - **Gate 6 FAIL:** fix the findings with the `evaluate-escalate` skill, then push once. The push triggers a new review.
   - **Gate 3 (conflicts):** several PRs are open at once, so this is routine. Lock the change (`run-lock.sh acquire <you> <id>`), merge `origin/main` into the branch, and resolve:
     - `Cargo.lock`, `package-lock.json`: take main's, then rerun `cargo check` / `npm i`.
     - Workspace member lists, `justfile` recipes, roadmap rows: keep both sides.
     - Code: keep both behaviours; if they truly conflict, the later PR adapts.
     Then run `just ci`, push once and release the lock.
   - **Any other failure:** comment the reason on the PR. For protected files, also open a `needs-owner` issue unless the PR links one.
2. **On GATE PASS,** do nothing: merge-on-green merges it. Never merge a PR yourself.
