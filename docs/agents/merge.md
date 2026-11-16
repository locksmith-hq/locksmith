# Merge policy (owner-only file)

The owner asked on 2026-11-16 for PRs to merge autonomously, with no waiting window.

- Only the **worker** merges, and only through the `merge-queue` skill.
- A PR merges only if `scripts/merge-gate.sh <pr>` prints `GATE PASS <sha>`. The script checks that:
  - the work is complete;
  - the guard passes;
  - GitHub reports the PR as mergeable, with no conflicts;
  - CI is green;
  - no protected files changed;
  - the independent review passed. That review is the `claude-review` workflow: Claude Opus running in GitHub Actions as the Claude GitHub App, posting `merge-review <sha>: PASS`. The verdict holds while the PR's own diff (by patch-id) is unchanged, so merging main in or pushes that add up to no net change do not need a new review.
- Merges are pinned to the reviewed SHA and always use a merge commit, so `git revert -m 1` undoes any of them.
- A PR that touches protected files never auto-merges. It gets a `needs-owner` issue instead.
- If the owner labels a PR `hold`, the worker does not merge it.
- If main CI goes red after a merge, fixing it comes before any other work.
- This file, `scripts/merge-gate.sh`, `.claude/skills/merge-queue`, `.claude/skills/merge-review` and the workflows change only in owner sessions.
