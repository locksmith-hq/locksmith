# Merge policy (owner-only file)

The owner asked on 2026-11-16 for PRs to merge autonomously, with no waiting window.

- Only the **worker** merges, and only through the `merge-queue` skill.
- A PR merges only if `scripts/merge-gate.sh <pr>` prints `GATE PASS <sha>`. The script checks that:
  - the work is complete;
  - the guard passes;
  - the branch is up to date with main;
  - CI is green;
  - no protected files changed.
- A fresh Opus reviewer that did not write the code must also give the diff a PASS.
- Merges are pinned to the reviewed SHA and always use a merge commit, so `git revert -m 1` undoes any of them.
- A PR that touches protected files never auto-merges. It gets a `needs-owner` issue instead.
- If the owner labels a PR `hold`, the worker does not merge it.
- If main CI goes red after a merge, fixing it comes before any other work.
- This file, `scripts/merge-gate.sh` and `.claude/skills/merge-queue` change only in owner sessions.
