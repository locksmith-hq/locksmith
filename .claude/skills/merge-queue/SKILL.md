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
1. Run `bash scripts/merge-gate.sh <pr>`. It checks gates 1–5: the PR is complete, the guard passes, the branch is up to date, CI is green, and no protected files changed.
   - If gate 3 fails, run `git merge --no-edit origin/main` on the branch, then `just ci`, then push once, and retry on the next run.
   - Any other failure: comment the reason on the PR. For protected files, also open a `needs-owner` issue.
2. **Review.** A fresh `opus` subagent that didn't write the code reviews `git diff origin/main...HEAD` against the change's proposal, design and specs, plus the AGENTS.md security rules. It checks:
   - the specs are met, with no stubs or fake tests;
   - nothing can leak a secret;
   - no reinvented OSS;
   - licences are compatible.

   It answers PASS or FAIL. Comment `merge-review <sha>: PASS|FAIL` with its reasons, and reuse an existing PASS for the same SHA.
3. On PASS, merge pinned to that SHA:
   `gh api -X PUT repos/locksmith-hq/locksmith/pulls/<pr>/merge -f merge_method=merge -f sha=<sha>`
4. After the merge, if the PR finished an OpenSpec change, use the `archive-change` skill.
