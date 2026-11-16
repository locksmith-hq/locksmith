# Autonomous merge gates (owner-only file)

The owner asked on 2026-11-16 for PRs to merge autonomously. Only the **worker** merges, and only by following this file. No agent branch may change this file or `common.md`; the guard enforces that.

## PRs are never drafts
GitHub refuses to merge a draft PR, and turning a draft into a normal PR needs the GraphQL API, which cloud runs can't use. Every agent opens normal PRs (`-F draft=false`). Only the `ready-to-merge` label marks a PR as finished. If a candidate is still a draft, comment `draft: owner must mark ready` and open a `needs-owner` issue.

## Merge queue (worker step 0, every run)
Candidates are open PRs whose head branch starts with `claude/` and that carry the label `ready-to-merge`. Process the oldest first, merge at most 2 per run, and stop at the first failure.

For each candidate, ALL of the following must hold, or it is not merged:

1. **Complete.** Every task in the change's `tasks.md` on the head branch is `[x]`, OR the PR is an archive, learning or research PR, which has no tasks.
2. **Guard.** `BRANCH=<head> bash scripts/check-task-edits.sh` passes on the checked-out head.
3. **Up to date.** The head contains `origin/main` (`git merge-base --is-ancestor origin/main HEAD`). If it doesn't:
   - run `git merge origin/main` (never rebase a pushed branch), then `just ci`;
   - push once, then stop processing this PR in this run;
   - CI will run, and the PR becomes eligible next run.
4. **CI green.** Every check-run on the head SHA has the conclusion `success` or `skipped`, none is pending, and `hygiene` is `success`.
5. **No protected files.** `git diff --name-only origin/main...HEAD` has no path under:
   - `.github/workflows/`, `.claude/`
   - `scripts/check-task-edits*`
   - `CLAUDE.md`, `openspec/config.yaml`
   - `docs/agents/merge.md`, `docs/agents/common.md`

   If any are changed, remove the label, open a `needs-owner` issue, and skip the PR.
6. **Independent review.** An `opus` subagent that did not write the code reviews `git diff origin/main...HEAD` against the change's proposal, design and specs, plus the CLAUDE.md security rules. It answers PASS or FAIL with reasons. It checks:
   - all specs are satisfied, with no stubs or fake tests;
   - no secret can be printed, logged or serialized;
   - no plaintext lives outside `secrecy` or `zeroize` types;
   - no reinvented OSS;
   - dependency licences are compatible.

   Post the verdict as a PR comment headed `merge-review <head SHA>`. If a PASS comment already exists for the same head SHA, reuse it.
7. **Objection window, for PRs that change `docs/agents/*` (learning PRs).**
   - When `ready-to-merge` is first added, the PR must also have a `needs-owner` issue that says "auto-merges after <time+24h> unless you comment hold". That issue triggers the owner email.
   - Merge only after 24h have passed and nobody has commented `hold` on the PR or the issue.
   - If the owner comments `hold`, remove the label and leave the PR alone.

## Merge
- Run `gh api -X PUT repos/locksmith-hq/locksmith/pulls/<n>/merge -f merge_method=merge -f sha=<head SHA>`.
- Passing `sha` makes GitHub refuse the merge if the head moved after the review. Use the merge method, never squash or rebase, so the history and progress logs stay intact.
- Comment on the PR with the merge-review link and the metadata, and close the related `needs-owner` issue if one exists.

## After a merge
- **Archive.** When a merged PR finished an OpenSpec change, archiving it is this run's next task:
  - create branch `claude/archive-<id>` from origin/main;
  - run `openspec archive <id> --yes`, which folds the delta specs into `openspec/specs/`;
  - update the change's status in `docs/roadmap.md`;
  - run `openspec validate --all` and `just ci`;
  - open a PR labelled `ready-to-merge`. It goes through the same gates in a later run.
- **Main CI.** If the next `ci` run on main fails, fixing main is the next run's first task, ahead of the merge queue and new work.

## Marking a PR ready (any agent)
When a change's last task is ticked and verified, or an archive, learning or research PR is complete:
- add the label `ready-to-merge`;
- comment a merge summary with three parts:
  - **What changed:** 3 lines.
  - **How it was verified:** commands and results.
  - **Risks:** what could break and how to undo it. Every merge is a merge commit, so `git revert -m 1 <sha>` undoes it.

Never mark a PR ready while a `needs-rescue` issue for that change is open.
