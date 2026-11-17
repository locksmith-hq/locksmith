---
name: archive-change
description: Archive a merged OpenSpec change so its delta specs fold into openspec/specs and the roadmap shows it done. Use right after a change's PR merges.
---

# Archive a change

Normally the PR that ticks the change's last task archives it (merge-queue, "Mark a PR ready" step 0): skip step 1 and run steps 2–4 on that PR's branch. Use a separate PR only for a finished change that was merged without its archive.

1. Run `git checkout -b claude/archive-<id> origin/main`.
2. Run `openspec archive <id> --yes`. If the CLI is missing, install it first with `npm i -g @fission-ai/openspec`.
3. In `docs/roadmap.md`, set the change's status to ☑.
4. Run `openspec validate --all` and `just ci`.
5. Commit, push once, and open a PR with `-F draft=false`. Mark it ready using the `merge-queue` skill. It merges through the same gates on a later run.
