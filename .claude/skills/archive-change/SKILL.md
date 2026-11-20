---
name: archive-change
description: Archive a finished OpenSpec change inside the PR that ticks its last task, so its delta specs fold into openspec/specs and the roadmap shows it done. A separate archive PR is only for a change merged without one.
---

# Archive a change

Normally the PR that ticks the change's last task archives it (`worker.md` step 7): skip step 1 and run steps 2–4 on that PR's branch. Use a separate PR only for a finished change that was merged without its archive.

1. Run `git checkout -b claude/archive-<id> origin/main`.
2. Run `openspec archive <id> --yes`. If the CLI is missing, install it first with `npm i -g @fission-ai/openspec`.
3. In `docs/roadmap.md`, set the change's status to ☑.
4. Run `openspec validate --all` and `just ci`.
5. Commit, push once, and open a PR with `-F draft=false`. Run `gh pr merge <n> --auto --merge`; it merges once the required checks pass.
