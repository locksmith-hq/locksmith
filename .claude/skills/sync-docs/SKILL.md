---
name: sync-docs
description: Bring this repo's docs back in line with its code, config and (where stated) live state. Use after a change to the code, infra or workflows the docs describe, or when asked to "sync docs" or "update the architecture doc".
---

# sync-docs

Shared skill (source: `locksmith-common`). Repo specifics live in `docs/sync-docs.md`; read it first. It lists
the docs to keep true (in priority order), where each claim is defined, and any read-only live checks.
Without it, the docs are `README.md` and `docs/**`, and the sources are the code, config and CI files they describe.

Never put a secret value, token or the owner's email in a doc. Never copy anything from a private repo into a public one.

## Steps

1. **What changed.** `git log --oneline -20 origin/main` plus the "last synced" date in the main doc; read the
   merged PRs since then.
2. **Read the sources, not memory.** For each claim in the docs, find where it is defined (code, config, workflows,
   `justfile`, scripts) and compare.
3. **Live state, only if `docs/sync-docs.md` says so.** Read-only commands only. If sign-in has expired, say so and
   skip that check; do not sign in.
4. **Edit.** Fix only what is wrong or missing. Keep each page's structure and any diagram matching the code.
   Bump the "last synced" / "last updated" line when you touch a page.
5. **Check.** `git diff --stat` touches only docs and this repo's `docs/sync-docs.md`. Grep the diff for anything
   shaped like a secret or an email (`grep -nE '@[a-z0-9-]+\.|ghp_|ghs_|BEGIN .*KEY'`). Every path and command you
   wrote exists.
6. **Ship.** Branch from `origin/main` (`claude/sync-docs-<date>`), commit "docs: sync with <what changed>", open a
   PR listing each fact you changed and its source. Docs only: no code or infra in the same PR.
