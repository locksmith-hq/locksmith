# G1 go public

## Why
The repo is private on GitHub Free, so Actions minutes run out and the owner paused `ci`, `claude-review` and `change-sync` (#307). A public repo has no minutes limit, so `ci` can come back on. The owner asked (#147, #307) for agents to prepare the repo for publicity; only the owner flips visibility. Today there is no `LICENSE`, the workspace says `license = "UNLICENSED"`, the README still describes the retired M0–M16 plan, and a full-history `gitleaks detect` reports 17 findings (mostly documented fake fixtures) that nobody has triaged for a public audience.

## What changes
- A full-history secret scan is triaged: every finding is a fake fixture or a revoked value, each with a recorded reason in `.gitleaksignore`; anything real is raised to the owner as a `needs-owner` security issue, never rewritten silently.
- Licences match the decision in `openspec/config.yaml`: AGPL-3.0 for server components, Apache-2.0 for SDKs, CLI, plugins and schemas. `LICENSE` files, per-crate/package `license` fields and a `cargo-deny` licence check agree; no `ee/`.
- A public-facing `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and an updated `SECURITY.md`: what Locksmith is, the security promise, quick start (`just up`), and an honest label of each protection (prevention, containment, detection).
- `scripts/public-check.sh` (seconds-long, runs in `just ci`): fails on a missing licence, a stale README link, a secret in the tree, and any path or string on a denylist of owner-only or agent-only material (internal tokens, app keys, private hostnames, account IDs).
- `docs/going-public.md`: the owner's flip checklist (visibility, re-enable `ci` and `claude-review`, branch rules, secret-scanning and advisory settings, rotate anything the scan flagged).

## Usable outcome
The owner can flip the repo to public with one checklist, knowing the history is clean, the licences are clear and a newcomer can read the README and run `just up`.

## Out of scope
Flipping visibility, changing repo, Actions or account settings, re-enabling workflows (the owner does these), rewriting git history (needs a `needs-owner` decision if the scan finds a real secret), a marketing site, trademark and logo work, release signing (P2), and relicensing decisions beyond the recorded AGPL/Apache split.

## Depends on
none. It touches docs, licences and a check script, not the S5/S6/X1 code.

## Protected files
`.github/workflows/*`, `AGENTS.md`, `CLAUDE.md` and the gate scripts are protected. If the denylist check or re-enabling `ci` needs a workflow change, it goes in a `needs-owner` issue with a patch, never an agent edit. `scripts/public-check.sh` is a new unprotected script wired into `justfile`.
