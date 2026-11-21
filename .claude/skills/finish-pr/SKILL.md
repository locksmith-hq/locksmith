---
name: finish-pr
description: Finish and unblock your own Locksmith PRs through GitHub auto-merge (red main first, review FAIL, conflicts, threads). Workers act only on PRs they opened; the lead may also act on a worker's PR. Worker step 0.
---

# Finish your PRs (GitHub merges; `docs/agents/merge.md`)

## Whose PR
A PR belongs to the App that opened it; a `claude/change-*` PR the owner account opened belongs to that change's lock holder. Act only on your own: `gh pr list --author "locksmith-$AGENT_PERSONA[bot]"` (`@me` does not work with an App token). The lead may also fix or auto-merge a worker's PR. A worker never pushes to, labels or auto-merges another worker's PR or any PR the lead opened. Never approve, use `--admin` or call the merge API.

## Main first
If the latest `ci` run on main failed, fix it first: `claude/fix-main-<date>`, the `evaluate-escalate` skill, then auto-merge it.

## Finish a PR
When the last task is ticked and verified, or a planning, archive or lead PR is done:
1. If it ticks a change's last task, archive the change in this PR first (`archive-change` steps 2–4).
2. Comment a summary: what changed (3 lines), how it was verified, the risks.
3. Run `gh pr merge <n> --auto --merge`. This starts the Claude review; GitHub merges once every required check and the `merge-ready` status pass.

Never while a `needs-rescue` issue is open for that change.

## Unblock your PRs
Oldest first, at most 4 per run; one failure does not stop the others. Lock the change first (`run-lock.sh acquire <you> <id>`; busy: move on) and release it after.
- **`merge-ready` failure, review FAIL (`review-failed` label):** fix the findings with `evaluate-escalate`, resolve their threads, push once. The push reruns the review.
- **Unchecked tasks:** finish them or turn auto-merge off (`gh pr merge <n> --disable-auto`).
- **Conflicts:** merge `origin/main` into the branch. `Cargo.lock`, `package-lock.json`: take main's, rerun `cargo check` / `npm i`. Workspace members, `justfile` recipes, roadmap rows: keep both. Code: keep both behaviours; if they truly conflict, the later PR adapts. Run `just ci`, push once.
- **Red CI:** job logs are blocked by the proxy; read `gh api repos/locksmith-hq/locksmith/check-runs/<job id>/annotations`, fix, push once.
- **`needs owner approval`** (an annotation of the failed review): never re-arm auto-merge; open a `Decision:` `needs-rescue`.
- **`merge-ready` stuck on pending** (review timed out): `gh pr merge <n> --disable-auto`, then `--auto --merge` again. Any other `merge-ready` error: read the annotations first.
