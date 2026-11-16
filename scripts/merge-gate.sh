#!/usr/bin/env bash
# Deterministic merge gates 1-5 for one PR (owner-only file; see .claude/skills/merge-queue).
#   scripts/merge-gate.sh <pr-number>
# Prints one line per gate and a final "GATE PASS <head-sha>" or "GATE FAIL <reason>".
# Gate 6: the latest verdict comment from the Claude GitHub App (claude-review workflow) must be
# "merge-review <sha>: PASS" for the current head SHA.
# Leaves the repo checked out at the PR head (detached).
set -uo pipefail
repo=locksmith-hq/locksmith
n="${1:?usage: merge-gate.sh <pr-number>}"
fail() { echo "GATE FAIL $*"; exit 1; }

pr=$(gh api "repos/$repo/pulls/$n") || fail "cannot read PR #$n"
state=$(jq -r .state <<<"$pr"); draft=$(jq -r .draft <<<"$pr")
head_ref=$(jq -r .head.ref <<<"$pr"); sha=$(jq -r .head.sha <<<"$pr")
[ "$state" = open ] || fail "PR is $state"
[ "$draft" = false ] || fail "PR is a draft (cloud runs cannot un-draft; needs owner)"
[[ "$head_ref" == claude/* ]] || fail "head $head_ref is not a claude/* branch"
jq -e '.labels[]|select(.name=="ready-to-merge")' <<<"$pr" >/dev/null || fail "no ready-to-merge label"
jq -e '.labels[]|select(.name=="hold")' <<<"$pr" >/dev/null && fail "owner hold label"

if ! { git fetch -q origin main "$head_ref" && git checkout -q --detach "$sha"; }; then fail "cannot check out $sha"; fi

# 1 complete: every tasks.md touched by this PR has no unchecked task
for f in $(git diff --name-only origin/main...HEAD -- 'openspec/changes/*/tasks.md'); do
  [ -f "$f" ] || continue
  if grep -qE '^\s*- \[ \]' "$f"; then fail "1 complete: unchecked tasks in $f"; fi
done
echo "ok 1 complete"
# 2 guard
BRANCH="$head_ref" bash scripts/check-task-edits.sh >/dev/null || fail "2 guard: check-task-edits failed"
echo "ok 2 guard"
# 3 up to date
git merge-base --is-ancestor origin/main HEAD || fail "3 behind main: merge origin/main into $head_ref, push, retry next run"
echo "ok 3 up-to-date"
# 4 CI green on the head SHA
# Latest run per check name; the claude-review jobs (review, mention) are judged by gate 6 instead.
runs=$(gh api "repos/$repo/commits/$sha/check-runs?per_page=100" -q '[.check_runs[]|select(.name!="review" and .name!="mention")|{n:.name,s:.status,c:.conclusion,t:(.started_at//"")}]|group_by(.n)|map(max_by(.t))')
[ "$(jq length <<<"$runs")" -gt 0 ] || fail "4 ci: no check runs yet"
jq -e 'all(.[]; .s=="completed")' <<<"$runs" >/dev/null || fail "4 ci: checks still running"
jq -e 'all(.[]; .c=="success" or .c=="skipped" or .c=="neutral")' <<<"$runs" >/dev/null || fail "4 ci: $(jq -r '[.[]|select(.c!="success" and .c!="skipped" and .c!="neutral")|.n]|join(",")' <<<"$runs") not green"
jq -e 'any(.[]; .n=="hygiene" and .c=="success")' <<<"$runs" >/dev/null || fail "4 ci: hygiene did not succeed"
echo "ok 4 ci-green"
# 5 no protected files
prot=$(git diff --name-only origin/main...HEAD -- .github/workflows .claude/settings.json .claude/settings.local.json .claude/agents .claude/skills/merge-queue .claude/skills/merge-review 'scripts/check-task-edits*' scripts/merge-gate.sh scripts/check-agent-docs.sh AGENTS.md CLAUDE.md openspec/config.yaml docs/agents/common.md docs/agents/merge.md)
[ -z "$prot" ] || fail "5 protected files changed: ${prot//$'\n'/ }"
echo "ok 5 no-protected-files"
# 6 independent review by the claude-review workflow (Claude GitHub App), for this exact head SHA
verdict=$(gh api "repos/$repo/issues/$n/comments?per_page=100" --paginate \
  -q '[.[]|select(.user.type=="Bot" and (.user.login|startswith("claude")))|.body|split("\n")[0]|select(startswith("merge-review "))]|last // ""')
[ -n "$verdict" ] || fail "6 review: no claude merge-review verdict yet (claude-review workflow runs on the ready-to-merge label)"
vsha=$(sed -nE 's/^merge-review ([0-9a-f]{7,40}): (PASS|FAIL).*/\1/p' <<<"$verdict")
vres=$(sed -nE 's/^merge-review ([0-9a-f]{7,40}): (PASS|FAIL).*/\2/p' <<<"$verdict")
[ -n "$vsha" ] && [[ "$sha" == "$vsha"* ]] || fail "6 review: latest verdict is for ${vsha:-unknown}, not head $sha (wait for re-review)"
[ "$vres" = PASS ] || fail "6 review: claude verdict FAIL for $sha (fix findings, push, review reruns)"
echo "ok 6 claude-review"
echo "GATE PASS $sha"
