#!/usr/bin/env bash
# Deterministic merge gates 1-5 for one PR (owner-only file; see .claude/skills/merge-queue).
#   scripts/merge-gate.sh <pr-number>
# Gates: complete, guard, mergeable, CI green, no protected files, Claude PASS (content-equivalent).
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
# Public repo: only same-repo PRs opened by the owner (agents push as the owner) can auto-merge.
# Anyone else's PR (forks, collaborators) is merged by hand after a code-owner review.
[ "$(jq -r .head.repo.full_name <<<"$pr")" = "$repo" ] || fail "fork PR: merged by hand after review"
[ "$(jq -r .user.login <<<"$pr")" = "${OWNER_LOGIN:-tomer555}" ] || fail "PR not opened by the owner: merged by hand after review"
# MERGE_ON_GREEN=1 (merge-on-green workflow, owner 2026-11-18): a non-agent branch needs no label and skips
# gates 5-6, so it merges once complete and CI is green. Agent (claude/*) PRs always run the full gate:
# ready-to-merge label plus a claude-review PASS, so they never merge before review.
on_green=0
[ "${MERGE_ON_GREEN:-0}" = 1 ] && [[ "$head_ref" != claude/* ]] && on_green=1
if [ "$on_green" != 1 ]; then
  [[ "$head_ref" == claude/* ]] || fail "head $head_ref is not a claude/* branch"
  jq -e '.labels[]|select(.name=="ready-to-merge")' <<<"$pr" >/dev/null || fail "no ready-to-merge label"
fi
jq -e '.labels[]|select(.name=="hold")' <<<"$pr" >/dev/null && fail "owner hold label"
# Owner can pause CI and review (gh workflow disable ci / claude-review): their gates are then skipped.
wf_off() { [ "$(gh api "repos/$repo/actions/workflows/$1" -q .state 2>/dev/null)" = disabled_manually ]; }

if ! { git fetch -q origin main "$head_ref" && git checkout -q --detach "$sha"; }; then fail "cannot check out $sha"; fi

# 1 complete: every tasks.md touched by this PR has no unchecked task.
# Planning PRs (#112) add or fix a change's plan, so its tasks are open by design; exempt only
# when the PR touches nothing outside openspec/changes/.
planning_only=false
# Owner branches under MERGE_ON_GREEN get the same exemption (an owner may add a change plan).
if { [[ "$head_ref" == claude/planning-* ]] || [ "$on_green" = 1 ]; } && ! git diff --name-only origin/main...HEAD | grep -qv '^openspec/changes/'; then
  planning_only=true
fi
$planning_only || for f in $(git diff --name-only origin/main...HEAD -- 'openspec/changes/*/tasks.md'); do
  [ -f "$f" ] || continue
  if grep -qE '^\s*- \[ \]' "$f"; then fail "1 complete: unchecked tasks in $f"; fi
done
echo "ok 1 complete"
# 2 guard
BRANCH="$head_ref" bash scripts/check-task-edits.sh >/dev/null || fail "2 guard: check-task-edits failed"
echo "ok 2 guard"
# 3 mergeable: GitHub can merge it without conflicts (being behind main is fine; main CI catches breakage)
m=$(gh api "repos/$repo/pulls/$n" -q .mergeable)
for _ in 1 2 3; do [ "$m" != null ] && break; sleep 3; m=$(gh api "repos/$repo/pulls/$n" -q .mergeable); done
[ "$m" = true ] || fail "3 not mergeable (conflicts: merge origin/main into $head_ref, resolve, push)"
echo "ok 3 mergeable"
# 4 CI green on the head SHA
if wf_off ci.yml; then echo "skip 4 ci: ci workflow disabled by owner"; else
# Latest run per check name; the claude-review jobs (review, mention) are judged by gate 6 instead.
runs=$(gh api "repos/$repo/commits/$sha/check-runs?per_page=100" -q '[.check_runs[]|select(.name!="review" and .name!="mention")|{n:.name,s:.status,c:.conclusion,t:(.started_at//"")}]|group_by(.n)|map(max_by(.t))')
[ "$(jq length <<<"$runs")" -gt 0 ] || fail "4 ci: no check runs yet"
jq -e 'all(.[]; .s=="completed")' <<<"$runs" >/dev/null || fail "4 ci: checks still running"
jq -e 'all(.[]; .c=="success" or .c=="skipped" or .c=="neutral")' <<<"$runs" >/dev/null || fail "4 ci: $(jq -r '[.[]|select(.c!="success" and .c!="skipped" and .c!="neutral")|.n]|join(",")' <<<"$runs") not green"
jq -e 'any(.[]; .n=="hygiene" and .c=="success")' <<<"$runs" >/dev/null || fail "4 ci: hygiene did not succeed"
echo "ok 4 ci-green"
fi
[ "$on_green" = 1 ] && { echo "GATE PASS $sha"; exit 0; }
# 5 no protected files
prot=$(git diff --name-only origin/main...HEAD -- .github/workflows .claude/settings.json .claude/settings.local.json .claude/agents .claude/skills/merge-queue .claude/skills/merge-review 'scripts/check-task-edits*' scripts/merge-gate.sh scripts/check-agent-docs.sh AGENTS.md CLAUDE.md openspec/config.yaml docs/agents/common.md docs/agents/merge.md scripts/run-lock.sh scripts/worker-has-work.sh scripts/owner-replies.sh scripts/change-status.sh scripts/change-issue.sh scripts/change-sync.sh scripts/roadmap-sync.sh scripts/issue-lib.sh scripts/dates-sync.sh)
[ -z "$prot" ] || fail "5 protected files changed: ${prot//$'\n'/ }"
echo "ok 5 no-protected-files"
# 6 independent review by the claude-review workflow (Claude GitHub App), for this exact head SHA
wf_off claude-review.yml && { echo "skip 6 review: claude-review workflow disabled by owner"; echo "GATE PASS $sha"; exit 0; }
verdict=$(gh api "repos/$repo/issues/$n/comments?per_page=100" --paginate \
  -q '[.[]|select(.user.type=="Bot" and (.user.login|startswith("claude")))|.body|split("\n")[0]|select(startswith("merge-review "))]|last // ""')
[ -n "$verdict" ] || fail "6 review: no claude merge-review verdict yet (claude-review workflow runs on the ready-to-merge label)"
vsha=$(sed -nE 's/^merge-review ([0-9a-f]{7,40}): (PASS|FAIL).*/\1/p' <<<"$verdict")
vres=$(sed -nE 's/^merge-review ([0-9a-f]{7,40}): (PASS|FAIL).*/\2/p' <<<"$verdict")
[ -n "$vsha" ] || fail "6 review: unreadable verdict"
if [[ "$sha" != "$vsha"* ]]; then
  # A PASS still counts if the PR's own change is identical to what was reviewed (only main was
  # merged in, or commits that net to nothing): compare patch-ids of the PR diffs against main.
  git cat-file -e "$vsha^{commit}" 2>/dev/null || git fetch -q origin "$vsha" 2>/dev/null || true
  pid() { git diff "$(git merge-base origin/main "$1")" "$1" | git patch-id --stable | cut -d' ' -f1; }
  if git cat-file -e "$vsha^{commit}" 2>/dev/null && [ "$(pid "$vsha")" = "$(pid HEAD)" ]; then
    echo "ok 6 verdict for $vsha still applies: PR content unchanged"
  else
    fail "6 review: verdict is for ${vsha}, PR content changed since (re-review runs on push)"
  fi
fi
[ "$vres" = PASS ] || fail "6 review: claude verdict FAIL for $sha (fix findings, push, review reruns)"
echo "ok 6 claude-review"
echo "GATE PASS $sha"
