#!/usr/bin/env bash
# Cheap "is there anything to do?" check so idle worker runs exit in seconds (idle agents spend nothing).
# Exit 0 and print the reasons when there is work; exit 1 and print "idle" when there is none.
set -uo pipefail
repo=locksmith-hq/locksmith
work=()
git fetch -q origin 2>/dev/null
# A worker acts only on PRs it opened (owner 2026-11-20); without a persona (identities paused) count every PR.
AGENT_PERSONA=${AGENT_PERSONA:-$(cat "${AGENT_ID_DIR:-$HOME/.config/locksmith-agent}/persona" 2>/dev/null)}  # agent-identity.sh records it; later shells lose the export
me=${AGENT_PERSONA:+locksmith-$AGENT_PERSONA[bot]}
mine='select(env.me == "" or .user.login == env.me)'; export me

# Your PRs whose merge review failed (fix the findings; worker.md step 0)
n=$(gh api "repos/$repo/issues?labels=review-failed&state=open" -q "[.[]|select(.pull_request)|$mine]|length")
[ "$n" -gt 0 ] && work+=("$n of your PR(s) failed merge review")

# Red main CI
c=$(gh api "repos/$repo/actions/workflows/ci.yml/runs?branch=main&per_page=1" -q '.workflow_runs[0].conclusion // ""')
[ "$c" = failure ] && work+=("main CI is red")

# Open change PRs whose latest ci run failed (worker.md step 0 fixes them first)
for b in $(gh api "repos/$repo/pulls?state=open&per_page=100" -q ".[]|$mine|.head.ref|select(startswith(\"claude/change-\"))"); do
  r=$(gh api "repos/$repo/actions/workflows/ci.yml/runs?branch=$b&per_page=1" -q '.workflow_runs[0].conclusion // ""')
  [ "$r" = failure ] && work+=("CI is red on $b")
done

# Changes a worker may take now (dependency-aware, not parked, not claimed), and finished ones to archive.
status=$(bash "$(dirname "$0")/change-status.sh")
while IFS=$'\t' read -r id state _; do
  case "$state" in
    ready|stackable) work+=("$id is $state") ;;
    finished) work+=("$id is finished but not archived") ;;
  esac
done <<<"$status"

# Plan ahead: with fewer than three takeable changes (one per scheduled worker; owner 2026-11-19: parallel work
# first), no open planning PR, and a roadmap row whose Needs are met, writing that row is work.
next=$(bash "$(dirname "$0")/change-status.sh" --plannable | head -1)
takeable=$(grep -cE $'\t(ready|stackable)\t' <<<"$status" || true)
plans=$(gh api "repos/$repo/pulls?state=open&per_page=100" -q '.[]|select(.head.ref|startswith("claude/planning-"))|[.number, (.auto_merge != null)]|@tsv')
[ "${takeable:-0}" -lt 3 ] && [ -z "$plans" ] && [ -n "$next" ] && work+=("fewer than 3 changes ready: plan the next one ($next)")
# A planning PR without auto-merge never merges and also suppresses planning, so workers would idle forever.
while IFS=$'\t' read -r pr auto; do
  [ "$auto" = false ] && work+=("planning PR #$pr does not have auto-merge on")
done <<<"$plans"

if [ "${#work[@]}" -gt 0 ]; then printf 'work: %s\n' "${work[@]}"; exit 0; fi
echo idle; exit 1
