#!/usr/bin/env bash
# Cheap "is there anything to do?" check so idle worker runs exit in seconds (idle agents spend nothing).
# Exit 0 and print the reasons when there is work; exit 1 and print "idle" when there is none.
set -uo pipefail
repo=locksmith-hq/locksmith
work=()
# An open harness-blocker labelled hold-workers stops every worker run (owner tags excepted, worker.md step 0) and the
# AWS tooling dispatcher, which runs this script per worker before it fires one.
[ "$(gh api "repos/$repo/issues?labels=harness-blocker,hold-workers&state=open&per_page=1" -q length 2>/dev/null)" = 1 ] && { echo idle; exit 1; }
git fetch -q origin 2>/dev/null
# A worker acts only on PRs it opened (owner 2026-11-20); without a persona count every PR (2026-11-23: the PM's
# review-failed #614 woke every worker that ran this before agent-start.sh).
AGENT_PERSONA=${1:-${AGENT_PERSONA:-$(cat "${AGENT_ID_DIR:-$HOME/.config/locksmith-agent}/persona" 2>/dev/null)}}  # $1 (worker.md step 0 runs before agent-start.sh records it)
me=${AGENT_PERSONA:+$(bash "$(dirname "$0")/agent-identity.sh" logins "$AGENT_PERSONA")}  # one login per line
# shellcheck disable=SC2016 # jq variables
mine='select(env.me == "" or (.user.login as $l | env.me | split("\n") | index($l)))'; export me

# Your PRs whose merge review failed (fix the findings; worker.md step 0)
n=$(gh api "repos/$repo/issues?labels=review-failed&state=open" -q "[.[]|select(.pull_request)|$mine]|length")
[ "$n" -gt 0 ] && work+=("$n of your PR(s) failed merge review")

# Red main CI
c=$(gh api "repos/$repo/actions/workflows/ci.yml/runs?branch=main&per_page=1" -q '.workflow_runs[0].conclusion // ""')
[ "$c" = failure ] && work+=("main CI is red")

# Open change PRs whose latest ci run failed (worker.md step 0 fixes them first), unless an open needs-rescue issue
# names the change (matched like change-status.sh): the lead has it, so waking a worker for it is wasted.
rescues=$(gh api "repos/$repo/issues?labels=needs-rescue&state=open&per_page=100" -q '.[]|(.title+" "+(.body // ""))|gsub("\n";" ")' 2>/dev/null)
for b in $(gh api "repos/$repo/pulls?state=open&per_page=100" -q ".[]|$mine|.head.ref|select(startswith(\"claude/change-\"))"); do
  [ -n "$rescues" ] && grep -qF -- "${b#claude/change-}" <<<"$rescues" && continue
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
