#!/usr/bin/env bash
# Cheap "is there anything to do?" check so idle worker runs exit in seconds (idle agents spend nothing).
# Exit 0 and print the reasons when there is work; exit 1 and print "idle" when there is none.
set -uo pipefail
repo=locksmith-hq/locksmith
work=()
git fetch -q origin 2>/dev/null

# Finished PRs waiting for the merge queue
n=$(gh api "repos/$repo/issues?labels=ready-to-merge&state=open" -q length)
[ "$n" -gt 0 ] && work+=("$n ready-to-merge PR(s)")

# Red main CI
c=$(gh api "repos/$repo/actions/workflows/ci.yml/runs?branch=main&per_page=1" -q '.workflow_runs[0].conclusion // ""')
[ "$c" = failure ] && work+=("main CI is red")

# Owner approved on a needs-owner issue (other replies are the lead's: owner-replies.sh)
while IFS=$'\t' read -r i k; do
  [ "$k" = approval ] && work+=("owner approved on #$i")
done < <(bash "$(dirname "$0")/owner-replies.sh")

# Changes a worker may take now (dependency-aware, not parked, not claimed), and finished ones to archive.
status=$(bash "$(dirname "$0")/change-status.sh")
while IFS=$'\t' read -r id state _; do
  case "$state" in
    ready|stackable) work+=("$id is $state") ;;
    finished) work+=("$id is finished but not archived") ;;
  esac
done <<<"$status"

# Plan ahead: with fewer than two takeable changes and no open planning PR, writing the next one is work.
takeable=$(grep -cE $'\t(ready|stackable)\t' <<<"$status" || true)
plans=$(gh api "repos/$repo/pulls?state=open&per_page=100" -q '.[]|select(.head.ref|startswith("claude/planning-"))|[.number, any(.labels[]; .name=="ready-to-merge")]|@tsv')
[ "${takeable:-0}" -lt 2 ] && [ -z "$plans" ] && work+=("fewer than 2 changes ready: plan the next one")
# An unlabelled planning PR is invisible to the merge queue and also suppresses planning, so workers would idle forever.
while IFS=$'\t' read -r pr labelled; do
  [ "$labelled" = false ] && work+=("planning PR #$pr is not marked ready")
done <<<"$plans"

if [ "${#work[@]}" -gt 0 ]; then printf 'work: %s\n' "${work[@]}"; exit 0; fi
echo idle; exit 1
