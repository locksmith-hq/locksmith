#!/usr/bin/env bash
# The tracking issue for one OpenSpec change (label `change`, title "<id>: <proposal title>").
# It carries the change's lock (run-lock.sh) and its status page (change-sync.sh).
#   scripts/change-issue.sh <id>          print the issue number, creating the issue if needed
#   scripts/change-issue.sh <id> --find   print it only if it exists; exit 1 otherwise
set -uo pipefail
repo=locksmith-hq/locksmith
id="${1:?usage: change-issue.sh <id> [--find]}"

n=$(gh api "repos/$repo/issues?labels=change&state=all&per_page=100" \
  -q "[.[]|select(.title|startswith(\"$id:\"))][0].number // empty")
if [ -z "$n" ]; then
  [ "${2:-}" = --find ] && exit 1
  title=$(sed -nE '1s/^# *(Proposal: *)?//p' "openspec/changes/$id/proposal.md" 2>/dev/null)
  n=$(gh api "repos/$repo/issues" -f title="$id: ${title:-$id}" -f 'labels[]=change' \
    -f body="Status page for OpenSpec change \`$id\`. Kept current by the change-sync workflow." -q .number) || exit 1
fi
echo "$n"
