#!/usr/bin/env bash
# The tracking issue for one OpenSpec change (label `change`, title "<id>: <proposal title>").
# It carries the change's lock (run-lock.sh) and its status page (change-sync.sh).
#   scripts/change-issue.sh <id>          print the issue number, creating the issue if needed
#   scripts/change-issue.sh <id> --find   print it only if it exists; exit 1 otherwise
set -uo pipefail
repo=locksmith-hq/locksmith
id="${1:?usage: change-issue.sh <id> [--find]}"

# The lowest-numbered issue with this title is canonical, so two workers that both create one agree.
lookup() { gh api "repos/$repo/issues?labels=change&state=all&per_page=100" \
  -q "[.[]|select(.title|startswith(\"$id:\"))|.number]|sort|.[0] // empty"; }

n=$(lookup)
if [ -z "$n" ]; then
  [ "${2:-}" = --find ] && exit 1
  # A typo once created a bogus issue (#501): the id must be a change directory or a roadmap id.
  [ -d "openspec/changes/$id" ] || grep -qF "\`$id\`" docs/roadmap.md || { echo "change-issue: unknown change id '$id'" >&2; exit 1; }
  title=$(sed -nE '/^# /{s/^# *(Proposal: *)?//p;q;}' "openspec/changes/$id/proposal.md" 2>/dev/null)
  mine=$(gh api "repos/$repo/issues" -f title="$id: ${title:-$id}" -f 'labels[]=change' \
    -f body="Status page for OpenSpec change \`$id\`. Kept current by the change-sync workflow." -q .number) || exit 1
  # New issues reach the list API after a few seconds; wait until ours shows, then take the lowest.
  for _ in 1 2 3 4 5 6 7 8 9 10; do n=$(lookup); [ -n "$n" ] && [ "$n" -le "$mine" ] && break; sleep 3; done
  n=${n:-$mine}
  [ "$n" != "$mine" ] && gh api -X PATCH "repos/$repo/issues/$mine" -f state=closed -f state_reason=not_planned \
    -f body="Duplicate of #$n (created concurrently)." >/dev/null
fi
echo "$n"
