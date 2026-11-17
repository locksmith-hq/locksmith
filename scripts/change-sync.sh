#!/usr/bin/env bash
# Rewrites each change's tracking issue as its status page: state, PR, dependencies, anything waiting
# on the owner, the summary, every task with its tick, and the last progress entry. Sets one
# `status:<state>` label (the Project board filters on it). Archived changes get status:done and close.
# tasks.md stays the source of truth; agents never edit these issues by hand.
#   scripts/change-sync.sh            all open changes, plus archived ones whose issue is still open
#   DRY_RUN=1 scripts/change-sync.sh  print the bodies instead of writing them
set -uo pipefail
repo=locksmith-hq/locksmith
here=$(dirname "$0")

label() { # <issue> <state>: swap the status:* label
  [ "${DRY_RUN:-0}" = 1 ] && return
  for l in $(gh api "repos/$repo/issues/$1/labels" -q '.[].name|select(startswith("status:"))'); do
    [ "$l" = "status:$2" ] || gh api -X DELETE "repos/$repo/issues/$1/labels/$l" >/dev/null 2>&1
  done
  gh api "repos/$repo/issues/$1/labels" -f "labels[]=status:$2" >/dev/null
}

render() { # <id> <state> <detail>
  local id=$1 state=$2 detail=$3 src pr owner rescue
  src=$(git show "origin/claude/change-$id:openspec/changes/$id/tasks.md" >/dev/null 2>&1 && echo "origin/claude/change-$id" || echo HEAD)
  pr=$(gh pr list -R "$repo" --head "claude/change-$id" --state open --json number,isDraft,labels \
    -q '.[0]|select(.!=null)|"#\(.number)\(if any(.labels[]; .name=="ready-to-merge") then " (ready to merge)" else "" end)"' 2>/dev/null)
  owner=$(gh api "repos/$repo/issues?labels=needs-owner&state=open&per_page=100" \
    -q ".[]|select((.title+\" \"+(.body // \"\"))|contains(\"$id\"))|\"- ⚠ **Needs owner:** #\(.number) \(.title)\"" 2>/dev/null)
  rescue=$(gh api "repos/$repo/issues?labels=needs-rescue&state=open&per_page=100" \
    -q ".[]|select((.title+\" \"+(.body // \"\"))|contains(\"$id\"))|\"- Rescue in progress: #\(.number) \(.title)\"" 2>/dev/null)
  echo "**Status:** \`$state\`${detail:+ ($detail)} · **PR:** ${pr:-none yet} · **Depends on:** $(sed -nE 's/^x-depends_on:[[:space:]]*\[(.*)\]/\1/p' "openspec/changes/$id/.openspec.yaml" 2>/dev/null || true)"
  echo
  [ -n "$owner$rescue" ] && printf '%s\n%s\n\n' "$owner" "$rescue" | grep -v '^$' && echo
  echo "## Summary"
  git show "$src:openspec/changes/$id/proposal.md" 2>/dev/null | awk '/^## Why/{f=1;next} /^## /{f=0} f' | sed '/^$/d' | head -8
  links=$(git show "$src:openspec/changes/$id/proposal.md" "$src:openspec/changes/$id/design.md" 2>/dev/null | grep -oE 'https://claude\.ai/(code/)?artifact/[A-Za-z0-9_-]+' | sort -u | paste -sd' ' - || true)
  echo; echo "Brief: ${links:-none} · [proposal](../blob/main/openspec/changes/$id/proposal.md) · [design](../blob/main/openspec/changes/$id/design.md)"
  t=$(git show "$src:openspec/changes/$id/tasks.md" 2>/dev/null)
  echo; echo "## Tasks ($(grep -cE '^\s*- \[[xX]\]' <<<"$t")/$(grep -cE '^\s*- \[[ xX]\]' <<<"$t") done)"
  grep -E '^(## |\s*- \[)' <<<"$t" | awk '/^## /{print ""; sub(/^## /, "### ")} 1'
  echo; echo "## Last progress"
  git show "$src:openspec/changes/$id/progress.md" 2>/dev/null | awk '/^## [0-9]/{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' | grep -v '^$' | head -8
  echo; echo "<!-- change-sync: generated from tasks.md and progress.md; edits here are overwritten -->"
}

bash "$here/change-status.sh" | while IFS=$'\t' read -r id state detail; do
  body=$(render "$id" "$state" "$detail")
  if [ "${DRY_RUN:-0}" = 1 ]; then printf '===== %s\n%s\n' "$id" "$body"; continue; fi
  n=$(bash "$here/change-issue.sh" "$id") || continue
  gh api -X PATCH "repos/$repo/issues/$n" -f body="$body" -f state=open >/dev/null && label "$n" "$state"
done

# Archived changes: mark done and close their issue.
for d in openspec/changes/archive/*/; do
  id=$(basename "$d" | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}-//')
  n=$(bash "$here/change-issue.sh" "$id" --find) || continue
  [ "$(gh api "repos/$repo/issues/$n" -q .state)" = open ] || continue
  [ "${DRY_RUN:-0}" = 1 ] && { echo "===== $id: would close #$n as done"; continue; }
  label "$n" "done"; gh api -X PATCH "repos/$repo/issues/$n" -f state=closed -f state_reason=completed >/dev/null
done
