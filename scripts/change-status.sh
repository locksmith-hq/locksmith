#!/usr/bin/env bash
# State of every open OpenSpec change, in roadmap order, so concurrent workers pick work that is not
# blocked. One line per change: <id> <state> <detail>
#   ready      deps merged, nothing open blocks it
#   stackable  a dep is unmerged but its PR is fully ticked; branch from that PR's branch
#   blocked    a dep is not finished (detail names it)
#   parked     an open needs-owner / needs-rescue issue names this change (detail: owner #n | rescue #n;
#              owner wins, since a rescue that failed twice also gets needs-owner)
#   claimed    another worker holds the change lock (detail: holder)
#   review     every task ticked on the branch; waiting for the merge queue
#   finished   every task ticked on main but not archived
# Usage: scripts/change-status.sh [--ready|--plannable]
#   --ready      prints only ids a worker may take now
#   --plannable  prints unwritten roadmap rows that can start today, in roadmap order: every id in the row's
#                `Needs` column is archived or fully ticked on its branch (`-` = needs nothing)
# Dependencies: `x-depends_on: [id, ...]` in the change's .openspec.yaml (x- keeps openspec validate quiet).
# OFFLINE=1 skips GitHub lookups (parked, claimed); used by the self-test.
set -uo pipefail
repo=locksmith-hq/locksmith
only_ready=0; [ "${1:-}" = --ready ] && only_ready=1

tasks_of() {
  local b="origin/claude/change-$1" p
  git show "$b:openspec/changes/$1/tasks.md" 2>/dev/null && return
  # A branch that archived the change in its PR has no live tasks.md; main's unticked copy would make it look ready.
  p=$(git ls-tree -r --name-only "$b" -- openspec/changes/archive 2>/dev/null | grep -m1 -E -- "-$1/tasks\.md$")
  if [ -n "$p" ]; then git show "$b:$p"; else cat "openspec/changes/$1/tasks.md" 2>/dev/null; fi
}
all_ticked() { ! grep -qE '^\s*- \[ \]' <<<"$1"; }
archived() { compgen -G "openspec/changes/archive/*-$1" >/dev/null; }
deps_of() { sed -nE 's/^x-depends_on:[[:space:]]*\[(.*)\][[:space:]]*$/\1/p' "openspec/changes/$1/.openspec.yaml" 2>/dev/null | tr ',' '\n' | tr -d ' "'"'" | grep -v '^$'; }

if [ "${1:-}" = --plannable ]; then
  awk -F'|' '
    /^\| *# *\|/ { n=0; for (i=2; i<=NF; i++) if ($i ~ /^ *Needs *$/) n=i; next }
    n && /^\| *[A-Z][0-9]+ *\|/ { id=$3; sub(/^[^`]*`/,"",id); sub(/`.*$/,"",id); d=$n; gsub(/[,`]/," ",d); print id, d }' docs/roadmap.md |
  while read -r id needs; do
    { [ -e "openspec/changes/$id" ] || archived "$id"; } && continue  # already written
    ok=1
    for d in $needs; do
      [ "$d" = - ] && continue
      archived "$d" || { [ -f "openspec/changes/$d/tasks.md" ] && all_ticked "$(tasks_of "$d")"; } || ok=0
    done
    [ "$ok" = 1 ] && echo "$id"
  done
  exit 0
fi

# Roadmap order first, then any change the roadmap does not name.
# shellcheck disable=SC2016 # literal backticks
ids=$( { grep -oE '`[a-z][0-9]+-[a-z0-9-]+`' docs/roadmap.md | tr -d '`'; ls openspec/changes; } |
  awk '!seen[$0]++' | while read -r id; do [ "$id" != archive ] && [ -f "openspec/changes/$id/tasks.md" ] && echo "$id"; done)

blockers=""
# One line per open blocker issue: "<number> <owner|rescue> <title and body on one line>", owner first.
[ "${OFFLINE:-0}" = 1 ] || blockers=$(gh api "repos/$repo/issues?state=open&per_page=100" \
  -q '.[]|select(any(.labels[]; .name=="needs-owner" or .name=="needs-rescue"))
    |"\(.number) \(if any(.labels[]; .name=="needs-owner") then "owner" else "rescue" end) \((.title+" "+(.body // ""))|gsub("\n";" "))"' 2>/dev/null)
blockers=$(sort -s -k2,2 <<<"${BLOCKERS:-$blockers}")

for id in $ids; do
  t=$(tasks_of "$id")
  if all_ticked "$t"; then
    if all_ticked "$(cat "openspec/changes/$id/tasks.md")"; then state=finished; else state=review; fi
    detail=""
  else
    state=ready; detail=""
    for d in $(deps_of "$id"); do
      archived "$d" && continue
      if [ -f "openspec/changes/$d/tasks.md" ] && all_ticked "$(tasks_of "$d")"; then
        [ "$state" = ready ] && { state=stackable; detail="on $d"; }
      else state=blocked; detail="needs $d"; break; fi
    done
    if [ "$state" != blocked ] && [ -n "$blockers" ]; then
      b=$(grep -F -- "$id" <<<"$blockers" | head -1)
      [ -n "$b" ] && { state=parked; detail="$(cut -d' ' -f2 <<<"$b") #$(cut -d' ' -f1 <<<"$b")"; }
    fi
    if [ "$state" = ready ] || [ "$state" = stackable ] && [ "${OFFLINE:-0}" != 1 ]; then
      h=$(bash scripts/run-lock.sh holder "status-check" "$id" 2>/dev/null)
      [ -n "$h" ] && { state=claimed; detail="$h"; }
    fi
  fi
  if [ "$only_ready" = 1 ]; then
    { [ "$state" = ready ] || [ "$state" = stackable ]; } && echo "$id"
  else
    printf '%s\t%s\t%s\n' "$id" "$state" "$detail"
  fi
done
