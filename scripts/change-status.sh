#!/usr/bin/env bash
# State of every open OpenSpec change, in roadmap order, so concurrent workers pick work that is not
# blocked. One line per change: <id> <state> <detail>
#   ready      deps merged, nothing open blocks it
#   stackable  a dep is unmerged but its PR is fully ticked; branch from that PR's branch
#   blocked    a dep is not finished (detail names it)
#   parked     an open needs-owner / needs-rescue issue names this change (detail: #n)
#   claimed    another worker holds the change lock (detail: holder)
#   review     every task ticked on the branch; waiting for the merge queue
#   finished   every task ticked on main but not archived
# Usage: scripts/change-status.sh [--ready]   (--ready prints only ids a worker may take now)
# Dependencies: `x-depends_on: [id, ...]` in the change's .openspec.yaml (x- keeps openspec validate quiet).
# OFFLINE=1 skips GitHub lookups (parked, claimed); used by the self-test.
set -uo pipefail
repo=locksmith-hq/locksmith
only_ready=0; [ "${1:-}" = --ready ] && only_ready=1

tasks_of() { git show "origin/claude/change-$1:openspec/changes/$1/tasks.md" 2>/dev/null || cat "openspec/changes/$1/tasks.md" 2>/dev/null; }
all_ticked() { ! grep -qE '^\s*- \[ \]' <<<"$1"; }
archived() { compgen -G "openspec/changes/archive/*-$1" >/dev/null; }
deps_of() { sed -nE 's/^x-depends_on:[[:space:]]*\[(.*)\][[:space:]]*$/\1/p' "openspec/changes/$1/.openspec.yaml" 2>/dev/null | tr ',' '\n' | tr -d ' "'"'" | grep -v '^$'; }

# Roadmap order first, then any change the roadmap does not name.
# shellcheck disable=SC2016 # literal backticks
ids=$( { grep -oE '`[a-z][0-9]+-[a-z0-9-]+`' docs/roadmap.md | tr -d '`'; ls openspec/changes; } |
  awk '!seen[$0]++' | while read -r id; do [ "$id" != archive ] && [ -f "openspec/changes/$id/tasks.md" ] && echo "$id"; done)

blockers=""
# One line per open blocker issue: "<number> <title and body on one line>".
[ "${OFFLINE:-0}" = 1 ] || blockers=$(gh api "repos/$repo/issues?state=open&per_page=100" \
  -q '.[]|select(any(.labels[]; .name=="needs-owner" or .name=="needs-rescue"))|"\(.number) \((.title+" "+(.body // ""))|gsub("\n";" "))"' 2>/dev/null)
blockers=${BLOCKERS:-$blockers}

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
      n=$(grep -F -- "$id" <<<"$blockers" | head -1 | cut -d' ' -f1)
      [ -n "$n" ] && { state=parked; detail="#$n"; }
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
