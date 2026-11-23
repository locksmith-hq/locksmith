#!/usr/bin/env bash
# State of every open OpenSpec change, in roadmap order, so concurrent workers pick work that is not
# blocked. One line per change: <id> <state> <detail>
#   ready      deps merged, nothing open blocks it
#   stackable  a dep is unmerged but its PR is fully ticked; branch from that PR's branch
#   blocked    a dep is not finished (detail names it)
#   parked     an open needs-rescue issue names this change (detail: rescue #n, or owner #n once the lead
#              escalated it with needs-owner), or an open needs-owner-only issue names it and the next unticked
#              task is a `Gate:` task (detail: owner #n). Owner gates go last, so they block only their own tasks (#470).
#   claimed    another worker holds the change lock (detail: holder)
#   owned      another agent App opened the change's PR (detail: its login); only that author continues it
#              (owner 2026-11-20). The caller is AGENT_PERSONA's App; without one, every App-owned PR counts.
#   review     every task ticked on the branch; waiting for the merge queue
#   finished   every task ticked on main but not archived
# Usage: scripts/change-status.sh [--ready|--plannable]
#   --ready      prints only ids a worker may take now
#   --plannable  prints unwritten roadmap rows that can start today, in roadmap order: every id in the row's
#                `Needs` column is archived or fully ticked on its branch (`-` = needs nothing;
#                `<id>:contract` = only that change's "Contract" task group must be ticked)
# Dependencies: `x-depends_on: [id, id:contract, ...]` in the change's .openspec.yaml (x- keeps openspec validate quiet).
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
# dep_state <id|id:contract>: merged (archived), branch (every task ticked on its branch; for :contract only its
# "Contract" task group, so dependents can start against the schema and mocks), or unmet.
dep_state() {
  local d="${1%:contract}" t
  archived "$d" && { echo merged; return; }
  [ -f "openspec/changes/$d/tasks.md" ] || { echo unmet; return; }
  t=$(tasks_of "$d")
  if [ "$1" != "$d" ]; then t=$(awk '/^## /{c=($0 ~ /[Cc]ontract/)} c' <<<"$t"); [ -n "$t" ] || { echo unmet; return; }; fi
  if all_ticked "$t"; then echo branch; else echo unmet; fi
}
deps_of() { sed -nE 's/^x-depends_on:[[:space:]]*\[(.*)\][[:space:]]*$/\1/p' "openspec/changes/$1/.openspec.yaml" 2>/dev/null | tr ',' '\n' | tr -d ' "'"'" | grep -v '^$'; }

if [ "${1:-}" = --plannable ]; then
  awk -F'|' '
    /^\| *# *\|/ { n=0; for (i=2; i<=NF; i++) if ($i ~ /^ *Needs *$/) n=i; next }
    n && /^\| *[A-Z][0-9]+ *\|/ { id=$3; sub(/^[^`]*`/,"",id); sub(/`.*$/,"",id); d=$n; gsub(/[,`]/," ",d); print id, d }' docs/roadmap.md |
  while read -r id needs; do
    { [ -e "openspec/changes/$id" ] || archived "$id"; } && continue  # already written
    ok=1
    for d in $needs; do
      [ "$d" = - ] || [ "$(dep_state "$d")" != unmet ] || ok=0
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
# One line per open blocker issue: "<number> <kind> <title and body on one line>"; kind is owner (escalated
# rescue: both labels), rescue, or gate (needs-owner only).
# shellcheck disable=SC2016 # jq variables
AGENT_PERSONA=${AGENT_PERSONA:-$(cat "${AGENT_ID_DIR:-$HOME/.config/locksmith-agent}/persona" 2>/dev/null)}  # agent-identity.sh records it; later shells lose the export
me=${AGENT_PERSONA:+$(bash "$(dirname "$0")/agent-identity.sh" logins "$AGENT_PERSONA")}  # one login per line
pr_authors=""; [ "${OFFLINE:-0}" = 1 ] || pr_authors=$(gh api "repos/$repo/pulls?state=open&per_page=100" -q '.[]|[.head.ref, .user.login]|@tsv' 2>/dev/null)
[ "${OFFLINE:-0}" = 1 ] || blockers=$(gh api "repos/$repo/issues?state=open&per_page=100" \
  -q '.[]|select(any(.labels[]; .name=="needs-owner" or .name=="needs-rescue"))
    |(any(.labels[]; .name=="needs-owner")) as $o | (any(.labels[]; .name=="needs-rescue")) as $r
    |"\(.number) \(if $o and $r then "owner" elif $r then "rescue" else "gate" end) \((.title+" "+(.body // ""))|gsub("\n";" "))"' 2>/dev/null)
blockers=${BLOCKERS:-$blockers}

for id in $ids; do
  t=$(tasks_of "$id")
  if all_ticked "$t"; then
    if all_ticked "$(cat "openspec/changes/$id/tasks.md")"; then state=finished; else state=review; fi
    detail=""
  else
    state=ready; detail=""
    for d in $(deps_of "$id"); do
      case "$(dep_state "$d")" in
        merged) ;;
        branch) [ "$state" = ready ] && { state=stackable; detail="on ${d%:contract}"; } ;;
        *) state=blocked; detail="needs $d"; break ;;
      esac
    done
    if [ "$state" != blocked ] && [ -n "$blockers" ]; then
      mine=$(grep -F -- "$id" <<<"$blockers")
      gate_next=$(grep -m1 -E '^\s*- \[ \]' <<<"$t" | grep -c 'Gate:')
      for k in owner rescue gate; do
        b=$(awk -v k="$k" '$2==k' <<<"$mine" | head -1)
        [ -z "$b" ] && continue
        [ "$k" = gate ] && [ "$gate_next" = 0 ] && continue
        state=parked; detail="$([ "$k" = rescue ] && echo rescue || echo owner) #$(cut -d' ' -f1 <<<"$b")"; break
      done
    fi
    if [ "$state" = ready ] || [ "$state" = stackable ] && [ "${OFFLINE:-0}" != 1 ]; then
      h=$(bash scripts/run-lock.sh holder "status-check" "$id" 2>/dev/null) || h="lock state unknown"  # fail closed
      [ -n "$h" ] && { state=claimed; detail="$h"; }
    fi
    if { [ "$state" = ready ] || [ "$state" = stackable ]; } && [ "${OFFLINE:-0}" != 1 ]; then
      a=$(awk -F'\t' -v b="claude/change-$id" '$1==b{print $2; exit}' <<<"$pr_authors")
      [[ "$a" == *"[bot]" ]] && ! grep -qxF "$a" <<<"$me" && { state=owned; detail="$a"; }
    fi
  fi
  if [ "$only_ready" = 1 ]; then
    { [ "$state" = ready ] || [ "$state" = stackable ]; } && echo "$id"
  else
    printf '%s\t%s\t%s\n' "$id" "$state" "$detail"
  fi
done
