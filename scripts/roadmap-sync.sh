#!/usr/bin/env bash
# Mirrors the roadmap into GitHub's own structure, so progress is visible without opening the repo:
#   milestone  = roadmap phase ("Phase 1: First vertical slice"); closes when all its changes are done
#   issue      = one per roadmap change (type Feature, label `change`), planned ones included
#   (no per-task issues: the change issue's checklist, written by change-sync.sh, is the task view; #470)
#   blocked by = the change's x-depends_on changes, plus open needs-owner / needs-rescue issues naming it
# change-sync.sh writes the status page and board Status of written changes; this script owns
# milestones, planned changes and relationships; it also closes the old per-task issues. Writes only what differs.
#   scripts/roadmap-sync.sh             DRY_RUN=1 prints the writes instead of making them
set -uo pipefail
repo=locksmith-hq/locksmith
here=$(dirname "$0")
# shellcheck source=scripts/issue-lib.sh
. "$here/issue-lib.sh"

w() { # write call: gh api with the given args (skipped in dry run)
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "would: gh api $*" >&2; echo '{}'; return 0; fi
  gh api "$@"
}
jqs() { jq -r "$@"; }

# Roadmap rows: phase US id US tier US outcome US gate (US = \x1f, so empty fields survive `read`)
rows=$(awk -F'|' '
  /^## Phase/ { p=$0; sub(/^## /,"",p); sub(/ *\(.*$/,"",p); next }
  /^\| *# *\|/ { gc=0; for (i=2; i<=NF; i++) if ($i ~ /Local gate/) gc=i; next }
  p && /^\| *[A-Z][0-9]+ *\|/ {
    c=$3; id=c; sub(/^[^`]*`/,"",id); sub(/`.*$/,"",id)
    tier=""; if (c ~ /\[opus\]/) tier="opus"; else if (c ~ /\[haiku\]/) tier="haiku"
    o=$4; g=(gc ? $gc : ""); gsub(/^ +| +$/,"",o); gsub(/^ +| +$/,"",g)
    printf "%s\x1f%s\x1f%s\x1f%s\x1f%s\n", p, id, tier, o, g }' docs/roadmap.md)
phases=$(awk '/^## Phase/{p=$0; sub(/^## /,"",p); d=p; sub(/ *\(.*$/,"",p); sub(/^[^(]*\(?/,"",d); sub(/\)$/,"",d); print p"\t"d}' docs/roadmap.md)

# 1. Milestones, one per phase.
ms=$(gh api "repos/$repo/milestones?state=all&per_page=100" -q '.[]|"\(.title)\t\(.number)"')
while IFS=$'\t' read -r title desc; do
  [ -z "$title" ] && continue
  grep -qF "$title"$'\t' <<<"$ms" && continue
  n=$(w "repos/$repo/milestones" -f title="$title" -f description="${desc:-$title}" -q .number)
  ms+=$'\n'"$title"$'\t'"$n"
done <<<"$phases"
milestone_of() { awk -F'\t' -v t="$1" '$1==t{print $2; exit}' <<<"$ms"; }

# Preload every change and task issue once (title, number, node id, state, milestone, type, labels, body).
load() { gh api --paginate "repos/$repo/issues?labels=$1&state=all&per_page=100" \
  -q '.[]|{n:.number,id:.id,t:.title,s:.state,m:(.milestone.number // 0),ty:(.type.name // ""),l:[.labels[].name],b:(.body // "")}|@json'; }
changes=$(load change); tasks=$(load task)
issue_of() { jq -rs --arg p "$1:" '[.[]|select(.t|startswith($p))]|sort_by(.n)|.[0]|select(.!=null)|@json' <<<"$changes"; }
status=$(bash "$here/change-status.sh")
blockers=$(gh api "repos/$repo/issues?state=open&per_page=100" \
  -q '.[]|select(any(.labels[]; .name=="needs-owner" or .name=="needs-rescue"))|"\(.id)\t\(.number)\t\((.title+" "+(.body // ""))|gsub("\n";" "))"')

ensure_meta() { # <issue-json> <milestone-number> <type> <labels...>: set what differs
  local j=$1 m=$2 ty=$3; shift 3; local n args=() l
  n=$(jqs .n <<<"$j")
  [ "$(jqs .m <<<"$j")" = "$m" ] || args+=(-F "milestone=$m")
  [ "$(jqs .ty <<<"$j")" = "$ty" ] || args+=(-f "type=$ty")
  [ ${#args[@]} -gt 0 ] && w -X PATCH "repos/$repo/issues/$n" "${args[@]}" >/dev/null
  for l in "$@"; do jq -e --arg l "$l" '.l|index($l)' <<<"$j" >/dev/null || w "repos/$repo/issues/$n/labels" -f "labels[]=$l" >/dev/null; done
}

while IFS=$'\x1f' read -r -u 3 phase id tier outcome gate; do
  [ -z "$id" ] && continue
  m=$(milestone_of "$phase"); track="track:$(tr '[:lower:]' '[:upper:]' <<<"${id:0:1}")"
  extra=(change "$track"); [ -n "$tier" ] && extra+=("tier:$tier")
  j=$(issue_of "$id")
  if compgen -G "openspec/changes/archive/*-$id" >/dev/null; then state="done"
  elif [ -d "openspec/changes/$id" ]; then state=written
  else state=planned; fi

  # 2. Issue per change; planned changes get a roadmap page here (written ones: change-sync.sh).
  if [ -z "$j" ]; then
    short=$(sed -E 's/\. .*//; s/\*\*//g' <<<"$outcome" | cut -c1-80)
    n=$(w "repos/$repo/issues" -f title="$id: $short" -f 'labels[]=change' -f type=Feature -F milestone="$m" -q .number)
    [ "${DRY_RUN:-0}" = 1 ] && continue
    j=$(gh api "repos/$repo/issues/$n" -q '{n:.number,id:.id,t:.title,s:.state,m:(.milestone.number // 0),ty:(.type.name // ""),l:[.labels[].name],b:(.body // "")}|@json')
  fi
  n=$(jqs .n <<<"$j")
  ensure_meta "$j" "$m" Feature "${extra[@]}"
  if [ "$state" = planned ]; then
    # shellcheck disable=SC2016 # literal backticks
    body=$(printf '**Status:** `planned` (not written yet) · **Phase:** %s%s\n\n## Outcome\n%s\n\n## Local gate\n%s\n\n<!-- change-sync: generated from docs/roadmap.md; edits here are overwritten -->' \
      "$phase" "${tier:+ · **Tier:** $tier}" "$outcome" "${gate:-see roadmap}")
    if [ "$(jqs .b <<<"$j")" != "$body" ]; then w -X PATCH "repos/$repo/issues/$n" -f body="$body" >/dev/null; fi
    if [ "${DRY_RUN:-0}" != 1 ]; then
      jq -e '.l|index("status:planned")' <<<"$j" >/dev/null || label "$n" planned
      board "$n" planned
    fi
    continue
  fi
  if [ "$state" = "done" ]; then   # archived: closed, Done on the board (also for changes finished before issues existed)
    if [ "${DRY_RUN:-0}" != 1 ]; then
      [ "$(jqs .s <<<"$j")" = open ] && { label "$n" "done"; w -X PATCH "repos/$repo/issues/$n" -f state=closed -f state_reason=completed >/dev/null; }
      board "$n" "done"
    fi
    continue
  fi

  # 3. Per-task issues are retired (#470): close any still open for this change.
  jq -r --arg p "$id " 'select(.s=="open" and (.t|startswith($p)))|.n' <<<"$tasks" | while read -r tnum; do
    w -X PATCH "repos/$repo/issues/$tnum" -f state=closed -f state_reason=not_planned >/dev/null
  done

  # 4. Blocked by: dependency changes and open owner/rescue issues that name this change.
  # shortcut: relationships are only added, never removed; a dropped dependency must be unlinked by hand.
  have=$(gh api "repos/$repo/issues/$n/dependencies/blocked_by" -q '.[].id' 2>/dev/null)
  want=$(for d in $(sed -nE 's/^x-depends_on:[[:space:]]*\[(.*)\]/\1/p' "openspec/changes/$id/.openspec.yaml" | tr ',' ' ' | sed 's/:contract//g'); do
           issue_of "$d" | jq -r '.id // empty'; done
         grep -F -- "$id" <<<"$blockers" | cut -f1)
  for b in $want; do grep -qx "$b" <<<"$have" || w "repos/$repo/issues/$n/dependencies/blocked_by" -F issue_id="$b" >/dev/null; done
done 3<<<"$rows"

# 5. A phase whose changes are all closed is done.
gh api "repos/$repo/milestones?state=open&per_page=100" -q '.[]|select(.open_issues==0 and .closed_issues>0)|.number' |
  while read -r mn; do w -X PATCH "repos/$repo/milestones/$mn" -f state=closed >/dev/null; done
