#!/usr/bin/env bash
# Fills GitHub's org issue fields Priority, Start date and Target date on every change and task issue,
# and keeps them current (run by change-sync on pushes, blocker labels and daily). Writes only differences.
#   Priority     current roadmap phase High, next Medium, later Low; a parked change (owner/rescue) Urgent;
#                tasks inherit their change; `x-priority: <Urgent|High|Medium|Low>` in .openspec.yaml wins.
#   Start date   not started yet: a forecast, refreshed each run. Started: when work began (first finished
#                task, the claim, or for a change archived before issues existed, its first commit), and
#                only ever moved earlier, so it stays fixed once work has begun.
#   Target date  closed: the actual close date. Open: a forecast from the pace (tasks closed in the last
#                7 days), with planned changes queued in roadmap order across $WORKERS workers.
#   DRY_RUN=1 prints the writes.
set -uo pipefail
repo=locksmith-hq/locksmith
here=$(dirname "$0")
workers=${WORKERS:-2}
est_tasks=${EST_TASKS:-20}   # task count assumed for a change whose tasks.md is not written yet
today=$(date -u +%F)
day() { date -u -d "$today $1 days" +%F 2>/dev/null || date -u -v"$( [ "$1" -lt 0 ] && echo "$1" || echo "+$1" )"d +%F; }   # GNU or BSD date

# Field ids are stable; the Actions token cannot list org-level fields, so fall back to the known ids.
# shortcut: if a field is ever recreated in org settings, update these ids (read them with a PAT).
fields=$(gh api "orgs/${repo%%/*}/issue-fields" -q '.[]|"\(.name)\t\(.id)"' 2>/dev/null) ||
  fields=$(printf 'Priority\t49990182\nStart date\t49990183\nTarget date\t49990184\n')
fid() { awk -F'\t' -v n="$1" '$1==n{print $2}' <<<"$fields"; }
F_PRI=$(fid Priority); F_START=$(fid "Start date"); F_TARGET=$(fid "Target date")
[ -n "$F_PRI" ] && [ -n "$F_START" ] && [ -n "$F_TARGET" ] || { echo "dates: org issue fields missing"; exit 0; }

# set_fields <issue> <priority> <start> <target>. A start prefixed with "~" is a forecast (always written);
# a plain start is actual and only replaces an empty or later value.
# shortcut: a forecast set yesterday can be one day early when work starts today; fine for planning views.
set_fields() {
  local n=$1 pri=$2 start=$3 target=$4 cur want=()
  cur=$(gh api "repos/$repo/issues/$n/issue-field-values" \
    -q '.[]|"\(.issue_field_id)\t\(.single_select_option.name // .value)"')
  have() { awk -F'\t' -v f="$1" '$1==f{print $2}' <<<"$cur"; }
  [ -n "$pri" ] && [ "$(have "$F_PRI")" != "$pri" ] && want+=("{\"field_id\":$F_PRI,\"value\":\"$pri\"}")
  if [ "${start:0:1}" = "~" ]; then start=${start:1}; [ "$(have "$F_START")" != "$start" ] && want+=("{\"field_id\":$F_START,\"value\":\"$start\"}")
  elif [ -n "$start" ]; then local c; c=$(have "$F_START"); { [ -z "$c" ] || [[ "$start" < "$c" ]]; } && want+=("{\"field_id\":$F_START,\"value\":\"$start\"}"); fi
  [ -n "$target" ] && [ "$(have "$F_TARGET")" != "$target" ] && want+=("{\"field_id\":$F_TARGET,\"value\":\"$target\"}")
  [ ${#want[@]} -eq 0 ] && return 0
  local body; body="{\"issue_field_values\":[$(IFS=,; echo "${want[*]}")]}"
  if [ "${DRY_RUN:-0}" = 1 ]; then echo "would set #$n $body"; return 0; fi
  gh api -X POST "repos/$repo/issues/$n/issue-field-values" --input - <<<"$body" >/dev/null || echo "dates: could not set #$n"
}

load() { gh api --paginate "repos/$repo/issues?labels=$1&state=all&per_page=100" \
  -q '.[]|"\(.number)\t\(.state)\t\((.closed_at // "")[0:10])\t\(.title)"'; }
changes=$(load change); tasks=$(load task)
status=$(bash "$here/change-status.sh")
rows=$(awk -F'|' '/^## Phase/{p=$0; sub(/^## /,"",p); sub(/:.*/,"",p); next}
  p && /^\| *[A-Z][0-9]+ *\|/ {c=$3; sub(/^[^`]*`/,"",c); sub(/`.*$/,"",c); print p"\t"c}' docs/roadmap.md)
issue_line() { awk -F'\t' -v p="$1:" 'index($4,p)==1' <<<"$changes" | sort -n | head -1; }
archived() { compgen -G "openspec/changes/archive/*-$1" >/dev/null; }
tasks_md() { git show "origin/claude/change-$1:openspec/changes/$1/tasks.md" 2>/dev/null || cat "openspec/changes/$1/tasks.md" 2>/dev/null; }

# Pace: tasks closed in the last 7 days, per day (at least 1).
week_ago=$(day -7)
closed7=$(awk -F'\t' -v w="$week_ago" '$2=="closed" && $3>=w' <<<"$tasks" | wc -l | tr -d ' ')
pace=$(( (closed7 + 6) / 7 )); [ "$pace" -lt 1 ] && pace=1

# Priority by phase: the first phase with an unfinished change is High, the next Medium, the rest Low.
open_phases=$(while IFS=$'\t' read -r ph id; do archived "$id" || echo "$ph"; done <<<"$rows" | awk '!s[$0]++')
pri_of_phase() { local i; i=$(grep -nxF "$1" <<<"$open_phases" | cut -d: -f1)
  case "${i:-0}" in 1) echo High ;; 2) echo Medium ;; 0) echo "" ;; *) echo Low ;; esac; }

# Lanes: one end date per worker; active changes go first, then planned ones in roadmap order.
lanes=(); for ((i=0; i<workers; i++)); do lanes+=(0); done
lane_take() { # <days> -> sets $end to the change's end offset, on the lane that frees up first (no subshell)
  local best=0 i; for ((i=1; i<workers; i++)); do [ "${lanes[$i]}" -lt "${lanes[$best]}" ] && best=$i; done
  lanes[best]=$(( lanes[best] + $1 )); end=${lanes[$best]}; }

while IFS=$'\t' read -r -u 3 phase id; do   # fd 3/4: gh inside the loops must not eat the rows
  line=$(issue_line "$id"); [ -z "$line" ] && continue
  IFS=$'\t' read -r n state closed _ <<<"$line"
  cstate=$(awk -F'\t' -v i="$id" '$1==i{print $2}' <<<"$status")
  pri=$(sed -nE 's/^x-priority:[[:space:]]*([A-Za-z]+).*/\1/p' "openspec/changes/$id/.openspec.yaml" 2>/dev/null)
  [ -z "$pri" ] && { [ "$cstate" = parked ] && pri=Urgent || pri=$(pri_of_phase "$phase"); }
  ctasks=$(awk -F'\t' -v p="$id " 'index($4,p)==1' <<<"$tasks" | sort -n)

  if [ "$state" = closed ] || archived "$id"; then
    start=$(awk -F'\t' '$2=="closed"{print $3}' <<<"$ctasks" | sort | head -1)
    [ -z "$start" ] && start=$(git log --format=%cs -- "openspec/changes/archive/"*"-$id" "openspec/changes/$id" | tail -1)
    set_fields "$n" "$pri" "$start" "${closed:-$today}"
    while IFS=$'\t' read -r -u 4 tn ts tc _; do [ -n "$tn" ] && set_fields "$tn" "$pri" "$tc" "$tc"; done 4<<<"$ctasks"
    continue
  fi

  # Open change: remaining tasks (written ones from tasks.md, else an estimate) at the measured pace.
  left=$(tasks_md "$id" | grep -cE '^[[:space:]]*- \[ \]'); [ -d "openspec/changes/$id" ] || left=$est_tasks
  days=$(( (left + pace - 1) / pace )); [ "$days" -lt 1 ] && days=1
  lane_take "$days"
  start=$(awk -F'\t' '$2=="closed"{print $3}' <<<"$ctasks" | sort | head -1)
  [ -z "$start" ] && [ "$cstate" = claimed ] && start=$today
  [ -z "$start" ] && start="~$(day $(( end - days )))"
  set_fields "$n" "$pri" "$start" "$(day "$end")"

  # Its tasks: closed ones get their close date; open ones are forecast one after another.
  k=0
  while IFS=$'\t' read -r -u 4 tn ts tc _; do
    [ -z "$tn" ] && continue
    if [ "$ts" = closed ]; then set_fields "$tn" "$pri" "$tc" "$tc"; continue; fi
    k=$((k + 1))
    tstart="~$(day $(( end - days + (k - 1) / pace )))"; [ "$k" = 1 ] && [ "$cstate" = claimed ] && tstart=$today
    set_fields "$tn" "$pri" "$tstart" "$(day $(( end - days + (k + pace - 1) / pace )))"
  done 4<<<"$ctasks"
done 3<<<"$rows"
echo "dates: pace $pace task(s)/day over the last 7 days, $workers workers"
