#!/usr/bin/env bash
# Fires worker routines only when there is work, a free slot and budget left (owner 2026-11-23: workers move off
# routine crons; 120 of 315 cron and event runs ended blocked or idle after paying their startup cost).
#   dispatch.sh run               (dispatch.yml) decide, then fire through route.sh, or only log while `shadow`
#   dispatch.sh plan              what run would fire now (read-only)
#   dispatch.sh record <role> <reason>   add a fire to the ledger (route.sh fire, for event wakes of workers)
#   dispatch.sh selftest
# Config: routing.json `dispatch` {shadow, slots, max_5h, max_day, run_minutes, workers}.
# State: fires are comments on the `dispatch-ledger` issue; a worker's run ends when its App posts on the
# `agent-log` issue (run-log skill: one run-metadata block per run). A worker is busy from its last fire until that post, or run_minutes.
set -uo pipefail
repo=locksmith-hq/locksmith
here=$(cd "$(dirname "$0")" && pwd)
cfg="${ROUTING:-$here/../docs/agents/routing.json}"

# {now, cfg, items:[{text, pref}], fires:[{role, at}], ends:[{role, at}]} -> "role<TAB>reason" per fire, then "#<TAB>why"
decide() {
  jq -r '
    def t: fromdateiso8601;
    (.now|t) as $n | .cfg as $c | .fires as $fires | .ends as $ends |
    def last_fire($w): [$fires[]|select(.role == $w)]|sort_by(.at|t)|last;
    def busy($w): last_fire($w) as $f |
      $f != null and ($n - ($f.at|t)) < $c.run_minutes * 60 and ([$ends[]|select(.role == $w and (.at|t) >= ($f.at|t))]|length) == 0;
    # Runs in a window: finished runs plus running ones. In shadow, cron runs are not ours: count our would-fires.
    def runs($s): if $c.shadow then [$fires[]|select($n - (.at|t) < $s)]|length
      else ([$ends[]|select($n - (.at|t) < $s)]|length) + ([$c.workers[]|select(busy(.))]|length) end;
    ([$c.workers[]|select(busy(.)|not)]) as $free |
    ([$c.slots - ($c.workers|length) + ($free|length), $c.max_5h - runs(18000), $c.max_day - runs(86400)]|min) as $room |
    (reduce .items[] as $i ({free: $free, out: []};
      if (.out|length) >= $room or (.free|length) == 0 then .
      else (if ($i.pref != null and (.free|index($i.pref))) then $i.pref else .free[0] end) as $w |
        .free -= [$w] | .out += ["\($w)\t\($i.text)"] end)) as $r |
    ($r.out[]),
    "#\tworkers free \($free|length)/\($c.workers|length), room \([$room, 0]|max), items \(.items|length), fired \($r.out|length)"'
}

# The oldest open ledger wins, so a duplicate made by a race (the issues list lags a create) is ignored.
ledger_find() { gh api "repos/$repo/issues?labels=dispatch-ledger&state=open&sort=created&direction=asc&per_page=1" -q '.[0].number // empty'; }
ledger() { # the open dispatch-ledger issue number, created on first use
  local n; n=$(ledger_find)
  [ -n "$n" ] || n=$(gh api "repos/$repo/issues" -f title="Dispatch ledger" -f "labels[]=dispatch-ledger" \
    -f body="<!-- agent -->
One comment per worker fire by scripts/dispatch.sh (and event wakes of workers). Do not comment here." -q .number)
  echo "$n"
}

record() { # <role> <reason> [would]
  gh api "repos/$repo/issues/${LEDGER:-$(ledger)}/comments" -f body="<!-- agent -->
${3:-fire} $1: $2" >/dev/null
}

state() { # the decide() input from GitHub
  local since lg log items
  since=$(date -u -d '-24 hours' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)
  lg=$(ledger_find)
  log=$(gh api "repos/$repo/issues?labels=agent-log&state=open&per_page=1" -q '.[0].number // empty')
  # Work lines from the global view (no persona: every PR). A red PR prefers the worker whose App opened it.
  items=$(AGENT_PERSONA='' AGENT_ID_DIR=/nonexistent bash "$here/worker-has-work.sh" 2>/dev/null | sed -n 's/^work: //p' |
    while IFS= read -r w; do
      pref=""; b=$(sed -nE 's/^CI is red on (claude\/[^ ]+)$/\1/p' <<<"$w")
      [ -n "$b" ] && pref=$(bash "$here/route.sh" role "$(gh api "repos/$repo/pulls?head=${repo%%/*}:$b&state=open" -q '.[0].user.login // ""')")
      jq -cn --arg t "$w" --arg p "$pref" '{text: $t, pref: (if $p == "" then null else $p end)}'
    done | jq -s .)
  jq -n --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson c "$(jq .dispatch "$cfg")" --argjson items "$items" \
    --argjson f "$( { [ -n "$lg" ] && gh api --paginate "repos/$repo/issues/$lg/comments?since=$since&per_page=100" -q '.[]|{at: .created_at, b: .body}'; } |
      jq -s '[.[]|(.b|capture("(?m)^(fire|would) (?<role>[a-z0-9-]+):")?) as $m|select($m)|{role: $m.role, at}]')" \
    --argjson e "$( [ -n "$log" ] && gh api --paginate "repos/$repo/issues/$log/comments?since=$since&per_page=100" -q '.[]|select(.body|contains("run-metadata"))|{at: .created_at, l: .user.login}' |
      while IFS= read -r x; do r=$(bash "$here/route.sh" role "$(jq -r .l <<<"$x")"); [[ "$r" == worker-* ]] && jq -c --arg r "$r" '{role: $r, at}' <<<"$x"; done | jq -s . || echo '[]')" \
    '{now: $now, cfg: $c, items: $items, fires: $f, ends: $e}'
}

run() {
  local shadow plan
  shadow=$(jq -r '.dispatch.shadow' "$cfg")
  plan=$(state | decide) || { echo "::error::dispatch: could not read state"; return 1; }
  echo "$plan"
  grep -qv '^#' <<<"$plan" && LEDGER=$(ledger)  # once per run: two creates in one run made two ledgers (#659, #660)
  while IFS=$'\t' read -r role why; do
    [ "$role" = "#" ] && { echo "::notice title=dispatch::$why"; continue; }
    if [ "$shadow" = true ]; then record "$role" "$why" would
    else bash "$here/route.sh" fire "$role" "dispatch: $why"; fi
  done <<<"$plan"
}

selftest() {
  local fail=0 got
  c='{"shadow":false,"slots":2,"max_5h":6,"max_day":20,"run_minutes":45,"workers":["worker-a","worker-b","worker-c"]}'
  d() { # <expected fires, ";"-joined> <items> <fires> <ends>
    got=$(jq -n --argjson c "$c" --argjson i "$2" --argjson f "$3" --argjson e "$4" \
      '{now: "2026-11-23T12:00:00Z", cfg: $c, items: $i, fires: $f, ends: $e}' | decide | grep -v '^#' | paste -sd ';' -)
    [ "$got" = "$(printf '%b' "$1")" ] && echo "ok: ${1:-no fire}" || { echo "FAIL: want '$1' got '$got'"; fail=1; }
  }
  red='{"text":"CI is red on claude/change-x","pref":"worker-b"}'; rdy='{"text":"d3 is ready","pref":null}'; rdy2='{"text":"t2 is ready","pref":null}'
  d '' '[]' '[]' '[]'                                                        # no work: no run
  d 'worker-b\tCI is red on claude/change-x' "[$red]" '[]' '[]'               # a red PR goes to its author
  d 'worker-b\tCI is red on claude/change-x;worker-a\td3 is ready' "[$red,$rdy,$rdy2]" '[]' '[]'  # slots cap at 2
  d '' "[$rdy]" '[{"role":"worker-a","at":"2026-11-23T11:30:00Z"},{"role":"worker-b","at":"2026-11-23T11:40:00Z"}]' '[]'  # both slots busy
  d 'worker-a\td3 is ready' "[$rdy]" '[{"role":"worker-a","at":"2026-11-23T11:30:00Z"}]' '[{"role":"worker-a","at":"2026-11-23T11:50:00Z"}]'  # its run ended: free
  d 'worker-a\td3 is ready' "[$rdy]" '[{"role":"worker-a","at":"2026-11-23T10:00:00Z"}]' '[]'  # past run_minutes: free
  d 'worker-a\tCI is red on claude/change-x' "[$red]" '[{"role":"worker-b","at":"2026-11-23T11:50:00Z"}]' '[]'  # author busy: another worker
  six=$(for h in 8 9 10 10 11 11; do printf '{"role":"worker-c","at":"2026-11-23T%02d:05:00Z"},' "$h"; done | sed 's/,$//')
  d '' "[$rdy]" '[]' "[$six]"                                                # 5-hour budget used up
  c=$(jq -c '.shadow = true' <<<"$c")
  d 'worker-a\td3 is ready' "[$rdy]" '[]' "[$six]"                           # shadow: cron runs don't use our budget
  d '' "[$rdy]" "[$(sed 's/"worker-c"/"worker-x"/g' <<<"$six")]" '[]'           # shadow: our own would-fires do
  [ "$fail" = 0 ] && echo "dispatch selftest: OK"; return "$fail"
}

case "${1:-}" in
  run) run ;;
  plan) state | tee "${DISPATCH_STATE:-/dev/null}" | decide ;;  # what run would do, read-only
  record) record "${2:?role}" "${3:?reason}" ;;
  selftest) selftest ;;
  *) sed -n '2,9p' "$0"; exit 2 ;;
esac
