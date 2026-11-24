#!/usr/bin/env bash
# Per-change locks for scheduled agents. A lock lives as comments on the change's tracking issue
# (scripts/change-issue.sh), so several agents run at once, each on a different change. Lock the id
# before working on a change, fixing its PR, or writing a new one (planning).
# Locks expire after TTL seconds so a crashed run never blocks the next one.
#   scripts/run-lock.sh acquire <holder> <change-id>   exit 0 = you hold it; exit 1 = busy; exit 3 = GitHub unreadable
#   scripts/run-lock.sh release <holder> <change-id>
#   scripts/run-lock.sh holder  <any> <change-id>      prints the current holder, if any
#   scripts/run-lock.sh claim   <holder> <id>...       acquires the first free id, prints it, stops; exit 1 = none free
set -uo pipefail
repo=locksmith-hq/locksmith
ttl="${RUN_LOCK_TTL:-5400}"  # 90 min: a worker run (about 40 min of tasks plus just ci and evaluation) must not outlive its lock
cmd="${1:-}"; me="${2:-}"; change="${3:-}"
# Agents shorten <holder> (four sessions were all `worker-012vq` on 2026-11-18, so `acquire` told a
# second session "already held" and it worked on another session's change). Add the real session id.
sid=$(env | grep -E '^CLAUDE_CODE_[A-Z_]*SESSION[A-Z_]*_ID=' | head -1 | cut -d= -f2- || true)
[ -n "$me" ] && [ -n "$sid" ] && [ "$cmd" != holder ] && me="${me%%@*}@$sid"
[ -n "$cmd" ] && [ -n "$me" ] && [ -n "$change" ] || { echo "usage: run-lock.sh acquire|release|holder|claim <holder> <change-id>..." >&2; exit 2; }

# Hand-written claim loops took every free lock (11 runs, 2026-11-19..21), so other workers skipped ready changes.
if [ "$cmd" = claim ]; then
  shift 2
  for id in "$@"; do bash "$0" acquire "$me" "$id" >/dev/null && { echo "$id"; exit 0; }; done
  exit 1
fi
# Fail closed: when GitHub cannot be read the lock state is unknown (exit 3), never "free". On 2026-11-23 the
# dispatcher saw b1 as ready while worker-b-1553 held it, and fired worker-b twice for it.
if [ "$cmd" = acquire ]; then issue=$(bash "$(dirname "$0")/change-issue.sh" "$change") || exit "$(( $? == 3 ? 3 : 1 ))"
else issue=$(bash "$(dirname "$0")/change-issue.sh" "$change" --find); rc=$?; [ "$rc" = 1 ] && exit 0; [ "$rc" = 0 ] || exit 3; fi

# Current holder: earliest LOCK after the last UNLOCK that is still within TTL.
holder() {
  local c
  c=$(gh api "repos/$repo/issues/$issue/comments?per_page=100" --paginate \
    -q '.[]|[.created_at, (.body|split("\n")[0])]|@tsv') || return 3
  [ -z "$c" ] && return 0
  awk -F'\t' -v now="$(date -u +%s)" -v ttl="$ttl" '
    function epoch(t,  c) { c = "date -u -d \"" t "\" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ \"" t "\" +%s"; c | getline e; close(c); return e }
    $2 ~ /^UNLOCK / { h = ""; next }
    $2 ~ /^LOCK / { split($2, f, " "); e = epoch($1); if (now - e < ttl) { if (h == "") { h = f[2]; he = e } } else { h = "" } }
    END { if (h != "") print h, now - he }' <<<"$c"
}
state() { out=$(holder) || { echo "run-lock: lock state of $change unknown (GitHub API failed)" >&2; exit 3; }; read -r cur age <<<"$out"; }
# The session id names the holder: agents vary the prefix between calls (worker-b-1566 locked b1 on 2026-11-24 and its
# release under another prefix did nothing), so a prefix mismatch must never leave a stale lock.
mine() { [ -n "${cur:-}" ] && { [ "$cur" = "$me" ] || { [ -n "$sid" ] && [ "${cur##*@}" = "$sid" ]; }; }; }

case "$cmd" in
  acquire)
    state
    if [ -n "${cur:-}" ] && ! mine; then echo "run-lock: busy (held by $cur for ${age}s)"; exit 1; fi
    mine && { echo "run-lock: already held by $cur"; exit 0; }
    gh api "repos/$repo/issues/$issue/comments" -f body="LOCK $me" -q .id >/dev/null || exit 1
    sleep 3
    state
    if mine; then echo "run-lock: acquired by $cur"; exit 0; fi
    echo "run-lock: lost race to ${cur:-unknown}"; exit 1
    ;;
  release)
    state
    if mine; then gh api "repos/$repo/issues/$issue/comments" -f body="UNLOCK $cur" -q .id >/dev/null; echo "run-lock: released"
    else echo "run-lock: not released: $change is held by ${cur:-nobody}, not $me" >&2; fi
    ;;
  holder) state; [ -z "${cur:-}" ] || echo "$cur" ;;  # exit 0 when free: change-status reads non-zero as unknown
  *) echo "usage: run-lock.sh acquire|release|holder|claim <holder> <change-id>..." >&2; exit 2 ;;
esac
