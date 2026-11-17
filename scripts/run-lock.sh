#!/usr/bin/env bash
# Per-change locks for scheduled agents. A lock lives as comments on the change's tracking issue
# (scripts/change-issue.sh), so several agents run at once, each on a different change. Lock the id
# before working on a change, fixing its PR, or writing a new one (planning).
# Locks expire after TTL seconds so a crashed run never blocks the next one.
#   scripts/run-lock.sh acquire <holder> <change-id>   exit 0 = you hold it; exit 1 = busy
#   scripts/run-lock.sh release <holder> <change-id>
#   scripts/run-lock.sh holder  <any> <change-id>      prints the current holder, if any
set -uo pipefail
repo=locksmith-hq/locksmith
ttl="${RUN_LOCK_TTL:-3000}"
cmd="${1:-}"; me="${2:-}"; change="${3:-}"
[ -n "$cmd" ] && [ -n "$me" ] && [ -n "$change" ] || { echo "usage: run-lock.sh acquire|release|holder <holder> <change-id>" >&2; exit 2; }

if [ "$cmd" = acquire ]; then issue=$(bash "$(dirname "$0")/change-issue.sh" "$change") || exit 1
else issue=$(bash "$(dirname "$0")/change-issue.sh" "$change" --find) || exit 0; fi

# Current holder: earliest LOCK after the last UNLOCK that is still within TTL.
holder() {
  gh api "repos/$repo/issues/$issue/comments?per_page=100" --paginate \
    -q '.[]|[.created_at, (.body|split("\n")[0])]|@tsv' |
  awk -F'\t' -v now="$(date -u +%s)" -v ttl="$ttl" '
    function epoch(t,  c) { c = "date -u -d \"" t "\" +%s 2>/dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ \"" t "\" +%s"; c | getline e; close(c); return e }
    $2 ~ /^UNLOCK / { h = ""; next }
    $2 ~ /^LOCK / { split($2, f, " "); e = epoch($1); if (now - e < ttl) { if (h == "") { h = f[2]; he = e } } else { h = "" } }
    END { if (h != "") print h, now - he }'
}

case "$cmd" in
  acquire)
    read -r cur age < <(holder)
    if [ -n "${cur:-}" ] && [ "$cur" != "$me" ]; then echo "run-lock: busy (held by $cur for ${age}s)"; exit 1; fi
    [ "${cur:-}" = "$me" ] && { echo "run-lock: already held by $me"; exit 0; }
    gh api "repos/$repo/issues/$issue/comments" -f body="LOCK $me" -q .id >/dev/null || exit 1
    sleep 3
    read -r cur age < <(holder)
    if [ "${cur:-}" = "$me" ]; then echo "run-lock: acquired by $me"; exit 0; fi
    echo "run-lock: lost race to ${cur:-unknown}"; exit 1
    ;;
  release)
    read -r cur _ < <(holder)
    if [ "${cur:-}" = "$me" ]; then gh api "repos/$repo/issues/$issue/comments" -f body="UNLOCK $me" -q .id >/dev/null; echo "run-lock: released"; fi
    ;;
  holder) read -r cur _ < <(holder); [ -n "${cur:-}" ] && echo "$cur" ;;
  *) echo "usage: run-lock.sh acquire|release|holder <holder> <change-id>" >&2; exit 2 ;;
esac
