#!/usr/bin/env bash
# Single active writer for scheduled agents (worker, rescue, review): "one active worker per inbox".
# The lock lives as comments on the open issue labelled run-lock; it expires after TTL seconds so a
# crashed run never blocks the next one.
#   scripts/run-lock.sh acquire <holder>   exit 0 = you hold it; exit 1 = busy (prints holder, age)
#   scripts/run-lock.sh release <holder>
set -uo pipefail
repo=locksmith-hq/locksmith
ttl="${RUN_LOCK_TTL:-3000}"
cmd="${1:-}"; me="${2:-}"
[ -n "$cmd" ] && [ -n "$me" ] || { echo "usage: run-lock.sh acquire|release <holder>" >&2; exit 2; }

issue=$(gh api "repos/$repo/issues?labels=run-lock&state=open" -q '.[0].number // empty')
if [ -z "$issue" ]; then
  issue=$(gh api "repos/$repo/issues" -f title="Agent run lock" -f 'labels[]=run-lock' \
    -f body="Single-writer lock for scheduled agents (scripts/run-lock.sh). Do not close." -q .number)
fi

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
  *) echo "usage: run-lock.sh acquire|release <holder>" >&2; exit 2 ;;
esac
