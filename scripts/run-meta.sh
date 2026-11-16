#!/usr/bin/env bash
# Collects the deterministic part of a scheduled agent run's metadata (docs/agents/common.md).
#   scripts/run-meta.sh start <kind>   record start time and HEAD (call first thing in a run)
#   scripts/run-meta.sh report         print the YAML block for the run so far
# The agent appends `subagents:` and outcome fields itself (it is the only one that knows them).
# Never prints secret values: only allow-listed env var names that look like session ids.
set -euo pipefail
state="${RUN_META_STATE:-/tmp/run-meta.env}"

case "${1:-}" in
  start)
    {
      echo "KIND=${2:-unknown}"
      echo "START_EPOCH=$(date -u +%s)"
      echo "BASE_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo none)"
    } > "$state"
    echo "run-meta: started ${2:-unknown}"
    ;;
  report)
    [ -f "$state" ] || { echo "run-meta: call 'start' first" >&2; exit 1; }
    # shellcheck disable=SC1090
    . "$state"
    now=$(date -u +%s)
    head=$(git rev-parse --short HEAD 2>/dev/null || echo none)
    branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo none)
    commits=0; stat="none"
    if [ "$BASE_SHA" != none ] && [ "$head" != none ]; then
      commits=$(git rev-list --count "$BASE_SHA..HEAD" 2>/dev/null || echo 0)
      stat=$(git diff --shortstat "$BASE_SHA" HEAD 2>/dev/null | sed 's/^ *//')
      [ -n "$stat" ] || stat="no changes"
    fi
    session=$(env | grep -E '^CLAUDE_CODE_[A-Z_]*SESSION[A-Z_]*_ID=' | head -1 | cut -d= -f2- || true)
    mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1048576}' /proc/meminfo 2>/dev/null || echo "?")
    cat <<EOF
\`\`\`yaml
run-metadata:
  kind: $KIND
  started: $(date -u -d "@$START_EPOCH" +%FT%TZ 2>/dev/null || date -u -r "$START_EPOCH" +%FT%TZ)
  finished: $(date -u +%FT%TZ)
  duration_s: $((now - START_EPOCH))
  session: ${session:-unknown}
  branch: $branch
  base_sha: $BASE_SHA
  head_sha: $head
  commits: $commits
  diff: "$stat"
  runner: "$(nproc 2>/dev/null || sysctl -n hw.ncpu) cpu, ${mem_gb} GB"
\`\`\`
EOF
    ;;
  *) echo "usage: $0 start <kind> | report" >&2; exit 2 ;;
esac
