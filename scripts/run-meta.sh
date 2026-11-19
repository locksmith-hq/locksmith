#!/usr/bin/env bash
# Collects the deterministic part of a scheduled agent run's metadata (docs/agents/common.md).
#   scripts/run-meta.sh start <kind>   record start time and HEAD (call first thing in a run)
#   scripts/run-meta.sh report         print the YAML body (no fences) for the run so far
#   scripts/run-meta.sh block < fields  print the complete ```yaml block: report + agent fields from stdin
# The agent appends `subagents:` and outcome fields itself (it is the only one that knows them).
# Never prints secret values: only allow-listed env var names that look like session ids.
set -euo pipefail
state="${RUN_META_STATE:-/tmp/run-meta.env}"

case "${1:-}" in
  start)
    {
      echo "KIND=${2:-unknown}"
      echo "START_EPOCH=$(date -u +%s)"
      rm -f /tmp/bg-times
      echo "BASE_SHA=$(git rev-parse --short origin/main 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo none)"
    } > "$state"
    echo "run-meta: started ${2:-unknown}"
    ;;
  report)
    if [ -f "$state" ]; then
      # shellcheck disable=SC1090
      . "$state"
    else
      # Never drop the block: a missing state file still yields session, branch and head.
      echo "run-meta: 'start' was not called; started/duration_s are unknown" >&2
      KIND=unknown; START_EPOCH=""; BASE_SHA=none
    fi
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
run-metadata:
  kind: $KIND
  started: $( [ -n "$START_EPOCH" ] && { date -u -d "@$START_EPOCH" +%FT%TZ 2>/dev/null || date -u -r "$START_EPOCH" +%FT%TZ; } || echo unknown)
  finished: $(date -u +%FT%TZ)
  duration_s: $( [ -n "$START_EPOCH" ] && echo $((now - START_EPOCH)) || echo unknown)
  session: ${session:-unknown}
  branch: $branch
  base_sha: $BASE_SHA
  head_sha: $head
  commits: $commits
  diff: "$stat"
  just_ci_s: "$(awk '$1=="ci"{printf "%s%ss exit %s", sep, $2, $3; sep=", "}' /tmp/bg-times 2>/dev/null)"
  runner: "$(nproc 2>/dev/null || sysctl -n hw.ncpu) cpu, ${mem_gb} GB"
EOF
    ;;
  block)
    # One fenced block, never nested: agent fields (2-space indented YAML) come on stdin.
    echo '```yaml'
    "$0" report
    fields=""; if [ ! -t 0 ]; then fields=$(sed '/^```/d'); printf '%s\n' "$fields"; fi
    echo '```'
    # evaluate-escalate step 4: never tick with `evaluator: n/a` (6 worker runs did on 2026-11-17/18).
    if grep -qE '^ *evaluator: *n/a' <<<"$fields"; then
      since=$(sed -n 's/^START_EPOCH=//p' "$state" 2>/dev/null || true)
      ticks=$( { git log --since="@${since:-$(date -u +%s)}" --no-merges -p -- '*tasks.md'; git diff HEAD -- '*tasks.md'; } 2>/dev/null | grep -c '^+.*\[x\]' || true)
      if [ "${ticks:-0}" -gt 0 ]; then echo "run-meta: WARN evaluator: n/a but this run ticked $ticks task(s): run the evaluator (evaluate-escalate step 3) or untick before you push" >&2; fi
    fi
    # worker.md step 6: 3 worker runs on 2026-11-18 were asked to plan and ended without planning.
    if grep -q '^KIND=worker' "$state" 2>/dev/null; then
      asked=$(bash "$(dirname "$0")/worker-has-work.sh" 2>/dev/null || true)
      if grep -q 'plan the next one' <<<"$asked"; then echo "run-meta: WARN planning is still asked and no planning PR is open: do worker.md step 6 before you finish" >&2; fi
    fi
    ;;
  eval)
    # evaluate-escalate step 4: record the independent evaluator's verdict for push-check.
    case "${2:-}" in PASS|FAIL) echo "EVAL=$2" >> "$state" ;; *) echo "usage: $0 eval PASS|FAIL" >&2; exit 2 ;; esac
    ;;
  push-check)
    # pre-push hook (agent-start.sh): the block WARN came after the push, and 2 runs on 2026-11-19 still
    # pushed ticks with `evaluator: n/a`. Refuse a push that ticks tasks unless `eval PASS` was recorded.
    [ -f "$state" ] || exit 0
    since=$(sed -n 's/^START_EPOCH=//p' "$state"); verdict=$(sed -n 's/^EVAL=//p' "$state" | tail -1)
    # HEAD --not origin/main: ticks other runs merged to main and this branch merged in are not ours.
    ticks=$(git log --since="@${since:-$(date -u +%s)}" --no-merges -p HEAD --not origin/main -- '*tasks.md' 2>/dev/null | grep -c '^+.*\[x\]' || true)
    if [ "${ticks:-0}" -gt 0 ] && [ "$verdict" != PASS ]; then
      echo "run-meta: push refused: this run ticked $ticks task(s) without an evaluator PASS. Run the evaluator (evaluate-escalate step 3), then 'bash scripts/run-meta.sh eval PASS', or untick." >&2
      exit 1
    fi
    ;;
  *) echo "usage: $0 start <kind> | report | block < agent-fields | eval PASS|FAIL | push-check" >&2; exit 2 ;;
esac
