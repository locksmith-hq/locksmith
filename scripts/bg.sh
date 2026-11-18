#!/usr/bin/env bash
# Run a long command in the background with a hard timeout; poll it instead of blocking
# (see .claude/skills/long-commands).
#   scripts/bg.sh start <name> <timeout-s> -- <cmd...>   start; log in /tmp/bg-<name>.log
#   scripts/bg.sh wait  <name> [max-s]                    poll until done (max 110 s, under the Bash tool's
#                                                          120 s limit; call again on 124); prints tail + exit code
# Each finished job appends "<name> <seconds> <exit>" to /tmp/bg-times; run-meta.sh reports it (just_ci_s).
#   scripts/bg.sh status <name>                           running | done <code>
set -uo pipefail
cmd="${1:-}"; name="${2:-}"; [ -n "$cmd" ] && [ -n "$name" ] || { echo "usage: bg.sh start|wait|status <name> ..." >&2; exit 2; }
log="/tmp/bg-$name.log"; rc="/tmp/bg-$name.rc"
case "$cmd" in
  start)
    t="${3:?timeout seconds}"; shift 3; [ "${1:-}" = "--" ] && shift
    rm -f "$rc"
    # No stdin: a command that reads it (a stray `cat`) hung a worker run for 30 min.
    ( s=$(date +%s); timeout -s KILL "$t" "$@" </dev/null >"$log" 2>&1; c=$?
      echo "$name $(( $(date +%s) - s )) $c" >>/tmp/bg-times; echo $c >"$rc" ) &
    echo "bg: started $name (timeout ${t}s), log $log"
    ;;
  status)
    if [ -f "$rc" ]; then echo "done $(cat "$rc")"; else echo running; fi
    ;;
  wait)
    max="${3:-110}"; [ "$max" -gt 110 ] && max=110; waited=0
    while [ ! -f "$rc" ] && [ "$waited" -lt "$max" ]; do sleep 5; waited=$((waited+5)); done
    tail -n 30 "$log" 2>/dev/null
    if [ -f "$rc" ]; then code=$(cat "$rc"); note=""; [ "$code" = 137 ] && note=" (killed by timeout)"; echo "bg: $name exited ${code}${note}"; exit "$code"
    else echo "bg: $name still running after ${max}s (check again later)"; exit 124; fi
    ;;
  *) echo "usage: bg.sh start|wait|status <name> ..." >&2; exit 2 ;;
esac
