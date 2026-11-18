#!/usr/bin/env bash
# First command of every scheduled agent run (see .claude/skills/run-start).
#   scripts/agent-start.sh <kind> [persona]
# Starts run metadata, runs preflight, switches to the persona's GitHub App identity when one is given,
# prints active lessons. Exit 1 if preflight has a FAIL.
set -uo pipefail
kind="${1:?usage: agent-start.sh <kind> [persona]}"
# Fresh origin/main first: lessons and gates read it (a stale view cost a worker 120 s, 2026-11-17).
git fetch -q origin || echo "WARN   git-fetch      failed"
bash scripts/run-meta.sh start "$kind"
echo "== preflight"
bash scripts/agent-preflight.sh; pf=$?
if [ -n "${2:-}" ]; then echo "== identity"; bash scripts/agent-identity.sh setup "$2" || pf=1; fi
echo "== active lessons (docs/agents/lessons.md on origin/main)"
git show origin/main:docs/agents/lessons.md 2>/dev/null | awk '/^## L[0-9]+/{p=1} p' || echo "(none)"
exit "$pf"
