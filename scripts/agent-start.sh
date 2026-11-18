#!/usr/bin/env bash
# First command of every scheduled agent run (see .claude/skills/run-start).
#   scripts/agent-start.sh <kind> [persona]
# Starts run metadata, runs preflight, checks the run already acts as its persona's GitHub App (the environment's
# setup script switched it once; persona is the argument, else AGENT_PERSONA),
# prints active lessons. Exit 1 if preflight has a FAIL.
set -uo pipefail
kind="${1:?usage: agent-start.sh <kind> [persona]}"
# Fresh origin/main first: lessons and gates read it (a stale view cost a worker 120 s, 2026-11-17).
git fetch -q origin || echo "WARN   git-fetch      failed"
bash scripts/run-meta.sh start "$kind"
echo "== preflight"
bash scripts/agent-preflight.sh; pf=$?
persona="${2:-${AGENT_PERSONA:-}}"
if [ -n "$persona" ]; then
  echo "== identity"
  # Setup ran once in the environment's setup script; a run must never act as the owner by accident.
  if [ "$(git config --local user.name)" = "locksmith-${persona}[bot]" ]; then echo "OK identity: locksmith-${persona}[bot]"
  else echo "FAIL identity: not set up as locksmith-${persona}[bot]; check the environment's setup script output"; pf=1; fi
fi
echo "== active lessons (docs/agents/lessons.md on origin/main)"
git show origin/main:docs/agents/lessons.md 2>/dev/null | awk '/^## L[0-9]+/{p=1} p' || echo "(none)"
exit "$pf"
