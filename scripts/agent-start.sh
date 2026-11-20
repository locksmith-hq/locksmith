#!/usr/bin/env bash
# First command of every scheduled agent run (see .claude/skills/run-start).
#   scripts/agent-start.sh <kind> [persona]
# Starts run metadata, runs preflight, switches to the persona's GitHub App when this environment holds its key
# (persona is the argument, else AGENT_PERSONA), prints active lessons. Exit 1 on a preflight or identity FAIL.
# Shortcut: an environment without AGENT_APP_KEY_<PERSONA> still runs as the owner; drop that once every key is set.
set -uo pipefail
kind="${1:?usage: agent-start.sh <kind> [persona]}"
# Fresh origin/main first: lessons and gates read it (a stale view cost a worker 120 s, 2026-11-17).
git fetch -q origin || echo "WARN   git-fetch      failed"
# A cron VM can start on a stale scratch branch, and change-status.sh reads the working tree: three runs
# on 2026-11-19 claimed the already-archived s5. Move a clean, fully pushed scratch checkout to origin/main.
b=$(git branch --show-current)
if { [ -z "$b" ] || [[ "$b" == claude/* && ! "$b" =~ ^claude/(change|planning|lead|fix-main)- ]]; } &&
  ! git rev-parse -q --verify "origin/$b" >/dev/null &&
  [ -z "$(git status --porcelain)" ] && [ -z "$(git rev-list -n1 HEAD --not --remotes)" ] &&
  [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  if [ -n "$b" ]; then git checkout -q -B "$b" origin/main; else git checkout -q --detach origin/main; fi &&
    echo "OK     checkout       stale ${b:-detached HEAD} moved to origin/main"
fi
bash scripts/run-meta.sh start "$kind"
# Ticks need an evaluator PASS before they leave the VM (run-meta.sh push-check); keep any existing hook.
# The hook runs main's copy, so a change branch that predates push-check can still push.
hook="$(git rev-parse --git-common-dir)/hooks/pre-push"
[ -e "$hook" ] || { printf '#!/bin/sh\ngit show origin/main:scripts/run-meta.sh | bash -s -- push-check\n' > "$hook" && chmod +x "$hook"; }
echo "== preflight"
bash scripts/agent-preflight.sh; pf=$?
persona="${2:-${AGENT_PERSONA:-}}"; var="AGENT_APP_KEY_$(tr '[:lower:]' '[:upper:]' <<<"$persona")"
echo "== identity"
if [ -n "$persona" ] && [ -n "${!var:-}" ]; then
  # A key is set, so a run must never fall back to the owner: setup undoes itself and prints FAIL on any error.
  bash scripts/agent-identity.sh setup "$persona" || pf=1
elif [ "$kind" = research ] || [ "$persona" = research ]; then
  echo "FAIL identity: research has open internet and never runs as the owner; set $var"; pf=1
else echo "WARN   identity: no ${persona:+$var }key in this environment; acting as the owner account"; fi
echo "== active lessons (docs/agents/lessons.md on origin/main)"
git show origin/main:docs/agents/lessons.md 2>/dev/null | awk '/^## L[0-9]+/{p=1} p' || echo "(none)"
exit "$pf"
