#!/usr/bin/env bash
# A worker with nothing to take or plan asks the PM for work (owner 2026-11-20): it opens one `needs-work`
# issue, which wakes the PM (routing.json channel). The PM closes it with what it did; closing wakes the worker.
# Skips while one is open, or when one was closed in the last 6h (the PM already looked; no hourly loop).
#   scripts/request-work.sh [role] [reason]   (role defaults to AGENT_PERSONA's role in routing.json)
set -uo pipefail
repo=locksmith-hq/locksmith
AGENT_PERSONA=${AGENT_PERSONA:-$(cat "${AGENT_ID_DIR:-$HOME/.config/locksmith-agent}/persona" 2>/dev/null)}  # agent-identity.sh records it; later shells lose the export
role=${1:-$(jq -r --arg l "locksmith-${AGENT_PERSONA:-}[bot]" '[.roles|to_entries[]|select(.value.logins|index($l))|.key][0] // empty' \
  "$(dirname "$0")/../docs/agents/routing.json")}
[ -n "$role" ] || { echo "usage: request-work.sh <role> [reason] (or set AGENT_PERSONA)"; exit 2; }
why=${2:-no change to take, continue or plan}
open=$(gh api "repos/$repo/issues?labels=needs-work&state=open" -q length) || exit 1
[ "$open" -gt 0 ] && { echo "needs-work: already open"; exit 0; }
since=$(date -u -d '6 hours ago' +%FT%TZ 2>/dev/null || date -u -v-6H +%FT%TZ)
recent=$(gh api "repos/$repo/issues?labels=needs-work&state=closed&since=$since" -q length) || exit 1
[ "$recent" -gt 0 ] && { echo "needs-work: the PM answered within 6h; not asking again"; exit 0; }
status=$(bash "$(dirname "$0")/change-status.sh" 2>/dev/null | cut -f1,2,3)
body=$(printf '<!-- agent -->\n<!-- raised-by: %s -->\n%s is idle: %s.\n\nPM: check the board and roadmap, decide what can be done (reprioritize, unblock, plan the next change, or hand a blocker to the lead), comment it here and close this issue, which wakes %s.\n\n```\n%s\n```\n' \
  "$role" "$role" "$why" "$role" "$status")
gh api "repos/$repo/issues" -f title="Workers idle: $role has no work" -f body="$body" -f 'labels[]=needs-work' -q .html_url
