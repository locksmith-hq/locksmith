#!/usr/bin/env bash
# Builds the owner-alert comment. The GitHub mobile push shows only the start of the comment,
# so the title, summary, change and brief come first. Reads OWNER, TITLE and BODY from the env.
set -euo pipefail

# First prose line of the issue body, without markdown markers, cut to 200 characters.
summary=$(printf '%s\n' "${BODY:-}" | sed -E 's/<!--.*-->//g; s/^[#>*[:space:]-]+//; s/\*\*//g' \
  | grep -m1 -vE '^[[:space:]]*$' || true)
[ ${#summary} -gt 200 ] && summary="${summary:0:197}..."
briefs=$(printf '%s\n' "${BODY:-}" | grep -oE 'https://claude\.ai/(code/)?artifact/[A-Za-z0-9_-]+' | sort -u | paste -sd' ' - || true)
# shortcut: change ids look like "a0-data-and-cloud-foundations"; match on that shape, not the change list.
change=$(printf '%s\n%s\n' "${TITLE:-}" "${BODY:-}" | grep -oE '\b[a-z][0-9]+-[a-z0-9]+(-[a-z0-9]+)*' | head -1 || true)

printf '@%s decision needed: %s\n\n' "$OWNER" "$TITLE"
[ -n "$summary" ] && printf '%s\n\n' "$summary"
printf -- '- Change: %s\n' "${change:-not named}"
printf -- '- Brief: %s\n' "${briefs:-none prepared}"
printf '\nReply `approved`, or reply with concerns. The scheduled agents wait until you answer here.\n'
