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
# An "Action:" line says exactly what the owner must do (merge a PR, run a command); approving alone doesn't do it.
action=$(printf '%s\n' "${BODY:-}" | sed -nE 's/^[*_[:space:]-]*Action:[*_[:space:]]*(.+)$/\1/p' | head -1)
# A bare "Action:" line introduces a list of steps, printed under Details.
[ -z "$action" ] && grep -qE '^[*_[:space:]-]*Action:[*_[:space:]]*$' <<<"${BODY:-}" && action='the steps under **Action** in Details below.'
# shellcheck disable=SC2016 # literal backticks for markdown
if [ -n "$action" ]; then printf -- '- **You:** %s\n\nReply when it is done, or with concerns.\n' "$action"
else printf '\nReply `approved`, or reply with concerns. Only the named change waits; the other agents keep working.\n'; fi
# The why, options and recommendation follow the ask, so the push preview still starts with the ask.
body=$(printf '%s\n' "${BODY:-}" | sed -E 's/<!--.*-->//g')
first=$(printf '%s\n' "$body" | grep -m1 -vE '^[[:space:]]*$' || true)
details=$(printf '%s\n' "$body" | grep -vxF -- "$first" \
  | grep -vE '^[*_[:space:]-]*Change:|^[[:space:]]*(---|_?Generated (with|by) )' || true)
[ -z "${details//[[:space:]]/}" ] || printf '\n**Details**\n\n%s\n' "$(printf '%s\n' "$details" | sed '/./,$!d')"
