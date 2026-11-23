#!/usr/bin/env bash
# Renders the README cast table from docs/agents/routing.json (names, titles, avatars), so renaming an agent is
# one edit there. Usage: scripts/team-sync.sh [--check]  (--check fails when the README is out of date)
set -euo pipefail
cd "$(dirname "$0")/.."
cell() { # <name> <title> <avatar> <blurb>
  printf '    <td align="center" width="25%%"><img src="docs/agents/avatars/%s" width="120" alt="%s"><br><b>%s</b><br>%s<br><sub>%s</sub></td>\n' "$3" "$1" "$1" "$2" "$4"
}
rows=$(jq -r '
  def c: "\(.name)\t\(.title)\t\(.avatar)\t\(.blurb)";
  ([.roles.lead, .roles.pm, .roles.research, .local.optimizer] | map(c) | join("\n")),
  "--",
  ([.roles["worker-a"], .roles["worker-b"], .roles["worker-c"]] | map(c) | join("\n"))' docs/agents/routing.json)
out='<table>'
section=1
while IFS= read -r line; do
  [ "$line" = "--" ] && { out+=$'\n  </tr>\n  <tr>'; continue; }
  [ "$out" = "<table>" ] && out+=$'\n  <tr>'
  IFS=$'\t' read -r n t a b <<<"$line"
  out+=$'\n'"$(cell "$n" "$t" "$a" "$b")"
done <<<"$rows"
out+=$'\n  </tr>\n</table>'
new=$(T="$out" awk '/<!-- team:start -->/{print; print ENVIRON["T"]; skip=1; next} /<!-- team:end -->/{skip=0} !skip' README.md)
if [ "${1:-}" = "--check" ]; then [ "$new" = "$(cat README.md)" ] || { echo "README team table is out of date: run scripts/team-sync.sh"; exit 1; }
else printf '%s\n' "$new" >README.md; fi
