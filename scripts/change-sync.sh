#!/usr/bin/env bash
# Rewrites each change's tracking issue as its status page: state, PR, dependencies, anything waiting
# on the owner (a parked change opens with why and who moves next), the summary, every task with its
# tick, and the last progress entry. Sets one `status:<state>` label (the Project board filters on it;
# a parked change gets status:parked-owner or status:parked-stuck). Archived changes get status:done and close.
# tasks.md stays the source of truth; agents never edit these issues by hand.
#   scripts/change-sync.sh            all open changes, plus archived ones whose issue is still open
#   DRY_RUN=1 scripts/change-sync.sh  print the bodies instead of writing them
set -uo pipefail
repo=locksmith-hq/locksmith
here=$(dirname "$0")

# shellcheck source=scripts/issue-lib.sh
. "$here/issue-lib.sh"

# Org issue fields (text) on a parked change: "Parked Reason" (Waiting on owner | Stuck) and "Parked Link"
# (the blocker issue); both cleared when it is not parked. Writes only differences.
# The Actions token cannot list org issue fields, so fall back to the known ids.
# shortcut: if a field is ever recreated in org settings, update these ids (read them with a PAT).
park_ids=$(gh api "orgs/${repo%%/*}/issue-fields" -q '.[]|"\(.name)\t\(.id)"' 2>/dev/null) ||
  park_ids=$(printf 'Parked Reason\t50026268\nParked Link\t50026309\n')
F_REASON=$(awk -F'\t' '$1=="Parked Reason"{print $2}' <<<"$park_ids"); F_LINK=$(awk -F'\t' '$1=="Parked Link"{print $2}' <<<"$park_ids")
park_fields() { # <issue> <reason> <link>; empty values clear
  [ -n "$F_REASON" ] && [ -n "$F_LINK" ] && [ "${DRY_RUN:-0}" != 1 ] || return 0
  local cur f want
  cur=$(gh api "repos/$repo/issues/$1/issue-field-values" -q '.[]|"\(.issue_field_id)\t\(.value)"') || return 0
  for f in "$F_REASON	$2" "$F_LINK	$3"; do
    want=${f#*$'\t'}; f=${f%%$'\t'*}
    [ "$(awk -F'\t' -v f="$f" '$1==f{print $2}' <<<"$cur")" = "$want" ] && continue
    if [ -n "$want" ]; then gh api -X POST "repos/$repo/issues/$1/issue-field-values" \
      --input - <<<"{\"issue_field_values\":[{\"field_id\":$f,\"value\":$(jq -Rn --arg v "$want" '$v')}]}" >/dev/null
    else gh api -X DELETE "repos/$repo/issues/$1/issue-field-values/$f" >/dev/null; fi || echo "park fields: could not update #$1"
  done
}

# The top of a parked change's page: why it waits and who moves next, in plain words.
parked_block() { # <owner|rescue> <blocker-issue> <id>
  local j title why
  j=$(gh api "repos/$repo/issues/$2" 2>/dev/null) || j='{}'
  title=$(jq -r '.title // ""' <<<"$j")
  # First sentence of the blocker's first real line (skips the agent marker, blank and "Change:" lines).
  why=$(jq -r '.body // ""' <<<"$j" | grep -vE '^\s*(<!--|$|Change:)' | head -1 | sed -E 's/([.!?]) .*/\1/' | cut -c1-240)
  if [ "$1" = owner ]; then
    echo "## ⏸ Parked: waiting for owner approval"; echo
    echo "- **Why:** ${why:-$title}"
    echo "- **You:** open #$2, pick an option or reply \`approved\`."
    echo "- **Meanwhile:** workers continue on other changes."
  else
    echo "## ⏸ Parked: stuck, the lead is rescuing it"; echo
    echo "- **Stuck on:** tasks ${title#Rescue: "$3" } (#$2)"
    echo "- **Why:** ${why:-see #$2}"
    echo "- **Next:** the lead retries at 09:35 and 23:35. After two failed rescues it comes to you as a \`needs-owner\` issue."
    echo "- **You:** nothing yet."
  fi
  echo
}

render() { # <id> <state> <detail>
  local id=$1 state=$2 detail=$3 src pr owner rescue
  src=$(git show "origin/claude/change-$id:openspec/changes/$id/tasks.md" >/dev/null 2>&1 && echo "origin/claude/change-$id" || echo HEAD)
  pr=$(gh pr list -R "$repo" --head "claude/change-$id" --state open --json number,isDraft,labels \
    -q '.[0]|select(.!=null)|"#\(.number)\(if any(.labels[]; .name=="ready-to-merge") then " (ready to merge)" else "" end)"' 2>/dev/null)
  owner=$(gh api "repos/$repo/issues?labels=needs-owner&state=open&per_page=100" \
    -q ".[]|select((.title+\" \"+(.body // \"\"))|contains(\"$id\"))|\"- ⚠ **Needs owner:** #\(.number) \(.title)\"" 2>/dev/null)
  rescue=$(gh api "repos/$repo/issues?labels=needs-rescue&state=open&per_page=100" \
    -q ".[]|select((.title+\" \"+(.body // \"\"))|contains(\"$id\"))|\"- Rescue in progress: #\(.number) \(.title)\"" 2>/dev/null)
  echo "**Status:** \`$state\`${detail:+ ($detail)} · **PR:** ${pr:-none yet} · **Depends on:** $(sed -nE 's/^x-depends_on:[[:space:]]*\[(.*)\]/\1/p' "openspec/changes/$id/.openspec.yaml" 2>/dev/null || true)"
  echo
  if [ "$state" = parked ]; then parked_block "${detail%% *}" "${detail##*#}" "$id"
  elif [ -n "$owner$rescue" ]; then printf '%s\n%s\n\n' "$owner" "$rescue" | grep -v '^$'; echo; fi
  echo "## Summary"
  git show "$src:openspec/changes/$id/proposal.md" 2>/dev/null | awk '/^## Why/{f=1;next} /^## /{f=0} f' | sed '/^$/d' | head -8
  links=$(git show "$src:openspec/changes/$id/proposal.md" "$src:openspec/changes/$id/design.md" 2>/dev/null | grep -oE 'https://claude\.ai/(code/)?artifact/[A-Za-z0-9_-]+' | sort -u | paste -sd' ' - || true)
  echo; echo "Brief: ${links:-none} · [proposal](../blob/main/openspec/changes/$id/proposal.md) · [design](../blob/main/openspec/changes/$id/design.md)"
  t=$(git show "$src:openspec/changes/$id/tasks.md" 2>/dev/null)
  echo; echo "## Tasks ($(grep -cE '^\s*- \[[xX]\]' <<<"$t")/$(grep -cE '^\s*- \[[ xX]\]' <<<"$t") done)"
  grep -E '^(## |\s*- \[)' <<<"$t" | awk '/^## /{print ""; sub(/^## /, "### ")} 1'
  echo; echo "## Last progress"
  git show "$src:openspec/changes/$id/progress.md" 2>/dev/null | awk '/^## [0-9]/{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' | grep -v '^$' | head -8
  echo; echo "<!-- change-sync: generated from tasks.md and progress.md; edits here are overwritten -->"
}

# Linked pull requests: the change's PR gets a managed block of closing keywords for the change
# issue and every task sub-issue, so each one lists the PR under Development and closes when it
# merges (the finishing PR also archives the change, so closing then is correct).
link_pr() { # <id> <change-issue>
  local pr cur tasks block new
  pr=$(gh api "repos/$repo/pulls?head=${repo%%/*}:claude/change-$1&state=open" -q '.[0].number // empty')
  [ -n "$pr" ] || return 0
  tasks=$(gh api --paginate "repos/$repo/issues?labels=task&state=all&per_page=100" \
    -q ".[]|select(.title|startswith(\"$1 \"))|.number" | sort -n)
  block=$(printf '<!-- issue-links:start -->\n---\nCloses #%s\n<details><summary>Task sub-issues</summary>\n\n' "$2"
    for t in $tasks; do echo "Closes #$t"; done
    printf '\n</details>\n<!-- issue-links:end -->')
  cur=$(gh api "repos/$repo/pulls/$pr" -q '.body // ""')
  new=$(awk '/<!-- issue-links:start -->/{skip=1} !skip{print} /<!-- issue-links:end -->/{skip=0}' <<<"$cur")
  new=$(printf '%s\n\n%s' "$new" "$block")
  [ "$(awk '/<!-- issue-links:start -->/,/<!-- issue-links:end -->/' <<<"$cur")" = "$block" ] && return 0
  gh api -X PATCH "repos/$repo/pulls/$pr" -f body="$new" >/dev/null || echo "links: could not update PR #$pr"
}

bash "$here/change-status.sh" | while IFS=$'\t' read -r id state detail; do
  body=$(render "$id" "$state" "$detail")
  if [ "${DRY_RUN:-0}" = 1 ]; then printf '===== %s\n%s\n' "$id" "$body"; continue; fi
  n=$(bash "$here/change-issue.sh" "$id") || continue
  # The label and the Parked Reason / Parked Link issue fields say why a change is parked.
  lstate=$state; [ "$state" = parked ] && { [ "${detail%% *}" = owner ] && lstate=parked-owner || lstate=parked-stuck; }
  # The title follows the proposal, so an issue opened by a planner's lock gets its real name.
  title=$(sed -nE '1s/^# *(Proposal: *)?//p' "openspec/changes/$id/proposal.md" 2>/dev/null)
  gh api -X PATCH "repos/$repo/issues/$n" -f title="$id: ${title:-$id}" -f body="$body" -f state=open >/dev/null && label "$n" "$lstate" && board "$n" "$lstate"
  if [ "$state" = parked ]; then park_fields "$n" "$([ "${detail%% *}" = owner ] && echo "Waiting on owner" || echo Stuck)" \
    "https://github.com/$repo/issues/${detail##*#}"; else park_fields "$n" "" ""; fi
  link_pr "$id" "$n"
done

# Archived changes: mark done and close their issue.
for d in openspec/changes/archive/*/; do
  id=$(basename "$d" | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}-//')
  n=$(bash "$here/change-issue.sh" "$id" --find) || continue
  [ "$(gh api "repos/$repo/issues/$n" -q .state)" = open ] || continue
  [ "${DRY_RUN:-0}" = 1 ] && { echo "===== $id: would close #$n as done"; continue; }
  label "$n" "done"; board "$n" "done"; gh api -X PATCH "repos/$repo/issues/$n" -f state=closed -f state_reason=completed >/dev/null
done
