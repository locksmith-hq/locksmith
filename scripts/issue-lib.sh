# shellcheck shell=bash
# Shared helpers for change-sync.sh and roadmap-sync.sh (sourced; needs $repo).
: "${repo:?issue-lib.sh needs repo}"
# label <issue> <state>: one status:* label. board <issue> <state>: the Project's Status field.

label() { # <issue> <state>: swap the status:* label
  [ "${DRY_RUN:-0}" = 1 ] && return
  for l in $(gh api "repos/$repo/issues/$1/labels" -q '.[].name|select(startswith("status:"))'); do
    [ "$l" = "status:$2" ] || gh api -X DELETE "repos/$repo/issues/$1/labels/$l" >/dev/null 2>&1
  done
  gh api "repos/$repo/issues/$1/labels" -f "labels[]=status:$2" >/dev/null
}

# Board: with GH_AUTOMATION_TOKEN (the repo's automation PAT, which needs Projects read/write; the Actions token cannot write
# Projects), each change issue is added to the org Project and its Status field follows the state.
project_owner=${PROJECT_OWNER:-locksmith-hq}; project_number=${PROJECT_NUMBER:-1}
board_ids=""; board_items=""
board() { # <issue> <state>
  [ -n "${GH_AUTOMATION_TOKEN:-}" ] && [ "${DRY_RUN:-0}" != 1 ] || return 0
  local name item opt
  case "$2" in claimed) name="In progress" ;; review) name="In review" ;; *) name="$(tr '[:lower:]' '[:upper:]' <<<"${2:0:1}")${2:1}" ;; esac
  if [ -z "$board_ids" ]; then
    # shellcheck disable=SC2016 # jq variables
    board_ids=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh project field-list "$project_number" --owner "$project_owner" --format json \
      -q '.fields[]|select(.name=="Status")|.id as $f|.options[]|"\($f)\t\(.id)\t\(.name)"') || { echo "board: cannot read the Project (check GH_AUTOMATION_TOKEN)"; return 0; }
    project_id=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh project view "$project_number" --owner "$project_owner" --format json -q .id)
    # Current board in one read: "<issue number>\t<status>". Writes below happen only on a difference,
    # because every write costs GraphQL quota shared with the workers' account.
    board_items=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-list "$project_number" --owner "$project_owner" --limit 500 \
      --format json -q '.items[]|select(.content.number!=null)|"\(.content.number)\t\(.status // "")"')
  fi
  [ "$(awk -F'\t' -v n="$1" '$1==n{print $2; exit}' <<<"$board_items")" = "$name" ] && return 0
  opt=$(awk -F'\t' -v n="$name" '$3==n{print $1"\t"$2}' <<<"$board_ids")
  [ -n "$opt" ] || { echo "board: no Status option named '$name'"; return 0; }
  item=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-add "$project_number" --owner "$project_owner" \
    --url "https://github.com/$repo/issues/$1" --format json -q .id) ||
    { echo "board: cannot add #$1 (GH_AUTOMATION_TOKEN needs Issues: Read on this repo and Projects: Read and write on the org)"; return 0; }
  GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-edit --project-id "$project_id" --id "$item" \
    --field-id "${opt%%$'\t'*}" --single-select-option-id "${opt#*$'\t'}" >/dev/null || echo "board: could not set #$1 to $name"
}
