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
  case "$2" in claimed) name="In progress" ;; review) name="In review" ;;
    parked-owner) name="Waiting on owner" ;; parked-stuck) name="Stuck" ;; *) name="$(tr '[:lower:]' '[:upper:]' <<<"${2:0:1}")${2:1}" ;; esac
  if [ -z "$board_ids" ]; then
    # One read of only what we need (not `gh project item-list`, which also reads linked PRs and fails
    # for a token without Pull requests access). Lines: "F<TAB>field<TAB>option<TAB>name" per Status
    # option, "I<TAB>issue<TAB>item<TAB>status" per item, "P<TAB>project-id".
    # shellcheck disable=SC2016 # GraphQL variables
    board_read=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh api graphql --paginate -F owner="$project_owner" -F num="$project_number" -f query='
      query($owner:String!, $num:Int!, $endCursor:String) { organization(login:$owner) { projectV2(number:$num) {
        id field(name:"Status") { ... on ProjectV2SingleSelectField { id options { id name } } }
        items(first:100, after:$endCursor) { pageInfo { hasNextPage endCursor }
          nodes { id content { ... on Issue { number } }
            fieldValueByName(name:"Status") { ... on ProjectV2ItemFieldSingleSelectValue { name } } } } } } }' \
      -q '.data.organization.projectV2 | ("P\t\(.id)"), (.field.id as $f | .field.options[] | "F\t\($f)\t\(.id)\t\(.name)"),
          (.items.nodes[] | select(.content.number != null) | "I\t\(.content.number)\t\(.id)\t\(.fieldValueByName.name // "")")') ||
      { echo "board: cannot read the Project (check GH_AUTOMATION_TOKEN)"; board_ids=failed; return 0; }
    project_id=$(awk -F'\t' '$1=="P"{print $2; exit}' <<<"$board_read")
    board_ids=$(awk -F'\t' '$1=="F"{print $2"\t"$3"\t"$4}' <<<"$board_read" | sort -u)
    board_items=$(awk -F'\t' '$1=="I"{print $2"\t"$4"\t"$3}' <<<"$board_read")
  fi
  [ "$board_ids" = failed ] && return 0
  [ "$(awk -F'\t' -v n="$1" '$1==n{print $2; exit}' <<<"$board_items")" = "$name" ] && return 0
  opt=$(awk -F'\t' -v n="$name" '$3==n{print $1"\t"$2}' <<<"$board_ids")
  # Until the owner adds the "Waiting on owner" / "Stuck" options, a parked change shows as Parked.
  [ -z "$opt" ] && [ "${2%%-*}" = parked ] && { name=Parked; opt=$(awk -F'\t' '$3=="Parked"{print $1"\t"$2}' <<<"$board_ids"); }
  [ -n "$opt" ] || { echo "board: no Status option named '$name'"; return 0; }
  item=$(awk -F'\t' -v n="$1" '$1==n{print $3; exit}' <<<"$board_items")
  [ -n "$item" ] || item=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-add "$project_number" --owner "$project_owner" \
    --url "https://github.com/$repo/issues/$1" --format json -q .id) ||
    { echo "board: cannot add #$1 (GH_AUTOMATION_TOKEN needs Issues: Read on this repo and Projects: Read and write on the org)"; return 0; }
  GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-edit --project-id "$project_id" --id "$item" \
    --field-id "${opt%%$'\t'*}" --single-select-option-id "${opt#*$'\t'}" >/dev/null || echo "board: could not set #$1 to $name"
}
