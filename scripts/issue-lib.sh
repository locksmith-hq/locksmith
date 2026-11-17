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
# Projects), each change issue is added to the org Project and its Status field follows the state. A parked change
# (parked-owner / parked-stuck) shows Status "Parked" plus two optional fields, cleared when it is not parked:
# "Parked reason" (single select: "Waiting on owner" / "Stuck") and "Parked issue" (text: link to the blocker issue).
project_owner=${PROJECT_OWNER:-locksmith-hq}; project_number=${PROJECT_NUMBER:-1}
board_ids=""; board_items=""; reason_ids=""; link_field=""
board_set() { # <item> <field-id> <option-id|--text value|--clear>
  local item=$1 field=$2; shift 2
  [ "$1" = --clear ] || [ "$1" = --text ] || set -- --single-select-option-id "$1"
  GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-edit --project-id "$project_id" --id "$item" --field-id "$field" "$@" >/dev/null
}
board() { # <issue> <state> [blocker-issue]
  [ -n "${GH_AUTOMATION_TOKEN:-}" ] && [ "${DRY_RUN:-0}" != 1 ] || return 0
  local name reason link item opt cur
  case "$2" in claimed) name="In progress" ;; review) name="In review" ;; parked*) name=Parked ;;
    *) name="$(tr '[:lower:]' '[:upper:]' <<<"${2:0:1}")${2:1}" ;; esac
  case "$2" in parked-owner) reason="Waiting on owner" ;; parked-stuck) reason=Stuck ;; *) reason="" ;; esac
  link=""; [ -n "$reason" ] && [ -n "${3:-}" ] && link="https://github.com/$repo/issues/$3"
  if [ -z "$board_ids" ]; then
    # One read of only what we need (not `gh project item-list`, which also reads linked PRs and fails
    # for a token without Pull requests access). Fields are listed, not looked up by name, because a
    # lookup of a missing field fails the whole query. Lines: "F|R<TAB>field<TAB>option<TAB>name" per Status
    # or Parked reason option, "T<TAB>field" for Parked issue, "P<TAB>project-id", and per item
    # "I<TAB>issue<TAB>item<TAB>status<TAB>reason<TAB>link".
    # shellcheck disable=SC2016 # GraphQL variables
    board_read=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh api graphql --paginate -F owner="$project_owner" -F num="$project_number" -f query='
      query($owner:String!, $num:Int!, $endCursor:String) { organization(login:$owner) { projectV2(number:$num) {
        id fields(first:50) { nodes { ... on ProjectV2SingleSelectField { id name options { id name } } ... on ProjectV2Field { id name } } }
        items(first:100, after:$endCursor) { pageInfo { hasNextPage endCursor }
          nodes { id content { ... on Issue { number } }
            fieldValues(first:30) { nodes {
              ... on ProjectV2ItemFieldSingleSelectValue { name field { ... on ProjectV2FieldCommon { name } } }
              ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2FieldCommon { name } } } } } } } } } }' \
      -q '.data.organization.projectV2 | ("P\t\(.id)"),
          (.fields.nodes[] | select(.name != null) | (.name|ascii_downcase) as $n | .id as $f |
            if $n == "status" then .options[] | "F\t\($f)\t\(.id)\t\(.name)"
            elif $n == "parked reason" then (.options // [])[] | "R\t\($f)\t\(.id)\t\(.name)"
            elif $n == "parked issue" then "T\t\($f)" else empty end),
          (.items.nodes[] | select(.content.number != null) |
            ([.fieldValues.nodes[] | select(.field.name != null) | {key: (.field.name|ascii_downcase), value: (.name // .text)}] | from_entries) as $v |
            "I\t\(.content.number)\t\(.id)\t\($v.status // "")\t\($v["parked reason"] // "")\t\($v["parked issue"] // "")")') ||
      { echo "board: cannot read the Project (check GH_AUTOMATION_TOKEN)"; board_ids=failed; return 0; }
    project_id=$(awk -F'\t' '$1=="P"{print $2; exit}' <<<"$board_read")
    board_ids=$(awk -F'\t' '$1=="F"{print $2"\t"$3"\t"$4}' <<<"$board_read" | sort -u)
    reason_ids=$(awk -F'\t' '$1=="R"{print $2"\t"$3"\t"$4}' <<<"$board_read" | sort -u)
    link_field=$(awk -F'\t' '$1=="T"{print $2; exit}' <<<"$board_read")
    board_items=$(awk -F'\t' '$1=="I"{print $2"\t"$4"\t"$3"\t"$5"\t"$6}' <<<"$board_read")
  fi
  [ "$board_ids" = failed ] && return 0
  # cur: status, reason, link. A field the Project lacks counts as already right.
  cur=$(awk -F'\t' -v n="$1" '$1==n{print $2"\t"$4"\t"$5; exit}' <<<"$board_items")
  IFS=$'\t' read -r c_status c_reason c_link <<<"$cur"
  [ -z "$reason_ids" ] && reason=$c_reason
  [ -z "$link_field" ] && link=$c_link
  [ "$c_status|$c_reason|$c_link" = "$name|$reason|$link" ] && return 0
  item=$(awk -F'\t' -v n="$1" '$1==n{print $3; exit}' <<<"$board_items")
  [ -n "$item" ] || item=$(GH_TOKEN=$GH_AUTOMATION_TOKEN gh project item-add "$project_number" --owner "$project_owner" \
    --url "https://github.com/$repo/issues/$1" --format json -q .id) ||
    { echo "board: cannot add #$1 (GH_AUTOMATION_TOKEN needs Issues: Read on this repo and Projects: Read and write on the org)"; return 0; }
  if [ "$c_status" != "$name" ]; then
    opt=$(awk -F'\t' -v n="$name" '$3==n{print $1"\t"$2}' <<<"$board_ids")
    if [ -n "$opt" ]; then board_set "$item" "${opt%%$'\t'*}" "${opt#*$'\t'}" || echo "board: could not set #$1 to $name"
    else echo "board: no Status option named '$name'"; fi
  fi
  if [ "$c_reason" != "$reason" ]; then
    opt=$(awk -F'\t' -v n="$reason" '$3==n{print $1"\t"$2}' <<<"$reason_ids")
    if [ -z "$reason" ]; then board_set "$item" "$(head -1 <<<"$reason_ids" | cut -f1)" --clear
    elif [ -n "$opt" ]; then board_set "$item" "${opt%%$'\t'*}" "${opt#*$'\t'}"
    else echo "board: no Parked reason option named '$reason'"; false; fi || echo "board: could not set the Parked reason of #$1"
  fi
  if [ "$c_link" != "$link" ]; then
    if [ -z "$link" ]; then board_set "$item" "$link_field" --clear; else board_set "$item" "$link_field" --text "$link"; fi ||
      echo "board: could not set the Parked issue of #$1"
  fi
}
