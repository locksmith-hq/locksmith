#!/usr/bin/env bash
# G16: a `hide` tool is not there for the agent (M2 task 7.2). The upstream (normal mode) has
# `list_issues` and `echo` allowed, `create_issue` and `delete_repository` hidden (explicitly and
# by the default). Probes through `smith mcp bridge github` and with an HTTP client of the agent's
# own on `/mcp/upstream/github`:
#   - `tools/list` lacks both hidden tools;
#   - a `tools/call` of each hidden tool by exact name, a case variant, a Unicode look-alike
#     (Cyrillic `е`), with trailing space, inside a JSON-RPC batch, and on a path of an upstream
#     the agent has no grant for or that does not exist, gets the very answer a never-existing
#     tool name gets (same JSON-RPC error message), and the upstream's private log shows no
#     `tools/call` for any of them;
#   - the ledger holds `mcp.upstream_call` denied events and no pending call for a hidden tool.
# Skips when the stack is down.
set -euo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
. "$here/lib.sh"
. "$here/upstream_lib.sh"
gw_init

GW_UP_TOOLS='list_issues = "allow"
echo = "allow"
create_issue = "hide"'
GW_UP_DEFAULT=hide
gw_up_start normal
gw_up_setup
mcp_up() { python3 -I "$here/mcp_up.py" "$@"; }

# name -> JSON-escaped tool name
declare -a names=(
  "exact-create:create_issue"
  "exact-delete:delete_repository"
  "case-create:Create_Issue"
  "case-delete:DELETE_REPOSITORY"
  "lookalike-create:crеate_issue"
  "lookalike-delete:dеlete_repository"
  "space-create:create_issue "
  "never:never_existed"
)
calls="$GW_WORK/calls.jsonl"
{
  printf '%s\n' '{"jsonrpc":"2.0","id":"list","method":"tools/list"}'
  for spec in "${names[@]}"; do
    id="${spec%%:*}"
    tool="${spec#*:}"
    printf '{"jsonrpc":"2.0","id":"%s","method":"tools/call","params":{"name":"%s","arguments":{}}}\n' "$id" "$tool"
  done
  printf '%s\n' '{"jsonrpc":"2.0","id":"allowed","method":"tools/call","params":{"name":"list_issues","arguments":{}}}'
} >"$calls"
batch="$GW_WORK/batch.jsonl"
printf '%s\n' '[{"jsonrpc":"2.0","id":"b1","method":"tools/call","params":{"name":"create_issue","arguments":{}}},{"jsonrpc":"2.0","id":"b2","method":"tools/call","params":{"name":"delete_repository","arguments":{}}}]' >"$batch"

check_replies() { # PREFIX FILE: list lacks hidden tools; every hidden-tool call is the never-existed answer
  local who="$1" file="$2" t never spec id got
  mcp_up tools "$file" list >"$GW_WORK/$who-tools.txt"
  grep -qx list_issues "$GW_WORK/$who-tools.txt" || gw_fail "$who: tools/list lacks list_issues"
  for t in create_issue delete_repository; do
    if grep -qx "$t" "$GW_WORK/$who-tools.txt"; then gw_fail "$who: tools/list shows the hidden tool $t"; fi
  done
  never="$(mcp_up outcome "$file" never)"
  [[ "$never" == error:* ]] || gw_fail "$who: an unknown tool did not get a JSON-RPC error ($never)"
  for spec in "${names[@]}"; do
    id="${spec%%:*}"
    got="$(mcp_up outcome "$file" "$id")"
    [[ "$got" == "$never" ]] || gw_fail "$who: $id answered '$got', a never-existed tool answers '$never'"
  done
  [[ "$(mcp_up outcome "$file" allowed)" == ok ]] || gw_fail "$who: the allowed tool did not work"
}

# 1. The bridge.
gw_up_bridge bridge "$calls" || gw_fail "smith mcp bridge failed (see bridge-bridge.err)"
check_replies bridge "$ARTIFACT_DIR/bridge-bridge.out"

# 2. The agent's own client, then the batch and the other paths.
gw_up_call curl /mcp/upstream/github "$calls" || gw_fail "the direct client could not initialize (see up-curl.err)"
check_replies curl "$ARTIFACT_DIR/up-curl.out"
gw_up_call batch /mcp/upstream/github "$batch" || gw_fail "the batch client could not initialize"
if grep -c . "$ARTIFACT_DIR/up-batch.http" >/dev/null && [[ "$(awk '$1=="batch"{print $2}' "$ARTIFACT_DIR/up-batch.http")" == 2* ]]; then
  # A batch that the server accepts must still answer both entries as unknown.
  for id in b1 b2; do
    [[ "$(mcp_up outcome "$ARTIFACT_DIR/up-batch.out" "$id")" == error:* ]] || gw_fail "batch: $id was not refused"
  done
fi
# Another upstream's path: unknown names and case variants answer the same for any tool.
single="$GW_WORK/single.jsonl"
printf '%s\n' '{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"create_issue","arguments":{}}}' >"$single"
for p in /mcp/upstream/other /mcp/upstream/GitHub /mcp/upstream/github/ /mcp/upstream/../upstream/github; do
  gw_up_call "path-$(printf '%s' "$p" | tr -c 'A-Za-z0-9' _)" "$p" "$single" || true
done

# 3. The upstream saw no call for a hidden tool, whatever the spelling.
for t in create_issue delete_repository Create_Issue DELETE_REPOSITORY "create_issue " "cr$(printf '\xd0\xb5')ate_issue" never_existed; do
  [[ "$(gw_up_tool_hits "$t")" == 0 ]] || gw_fail "the upstream received a tools/call for '$t'"
done
[[ "$(gw_up_tool_hits list_issues)" -ge 2 ]] || gw_fail "the allowed tool never reached the upstream"

# 4. Ledger: denied events, no pending call for a hidden tool.
gw_ledger final
denied_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_call denied)"
pending_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_call pending)"
echo "ledger denied=$denied_n pending=$pending_n" >"$ARTIFACT_DIR/results.txt"
(( denied_n >= 16 )) || gw_fail "expected a denied event per refused call (at least 16), got $denied_n"
(( pending_n == 2 )) || gw_fail "expected 2 pending calls (list_issues, once per client), got $pending_n"
echo "G16 ok"
