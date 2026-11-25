#!/usr/bin/env bash
# G15: an upstream MCP server that reflects the credential it was sent (M2 task 7.1). The upstream
# credential is the case canary (a bound `mcp_upstream`, header `Authorization: Bearer {secret}`);
# the fixture runs in `echo-credential` mode: it puts the credential it received into a tool
# result (text, structured content, an error result, the base64, hex and JSON-nested forms), into
# the description of a listed tool, and into a JSON-RPC error. The agent probes the gateway two
# ways, through `smith mcp bridge github` and with its own HTTP client (curl-like, the agent token
# only) on `/mcp/upstream/github`:
#   - every tool of the list (`list_issues`, `create_issue` (an isError result), `echo`) and an
#     unknown name (the upstream's own error would quote the credential);
#   - the oracle scans every reply, the bridge output, the agent HOME, the gateway log and the
#     ledger for the canary and its encodings;
#   - the case asserts the fixture's private log received the canary (so the probes really made
#     the upstream reflect it) and that the ledger holds a `mcp.upstream_call` / `mcp.upstream_outcome`
#     pair per allowed call.
# Skips when the stack is down.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
. "$(dirname "${BASH_SOURCE[0]}")/upstream_lib.sh"
gw_init

GW_UP_TOOLS='list_issues = "allow"
create_issue = "allow"
echo = "allow"
delete_repository = "deny"'
gw_up_start echo-credential
gw_up_setup

calls="$GW_WORK/calls.jsonl"
cat >"$calls" <<'JSON'
{"jsonrpc":"2.0","id":"list","method":"tools/list"}
{"jsonrpc":"2.0","id":"issues","method":"tools/call","params":{"name":"list_issues","arguments":{}}}
{"jsonrpc":"2.0","id":"create","method":"tools/call","params":{"name":"create_issue","arguments":{"title":"x"}}}
{"jsonrpc":"2.0","id":"echo","method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}
{"jsonrpc":"2.0","id":"unknown","method":"tools/call","params":{"name":"nope","arguments":{}}}
{"jsonrpc":"2.0","id":"denied","method":"tools/call","params":{"name":"delete_repository","arguments":{}}}
JSON

# 1. Through the bridge (an agent's MCP client).
gw_up_bridge bridge "$calls" || gw_fail "smith mcp bridge failed (see bridge-bridge.err)"
for id in list issues create echo; do
  [[ "$(python3 -I "$(dirname "${BASH_SOURCE[0]}")/mcp_up.py" outcome "$ARTIFACT_DIR/bridge-bridge.out" "$id")" != none ]] ||
    gw_fail "bridge: no reply for $id"
done
[[ "$(python3 -I "$(dirname "${BASH_SOURCE[0]}")/mcp_up.py" outcome "$ARTIFACT_DIR/bridge-bridge.out" unknown)" == error:* ]] ||
  gw_fail "bridge: the unknown tool was not an error"

# 2. With the agent's own HTTP client.
gw_up_call curl /mcp/upstream/github "$calls" || gw_fail "the direct client could not initialize (see up-curl.err)"
python3 -I "$(dirname "${BASH_SOURCE[0]}")/mcp_up.py" tools "$ARTIFACT_DIR/up-curl.out" list >"$GW_WORK/curl-tools.txt"
grep -qx echo "$GW_WORK/curl-tools.txt" || gw_fail "curl: tools/list does not list echo"

# 3. The upstream reflected the credential (so the probes were real): its private log holds it.
if ! grep -qF -- "$(<"$CANARY_FILE")" "$GW_UP_LOG"; then
  gw_fail "the upstream never received the credential (the gateway injected nothing)"
fi
[[ "$(gw_up_tool_hits delete_repository)" == 0 ]] || gw_fail "a denied tool reached the upstream"
[[ "$(gw_up_tool_hits nope)" == 0 ]] || gw_fail "an unknown tool reached the upstream"

# 4. Ledger: a call/outcome pair per allowed call, a denied event for the refusals.
gw_ledger final
calls_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_call pending)"
ok_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_outcome ok)"
denied_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_call denied)"
echo "ledger pending=$calls_n ok=$ok_n denied=$denied_n" >"$ARTIFACT_DIR/results.txt"
(( calls_n >= 6 )) || gw_fail "expected at least 6 pending upstream calls (3 tools, two clients), got $calls_n"
(( ok_n >= 6 )) || gw_fail "expected at least 6 ok outcomes, got $ok_n"
(( denied_n >= 2 )) || gw_fail "expected denied events for the unknown and denied tools, got $denied_n"
echo "G15 ok"
