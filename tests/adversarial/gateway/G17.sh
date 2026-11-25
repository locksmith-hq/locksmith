#!/usr/bin/env bash
# G17: a credential planted in an upstream result never reaches the agent (M2 task 7.3). The
# fixture runs in `echo-credential-sse` mode: every answer is a `text/event-stream` body, and the
# credential it received (the case canary) is put into the text of a tool result, structured
# content, a tool error (`create_issue` -> isError), a listed tool's description, a JSON-RPC
# error, an SSE event of its own, and the base64, hex and JSON-nested forms. Probed through
# `smith mcp bridge github` and with the agent's own client on `/mcp/upstream/github`. The
# oracle scans every reply, the bridge output, the agent HOME, the gateway log and the ledger.
# Also: a result the redactor cannot scan (over 1 MiB, from `echo` with a large `text`) is a
# fixed error (`redaction_failed`, or `upstream_error` when a size limit trips first), no part of the body. Accepted residual encodings are listed
# in residuals.toml. Skips when the stack is down.
set -euo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
. "$here/lib.sh"
. "$here/upstream_lib.sh"
gw_init
mcp_up() { python3 -I "$here/mcp_up.py" "$@"; }

GW_UP_TOOLS='list_issues = "allow"
create_issue = "allow"
echo = "allow"'
gw_up_start echo-credential-sse
gw_up_setup

calls="$GW_WORK/calls.jsonl"
cat >"$calls" <<'JSON'
{"jsonrpc":"2.0","id":"list","method":"tools/list"}
{"jsonrpc":"2.0","id":"issues","method":"tools/call","params":{"name":"list_issues","arguments":{}}}
{"jsonrpc":"2.0","id":"create","method":"tools/call","params":{"name":"create_issue","arguments":{"title":"x"}}}
{"jsonrpc":"2.0","id":"echo","method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}
{"jsonrpc":"2.0","id":"unknown","method":"tools/call","params":{"name":"nope","arguments":{}}}
JSON
python3 -I -c '
import json
print(json.dumps({"jsonrpc":"2.0","id":"huge","method":"tools/call","params":{"name":"echo","arguments":{"text":"x"*(1536*1024)}}}))
' >"$GW_WORK/huge.jsonl"

for who in bridge curl; do
  if [[ "$who" == bridge ]]; then
    gw_up_bridge bridge "$calls" || gw_fail "smith mcp bridge failed (see bridge-bridge.err)"
    out="$ARTIFACT_DIR/bridge-bridge.out"
  else
    gw_up_call curl /mcp/upstream/github "$calls" || gw_fail "the direct client could not initialize"
    out="$ARTIFACT_DIR/up-curl.out"
  fi
  [[ "$(mcp_up outcome "$out" issues)" == ok ]] || gw_fail "$who: list_issues did not answer ok"
  [[ "$(mcp_up outcome "$out" create)" != none ]] || gw_fail "$who: no reply for the erroring tool"
  [[ "$(mcp_up outcome "$out" unknown)" == error:* ]] || gw_fail "$who: the unknown tool was not an error"
done

# The planted forms reach the upstream's log only: the fixture received the credential.
grep -qF -- "$(<"$CANARY_FILE")" "$GW_UP_LOG" || gw_fail "the upstream never received the credential"

# An unscannable result is refused with the fixed slug; nothing of the body comes back.
gw_up_call huge /mcp/upstream/github "$GW_WORK/huge.jsonl" || gw_fail "the direct client could not initialize (huge)"
huge="$(mcp_up outcome "$ARTIFACT_DIR/up-huge.out" huge)"
case "$huge" in
  # The redactor's own bound gives redaction_failed; a transport size limit (upstream_error) may trip
  # first on a body this large. Either is a fixed slug with nothing of the body.
  error:redaction_failed | error:upstream_error) ;;
  *) gw_fail "huge: expected a fixed refusal (redaction_failed), got '$huge'" ;;
esac
if grep -q 'xxxxxxxxxxxxxxxx' "$ARTIFACT_DIR/up-huge.out"; then gw_fail "huge: part of the unscannable body reached the agent"; fi

# Ledger: outcome events exist; the chain holds nothing from the results (the oracle scans it).
gw_ledger final
ok_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_outcome ok)"
err_n="$(gw_ledger_count "$GW_LEDGER" mcp.upstream_outcome error)"
echo "ledger ok=$ok_n error=$err_n" >"$ARTIFACT_DIR/results.txt"
(( ok_n >= 4 )) || gw_fail "expected ok outcomes for the allowed calls, got $ok_n"
(( err_n >= 1 )) || gw_fail "expected an error outcome for the unscannable result, got $err_n"
echo "G17 ok"
