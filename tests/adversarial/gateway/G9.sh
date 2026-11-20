#!/usr/bin/env bash
# G9: agent MCP on the gateway (`/mcp`, change m1-remote-mcp task 6.1): value-like fields in the
# tool list, a sentinel secret in results, logs and audit rows, and off-tool calls by name.
# The canary is the sentinel: it is the stored value of a secret the agent holds a grant for,
# bound to fixtures/http_upstream.py, which echoes the injected credential in many forms. The
# agent speaks Streamable HTTP to the gateway's /mcp with its agent token (mcp_check.py call):
#   - tool list: every input and output schema is scanned for a value-like property name or an
#     open map (the rule of `ls_mcp_server::find_value_like_field`); `list_my_keys`,
#     `relay_http_request` and `explain_block` are listed, `issue_short_lived_credential` (off by
#     default) is not; result keys are scanned too;
#   - results: `list_my_keys`, a relay to the echoing provider and `explain_block`; the replies
#     (and the decoded relay result, via gw_unwrap), the ledger export and gateway.log are in
#     ARTIFACT_DIR, which run.sh scans for the sentinel in every encoding;
#   - off tools by name: `issue_short_lived_credential` (off by default), a hub-only tool
#     (`revoke_grant`), a made-up `get_secret_value`, and the off tool with other casing, a
#     trailing space and a path prefix: each is an error, never a result, and never a credential
#     (no `lsst_` text);
#   - switch: the operator turns `relay_http_request` off; once the cache window has passed it is
#     absent from the list and calling it by name is refused, and the provider sees no new request;
#   - ledger: one `mcp.call` event per call, layer `agent`, the attributes only layer, tool and
#     reason, a `denied` event for the off tool by its registry name, `unknown` for any other
#     name (client text never reaches the ledger).
# The control plane's own log is not an artifact here: the gate's leak scan (`just leak-scan`)
# covers Loki and Postgres for the same canary.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/lib.sh"
gw_init
chk="$here/mcp_check.py"

gw_fixture api provider
provider_port="$GW_FIXTURE_PORT"
api="http://127.0.0.1:$provider_port"
gw_setup "$api"

auth="$(gw_auth_header)"
sid="$GW_SECRET_ID"

# calls NAME: run the calls in GW_WORK/NAME.jsonl as the agent; replies in ARTIFACT_DIR/mcp-NAME.out.
calls() {
  python3 -I "$chk" call "$GW_GATEWAY_URL" "$auth" "$GW_WORK/$1.jsonl" "$ARTIFACT_DIR/mcp-$1" ||
    gw_fail "MCP session $1 failed (see mcp-$1.out)"
}
# req ID TOOL ARGS_JSON: one tools/call line.
req() {
  python3 -I -c '
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": sys.argv[1], "method": "tools/call",
                  "params": {"name": sys.argv[2], "arguments": json.loads(sys.argv[3])}}))
' "$1" "$2" "$3"
}
list_req='{"jsonrpc":"2.0","id":"list","method":"tools/list"}'

# 1. Defaults: the tool list, the read tools, a relay, and the off tools by name.
{
  echo "$list_req"
  req keys list_my_keys '{}'
  req relay relay_http_request "{\"secret_id\":\"$sid\",\"version\":1,\"method\":\"GET\",\"url\":\"$api/g9/mcp\"}"
  req explain explain_block '{"reason":"redaction_failed"}'
  req off1 issue_short_lived_credential "{\"secret_id\":\"$sid\",\"job\":\"g9\"}"
  req off2 ISSUE_SHORT_LIVED_CREDENTIAL "{\"secret_id\":\"$sid\",\"job\":\"g9\"}"
  req off3 "issue_short_lived_credential " "{\"secret_id\":\"$sid\",\"job\":\"g9\"}"
  req off4 "../issue_short_lived_credential" "{\"secret_id\":\"$sid\",\"job\":\"g9\"}"
  req off5 revoke_grant "{\"grant_id\":\"$GW_GRANT_ID\"}"
  req off6 get_secret_value "{\"secret_id\":\"$sid\"}"
  req off7 read_secret "{\"secret_id\":\"$sid\",\"version\":1}"
} >"$GW_WORK/defaults.jsonl"
calls defaults
gw_unwrap "$ARTIFACT_DIR/mcp-defaults.out"

python3 -I "$chk" scan-tools "$ARTIFACT_DIR/mcp-defaults.out" \
  --present list_my_keys --present relay_http_request --present explain_block \
  --absent issue_short_lived_credential --absent revoke_grant >"$ARTIFACT_DIR/tools.txt" ||
  gw_fail "tool list scan failed"
python3 -I "$chk" scan-keys "$ARTIFACT_DIR/mcp-defaults.out" >>"$ARTIFACT_DIR/tools.txt" ||
  gw_fail "a tool result carries a value-like key"

python3 -I - "$ARTIFACT_DIR/mcp-defaults.out" <<'PY' || gw_fail "unexpected MCP replies (see mcp-defaults.out)"
import json, sys
replies = {}
for line in open(sys.argv[1]):
    if line.strip():
        m = json.loads(line)
        replies[str(m.get("id"))] = m

def failed(m):
    """A JSON-RPC error, or a tool result flagged isError."""
    return m is None or "error" in m or bool((m.get("result") or {}).get("isError"))

def text(m):
    r = (m or {}).get("result") or {}
    return "".join(c.get("text", "") for c in r.get("content", []) if isinstance(c, dict))

for i in ("keys", "relay", "explain"):
    if failed(replies.get(i)):
        sys.exit("call %s did not succeed" % i)
for i in ("off1", "off2", "off3", "off4", "off5", "off6", "off7"):
    m = replies.get(i)
    if not failed(m):
        sys.exit("off-tool call %s was not refused" % i)
    blob = json.dumps(m)
    if "lsst_" in blob:
        sys.exit("off-tool call %s returned a credential" % i)
    if "structuredContent" in (m.get("result") or {}):
        sys.exit("off-tool call %s returned a result" % i)
print("replies ok")
PY

# The relay reached the provider once, with the key in the bound header only.
hits="$(grep -c ' /g9/' "$ARTIFACT_DIR/provider-hits.log" || true)"
good="$(grep -c ' /g9/.* key=ok where=authorization$' "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits" == 1 && "$good" == 1 ]] ||
  gw_fail "the provider saw $hits requests, $good with the key in the bound header only (expected 1, 1)"
! grep -rq 'lsst_' "$ARTIFACT_DIR"/mcp-defaults.* || gw_fail "a short-lived credential appears in the replies"

# 2. The switch: turn the relay tool off; after the cache window it is hidden and refused.
gw_cp PUT /v1/mcp/tools/agent/relay_http_request "$(gw_body switch '{"enabled":false}')" switch
[[ "$GW_STATUS" == 200 ]] || gw_fail "turning the relay tool off returned $GW_STATUS"
echo "$list_req" >"$GW_WORK/switched.jsonl"
hidden=""
for _ in $(seq 1 20); do
  calls switched
  if python3 -I "$chk" scan-tools "$ARTIFACT_DIR/mcp-switched.out" --absent relay_http_request \
    >"$ARTIFACT_DIR/tools-switched.txt" 2>/dev/null; then
    hidden=1
    break
  fi
  sleep 1
done
[[ -n "$hidden" ]] || gw_fail "relay_http_request was still listed 20 s after it was turned off"
req after relay_http_request "{\"secret_id\":\"$sid\",\"version\":1,\"method\":\"GET\",\"url\":\"$api/g9/off\"}" >"$GW_WORK/switched.jsonl"
calls switched
python3 -I - "$ARTIFACT_DIR/mcp-switched.out" <<'PY' || gw_fail "calling the off relay tool by name was not refused"
import json, sys
for line in open(sys.argv[1]):
    if line.strip():
        m = json.loads(line)
        if str(m.get("id")) == "after":
            if "error" in m or (m.get("result") or {}).get("isError"):
                sys.exit(0)
sys.exit(1)
PY
hits_after="$(grep -c ' /g9/' "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits_after" == 1 ]] || gw_fail "the provider saw $hits_after requests after the tool was turned off (expected 1)"
gw_cp PUT /v1/mcp/tools/agent/relay_http_request "$(gw_body switch-on '{"enabled":true}')" switch-on

# 3. The ledger: one mcp.call per call, names and outcomes only.
sleep 1
gw_ledger after
python3 -I - "$GW_LEDGER" "$GW_AGENT_ID" "$ARTIFACT_DIR/ledger-summary.txt" <<'PY' || gw_fail "ledger check failed (see ledger-summary.txt)"
import json, sys
path, agent, out = sys.argv[1:4]
events = [e for e in json.load(open(path)) if e["kind"] == "mcp.call" and e["actor"] == "agent:" + agent]
registry = {"list_my_keys", "relay_http_request", "explain_block", "issue_short_lived_credential"}
by = {}
for e in events:
    attrs = e.get("attrs") or {}
    extra = set(attrs) - {"layer", "tool", "reason"}
    if extra:
        sys.exit("mcp.call carries unexpected attributes: %s" % sorted(extra))
    if attrs.get("layer") != "agent":
        sys.exit("mcp.call layer is %r" % attrs.get("layer"))
    tool = attrs.get("tool")
    if tool not in registry and tool != "unknown":
        sys.exit("mcp.call names %r (a registry name or unknown only)" % tool)
    by[(tool, e["outcome"])] = by.get((tool, e["outcome"]), 0) + 1
lines = ["%s %s %d" % (t, o, n) for (t, o), n in sorted(by.items())]
open(out, "w").write("\n".join(lines) + "\n")
# Calls: 3 ok, then the off tool by its exact name (1), seven other refused names counted as
# unknown (off2..off7 = 6, plus the call after the switch is the registry name, denied).
if by.get(("issue_short_lived_credential", "denied"), 0) < 1:
    sys.exit("no denied mcp.call for issue_short_lived_credential")
if by.get(("unknown", "denied"), 0) < 6:
    sys.exit("fewer than 6 denied mcp.call events for unknown tool names")
if by.get(("relay_http_request", "denied"), 0) < 1:
    sys.exit("no denied mcp.call for the relay tool after it was turned off")
for t in ("list_my_keys", "relay_http_request", "explain_block"):
    if by.get((t, "ok"), 0) < 1:
        sys.exit("no ok mcp.call for %s" % t)
PY
echo "G9 ok"
