#!/usr/bin/env bash
# G10: hub MCP on the control plane (`/mcp`, change m1-remote-mcp task 6.1): value-like fields in
# the tool list, a sentinel secret in results and audit rows, and off-tool calls by name.
# The person signs in on Keycloak as the seeded dev user (scripts/mcp-e2e.py: authorization code
# + PKCE on the `locksmith-mcp` client, token audience the hub MCP URL). In that person's
# personal org the console API (a console-audience token) creates a project, an environment, a
# secret whose only version is the canary (the sentinel), an agent and a grant. Then, over
# Streamable HTTP at /mcp with the MCP token (mcp_check.py call):
#   - tool list: every input and output schema is scanned for a value-like property name or an
#     open map; the six read tools are listed, `revoke_grant` and `pause_agents` (off by default)
#     are not; result keys are scanned too;
#   - results: list_projects, list_secret_names, read_activity, list_agents, list_grants and
#     explain_block all succeed, and run.sh scans every saved reply, the decoded text and the
#     ledger export for the sentinel in every encoding;
#   - off tools by name: `revoke_grant` on the real grant, `pause_agents`, other casing, a
#     trailing space and a made-up `read_secret`: each is an error, no result; the grant is not
#     revoked (no `grant.revoked` event);
#   - ledger: one `mcp.call` event per call, layer `hub`, the attributes only layer, tool and
#     reason, `denied` for the off tools by their registry name, `unknown` for any other name.
# Skips (`skip: stack not running`) when Keycloak or the hub /mcp is not up (`just up` with the
# auth profile, `just api` with LOCKSMITH_MCP_RESOURCE_URL). The control plane's own log is not an
# artifact here: the gate's leak scan covers Loki and Postgres for the same canary.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/lib.sh"
gw_init
chk="$here/mcp_check.py"
export API_URL="$GW_API"

rc=0
why="$(python3 -I "$chk" hub-ready 2>&1)" || rc=$?
if [[ "$rc" == 3 ]]; then
  echo "skip: stack not running ($why)"
  exit 77
fi
[[ "$rc" == 0 ]] || gw_fail "hub /mcp readiness: $why"

python3 -I "$chk" console-token "$GW_WORK/console.hdr" || gw_fail "console sign-in failed"
python3 -I "$chk" hub-token "$GW_WORK/hub.hdr" || gw_fail "hub MCP sign-in failed"
python3 -I "$chk" hub-setup "$CANARY_FILE" "$GW_WORK/console.hdr" "$ARTIFACT_DIR/setup/ids.json" ||
  gw_fail "could not create the sentinel secret in the person's org"
ids() { gw_json "$ARTIFACT_DIR/setup/ids.json" "$1"; }
project="$(ids project)"
environment="$(ids environment)"
agent="$(ids agent)"
grant="$(ids grant)"

python3 -I "$chk" ledger "$GW_API" "$GW_WORK/console.hdr" "$GW_WORK/ledger-before.json" || gw_fail "ledger read failed"

req() { # req ID TOOL ARGS_JSON
  python3 -I -c '
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": sys.argv[1], "method": "tools/call",
                  "params": {"name": sys.argv[2], "arguments": json.loads(sys.argv[3])}}))
' "$1" "$2" "$3"
}
{
  echo '{"jsonrpc":"2.0","id":"list","method":"tools/list"}'
  req projects list_projects '{}'
  req names list_secret_names "{\"project_id\":\"$project\",\"environment_id\":\"$environment\"}"
  req activity read_activity '{}'
  req agents list_agents '{}'
  req grants list_grants "{\"agent_id\":\"$agent\"}"
  req explain explain_block '{"reason":"no_grant"}'
  req off1 revoke_grant "{\"grant_id\":\"$grant\"}"
  req off2 pause_agents '{}'
  req off3 pause_agents "{\"agent_ids\":[\"$agent\"]}"
  req off4 REVOKE_GRANT "{\"grant_id\":\"$grant\"}"
  req off5 "revoke_grant " "{\"grant_id\":\"$grant\"}"
  req off6 read_secret "{\"secret_id\":\"$(ids secret)\",\"version\":1}"
  req off7 get_secret_value "{\"secret_id\":\"$(ids secret)\"}"
} >"$GW_WORK/hub.jsonl"
python3 -I "$chk" call "$GW_API" "$GW_WORK/hub.hdr" "$GW_WORK/hub.jsonl" "$ARTIFACT_DIR/mcp-hub" ||
  gw_fail "hub MCP session failed (see mcp-hub.out)"

python3 -I "$chk" scan-tools "$ARTIFACT_DIR/mcp-hub.out" \
  --present list_projects --present list_secret_names --present read_activity \
  --present list_agents --present list_grants --present explain_block \
  --absent revoke_grant --absent pause_agents >"$ARTIFACT_DIR/tools.txt" || gw_fail "tool list scan failed"
python3 -I "$chk" scan-keys "$ARTIFACT_DIR/mcp-hub.out" >>"$ARTIFACT_DIR/tools.txt" ||
  gw_fail "a tool result carries a value-like key"

python3 -I - "$ARTIFACT_DIR/mcp-hub.out" <<'PY' || gw_fail "unexpected MCP replies (see mcp-hub.out)"
import json, sys
replies = {}
for line in open(sys.argv[1]):
    if line.strip():
        m = json.loads(line)
        replies[str(m.get("id"))] = m

def failed(m):
    return m is None or "error" in m or bool((m.get("result") or {}).get("isError"))

def text(m):
    r = (m or {}).get("result") or {}
    return "".join(c.get("text", "") for c in r.get("content", []) if isinstance(c, dict))

for i in ("projects", "names", "activity", "agents", "grants"):
    if failed(replies.get(i)):
        sys.exit("call %s did not succeed" % i)
# explain_block answers from the static table: the rule, no error.
if failed(replies.get("explain")) or "no_grant" not in text(replies.get("explain")):
    sys.exit("explain_block did not explain no_grant")
for i in ("off1", "off2", "off3", "off4", "off5", "off6", "off7"):
    m = replies.get(i)
    if not failed(m):
        sys.exit("off-tool call %s was not refused" % i)
    if "structuredContent" in (m.get("result") or {}):
        sys.exit("off-tool call %s returned a result" % i)
print("replies ok")
PY

# The ledger, as the person: new mcp.call events since the snapshot, names and outcomes only.
sleep 1
python3 -I "$chk" ledger "$GW_API" "$GW_WORK/console.hdr" "$ARTIFACT_DIR/ledger-after.json" || gw_fail "ledger read failed"
python3 -I - "$GW_WORK/ledger-before.json" "$ARTIFACT_DIR/ledger-after.json" "$ARTIFACT_DIR/ledger-summary.txt" <<'PY' || gw_fail "ledger check failed (see ledger-summary.txt)"
import json, sys
before, after, out = sys.argv[1:4]
seen = {e["id"] for e in json.load(open(before))}
new = [e for e in json.load(open(after)) if e["id"] not in seen]
if any(e["kind"] == "grant.revoked" for e in new):
    sys.exit("an off tool revoked the grant")
registry = {"list_projects", "list_secret_names", "read_activity", "list_agents", "list_grants",
            "explain_block", "revoke_grant", "pause_agents"}
by = {}
for e in new:
    if e["kind"] != "mcp.call":
        continue
    attrs = {k: (v.get("code") if isinstance(v, dict) else v) for k, v in (e.get("attrs") or {}).items()}
    extra = set(attrs) - {"layer", "tool", "reason"}
    if extra:
        sys.exit("mcp.call carries unexpected attributes: %s" % sorted(extra))
    if attrs.get("layer") != "hub":
        sys.exit("mcp.call layer is %r" % attrs.get("layer"))
    tool = attrs.get("tool")
    if tool not in registry and tool != "unknown":
        sys.exit("mcp.call names %r (a registry name or unknown only)" % tool)
    by[(tool, e["outcome"])] = by.get((tool, e["outcome"]), 0) + 1
open(out, "w").write("".join("%s %s %d\n" % (t, o, n) for (t, o), n in sorted(by.items())))
if by.get(("explain_block", "ok"), 0) < 1:
    sys.exit("no ok mcp.call for explain_block")
for t in ("list_projects", "list_secret_names", "read_activity", "list_agents", "list_grants"):
    if by.get((t, "ok"), 0) < 1:
        sys.exit("no ok mcp.call for %s" % t)
if by.get(("revoke_grant", "denied"), 0) < 1 or by.get(("pause_agents", "denied"), 0) < 2:
    sys.exit("denied mcp.call events for the off tools are missing")
if by.get(("unknown", "denied"), 0) < 3:
    sys.exit("fewer than 3 denied mcp.call events for unknown tool names")
PY
echo "G10 ok"
