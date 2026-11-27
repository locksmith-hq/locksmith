# shellcheck shell=bash
# Shared setup for the upstream-MCP cases (G15-G17), sourced after lib.sh and gw_init.
#
#   gw_up_start MODE            start fixtures/mcp_upstream.py in MODE; its header log (it holds the
#                               very credential the gateway injects) is GW_WORK/mcp-up-headers.log,
#                               private, never in ARTIFACT_DIR. Sets GW_UP_PORT.
#   GW_UP_TOOLS="..."           extra lines for the [mcp_upstream.tools] table (TOML)
#   GW_UP_DEFAULT=hide          the upstream's default decision
#   gw_up_setup                 gw_setup with one `github` upstream bound to the canary secret
#   gw_up_call NAME PATH CALLS  scripted MCP client against the gateway (curl-like; own session)
#   gw_up_bridge NAME CALLS     `smith mcp bridge github` as the agent, fed CALLS (JSON-RPC lines)
#   gw_up_hits [METHOD]         how many requests the upstream received (tools/call only with METHOD)

GW_UP_DEFAULT="${GW_UP_DEFAULT:-hide}"
GW_UP_TOOLS="${GW_UP_TOOLS:-}"
GW_UP_LOG=""

gw_up_start() {
  local mode="$1" pf="$GW_WORK/mcp-up.port" pid i
  GW_UP_LOG="$GW_WORK/mcp-up-headers.log"
  : >"$GW_UP_LOG"
  rm -f "$pf"
  python3 -I "$GW_ROOT/tests/adversarial/fixtures/mcp_upstream.py" "$mode" "$pf" "$GW_UP_LOG" \
    2>>"$ARTIFACT_DIR/mcp-up-fixture.err" &
  pid=$!
  gw_on_exit "kill $pid 2>/dev/null; wait $pid 2>/dev/null"
  for i in $(seq 1 100); do
    [[ -s "$pf" ]] && break
    sleep 0.05
  done
  [[ -s "$pf" ]] || gw_fail "the upstream MCP fixture did not start"
  GW_UP_PORT="$(<"$pf")"
}

gw_up_bind() {
  GW_BINDINGS="$GW_WORK/bindings.toml"
  {
    printf 'org_id = "%s"\n' "$GW_ORG"
    printf '[[mcp_upstream]]\nname = "github"\nurl = "http://127.0.0.1:%s/mcp"\nsecret_id = "%s"\n' "$GW_UP_PORT" "$GW_SECRET_ID"
    printf 'header = "Authorization"\ntemplate = "Bearer {secret}"\nallow_private_hosts = true\ndefault = "%s"\n' "$GW_UP_DEFAULT"
    printf '[mcp_upstream.tools]\n%s\n' "$GW_UP_TOOLS"
  } >"$GW_BINDINGS"
}

gw_up_setup() {
  GW_BIND_FN=gw_up_bind
  gw_setup
}

# gw_up_call NAME PATH CALLS_FILE: replies to ARTIFACT_DIR/up-NAME.out, statuses to .http.
gw_up_call() {
  local name="$1" path="$2" calls="$3" auth
  auth="$(gw_auth_header)"
  python3 -I "$GW_ROOT/tests/adversarial/gateway/mcp_up.py" call "$GW_GATEWAY_URL" "$auth" "$path" "$calls" \
    "$ARTIFACT_DIR/up-$name" 2>>"$ARTIFACT_DIR/up-$name.err"
}

# gw_up_bridge NAME CALLS_FILE: replies to ARTIFACT_DIR/bridge-NAME.out (stderr to .err).
gw_up_bridge() {
  local name="$1" calls="$2"
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"adversarial","version":"0"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    cat "$calls"
  } | gw_agent "$GW_SMITH_BIN" mcp bridge github >"$ARTIFACT_DIR/bridge-$name.out" 2>"$ARTIFACT_DIR/bridge-$name.err"
}

# gw_up_hits [tools/call]: requests the upstream received; with an argument, its tools/call ones.
# gw_up_tool_hits TOOL: tools/call requests for TOOL.
gw_up_hits() {
  python3 -I -c '
import json, sys
n = 0
for line in open(sys.argv[1]):
    if sys.argv[2] == "all" or json.loads(line).get("rpc") == "tools/call":
        n += 1
print(n)
' "$GW_UP_LOG" "${1:-all}"
}

gw_up_tool_hits() {
  python3 -I -c '
import json, sys
print(sum(1 for l in open(sys.argv[1]) if json.loads(l).get("tool") == sys.argv[2]))
' "$GW_UP_LOG" "$1"
}
