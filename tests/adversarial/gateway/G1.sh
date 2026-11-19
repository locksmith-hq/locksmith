#!/usr/bin/env bash
# G1: environment and files. After an agent logs in and relays through the gateway (with `smith`
# and with the `locksmith-mcp` tool), everything a local agent can read about itself and the
# Locksmith processes is saved for the oracle:
#   - the agent's environment and shell variables (`env`, `set`);
#   - /proc/<pid>/environ and cmdline of `smith login --agent` (enrollment secret on stdin),
#     `smith relay`, `locksmith-mcp` (each caught while it runs), the gateway and the control
#     plane when this user can read them;
#   - the `smith` state directory (agent HOME and LOCKSMITH_HOME, kept under ARTIFACT_DIR/agent)
#     and the agent's shell history after it ran `smith` commands in an interactive shell.
# run.sh scans all of it for the canary. This case also scans it for the enrollment secret
# (whose random part is used as a second canary), after checking on a private copy that the
# oracle does find the enrollment secret.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$api"
P="$ARTIFACT_DIR/proc"
mkdir -p "$P"

# gw_find_pid ANCESTOR BIN: the pid of the process below ANCESTOR (inclusive) running BIN,
# polled until it has exec'd.
gw_find_pid() {
  local root="$1" bin="$2" i p q exe
  bin="$(readlink -f "$bin")"
  for i in $(seq 1 200); do
    for p in "$root" $(pgrep -P "$root" 2>/dev/null || true); do
      for q in "$p" $(pgrep -P "$p" 2>/dev/null || true); do
        exe="$(readlink -f "/proc/$q/exe" 2>/dev/null || true)"
        if [[ "$exe" == "$bin" ]]; then
          echo "$q"
          return 0
        fi
      done
    done
    sleep 0.05
  done
  return 1
}

# dump_proc NAME PID: environ, cmdline and status of PID to proc/NAME.*.
dump_proc() {
  local name="$1" pid="$2" f
  for f in environ cmdline status; do
    cat "/proc/$pid/$f" >"$P/$name.$f" 2>/dev/null || gw_fail "cannot read /proc/$pid/$f ($name)"
  done
  tr '\0' '\n' <"$P/$name.environ" >"$P/$name.environ.txt" || true
  tr '\0' ' ' <"$P/$name.cmdline" >"$P/$name.cmdline.txt" || true
}

# dump_proc_private NAME PID: for processes that inherit the operator's environment (the gateway,
# the control plane), which holds real credentials: the full files go to GW_WORK (scanned below,
# never kept) and only variable names, cmdline and status reach the artifacts.
dump_proc_private() {
  local name="$1" pid="$2" f
  mkdir -p "$GW_WORK/privproc"
  for f in environ cmdline status; do
    cat "/proc/$pid/$f" >"$GW_WORK/privproc/$name.$f" 2>/dev/null || gw_fail "cannot read /proc/$pid/$f ($name)"
  done
  tr '\0' '\n' <"$GW_WORK/privproc/$name.environ" | sed 's/=.*//' >"$P/$name.environ-names.txt"
  tr '\0' ' ' <"$GW_WORK/privproc/$name.cmdline" >"$P/$name.cmdline.txt"
  cp "$GW_WORK/privproc/$name.status" "$P/$name.status"
}

# 1. A second login with the enrollment secret on stdin (the documented non-env path): catch the
# process while it waits for stdin.
mkfifo "$GW_WORK/login.in"
gw_smith login2 login --agent <"$GW_WORK/login.in" &
bg=$!
exec 3>"$GW_WORK/login.in"
pid="$(gw_find_pid "$bg" "$GW_SMITH_BIN")" || gw_fail "smith login did not start"
dump_proc smith-login "$pid"
cat "$GW_ENROLLMENT_FILE" >&3
printf '\n' >&3
exec 3>&-
wait "$bg" || gw_fail "smith login --agent with stdin failed (see smith-login2.err)"

# 2. `smith relay` with the body on stdin: catch it while it waits for the body.
mkfifo "$GW_WORK/relay.in"
gw_smith relay relay --secret-id "$GW_SECRET_ID" -X POST --data-stdin --show all "$api/g1/relay" \
  <"$GW_WORK/relay.in" &
bg=$!
exec 3>"$GW_WORK/relay.in"
pid="$(gw_find_pid "$bg" "$GW_SMITH_BIN")" || gw_fail "smith relay did not start"
dump_proc smith-relay "$pid"
printf 'g1 body\n' >&3
exec 3>&-
wait "$bg" || gw_fail "smith relay failed (see smith-relay.err)"
grep -q '^HTTP 200' "$ARTIFACT_DIR/smith-relay.out" || gw_fail "smith relay did not get 200"

# 3. locksmith-mcp: initialize, then relay_request; catch the server while it runs.
mkfifo "$GW_WORK/mcp.in"
gw_agent "$GW_MCP_BIN" <"$GW_WORK/mcp.in" >"$ARTIFACT_DIR/mcp-relay.out" 2>"$ARTIFACT_DIR/mcp-relay.err" &
bg=$!
exec 3>"$GW_WORK/mcp.in"
pid="$(gw_find_pid "$bg" "$GW_MCP_BIN")" || gw_fail "locksmith-mcp did not start"
{
  printf '%s\n' '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"adversarial","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_grants","arguments":{}}}\n'
  printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"relay_request","arguments":{"secret_id":"%s","url":"%s/g1/mcp"}}}\n' \
    "$GW_SECRET_ID" "$api"
} >&3
for _ in $(seq 1 300); do
  grep -q '"id":2' "$ARTIFACT_DIR/mcp-relay.out" 2>/dev/null && break
  sleep 0.1
done
dump_proc locksmith-mcp "$pid"
exec 3>&-
wait "$bg" || true
grep -q '"id":2' "$ARTIFACT_DIR/mcp-relay.out" || gw_fail "locksmith-mcp gave no relay_request reply"
grep -q 'REDACTED' "$ARTIFACT_DIR/mcp-relay.out" || gw_fail "relay_request reply shows no redaction (did the relay reach the provider?)"
gw_unwrap "$ARTIFACT_DIR/mcp-relay.out"

# The provider got the key, in the bound header only, for both relays.
n="$(grep -c 'key=ok where=authorization$' "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$n" -ge 2 ]] || gw_fail "the provider did not receive the key in the bound header for both relays ($n)"

# 4. The gateway and the control plane, after they served the relays.
dump_proc_private gateway "$GW_GATEWAY_PID"
for pid in $(pgrep -x locksmith-api 2>/dev/null || true); do
  [[ -r "/proc/$pid/environ" ]] && dump_proc_private "locksmith-api-$pid" "$pid"
done

# 5. The agent's own environment and shell, and an interactive shell whose history is saved.
gw_agent env >"$ARTIFACT_DIR/agent-env.txt" 2>&1
gw_agent bash --norc --noprofile -c set >"$ARTIFACT_DIR/agent-set.txt" 2>&1
GW_SMITH_DIR="$(dirname "$GW_SMITH_BIN")"
gw_agent bash --norc --noprofile -i >"$ARTIFACT_DIR/agent-shell.out" 2>"$ARTIFACT_DIR/agent-shell.err" <<EOF
export PATH="$GW_SMITH_DIR:\$PATH"
smith grants
smith --json relay --secret-id $GW_SECRET_ID $api/g1/shell
env | sort
cat \$LOCKSMITH_HOME/agent.json >/dev/null
exit
EOF
[[ -s "$GW_AGENT_HOME/.bash_history" ]] || gw_fail "the agent shell wrote no history"
gw_unwrap "$ARTIFACT_DIR/agent-shell.out"

# 6. The state directory listing (the files themselves are already under ARTIFACT_DIR/agent).
ls -laR "$GW_AGENT_HOME" >"$ARTIFACT_DIR/agent-ls.txt" 2>&1
mode="$(stat -c '%a' "$GW_AGENT_HOME/agent.json")"
[[ "$mode" == 600 ]] || gw_fail "agent.json has mode $mode, expected 600"

# 7. The enrollment secret: lse_ + base64url(org(16) || agent(16) || random(32)). Its random
# part, as a canary, appears in the enrollment text at base64 offset 2; the oracle finds it in
# every encoding it knows. A private copy proves the detection before the real scan.
python3 -I -c '
import base64, sys
t = open(sys.argv[1]).read().strip()
assert t.startswith("lse_")
raw = base64.urlsafe_b64decode(t[4:] + "=" * (-len(t[4:]) % 4))
assert len(raw) == 64
with open(sys.argv[2], "w") as fh:
    fh.write(base64.urlsafe_b64encode(raw[32:]).rstrip(b"=").decode() + "\n")
' "$GW_ENROLLMENT_FILE" "$GW_WORK/enrollment.canary"
mkdir -p "$GW_WORK/enroll-probe"
{ echo "LOCKSMITH_ENROLLMENT_SECRET=$(<"$GW_ENROLLMENT_FILE")"; } >"$GW_WORK/enroll-probe/env.txt"
if python3 -I "$GW_ROOT/tests/kit/oracle.py" scan --canary-file "$GW_WORK/enrollment.canary" \
  "$GW_WORK/enroll-probe" >"$GW_WORK/enroll-probe.scan" 2>&1; then
  gw_fail "the enrollment check cannot see a planted enrollment secret"
fi
for cf in "$CANARY_FILE" "$GW_WORK/enrollment.canary"; do
  if python3 -I "$GW_ROOT/tests/kit/oracle.py" scan --canary-file "$cf" "$GW_WORK/privproc" \
    >"$GW_WORK/privproc.scan" 2>&1; then :; else
    gw_fail "a secret is in the gateway or control plane process files (not kept)"
  fi
done
rc=0
python3 -I "$GW_ROOT/tests/kit/oracle.py" scan --canary-file "$GW_WORK/enrollment.canary" \
  "$ARTIFACT_DIR" >"$ARTIFACT_DIR/enrollment.scan" 2>&1 || rc=$?
if [[ $rc -ne 0 ]]; then
  sed 's/^/enrollment secret: /' "$ARTIFACT_DIR/enrollment.scan" >&2
  gw_fail "the enrollment secret is in the artifacts (oracle exit $rc)"
fi
echo "G1: environment, /proc, state directory and history checked; enrollment secret not found"
