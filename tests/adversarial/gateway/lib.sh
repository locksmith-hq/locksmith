# shellcheck shell=bash
# Shared setup for the gateway cases (tests/adversarial/gateway/G*.sh), sourced after
# `set -euo pipefail`. A case acts only through what an agent can reach; this file plays the
# operator. Typical use:
#
#   . "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
#   gw_init                  # case contract checks; exit 77 `skip: stack not running`
#   gw_setup [origin]        # org, canary secret, binding, agent, grant; gateway; smith login
#   gw_smith relay relay --secret-id "$GW_SECRET_ID" "$url"
#
# Everything a case receives goes under ARTIFACT_DIR (the oracle scans it):
#   setup/       control-plane responses to the operator calls (enrollment secret masked)
#   agent/       the agent's HOME and LOCKSMITH_HOME (the smith state directory)
#   smith-<name>.out / .err   each gw_smith call
#   gateway.log  the gateway's stdout and stderr
# Private files (the version request body that holds the canary, the enrollment secret, the
# bindings file) go to GW_WORK, outside ARTIFACT_DIR. Nothing here prints a secret.
#
# Environment (optional): E2E_API_URL (control plane, default http://127.0.0.1:8080),
# LOCKSMITH_GATEWAY_BIN, LOCKSMITH_SMITH_BIN, LOCKSMITH_MCP_BIN (prebuilt binaries; otherwise
# they are built with cargo), ADVERSARIAL_KEEP=1 (keep GW_WORK).

GW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GW_API="${E2E_API_URL:-http://127.0.0.1:8080}"
GW_API="${GW_API%/}"
GW_ENV_FILE="$GW_ROOT/infra/compose/.env.example"
GW_GATEWAY_PID=""
GW_EXIT_HOOKS=()
GW_N=0

gw_fail() {
  echo "${GW_CASE:-gateway} FAIL: $*" >&2
  exit 1
}

# gw_curl ARGS...: curl to the local stack, never through a proxy.
gw_curl() {
  curl --noproxy '*' -sS -m "${GW_CURL_TIMEOUT:-30}" "$@"
}

# gw_on_exit CMD: run CMD (a string, eval'd) when the case exits, before the gateway stops.
gw_on_exit() {
  GW_EXIT_HOOKS+=("$1")
}

gw_cleanup() {
  local rc=$? h
  for h in ${GW_EXIT_HOOKS[@]+"${GW_EXIT_HOOKS[@]}"}; do
    eval "$h" || true
  done
  if [[ -n "$GW_GATEWAY_PID" ]]; then
    kill "$GW_GATEWAY_PID" 2>/dev/null || true
    wait "$GW_GATEWAY_PID" 2>/dev/null || true
  fi
  if [[ -n "${GW_WORK:-}" && "${ADVERSARIAL_KEEP:-}" != 1 ]]; then
    rm -rf "$GW_WORK"
  fi
  return "$rc"
}

# gw_init: check the case contract and the stack, set up GW_WORK and the exit trap. Exits 77
# with `skip: stack not running` when the control plane, OpenBao or Postgres is not reachable.
gw_init() {
  : "${CANARY_FILE:?CANARY_FILE is required}" "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"
  GW_CASE="${GW_CASE:-$(basename "$0" .sh)}"
  umask 077
  command -v curl >/dev/null 2>&1 || { echo "skip: curl is not installed"; exit 77; }
  gw_require_stack
  # run.sh replaces HOME with a throwaway directory; keep rustup and cargo on the real home.
  local real_home
  real_home="$(eval echo "~$(id -un)")"
  export RUSTUP_HOME="${RUSTUP_HOME:-$real_home/.rustup}"
  export CARGO_HOME="${CARGO_HOME:-$real_home/.cargo}"
  export PATH="/opt/homebrew/opt/rustup/bin:$CARGO_HOME/bin:$PATH"
  # run.sh keeps its work directory with ADVERSARIAL_KEEP=1; GW_WORK sits next to ARTIFACT_DIR.
  if [[ "$ARTIFACT_DIR" == *.artifacts ]]; then
    GW_WORK="${ARTIFACT_DIR%.artifacts}.work"
    mkdir -p "$GW_WORK"
  else
    GW_WORK="$(mktemp -d)"
  fi
  trap gw_cleanup EXIT
  mkdir -p "$ARTIFACT_DIR/setup" "$ARTIFACT_DIR/agent"
}

# gw_require_stack: exit 77 unless `just up` and `just api` are running.
gw_require_stack() {
  local missing=()
  gw_curl -f -o /dev/null -m 3 "$GW_API/readyz" 2>/dev/null || missing+=("control plane at $GW_API (just api)")
  gw_curl -o /dev/null -m 3 "$(gw_env OPENBAO_ADDR)/v1/sys/health" 2>/dev/null || missing+=("OpenBao (just up)")
  (exec 3<>/dev/tcp/127.0.0.1/5432) 2>/dev/null || missing+=("Postgres (just up)")
  if [[ ${#missing[@]} -gt 0 ]]; then
    local IFS=,
    echo "skip: stack not running (${missing[*]})"
    exit 77
  fi
}

# gw_env NAME: a dev-only value from infra/compose/.env.example.
gw_env() {
  sed -n "s/^$1=//p" "$GW_ENV_FILE" | head -n 1
}

# gw_build: the gateway, smith and locksmith-mcp binaries (prebuilt ones via LOCKSMITH_*_BIN).
gw_build() {
  local bindir="${CARGO_TARGET_DIR:-$GW_ROOT/target}/debug"
  if [[ -z "${LOCKSMITH_GATEWAY_BIN:-}" || -z "${LOCKSMITH_SMITH_BIN:-}" || -z "${LOCKSMITH_MCP_BIN:-}" ]]; then
    (cd "$GW_ROOT" && cargo build -q -p ls-gateway -p smith-cli -p locksmith-mcp) ||
      gw_fail "cargo build of the gateway, smith and locksmith-mcp failed"
  fi
  GW_GATEWAY_BIN="${LOCKSMITH_GATEWAY_BIN:-$bindir/locksmith-gateway}"
  GW_SMITH_BIN="${LOCKSMITH_SMITH_BIN:-$bindir/smith}"
  GW_MCP_BIN="${LOCKSMITH_MCP_BIN:-$bindir/locksmith-mcp}"
  local b
  for b in "$GW_GATEWAY_BIN" "$GW_SMITH_BIN" "$GW_MCP_BIN"; do
    [[ -x "$b" ]] || gw_fail "missing binary $b"
  done
}

# gw_json FILE KEY[.KEY...]: print one string field of a JSON file (ids only, never values).
gw_json() {
  python3 -I -c '
import json, sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    v = v[k]
if not isinstance(v, str):
    sys.exit("not a string: " + sys.argv[2])
print(v)
' "$1" "$2"
}

# gw_cp METHOD PATH [BODY_FILE] [NAME]: call the control plane as the operator (dev org header
# when GW_ORG is set). The response body goes to ARTIFACT_DIR/setup/<n>-<NAME>.json (to GW_WORK
# instead when GW_CP_PRIVATE=1, for a response that holds a secret); sets GW_BODY and GW_STATUS.
# The body is read from a file so no value appears on a command line.
gw_cp() {
  local method="$1" path="$2" body="${3:-}" name="${4:-call}" args=() dir="$ARTIFACT_DIR/setup"
  [[ "${GW_CP_PRIVATE:-}" == 1 ]] && dir="$GW_WORK"
  GW_N=$((GW_N + 1))
  GW_BODY="$dir/$(printf '%02d' "$GW_N")-$name.json"
  args=(-X "$method" -o "$GW_BODY" -w '%{http_code}' -H 'Accept: application/json')
  [[ -n "${GW_ORG:-}" ]] && args+=(-H "X-Locksmith-Dev-Org: $GW_ORG")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  GW_STATUS="$(gw_curl "${args[@]}" "$GW_API$path")" || gw_fail "$method $path: control plane unreachable"
}

# gw_post PATH BODY_FILE NAME: POST that must return 201; prints nothing.
gw_post() {
  gw_cp POST "$1" "$2" "$3"
  [[ "$GW_STATUS" == 201 ]] || gw_fail "POST $1 returned $GW_STATUS"
}

# gw_body NAME JSON: write a request body to GW_WORK (for bodies without a secret).
gw_body() {
  printf '%s' "$2" >"$GW_WORK/$1.json"
  echo "$GW_WORK/$1.json"
}

# gw_setup [ORIGIN] [HEADER] [TEMPLATE]: create an org, a project and environment, the canary
# secret (CANARY_FILE) as a version, an agent and a grant through the control plane; bind the
# secret to ORIGIN (default the WireMock upstream, http://127.0.0.1:8089) in HEADER with TEMPLATE
# (default `Authorization: Bearer {secret}`); start a gateway for the org; log the agent in with
# `smith login --agent`. Sets GW_ORG, GW_PROJECT, GW_ENVIRONMENT, GW_SECRET_ID, GW_AGENT_ID,
# GW_GRANT_ID, GW_ENROLLMENT_FILE, GW_BINDINGS, GW_GATEWAY_URL, GW_AGENT_HOME. A case may set
# GW_BIND_FN to its own function (same arguments) that writes GW_BINDINGS instead of gw_bind.
gw_setup() {
  local origin="${1:-${E2E_WIREMOCK_URL:-http://127.0.0.1:8089}}"
  local header="${2:-Authorization}" template="${3:-}"
  [[ -n "$template" ]] || template='Bearer {secret}'
  gw_build
  GW_ORG=""
  gw_post /v1/orgs "$(gw_body org "{\"name\":\"adv-$GW_CASE-$(date +%s%N)\"}")" org
  GW_ORG="$(gw_json "$GW_BODY" id)"
  gw_post /v1/projects "$(gw_body project '{"name":"adv"}')" project
  GW_PROJECT="$(gw_json "$GW_BODY" id)"
  gw_post "/v1/projects/$GW_PROJECT/environments" "$(gw_body environment '{"name":"adv"}')" environment
  GW_ENVIRONMENT="$(gw_json "$GW_BODY" id)"
  local secrets="/v1/projects/$GW_PROJECT/environments/$GW_ENVIRONMENT/secrets"
  gw_post "$secrets" "$(gw_body secret '{"name":"UPSTREAM_KEY"}')" secret
  GW_SECRET_ID="$(gw_json "$GW_BODY" id)"
  # The only request that carries the canary: its body is written by Python straight to a 0600
  # file in GW_WORK.
  python3 -I -c '
import json, sys
v = open(sys.argv[1]).read().strip()
with open(sys.argv[2], "w") as fh:
    json.dump({"value": v}, fh)
' "$CANARY_FILE" "$GW_WORK/version.json"
  gw_post "$secrets/$GW_SECRET_ID/versions" "$GW_WORK/version.json" version
  rm -f "$GW_WORK/version.json"

  # The response holds the enrollment secret: it lands in GW_WORK, and only a masked copy goes
  # to the artifacts.
  GW_CP_PRIVATE=1 gw_post /v1/agents "$(gw_body agent "{\"name\":\"adv-agent-$GW_CASE\"}")" agent
  GW_ENROLLMENT_FILE="$GW_WORK/enrollment"
  python3 -I -c '
import json, sys
doc = json.load(open(sys.argv[1]))
with open(sys.argv[2], "w") as fh:
    fh.write(doc["enrollment_secret"])
doc["enrollment_secret"] = "<masked by lib.sh>"
with open(sys.argv[3], "w") as fh:
    json.dump(doc, fh)
' "$GW_BODY" "$GW_ENROLLMENT_FILE" "$ARTIFACT_DIR/setup/$(basename "$GW_BODY")"
  rm -f "$GW_BODY"
  GW_BODY="$ARTIFACT_DIR/setup/$(basename "$GW_BODY")"
  GW_AGENT_ID="$(gw_json "$GW_BODY" agent.id)"
  gw_post "/v1/agents/$GW_AGENT_ID/grants" "$(gw_body grant "{\"secret_id\":\"$GW_SECRET_ID\"}")" grant
  GW_GRANT_ID="$(gw_json "$GW_BODY" id)"

  "${GW_BIND_FN:-gw_bind}" "$origin" "$header" "$template"
  gw_start_gateway
  gw_login
}

# gw_bind ORIGIN HEADER TEMPLATE: write the gateway bindings file (one binding for the secret).
gw_bind() {
  GW_BINDINGS="$GW_WORK/bindings.toml"
  python3 -I -c '
import json, sys
org, sid, origin, header, template, out = sys.argv[1:7]
q = json.dumps  # a JSON string is a valid TOML basic string
with open(out, "w") as fh:
    fh.write("org_id = %s\n[[binding]]\nsecret_id = %s\norigin = %s\nheader = %s\ntemplate = %s\nallow_private_hosts = true\n"
             % (q(org), q(sid), q(origin), q(header), q(template)))
' "$GW_ORG" "$GW_SECRET_ID" "$1" "$2" "$3" "$GW_BINDINGS"
}

# gw_start_gateway: start the built gateway for GW_BINDINGS on a free loopback port, logging to
# ARTIFACT_DIR/gateway.log; wait for /readyz. Sets GW_GATEWAY_URL and GW_GATEWAY_PID. When
# GW_GATEWAY_ENV_FN names a function, it runs in the gateway's environment just before the start.
gw_start_gateway() {
  local port i
  port="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  GW_GATEWAY_URL="http://127.0.0.1:$port"
  (
    set -a
    # shellcheck disable=SC1090
    . "$GW_ENV_FILE"
    set +a
    export LOCKSMITH_GATEWAY_BIND="127.0.0.1:$port" LOCKSMITH_GATEWAY_BINDINGS="$GW_BINDINGS"
    export LOCKSMITH_CONTROL_PLANE_URL="$GW_API" OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
    # A case may export more settings (GW_GATEWAY_URL is known here), e.g. oauth_lib.sh.
    if [[ -n "${GW_GATEWAY_ENV_FN:-}" ]]; then
      "$GW_GATEWAY_ENV_FN"
    fi
    exec "$GW_GATEWAY_BIN"
  ) >>"$ARTIFACT_DIR/gateway.log" 2>&1 &
  GW_GATEWAY_PID=$!
  for i in $(seq 1 120); do
    if gw_curl -f -o /dev/null -m 2 "$GW_GATEWAY_URL/readyz" 2>/dev/null; then
      return 0
    fi
    kill -0 "$GW_GATEWAY_PID" 2>/dev/null || gw_fail "the gateway exited during start (see gateway.log)"
    sleep 0.25
  done
  gw_fail "the gateway did not become ready on $GW_GATEWAY_URL"
}

# gw_agent CMD...: run CMD as the agent: an empty environment except PATH, HOME and the
# connector settings (LOCKSMITH_HOME is the agent state directory under ARTIFACT_DIR). With
# GW_WITH_ENROLLMENT=1 the enrollment secret is on the environment, as a launcher would supply it.
gw_agent() {
  GW_AGENT_HOME="$ARTIFACT_DIR/agent"
  local path="$PATH" enroll="${GW_WITH_ENROLLMENT:-}"
  (
    local v
    while IFS= read -r v; do
      unset "$v" 2>/dev/null || true
    done < <(compgen -e)
    export PATH="$path" HOME="$GW_AGENT_HOME" LOCKSMITH_HOME="$GW_AGENT_HOME"
    export LOCKSMITH_CONTROL_PLANE_URL="$GW_API" LOCKSMITH_GATEWAY_URL="$GW_GATEWAY_URL"
    if [[ "$enroll" == 1 ]]; then
      LOCKSMITH_ENROLLMENT_SECRET="$(<"$GW_ENROLLMENT_FILE")"
      export LOCKSMITH_ENROLLMENT_SECRET
    fi
    exec "$@"
  )
}

# gw_smith NAME ARGS...: run `smith ARGS` as the agent; stdout and stderr go to
# ARTIFACT_DIR/smith-NAME.out and .err. Returns smith's exit code.
gw_smith() {
  local name="$1"
  shift
  gw_agent "$GW_SMITH_BIN" "$@" >"$ARTIFACT_DIR/smith-$name.out" 2>"$ARTIFACT_DIR/smith-$name.err"
}

# gw_login: `smith login --agent` with the enrollment secret on the environment; checks that a
# state file was written.
gw_login() {
  GW_WITH_ENROLLMENT=1 gw_smith login login --agent || gw_fail "smith login --agent failed (see smith-login.err)"
  [[ -s "$GW_AGENT_HOME/agent.json" ]] || gw_fail "smith login --agent wrote no state file"
}

# gw_fixture ROLE NAME: start fixtures/http_upstream.py as ROLE (`api`: the provider, given the
# canary so it logs whether and where the key arrived; `evil`: an attacker's host that logs every
# byte it receives). Its log is ARTIFACT_DIR/NAME-hits.log. Sets GW_FIXTURE_PORT; stopped when
# the case exits.
gw_fixture() {
  local role="$1" name="$2" pf="$GW_WORK/$2.port" pid i
  local fixture="$GW_ROOT/tests/adversarial/fixtures/http_upstream.py" args=()
  [[ "$role" == api ]] && args=("$CANARY_FILE")
  rm -f "$pf"
  : >"$ARTIFACT_DIR/$name-hits.log"
  python3 -I "$fixture" "$role" "$pf" "$ARTIFACT_DIR/$name-hits.log" ${args[@]+"${args[@]}"} \
    2>>"$ARTIFACT_DIR/$name-fixture.err" &
  pid=$!
  gw_on_exit "kill $pid 2>/dev/null; wait $pid 2>/dev/null"
  for i in $(seq 1 100); do
    [[ -s "$pf" ]] && break
    sleep 0.05
  done
  [[ -s "$pf" ]] || gw_fail "fixture $name did not start"
  GW_FIXTURE_PORT="$(<"$pf")"
}

# gw_auth_header: write `Authorization: Bearer <agent token>` (from the agent state file) to a
# private file in GW_WORK and print its path, for `curl -H @file`, so the token is never on a
# command line.
gw_auth_header() {
  python3 -I -c '
import json, sys
t = json.load(open(sys.argv[1]))["access_token"]
with open(sys.argv[2], "w") as fh:
    fh.write("Authorization: Bearer %s\n" % t)
' "$GW_AGENT_HOME/agent.json" "$GW_WORK/agent-auth.hdr"
  echo "$GW_WORK/agent-auth.hdr"
}

# gw_relay_raw NAME BODY_FILE: POST BODY_FILE to the gateway's /v1/relay with the agent's token,
# as an agent with its own HTTP client would (smith and locksmith-mcp refuse credential headers
# before they reach the gateway; this tests the gateway's own checks). The response head and body
# go to ARTIFACT_DIR/raw-NAME.hdr and .out; prints the HTTP status.
gw_relay_raw() {
  local name="$1" body="$2" auth
  auth="$(gw_auth_header)"
  gw_curl -X POST -H "@$auth" -H 'Content-Type: application/json' --data-binary "@$body" \
    -D "$ARTIFACT_DIR/raw-$name.hdr" -o "$ARTIFACT_DIR/raw-$name.out" -w '%{http_code}' \
    "$GW_GATEWAY_URL/v1/relay" 2>>"$ARTIFACT_DIR/raw-$name.err" || echo 000
}

# gw_mcp NAME TOOL_CALLS_FILE: run locksmith-mcp as the agent, send initialize and then each line
# of TOOL_CALLS_FILE (JSON-RPC requests), and save the replies to ARTIFACT_DIR/mcp-NAME.out
# (stderr to .err). Returns the server's exit code.
gw_mcp() {
  local name="$1" calls="$2"
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"adversarial","version":"0"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    cat "$calls"
  } | gw_agent "$GW_MCP_BIN" >"$ARTIFACT_DIR/mcp-$name.out" 2>"$ARTIFACT_DIR/mcp-$name.err"
}

# gw_ledger NAME: the org's audit events (every page, newest first) as the operator, to
# ARTIFACT_DIR/ledger-NAME.json (a JSON array). Sets GW_LEDGER to that path.
gw_ledger() {
  local name="$1" cursor="" page=0 q
  GW_LEDGER="$ARTIFACT_DIR/ledger-$name.json"
  rm -f "$GW_WORK"/ledger-page-*.json
  while :; do
    page=$((page + 1))
    q="limit=100"
    [[ -n "$cursor" ]] && q="$q&cursor=$cursor"
    gw_cp GET "/v1/audit/events?$q" "" "ledger-$name-$page"
    [[ "$GW_STATUS" == 200 ]] || gw_fail "GET /v1/audit/events returned $GW_STATUS"
    cp "$GW_BODY" "$GW_WORK/ledger-page-$(printf '%04d' "$page").json"
    cursor="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("next") or "")' "$GW_BODY")"
    [[ -n "$cursor" ]] || break
  done
  python3 -I -c '
import json, sys
items = []
for p in sys.argv[2:]:
    items += json.load(open(p))["items"]
json.dump(items, open(sys.argv[1], "w"), indent=1)
' "$GW_LEDGER" "$GW_WORK"/ledger-page-*.json
}

# gw_ledger_count FILE KIND [OUTCOME]: how many events of KIND (e.g. `relay.attempt`) in a
# gw_ledger file, optionally with OUTCOME, for this case's agent.
gw_ledger_count() {
  python3 -I -c '
import json, sys
f, kind, outcome, agent = sys.argv[1:5]
n = sum(1 for e in json.load(open(f))
        if e["kind"] == kind and (not outcome or e["outcome"] == outcome)
        and e["actor"] == "agent:" + agent)
print(n)
' "$1" "$2" "${3:-}" "$GW_AGENT_ID"
}

# gw_unwrap FILE...: for each saved relay reply, also write the bytes an agent gets by decoding
# it, so the oracle judges the reply as the agent can trivially read it:
#   - MCP replies (JSON-RPC lines): the `relay_request` tool result is a JSON document inside the
#     result's text, so it arrives escaped twice. Each tool result whose text is a relayed
#     response goes to FILE-<id>.view (FILE without .out): `HTTP <status>`, the header lines
#     `name: value`, a blank line and the body bytes (`body` as UTF-8, or `body_base64` decoded),
#     the same layout as `smith relay --show all`. A refusal (isError) gets a view of its text.
#   - anything else (smith --json output, a raw /v1/relay response): the decoded `body_base64`
#     bytes go to FILE.body.
gw_unwrap() {
  python3 -I - "$@" <<'PY'
import base64, json, sys

def b64(b):
    try:
        return base64.b64decode(b)
    except ValueError:
        return None

def walk(v, out):
    if isinstance(v, dict):
        b = v.get("body_base64")
        if isinstance(b, str):
            d = b64(b)
            if d is not None:
                out.append(d)
        for x in v.values():
            walk(x, out)
    elif isinstance(v, list):
        for x in v:
            walk(x, out)
    elif isinstance(v, str) and "body_base64" in v:
        try:
            walk(json.loads(v), out)
        except ValueError:
            pass

def view(text):
    """The bytes an agent reads from one MCP tool result's text."""
    try:
        doc = json.loads(text)
    except ValueError:
        return text.encode("utf-8", "surrogatepass")
    if not isinstance(doc, dict) or "status" not in doc:
        return text.encode("utf-8", "surrogatepass")
    lines = [b"HTTP %s" % str(doc.get("status")).encode()]
    hdrs = doc.get("headers") or []
    if isinstance(hdrs, dict):
        hdrs = list(hdrs.items())
    for h in hdrs:
        if isinstance(h, (list, tuple)) and len(h) == 2:
            lines.append(("%s: %s" % (h[0], h[1])).encode("utf-8", "surrogatepass"))
    body = b""
    if isinstance(doc.get("body"), str):
        body = doc["body"].encode("utf-8", "surrogatepass")
    elif isinstance(doc.get("body_base64"), str):
        body = b64(doc["body_base64"]) or b""
    return b"\n".join(lines) + b"\n\n" + body

def mcp_result(msg):
    r = msg.get("result") if isinstance(msg, dict) else None
    if not isinstance(r, dict) or not isinstance(r.get("content"), list):
        return None
    return "".join(c.get("text", "") for c in r["content"] if isinstance(c, dict))

for p in sys.argv[1:]:
    out = []
    try:
        text = open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    try:
        docs = [json.loads(text)]
    except ValueError:
        docs = []
        for line in text.splitlines():
            try:
                docs.append(json.loads(line))
            except ValueError:
                pass
    stem = p[:-4] if p.endswith(".out") else p
    for d in docs:
        t = mcp_result(d)
        if t is not None and "id" in d:
            with open("%s-%s.view" % (stem, d["id"]), "wb") as fh:
                fh.write(view(t))
        else:
            walk(d, out)
    if out:
        with open(p + ".body", "wb") as fh:
            fh.write(b"\n".join(out))
PY
}
