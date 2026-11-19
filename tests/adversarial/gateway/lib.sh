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
# when GW_ORG is set). The response body goes to ARTIFACT_DIR/setup/<n>-<NAME>.json; sets GW_BODY
# and GW_STATUS. The body is read from a file so no value appears on a command line.
gw_cp() {
  local method="$1" path="$2" body="${3:-}" name="${4:-call}" args=()
  GW_N=$((GW_N + 1))
  GW_BODY="$ARTIFACT_DIR/setup/$(printf '%02d' "$GW_N")-$name.json"
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
# GW_GRANT_ID, GW_ENROLLMENT_FILE, GW_BINDINGS, GW_GATEWAY_URL, GW_AGENT_HOME.
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

  gw_post /v1/agents "$(gw_body agent "{\"name\":\"adv-agent-$GW_CASE\"}")" agent
  GW_AGENT_ID="$(gw_json "$GW_BODY" agent.id)"
  GW_ENROLLMENT_FILE="$GW_WORK/enrollment"
  # Keep the enrollment secret private; the artifact copy is masked.
  python3 -I -c '
import json, sys
doc = json.load(open(sys.argv[1]))
with open(sys.argv[2], "w") as fh:
    fh.write(doc["enrollment_secret"])
doc["enrollment_secret"] = "<masked by lib.sh>"
with open(sys.argv[1], "w") as fh:
    json.dump(doc, fh)
' "$GW_BODY" "$GW_ENROLLMENT_FILE"
  gw_post "/v1/agents/$GW_AGENT_ID/grants" "$(gw_body grant "{\"secret_id\":\"$GW_SECRET_ID\"}")" grant
  GW_GRANT_ID="$(gw_json "$GW_BODY" id)"

  gw_bind "$origin" "$header" "$template"
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
# ARTIFACT_DIR/gateway.log; wait for /readyz. Sets GW_GATEWAY_URL and GW_GATEWAY_PID.
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
