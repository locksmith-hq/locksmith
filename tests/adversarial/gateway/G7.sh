#!/usr/bin/env bash
# G7: human-token abuse (T1). A human access token is an OIDC JWT from the local Keycloak, verified
# by the control plane against the issuer's JWKS. The token is minted the way `just auth-e2e` does
# (authorization code + PKCE for the seeded verified user) and only ever written to private files
# in GW_WORK, passed to curl with `-H @file`. Probes:
#   - baseline: the real token at GET /v1/projects (200) and at POST /v1/auth/sign-in (204);
#   - forged: the real token with its payload altered (sub, exp pushed out, a past `exp` with the
#     real signature kept), an unknown `kid`, a real `kid` with a garbage / truncated / empty
#     signature, `alg: none`, `alg: HS256`, a missing `kid`, two parts, an empty and a garbage
#     token: all 401 at the control plane;
#   - bad bearer plus a valid dev header: still 401 (a bad token is never downgraded to dev auth);
#   - replay: the valid token sent with another org's dev header is bound to its own org (the
#     header is ignored, org B's project is not listed); the agent's token at the human routes is
#     refused (an agent token is not a human token);
#   - dev header off: a second control plane started WITHOUT LOCKSMITH_DEV_AUTH refuses the
#     X-Locksmith-Dev-Org header (401) while the real human token still works there;
#   - human token at agent routes (the gateway's /v1/relay and /v1/grants): 401, no decrypt, the
#     provider sees nothing; and at the control plane's /internal/v1 routes: 401. The dev header
#     alone at the internal routes is refused too.
# Not testable here: a correctly signed token past its `exp` (Keycloak's token lifetime is not
# ours to shorten from a case); it is covered by unit tests in services/control-plane/src/human.rs.
# Needs Keycloak (`just up`, the `auth` profile) and `just api` (dev auth on, OIDC configured); the
# case skips with exit 77 when the issuer is not reachable.
# Checks: every refused probe is 401 and never 200; `relay.attempt` does not move for the agent;
# the provider sees no request.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

KC="${KEYCLOAK_URL:-http://localhost:8180}"
gw_curl -f -o /dev/null -m 3 "${KC%/}/realms/locksmith/.well-known/openid-configuration" 2>/dev/null || {
  echo "skip: stack not running (Keycloak at ${KC%/}, just up)"
  exit 77
}

gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$api"
mkdir -p "$GW_WORK/tok"
: >"$ARTIFACT_DIR/results.txt"

# Mint a human token for the seeded verified user, reusing scripts/auth-e2e.py's sign-in (no
# password grant). The header file holds the token; nothing is printed.
KEYCLOAK_URL="$KC" python3 -I - "$GW_ROOT/scripts/auth-e2e.py" "$GW_WORK/tok" <<'PY'
import base64, importlib.util, json, os, sys
sys.dont_write_bytecode = True  # scripts/__pycache__ holds a tracked .pyc
os.environ["no_proxy"] = os.environ["NO_PROXY"] = "*"
for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(k, None)
spec = importlib.util.spec_from_file_location("auth_e2e", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
out = sys.argv[2]
tok, _ = m.sign_in(*m.SEEDED_OK)
if not tok:
    sys.exit("no human token for the seeded user")
h, p, s = tok.split(".")
def d(x): return json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
def e(o): return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
hd, pl = d(h), d(p)
def put(name, token):
    with open(os.path.join(out, name + ".hdr"), "w") as fh:
        fh.write("Authorization: Bearer %s\n" % token)
put("real", tok)
far = 4102444800
put("payload-sub", ".".join([h, e({**pl, "sub": "0" * 8 + "-0000-0000-0000-" + "0" * 12}), s]))
put("payload-email", ".".join([h, e({**pl, "email": "admin@locksmith.test", "email_verified": True}), s]))
put("payload-exp-far", ".".join([h, e({**pl, "exp": far}), s]))
put("payload-exp-past", ".".join([h, e({**pl, "exp": 1000000000}), s]))
put("kid-unknown", ".".join([e({**hd, "kid": "no-such-key"}), p, s]))
put("kid-garbage-sig", ".".join([h, p, "A" * len(s)]))
put("sig-truncated", ".".join([h, p, s[: len(s) // 2]]))
put("sig-empty", ".".join([h, p, ""]))
put("alg-none", ".".join([e({**hd, "alg": "none"}), p, ""]))
put("alg-none-sig", ".".join([e({**hd, "alg": "none"}), p, s]))
put("alg-hs256", ".".join([e({**hd, "alg": "HS256"}), p, s]))
put("kid-missing", ".".join([e({k: v for k, v in hd.items() if k != "kid"}), p, s]))
put("two-parts", h + "." + p)
put("empty", "")
put("garbage", "not-a-jwt")
PY
[[ -s "$GW_WORK/tok/real.hdr" ]] || gw_fail "could not mint a human token from Keycloak"

# cp_status NAME METHOD PATH [HEADER_FILE] [EXTRA_HEADER]: call the control plane at $cp_url with
# the header file (if any) and an extra `Name: value` header; prints the status.
cp_url="$GW_API"
cp_status() {
  local name="$1" method="$2" path="$3" hdr="${4:-}" extra="${5:-}"
  gw_curl -X "$method" ${hdr:+-H "@$hdr"} ${extra:+-H "$extra"} -H 'Content-Type: application/json' --data-binary '{}' \
    -o "$ARTIFACT_DIR/cp-$name.out" -w '%{http_code}' "$cp_url$path" 2>>"$ARTIFACT_DIR/cp-$name.err" || echo 000
}
expect() {
  local name="$1" got="$2" want="$3"
  echo "$name status=$got" >>"$ARTIFACT_DIR/results.txt"
  [[ "$got" == "$want" ]] || gw_fail "$name: answered $got (expected $want)"
}

# Baseline.
expect baseline-projects "$(cp_status baseline-projects GET /v1/projects "$GW_WORK/tok/real.hdr")" 200
expect baseline-sign-in "$(cp_status baseline-sign-in POST /v1/auth/sign-in "$GW_WORK/tok/real.hdr")" 204

# Forged tokens at the control plane.
for f in "$GW_WORK"/tok/*.hdr; do
  name="$(basename "$f" .hdr)"
  [[ "$name" == real ]] && continue
  expect "forged-$name" "$(cp_status "forged-$name" GET /v1/projects "$f")" 401
  expect "forged-$name-sign-in" "$(cp_status "forged-$name-si" POST /v1/auth/sign-in "$f")" 401
  # A bad bearer is not downgraded to the dev header.
  expect "forged-$name-with-dev-header" "$(cp_status "forged-$name-dev" GET /v1/projects "$f" "X-Locksmith-Dev-Org: $GW_ORG")" 401
done
printf 'Authorization: Basic %s\n' "$(printf 'a:b' | base64)" >"$GW_WORK/tok/basic.hdr"
expect scheme-basic "$(cp_status scheme-basic GET /v1/projects "$GW_WORK/tok/basic.hdr")" 401

# Replay: a valid human token with another org's dev header stays bound to the token's own org.
gw_post /v1/projects "$(gw_body project-b '{"name":"g7-org-b-marker"}')" project-b
python3 -I -c '
import json, sys
s = json.load(open(sys.argv[1]))
sys.exit(1 if "g7-org-b-marker" in json.dumps(s) else 0)
' "$ARTIFACT_DIR/cp-baseline-projects.out" || gw_fail "baseline project list holds org B's marker"
expect replay-other-org-header "$(cp_status replay-other-org GET /v1/projects "$GW_WORK/tok/real.hdr" "X-Locksmith-Dev-Org: $GW_ORG")" 200
if grep -q "g7-org-b-marker" "$ARTIFACT_DIR/cp-replay-other-org.out"; then
  gw_fail "a human token with another org's dev header listed that org's project"
fi
# The agent's token is not a human token.
auth="$(gw_auth_header)"
expect agent-token-at-projects "$(cp_status agent-projects GET /v1/projects "$auth")" 401
expect agent-token-at-sign-in "$(cp_status agent-sign-in POST /v1/auth/sign-in "$auth")" 401

# Dev header off: a second control plane without LOCKSMITH_DEV_AUTH.
off_port="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
bindir="${CARGO_TARGET_DIR:-$GW_ROOT/target}/debug"
if [[ -z "${LOCKSMITH_API_BIN:-}" ]]; then
  (cd "$GW_ROOT" && cargo build -q -p ls-control-plane --bin locksmith-api) || gw_fail "cargo build of locksmith-api failed"
fi
api_bin="${LOCKSMITH_API_BIN:-$bindir/locksmith-api}"
[[ -x "$api_bin" ]] || gw_fail "missing binary $api_bin"
(
  set -a
  # shellcheck disable=SC1090
  . "$GW_ENV_FILE"
  set +a
  unset LOCKSMITH_DEV_AUTH LOCKSMITH_ALLOW_DEV_AUTH
  export LOCKSMITH_BIND="127.0.0.1:$off_port" OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
  exec "$api_bin"
) >>"$ARTIFACT_DIR/control-plane-devoff.log" 2>&1 &
off_pid=$!
gw_on_exit "kill $off_pid 2>/dev/null; wait $off_pid 2>/dev/null"
for i in $(seq 1 120); do
  gw_curl -f -o /dev/null -m 2 "http://127.0.0.1:$off_port/readyz" 2>/dev/null && break
  kill -0 "$off_pid" 2>/dev/null || gw_fail "the dev-auth-off control plane exited during start (see control-plane-devoff.log)"
  sleep 0.25
done
gw_curl -f -o /dev/null -m 2 "http://127.0.0.1:$off_port/readyz" 2>/dev/null || gw_fail "the dev-auth-off control plane did not become ready"
cp_url="http://127.0.0.1:$off_port"
dev="X-Locksmith-Dev-Org: $GW_ORG"
expect devoff-header-projects "$(cp_status devoff-projects GET /v1/projects "" "$dev")" 401
expect devoff-header-create "$(cp_status devoff-create POST /v1/projects "" "$dev")" 401
expect devoff-header-agents "$(cp_status devoff-agents GET /v1/agents "" "$dev")" 401
expect devoff-header-audit "$(cp_status devoff-audit GET /v1/audit/events "" "$dev")" 401
expect devoff-header-internal "$(cp_status devoff-internal GET "/internal/v1/agents/$GW_AGENT_ID/grants" "" "$dev")" 401
expect devoff-header-case "$(cp_status devoff-case GET /v1/projects "" "x-locksmith-dev-org: $GW_ORG")" 401
expect devoff-no-credentials "$(cp_status devoff-none GET /v1/projects)" 401
expect devoff-human-token "$(cp_status devoff-human GET /v1/projects "$GW_WORK/tok/real.hdr")" 200
cp_url="$GW_API"

# The human token at agent routes (the gateway) and internal routes (the control plane).
printf '%s' "{\"secret_id\":\"$GW_SECRET_ID\",\"version\":1,\"method\":\"GET\",\"url\":\"$api/g7/probe\"}" >"$GW_WORK/relay.json"
gw_ledger before
attempts_before="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
gw_status() {
  local name="$1" method="$2" path="$3" hdr="$4"
  gw_curl -X "$method" -H "@$hdr" -H 'Content-Type: application/json' --data-binary "@$GW_WORK/relay.json" \
    -o "$ARTIFACT_DIR/gw-$name.out" -w '%{http_code}' "$GW_GATEWAY_URL$path" 2>>"$ARTIFACT_DIR/gw-$name.err" || echo 000
}
expect gateway-relay-human "$(gw_status relay-human POST /v1/relay "$GW_WORK/tok/real.hdr")" 401
expect gateway-grants-human "$(gw_status grants-human GET /v1/grants "$GW_WORK/tok/real.hdr")" 401
for f in payload-sub payload-exp-far alg-none kid-garbage-sig; do
  expect "gateway-relay-forged-$f" "$(gw_status "relay-$f" POST /v1/relay "$GW_WORK/tok/$f.hdr")" 401
done
for spec in "GET /internal/v1/agents/$GW_AGENT_ID/grants" \
            "GET /internal/v1/secrets/$GW_SECRET_ID/versions/1/material" \
            "POST /internal/v1/audit/events"; do
  set -- $spec
  n="internal-$(echo "$2" | tr '/' '_' | cut -c1-50)"
  expect "human-at-$1-$2" "$(cp_status "$n" "$1" "$2" "$GW_WORK/tok/real.hdr")" 401
  expect "human-and-dev-at-$1-$2" "$(cp_status "$n-dev" "$1" "$2" "$GW_WORK/tok/real.hdr" "$dev")" 401
  expect "dev-at-$1-$2" "$(cp_status "$n-devonly" "$1" "$2" "" "$dev")" 401
done

# Nothing decrypted, nothing reached the provider.
gw_ledger after
attempts_after="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
[[ "$attempts_after" == "$attempts_before" ]] || gw_fail "relay.attempt moved across refused probes: $attempts_before -> $attempts_after"
hits="$(grep -c . "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits" == 0 ]] || gw_fail "provider saw $hits requests (expected 0)"
echo "G7 ok"
