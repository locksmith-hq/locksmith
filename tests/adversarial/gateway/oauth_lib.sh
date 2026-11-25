# shellcheck shell=bash
# Shared setup for the OAuth connection cases (G13, G14; change c1-oauth-connections group 7) and
# live.sh's `oauth` prompt, sourced after lib.sh and gw_init. Typical use:
#
#   oa_start                 # provider stub + human issuer (fixtures/oauth_provider.py)
#   gw_setup                 # lib.sh: the gateway starts with OAuth on (oa_gateway_env)
#   oa_people                # alice and bob in GW_ORG, with human tokens from the stub issuer
#   oa_connect alice c1 '{"provider":"mock","return_to":"'"$OA_RETURN_TO"'"}'
#   oa_consent c1 && oa_callback c1 "$OA_CB"     # the browser's part; OA_RESULT, OA_RFLOW
#   oa_confirm alice "$OA_RFLOW" c1              # OA_CONN on 200
#   oa_grant "$OA_CONN"                          # the person's grant for GW_AGENT_ID
#
# The stub is both the people's issuer (the gateway verifies their tokens with its JWKS) and the
# third-party provider: the gateway's dev-only `mock` registry entry is pointed at it through
# LOCKSMITH_OAUTH_MOCK_ISSUER, so the gateway's own OAuth endpoints, client, vault and relay run
# unchanged. The provider issues the case canary as access and refresh token.
#
# The operator's database writes (the two people, the connection grant, read-only checks) go
# through psql as the compose bootstrap user, because the NestJS routes that create grants
# (task 6.1) are not in this stack. Responses go to ARTIFACT_DIR/oauth-<name>.* (the oracle scans
# them); human tokens, codes and callback URLs stay in GW_WORK.

OA_FIXTURE="$GW_ROOT/tests/adversarial/fixtures/oauth_provider.py"
OA_AUDIENCE=locksmith-api
OA_CONSOLE=http://localhost:5173
OA_RETURN_TO="$OA_CONSOLE/settings/connections"

# oa_psql ARGS...: psql as the compose bootstrap user (operator checks only).
oa_psql() {
  PGCONNECT_TIMEOUT=5 psql "$(gw_env DATABASE_OWNER_URL)" -X -q -v ON_ERROR_STOP=1 -At "$@"
}

# oa_start: the provider stub on a free port; GW_GATEWAY_ENV_FN turns OAuth on in the gateway that
# gw_setup starts. Sets OA_BASE, OA_ISSUER (the provider realm), OA_IDP (the people's issuer),
# OA_HOST (the provider's only API host), OA_HITS (its request log) and OA_MODE_FILE.
oa_start() {
  command -v psql >/dev/null 2>&1 || { echo "skip: psql is not installed"; exit 77; }
  command -v openssl >/dev/null 2>&1 || { echo "skip: openssl is not installed"; exit 77; }
  python3 -I "$OA_FIXTURE" keygen "$GW_WORK/idp" || gw_fail "oauth_provider.py keygen failed"
  OA_MODE_FILE="$GW_WORK/oauth.mode"
  echo normal >"$OA_MODE_FILE"
  gw_env LOCKSMITH_OAUTH_MOCK_CLIENT_SECRET >"$GW_WORK/oauth-client.secret"
  OA_HITS="$ARTIFACT_DIR/oauth-provider-hits.log"
  : >"$OA_HITS"
  local pf="$GW_WORK/oauth.port" pid i
  rm -f "$pf"
  python3 -I "$OA_FIXTURE" serve "$pf" "$OA_HITS" "$OA_MODE_FILE" "$CANARY_FILE" "$GW_WORK/idp" \
    "$(gw_env LOCKSMITH_OAUTH_MOCK_CLIENT_ID)" "$GW_WORK/oauth-client.secret" \
    2>>"$ARTIFACT_DIR/oauth-provider.err" &
  pid=$!
  gw_on_exit "kill $pid 2>/dev/null; wait $pid 2>/dev/null"
  for i in $(seq 1 100); do
    [[ -s "$pf" ]] && break
    sleep 0.05
  done
  [[ -s "$pf" ]] || gw_fail "the OAuth provider stub did not start"
  OA_HOST="127.0.0.1:$(<"$pf")"
  OA_BASE="http://$OA_HOST"
  OA_ISSUER="$OA_BASE/realms/provider"
  OA_IDP="$OA_BASE/idp"
  GW_GATEWAY_ENV_FN=oa_gateway_env
}

# oa_gateway_env: run by lib.sh in the gateway's environment (after .env.example is sourced).
# The gateway connects as its own role (C1 decision 7), verifies people with the stub issuer,
# enables the `mock` provider at the stub, and registers its own callback.
oa_gateway_env() {
  export DATABASE_URL="$LOCKSMITH_GATEWAY_DATABASE_URL"
  export LOCKSMITH_OIDC_ISSUER="$OA_IDP" LOCKSMITH_OIDC_AUDIENCE="$OA_AUDIENCE"
  export LOCKSMITH_OIDC_JWKS_URL="$OA_IDP/jwks"
  export LOCKSMITH_OAUTH_MOCK_ISSUER="$OA_ISSUER"
  export LOCKSMITH_GATEWAY_OAUTH_REDIRECT_URL="$GW_GATEWAY_URL/oauth/callback"
  export LOCKSMITH_GATEWAY_OAUTH_CONSOLE_ORIGINS="$OA_CONSOLE"
}

# oa_people: alice and bob, people of GW_ORG at the stub issuer (subjects unique per run), and a
# human token for each (GW_WORK/<who>.hdr). Sets OA_ALICE and OA_BOB (user ids).
oa_people() {
  local who sub id
  OA_RUN="$(python3 -I -c 'import secrets; print(secrets.token_hex(4))')"
  for who in alice bob; do
    sub="$who-$GW_CASE-$OA_RUN"
    id="$(oa_psql -v iss="$OA_IDP" -v sub="$sub" -v org="$GW_ORG" <<'SQL'
INSERT INTO users (issuer, subject, email, email_verified, personal_org_id)
VALUES (:'iss', :'sub', :'sub' || '@example.test', true, :'org') RETURNING id;
SQL
)" || gw_fail "could not create $who"
    [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || gw_fail "no user id for $who"
    python3 -I "$OA_FIXTURE" mint "$GW_WORK/idp" "$OA_IDP" "$OA_AUDIENCE" "$sub" "$GW_WORK/$who.hdr" ||
      gw_fail "could not mint a token for $who"
    printf -v "OA_${who^^}" '%s' "$id"
  done
  echo "people alice=$OA_ALICE bob=$OA_BOB" >>"$ARTIFACT_DIR/results.txt"
}

# oa_call WHO METHOD PATH NAME [BODY_JSON]: call the gateway as person WHO (`none`: no bearer)
# from the console origin. The response goes to ARTIFACT_DIR/oauth-NAME.out and .hdr; prints the
# HTTP status.
oa_call() {
  local who="$1" method="$2" path="$3" name="$4" body="${5:-}" args=()
  args=(-X "$method" -H "Origin: $OA_CONSOLE" -D "$ARTIFACT_DIR/oauth-$name.hdr"
    -o "$ARTIFACT_DIR/oauth-$name.out" -w '%{http_code}')
  [[ "$who" != none ]] && args+=(-H "@$GW_WORK/$who.hdr")
  if [[ -n "$body" ]]; then
    printf '%s' "$body" >"$GW_WORK/oa-$name.json"
    args+=(-H 'Content-Type: application/json' --data-binary "@$GW_WORK/oa-$name.json")
  fi
  gw_curl "${args[@]}" "$GW_GATEWAY_URL$path" 2>>"$ARTIFACT_DIR/oauth-$name.err" || echo 000
}

# oa_field NAME KEY: one top-level field of ARTIFACT_DIR/oauth-NAME.out ("" when absent).
oa_field() {
  python3 -I -c '
import json, sys
try:
    v = json.load(open(sys.argv[1])).get(sys.argv[2])
except (OSError, ValueError, AttributeError):
    v = None
print("" if v is None else (json.dumps(v) if isinstance(v, (bool, list, dict)) else v))
' "$ARTIFACT_DIR/oauth-$1.out" "$2"
}

# oa_param URL KEY: one query parameter of URL ("" when absent).
oa_param() {
  python3 -I -c '
import sys, urllib.parse
q = urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query, keep_blank_values=True)
print((q.get(sys.argv[2]) or [""])[0])
' "$1" "$2"
}

# oa_connect WHO NAME BODY_JSON: POST /v1/oauth/connect; sets OA_STATUS, and on 200 OA_FLOW and
# OA_AUTHORIZE (the authorize URL, also in GW_WORK/NAME.authorize). Not for `$(...)`.
oa_connect() {
  OA_STATUS="$(oa_call "$1" POST /v1/oauth/connect "$2" "$3")"
  OA_FLOW="" OA_AUTHORIZE=""
  if [[ "$OA_STATUS" == 200 ]]; then
    OA_FLOW="$(oa_field "$2" flow_id)"
    OA_AUTHORIZE="$(oa_field "$2" authorize_url)"
    printf '%s\n' "$OA_AUTHORIZE" >"$GW_WORK/$2.authorize"
  fi
}

# oa_consent NAME [AUTHORIZE_URL]: the person's browser at the provider: GET the authorize URL
# (default OA_AUTHORIZE) without following; sets OA_CB to the provider's redirect (the gateway
# callback with code and state, kept in GW_WORK only). Fails unless the provider redirected.
oa_consent() {
  local name="$1" url="${2:-$OA_AUTHORIZE}" st
  [[ "$url" == "$OA_BASE/"* ]] || gw_fail "$name: the authorize URL is not the provider's"
  st="$(gw_curl -o /dev/null -D "$GW_WORK/$name.consent.hdr" -w '%{http_code}' "$url" 2>/dev/null)" || st=000
  [[ "$st" == 302 ]] || gw_fail "$name: the provider's authorize answered $st"
  OA_CB="$(sed -n 's/^[Ll]ocation: *//p' "$GW_WORK/$name.consent.hdr" | tr -d '\r' | head -n 1)"
  printf '%s\n' "$OA_CB" >"$GW_WORK/$name.cb"
}

# oa_callback NAME URL: the browser follows the provider's redirect to the gateway callback (URL
# must be on the gateway). The answer's head goes to ARTIFACT_DIR/oauth-NAME-callback.hdr.
# Sets OA_STATUS, OA_LOCATION, OA_RESULT and OA_RFLOW (the redirect's `result`, `flow`).
oa_callback() {
  local name="$1" url="$2" st
  [[ "$url" == "$GW_GATEWAY_URL/oauth/callback"* ]] || gw_fail "$name: not a gateway callback URL"
  st="$(gw_curl -o "$ARTIFACT_DIR/oauth-$name-callback.out" -D "$ARTIFACT_DIR/oauth-$name-callback.hdr" \
    -w '%{http_code}' "$url" 2>>"$ARTIFACT_DIR/oauth-$name-callback.err")" || st=000
  OA_LOCATION="$(sed -n 's/^[Ll]ocation: *//p' "$ARTIFACT_DIR/oauth-$name-callback.hdr" | tr -d '\r' | head -n 1)"
  OA_RESULT="$(oa_param "$OA_LOCATION" result)"
  OA_RFLOW="$(oa_param "$OA_LOCATION" flow)"
  echo "$name callback status=$st result=$OA_RESULT" >>"$ARTIFACT_DIR/results.txt"
  OA_STATUS="$st"
}

# oa_redirect_clean NAME: the callback's redirect is on the console origin and carries only `flow`
# and `result` (no code, state or token).
oa_redirect_clean() {
  python3 -I -c '
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
assert "%s://%s" % (u.scheme, u.netloc) == sys.argv[2], "redirect left the console origin"
keys = {k for k, _ in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
assert keys <= {"flow", "result"}, "redirect carries %s" % sorted(keys - {"flow", "result"})
assert not u.fragment, "redirect has a fragment"
' "$OA_LOCATION" "$OA_CONSOLE" || gw_fail "$1: the callback redirect is not clean (see oauth-$1-callback.hdr)"
}

# oa_confirm WHO FLOW NAME: POST /v1/oauth/flows/FLOW/confirm as WHO; sets OA_STATUS, and on 200
# OA_CONN (the connection id).
oa_confirm() {
  OA_STATUS="$(oa_call "$1" POST "/v1/oauth/flows/$2/confirm" "$3")"
  OA_CONN=""
  if [[ "$OA_STATUS" == 200 ]]; then OA_CONN="$(oa_field "$3" id)"; fi
}

# oa_flow WHO NAME: connect (provider `mock`, OA_RETURN_TO), consent and callback as WHO; fails
# unless the callback answered pending_confirm. Sets OA_FLOW, OA_RFLOW.
oa_flow() {
  oa_connect "$1" "$2" "{\"provider\":\"mock\",\"return_to\":\"$OA_RETURN_TO\"}"
  [[ "$OA_STATUS" == 200 ]] || gw_fail "$2: connect as $1 returned $OA_STATUS (see oauth-$2.out)"
  oa_consent "$2"
  oa_callback "$2" "$OA_CB"
  [[ "$OA_STATUS" == 302 && "$OA_RESULT" == pending_confirm ]] ||
    gw_fail "$2: callback returned $OA_STATUS result=$OA_RESULT (expected 302 pending_confirm)"
  [[ "$OA_RFLOW" == "$OA_FLOW" ]] || gw_fail "$2: the callback redirect names another flow"
  oa_redirect_clean "$2"
}

# oa_grant CONNECTION: the connection's person (alice) lets GW_AGENT_ID use it (the row the NestJS
# route of task 6.1 would write).
oa_grant() {
  oa_psql -v org="$GW_ORG" -v agent="$GW_AGENT_ID" -v conn="$1" -v by="$OA_ALICE" >/dev/null <<'SQL' || gw_fail "could not grant the connection"
INSERT INTO oauth_connection_grants (org_id, agent_id, connection_id, created_by)
VALUES (:'org', :'agent', :'conn', :'by');
SQL
}

# oa_count SQL: a count from the database as the operator (SQL names :'org' for GW_ORG).
oa_count() {
  oa_psql -v org="$GW_ORG" <<<"$1" || gw_fail "query failed: $1"
}

# oa_hits ROUTE [KEY=VALUE...]: how many provider requests of ROUTE match every KEY=VALUE (values
# compared as JSON text: true, false, "ok" is written ok).
oa_hits() {
  python3 -I - "$OA_HITS" "$@" <<'PY'
import json, sys
path, route, conds = sys.argv[1], sys.argv[2], sys.argv[3:]
n = 0
for line in open(path):
    try:
        h = json.loads(line)
    except ValueError:
        continue
    if h.get("route") != route:
        continue
    ok = True
    for c in conds:
        k, _, v = c.partition("=")
        got = h.get(k)
        got = json.dumps(got) if not isinstance(got, str) else got
        if got != v:
            ok = False
    n += ok
print(n)
PY
}

# oa_mode MODE [TARGET]: switch the provider stub (see fixtures/oauth_provider.py).
oa_mode() {
  printf '%s\n%s\n' "$1" "${2:-}" >"$OA_MODE_FILE"
}

# oa_relay_raw NAME CONNECTION METHOD URL: POST /v1/relay with connection_id as the agent with
# its own HTTP client; prints the status (response in ARTIFACT_DIR/raw-NAME.*).
oa_relay_raw() {
  gw_relay_raw "$1" "$(gw_body "relay-$1" "{\"connection_id\":\"$2\",\"method\":\"$3\",\"url\":\"$4\"}")"
}

# oa_slug FILE: the `error` field of a JSON error body ("" when none).
oa_slug() {
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("error",""))' "$1" 2>/dev/null || true
}

# oa_ledger_has FILE KIND [OUTCOME] [ACTOR] [PERSON]: how many events of KIND (optionally with
# OUTCOME, the exact ACTOR text, and PERSON as the `person` attribute) the ledger file holds.
oa_ledger_has() {
  python3 -I - "$@" <<'PY'
import json, sys
f, kind = sys.argv[1], sys.argv[2]
outcome, actor, person = (sys.argv[3:] + ["", "", ""])[:3]
def ids(v):
    if isinstance(v, dict):
        for x in v.values():
            yield from ids(x)
    elif isinstance(v, list):
        for x in v:
            yield from ids(x)
    elif isinstance(v, str):
        yield v
n = 0
for e in json.load(open(f)):
    if e.get("kind") != kind or (outcome and e.get("outcome") != outcome):
        continue
    if actor and e.get("actor") != actor:
        continue
    if person and person not in ids((e.get("attrs") or {}).get("person")):
        continue
    n += 1
print(n)
PY
}

# oa_dump NAME: the org's OAuth rows as JSON (ARTIFACT_DIR/db-NAME.json), token material as hex,
# so the oracle sees what the database holds.
oa_dump() {
  oa_psql -v org="$GW_ORG" >"$ARTIFACT_DIR/db-$1.json" <<'SQL' || gw_fail "could not dump the OAuth tables"
SELECT json_build_object(
  'connections', (SELECT coalesce(json_agg(c), '[]') FROM oauth_connections c WHERE org_id = :'org'),
  'flows', (SELECT coalesce(json_agg(json_build_object('id', f.id, 'user_id', f.user_id,
      'provider', f.provider, 'status', f.status, 'return_to', f.return_to,
      'state_hash', encode(f.state_hash, 'hex'), 'sealed_verifier', encode(f.sealed_verifier, 'hex'))), '[]')
    FROM oauth_flows f WHERE org_id = :'org'),
  'material', (SELECT coalesce(json_agg(json_build_object('connection_id', m.connection_id,
      'generation', m.generation, 'ciphertext', encode(m.ciphertext, 'hex'),
      'wrapped_dek', encode(m.wrapped_dek, 'hex'), 'key_id', m.key_id)), '[]')
    FROM oauth_token_material m WHERE org_id = :'org'),
  'grants', (SELECT coalesce(json_agg(g), '[]') FROM oauth_connection_grants g WHERE org_id = :'org'),
  'providers', (SELECT coalesce(json_agg(p), '[]') FROM oauth_providers p WHERE org_id = :'org'));
SQL
}
