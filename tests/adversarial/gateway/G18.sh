#!/usr/bin/env bash
# G18: honey tokens (t5-honey-tokens task 6.1, gateway half). A decoy secret is planted where an
# agent will look and the agent uses it two ways; both are refused and both raise an alarm:
#   - by value: the agent reads a planted `.env` (the decoy as `smith honey plant` writes it) and
#     sends the decoy inside a relayed request (a header-less POST body through `smith relay`
#     and the raw /v1/relay body), through a binding of the real canary secret: refused with the
#     fixed `denied` answer, the upstream sees nothing (`honey.triggered`, path `value_match`);
#   - by reference: the agent relays through a binding and a grant on the honey secret itself:
#     refused before any unwrap, the same fixed answer (`honey.triggered`, path `relay`).
# The ledger holds both `honey.triggered` events for the agent (outcome `denied`, target the honey
# secret) and the upstream received neither the decoy nor the canary for those two calls. The
# decoy value never appears in the artifacts the agent produced or in the gateway log; the oracle
# scans them for the canary and this case scans them for the decoy as well.
#
# The honey row is made the way the NestJS API makes it (a `secrets` row of kind `honey`, then the
# core's `POST /internal/v1/honey/mint` with the gateway service token seals the value, so no
# value is ever on a command line); the owner reads it back through the gateway's owner-only
# `GET /v1/honey-tokens/{id}/value` with a Keycloak person token, exactly as `smith honey plant`
# does. The owner's inbox item is not part of this case: apps/api has no server in this suite;
# `apps/api/src/domains/notifications/honey-alert.test.ts` covers it.
#
# Needs `just up` (the auth profile, Keycloak) and `just api`; skips when the stack is down.
set -euo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
. "$here/lib.sh"
gw_init

KC="${KEYCLOAK_URL:-http://localhost:8180}"
gw_curl -f -o /dev/null -m 3 "${KC%/}/realms/locksmith/.well-known/openid-configuration" 2>/dev/null || {
  echo "skip: stack not running (Keycloak at ${KC%/}, just up)"
  exit 77
}
command -v psql >/dev/null 2>&1 || { echo "skip: psql is not installed"; exit 77; }
gw_build
gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
: >"$ARTIFACT_DIR/results.txt"

# A person token for the seeded user (scripts/auth-e2e.py's sign-in); the header file holds it.
mkdir -p "$GW_WORK/tok"
KEYCLOAK_URL="$KC" python3 -I - "$GW_ROOT/scripts/auth-e2e.py" "$GW_WORK/tok/person.hdr" <<'PY'
import importlib.util, os, sys
sys.dont_write_bytecode = True  # scripts/__pycache__ holds a tracked .pyc
os.environ["no_proxy"] = os.environ["NO_PROXY"] = "*"
for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
    os.environ.pop(k, None)
spec = importlib.util.spec_from_file_location("auth_e2e", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
tok, _ = m.sign_in(*m.SEEDED_OK)
if not tok:
    sys.exit("no person token for the seeded user")
with open(sys.argv[2], "w") as fh:
    fh.write("Authorization: Bearer %s\n" % tok)
PY
person="$GW_WORK/tok/person.hdr"
[[ -s "$person" ]] || gw_fail "could not mint a person token from Keycloak"

# The person's own org (created on first sign-in): the gateway's reveal route is bound to it.
GW_ORG=""
gw_curl -X POST -H "@$person" -o /dev/null -w '%{http_code}' "$GW_API/v1/auth/sign-in" >"$GW_WORK/signin.code" 2>/dev/null || true
gw_curl -H "@$person" -H 'Accept: application/json' -o "$GW_WORK/org.json" -w '%{http_code}' \
  "$GW_API/v1/orgs/current" >"$GW_WORK/org.code" || gw_fail "GET /v1/orgs/current: control plane unreachable"
[[ "$(<"$GW_WORK/org.code")" == 200 ]] || gw_fail "GET /v1/orgs/current returned $(<"$GW_WORK/org.code")"
GW_ORG="$(gw_json "$GW_WORK/org.json" id)"

# Operator setup through the control plane (dev auth, the person's org): project, environment, the
# canary secret as a version, an agent.
gw_post /v1/projects "$(gw_body project "{\"name\":\"adv-g18-$(date +%s%N)\"}")" project
GW_PROJECT="$(gw_json "$GW_BODY" id)"
gw_post "/v1/projects/$GW_PROJECT/environments" "$(gw_body environment '{"name":"adv"}')" environment
GW_ENVIRONMENT="$(gw_json "$GW_BODY" id)"
secrets="/v1/projects/$GW_PROJECT/environments/$GW_ENVIRONMENT/secrets"
gw_post "$secrets" "$(gw_body secret '{"name":"UPSTREAM_KEY"}')" secret
GW_SECRET_ID="$(gw_json "$GW_BODY" id)"
python3 -I -c '
import json, sys
with open(sys.argv[2], "w") as fh:
    json.dump({"value": open(sys.argv[1]).read().strip()}, fh)
' "$CANARY_FILE" "$GW_WORK/version.json"
gw_post "$secrets/$GW_SECRET_ID/versions" "$GW_WORK/version.json" version
rm -f "$GW_WORK/version.json"
GW_CP_PRIVATE=1 gw_post /v1/agents "$(gw_body agent '{"name":"adv-agent-g18"}')" agent
GW_ENROLLMENT_FILE="$GW_WORK/enrollment"
python3 -I -c '
import json, sys
doc = json.load(open(sys.argv[1]))
with open(sys.argv[2], "w") as fh:
    fh.write(doc["enrollment_secret"])
doc["enrollment_secret"] = "<masked by G18.sh>"
with open(sys.argv[3], "w") as fh:
    json.dump(doc, fh)
' "$GW_BODY" "$GW_ENROLLMENT_FILE" "$ARTIFACT_DIR/setup/$(basename "$GW_BODY")"
rm -f "$GW_BODY"
GW_BODY="$ARTIFACT_DIR/setup/$(basename "$GW_BODY")"
GW_AGENT_ID="$(gw_json "$GW_BODY" agent.id)"
gw_post "/v1/agents/$GW_AGENT_ID/grants" "$(gw_body grant "{\"secret_id\":\"$GW_SECRET_ID\"}")" grant

# The honey secret: a `secrets` row of kind `honey` (the NestJS API's insert), then the core seals
# a minted value as version 1 (service token; the response never carries the value).
eval "$(grep -E '^POSTGRES_(USER|PASSWORD|DB)=' "$GW_ENV_FILE")"
honey_name="adv-honey-$(date +%s%N)"
GW_HONEY_ID="$(PGHOST=127.0.0.1 PGPORT=5432 PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE="$POSTGRES_DB" \
  psql -X -q -t -A -v ON_ERROR_STOP=1 \
  -v org="$GW_ORG" -v project="$GW_PROJECT" -v env="$GW_ENVIRONMENT" -v name="$honey_name" <<'SQL' | head -n 1
INSERT INTO secrets (org_id, project_id, environment_id, name, kind, honey_template)
VALUES (:'org', :'project', :'env', :'name', 'honey', 'generic_api_key')
RETURNING id;
SQL
)"
[[ -n "$GW_HONEY_ID" ]] || gw_fail "could not insert the honey secret row"
service_token="$(gw_env LOCKSMITH_GATEWAY_SERVICE_TOKEN)"
[[ -n "$service_token" ]] || gw_fail "no LOCKSMITH_GATEWAY_SERVICE_TOKEN in $GW_ENV_FILE"
printf 'Authorization: Bearer %s\nX-Locksmith-Org: %s\n' "$service_token" "$GW_ORG" >"$GW_WORK/service.hdr"
status="$(gw_curl -X POST -H "@$GW_WORK/service.hdr" -H 'Content-Type: application/json' \
  --data-binary "{\"template\":\"generic_api_key\",\"secret_id\":\"$GW_HONEY_ID\"}" \
  -o "$ARTIFACT_DIR/setup/honey-mint.json" -w '%{http_code}' "$GW_API/internal/v1/honey/mint")" ||
  gw_fail "honey mint: control plane unreachable"
[[ "$status" == 201 ]] || gw_fail "honey mint returned $status (see setup/honey-mint.json)"
gw_post "/v1/agents/$GW_AGENT_ID/grants" "$(gw_body grant-honey "{\"secret_id\":\"$GW_HONEY_ID\"}")" grant-honey

# Bindings: the real secret, and the honey secret (an agent that was granted the decoy).
GW_BINDINGS="$GW_WORK/bindings.toml"
python3 -I -c '
import json, sys
org, sid, hid, origin, out = sys.argv[1:6]
q = json.dumps
with open(out, "w") as fh:
    fh.write("org_id = %s\n" % q(org))
    for s in (sid, hid):
        fh.write("[[binding]]\nsecret_id = %s\norigin = %s\nheader = \"Authorization\"\ntemplate = \"Bearer {secret}\"\nallow_private_hosts = true\n" % (q(s), q(origin)))
' "$GW_ORG" "$GW_SECRET_ID" "$GW_HONEY_ID" "$api" "$GW_BINDINGS"
gw_start_gateway
gw_login

# The owner plants the decoy where the agent will read it: the reveal route, the person's token,
# written straight to a 0600 file (`smith honey plant` does the same). The decoy is a case secret
# from here on: it stays in GW_WORK and is only ever sent by the "agent" below.
reveal="$(gw_curl -H "@$person" -o "$GW_WORK/planted.env" -w '%{http_code}' \
  "$GW_GATEWAY_URL/v1/honey-tokens/$GW_HONEY_ID/value")" || gw_fail "the reveal route is unreachable"
[[ "$reveal" == 200 && -s "$GW_WORK/planted.env" ]] || gw_fail "the owner could not read the decoy (status $reveal)"
# Reject the case when an agent token can read it: that would be a leak by itself.
agent_reveal="$(gw_curl -H "@$(gw_auth_header)" -o /dev/null -w '%{http_code}' \
  "$GW_GATEWAY_URL/v1/honey-tokens/$GW_HONEY_ID/value" 2>/dev/null || echo 000)"
case "$agent_reveal" in 401 | 403 | 404) ;; *) gw_fail "the agent's token reached the honey reveal route ($agent_reveal)" ;; esac
echo "owner-reveal=$reveal agent-reveal=$agent_reveal" >>"$ARTIFACT_DIR/results.txt"

# 1. By value. The agent reads .env and relays the decoy in a body (smith, then raw).
python3 -I -c '
import sys
v = open(sys.argv[1]).read().strip()
open(sys.argv[2], "w").write("api_key=" + v)
' "$GW_WORK/planted.env" "$GW_WORK/value-body.txt"
rc=0
gw_smith value-smith relay --secret-id "$GW_SECRET_ID" --show all -X POST \
  --data "@$GW_WORK/value-body.txt" "$api/g18/value-smith" || rc=$?
[[ $rc -ne 0 ]] || gw_fail "smith relay with the decoy in the body was answered"
grep -q 'denied' "$ARTIFACT_DIR/smith-value-smith.err" || gw_fail "the by-value refusal was not the fixed 'denied' (see smith-value-smith.err)"
echo "value-smith refused rc=$rc" >>"$ARTIFACT_DIR/results.txt"

# 2. By reference: the honey secret itself through its binding.
rc=0
gw_smith ref-smith relay --secret-id "$GW_HONEY_ID" --show all "$api/g18/ref-smith" || rc=$?
[[ $rc -ne 0 ]] || gw_fail "smith relay through the honey binding was answered"
grep -q 'denied' "$ARTIFACT_DIR/smith-ref-smith.err" || gw_fail "the by-reference refusal was not the fixed 'denied' (see smith-ref-smith.err)"
echo "ref-smith refused rc=$rc" >>"$ARTIFACT_DIR/results.txt"

# The upstream never saw either call; the by-value and by-reference answers are the same fixed
# slug as any other policy refusal (no tripwire tell): compare with a plain refusal.
if grep -q '/g18/' "$ARTIFACT_DIR/provider-hits.log"; then
  gw_fail "an /g18/ request reached the upstream (see provider-hits.log)"
fi
rc=0
gw_smith plain-refusal relay --secret-id "$(python3 -I -c 'import uuid; print(uuid.uuid4())')" "$api/g18/plain" || rc=$?
[[ $rc -ne 0 ]] || gw_fail "a relay through an unknown secret was answered"
python3 -I - "$ARTIFACT_DIR/smith-value-smith.err" "$ARTIFACT_DIR/smith-ref-smith.err" "$ARTIFACT_DIR/smith-plain-refusal.err" <<'PY' ||
import re, sys
def slug(p):
    m = re.search(r"\b(denied|not_found|unavailable|response_withheld)\b", open(p).read())
    return m.group(1) if m else None
v, r, p = (slug(f) for f in sys.argv[1:4])
if not (v == r == "denied"):
    sys.exit("by-value %r and by-reference %r were not both the fixed 'denied'" % (v, r))
PY
  gw_fail "the honey refusals are not the fixed 'denied' answer"

# The ledger: two honey.triggered events for this agent, outcome denied, target the honey secret,
# one per path; nothing else about the decoy.
gw_ledger final
python3 -I - "$GW_LEDGER" "$GW_AGENT_ID" "$GW_HONEY_ID" <<'PY' || gw_fail "the ledger does not hold the two honey.triggered events (see ledger-final.json)"
import json, sys
f, agent, honey = sys.argv[1:4]
ev = [e for e in json.load(open(f)) if e["kind"] == "honey.triggered" and e["actor"] == "agent:" + agent]
if len(ev) != 2:
    sys.exit("expected 2 honey.triggered events for the agent, got %d" % len(ev))
for e in ev:
    if e["outcome"] != "denied":
        sys.exit("honey.triggered outcome %r, expected denied" % e["outcome"])
    if honey not in json.dumps(e):
        sys.exit("honey.triggered does not name the honey secret")
paths = sorted(json.dumps(e) for e in ev)
if not (any("value_match" in p for p in paths) and any('"relay"' in p for p in paths)):
    sys.exit("expected one value_match and one relay event")
PY
echo "ledger honey.triggered=2" >>"$ARTIFACT_DIR/results.txt"

# The decoy appears nowhere the agent or the log could keep it: not in the artifacts, and not in
# the ledger (the oracle scans the canary; this scans the decoy in the same encodings).
python3 -I - "$GW_WORK/planted.env" "$ARTIFACT_DIR" <<'PY' || gw_fail "the decoy value reached the artifacts, the gateway log or the ledger"
import base64, binascii, os, sys
v = open(sys.argv[1], "rb").read().strip()
forms = {v, base64.b64encode(v), base64.urlsafe_b64encode(v).rstrip(b"="), binascii.hexlify(v)}
for root, _, files in os.walk(sys.argv[2]):
    for n in files:
        p = os.path.join(root, n)
        data = open(p, "rb").read()
        for f in forms:
            if f and f in data:
                sys.exit("decoy found in %s" % os.path.relpath(p, sys.argv[2]))
PY
echo "G18 ok"
