#!/usr/bin/env bash
# G6: token abuse. The agent's access token is an EdDSA JWT minted by the control plane; the
# gateway verifies it against the JWKS and checks the grant on every relay. Probes, each sent to
# the gateway's /v1/relay for a bound URL (the provider fixture logs whether the key arrived):
#   - baseline: the agent's own token relays (200, provider got the key once);
#   - forged: the real token with its payload altered (sub, org, exp pushed out), a past `exp`
#     with the real signature kept (so the signature, not the clock, is what is tested), an
#     unknown `kid`, a real `kid` with a garbage signature, `alg: none`, `alg: HS256`, a missing
#     `kid`, an empty and a truncated token;
#   - another org: a real token minted for an agent of a second org (refused: the gateway serves
#     one org);
#   - internal routes: the agent token at /internal/v1 routes of the control plane (401);
#   - revoke: DELETE the grant, wait past the gateway's grant-cache TTL (10 s), replay the same
#     still-valid token: refused 403 `denied`.
# Expiry by the clock (a correctly signed token past its `exp`) cannot be minted here: the TTL
# is fixed at 15 minutes in the control plane and the signing key is not available to the case.
# It is covered by `forged_expired_wrong_audience_and_wrong_org_are_refused` in
# services/gateway/src/auth.rs (task 5 adds the in-process variant).
# Checks: every refused probe is 401 or 403 and never 200; no decrypt: the ledger's
# `relay.attempt` count does not move across the refused probes; after the revoke one
# `relay.denied` event is appended for the agent; the provider sees exactly one request.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$api"

printf '%s' "{\"secret_id\":\"$GW_SECRET_ID\",\"version\":1,\"method\":\"GET\",\"url\":\"$api/g6/probe\"}" >"$GW_WORK/relay.json"

# relay_with HEADER_FILE NAME: POST the relay body with an arbitrary Authorization header file.
relay_with() {
  local hdr="$1" name="$2"
  gw_curl -X POST ${hdr:+-H "@$hdr"} -H 'Content-Type: application/json' --data-binary "@$GW_WORK/relay.json" \
    -D "$ARTIFACT_DIR/raw-$name.hdr" -o "$ARTIFACT_DIR/raw-$name.out" -w '%{http_code}' \
    "$GW_GATEWAY_URL/v1/relay" 2>>"$ARTIFACT_DIR/raw-$name.err" || echo 000
}

: >"$ARTIFACT_DIR/results.txt"
expect_refused() {
  local name="$1" status="$2"
  echo "$name gateway=$status" >>"$ARTIFACT_DIR/results.txt"
  [[ "$status" == 401 || "$status" == 403 ]] || gw_fail "$name: gateway answered $status (expected 401 or 403)"
}

# Baseline.
gw_ledger before
attempts_before="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
status="$(gw_relay_raw baseline "$GW_WORK/relay.json")"
echo "baseline gateway=$status" >>"$ARTIFACT_DIR/results.txt"
[[ "$status" == 200 ]] || gw_fail "baseline relay returned $status"
gw_ledger baseline
attempts_ok="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
[[ "$attempts_ok" == $((attempts_before + 1)) ]] || gw_fail "baseline: relay.attempt $attempts_before -> $attempts_ok (expected +1)"

# Forged tokens, built from the agent's real token (private files in GW_WORK).
mkdir -p "$GW_WORK/tok"
python3 -I - "$GW_AGENT_HOME/agent.json" "$GW_WORK/tok" <<'PY'
import base64, json, os, sys
doc = json.load(open(sys.argv[1]))
out = sys.argv[2]
tok = doc["access_token"]
h, p, s = tok.split(".")
def d(x): return json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
def e(o): return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
hd, pl = d(h), d(p)
def put(name, token):
    with open(os.path.join(out, name + ".hdr"), "w") as fh:
        fh.write("Authorization: Bearer %s\n" % token)
far = 4102444800
put("payload-sub", ".".join([h, e({**pl, "sub": "0" * 8 + "-0000-0000-0000-" + "0" * 12}), s]))
put("payload-org", ".".join([h, e({**pl, "org": "0" * 8 + "-0000-0000-0000-" + "0" * 12}), s]))
put("payload-exp-far", ".".join([h, e({**pl, "exp": far}), s]))
put("payload-exp-past", ".".join([h, e({**pl, "exp": 1000000000}), s]))
put("kid-unknown", ".".join([e({**hd, "kid": "no-such-key"}), p, s]))
put("kid-garbage-sig", ".".join([h, p, "A" * len(s)]))
put("sig-truncated", ".".join([h, p, s[: len(s) // 2]]))
put("sig-empty", ".".join([h, p, ""]))
put("alg-none", ".".join([e({**hd, "alg": "none"}), p, ""]))
put("alg-none-sig", ".".join([e({**hd, "alg": "none"}), p, s]))
put("alg-hs256", ".".join([e({**hd, "alg": "HS256"}), p, s]))
nk = {k: v for k, v in hd.items() if k != "kid"}
put("kid-missing", ".".join([e(nk), p, s]))
put("two-parts", h + "." + p)
put("empty", "")
put("garbage", "not-a-jwt")
PY
for f in "$GW_WORK"/tok/*.hdr; do
  name="$(basename "$f" .hdr)"
  expect_refused "forged-$name" "$(relay_with "$f" "forged-$name")"
done
expect_refused "no-header" "$(relay_with "" no-header)"
printf 'Authorization: Basic %s\n' "$(printf 'a:b' | base64)" >"$GW_WORK/tok/basic.hdr"
expect_refused "scheme-basic" "$(relay_with "$GW_WORK/tok/basic.hdr" scheme-basic)"

# A token minted for an agent of another org.
saved_org="$GW_ORG"
GW_ORG=""
gw_post /v1/orgs "$(gw_body orgb "{\"name\":\"adv-$GW_CASE-b-$(date +%s%N)\"}")" orgb
GW_ORG="$(gw_json "$GW_BODY" id)"
GW_CP_PRIVATE=1 gw_post /v1/agents "$(gw_body agentb "{\"name\":\"adv-agent-b-$GW_CASE\"}")" agentb
python3 -I - "$GW_BODY" "$GW_WORK/enroll-b.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
json.dump({"enrollment_secret": doc["enrollment_secret"]}, open(sys.argv[2], "w"))
PY
rm -f "$GW_BODY"
gw_cp POST /v1/agent-tokens "$GW_WORK/enroll-b.json" tokenb
[[ "$GW_STATUS" == 200 || "$GW_STATUS" == 201 ]] || gw_fail "org B token mint returned $GW_STATUS"
python3 -I - "$GW_BODY" "$GW_WORK/tok-b.hdr" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write("Authorization: Bearer %s\n" % doc["access_token"])
doc["access_token"] = "<masked>"
json.dump(doc, open(sys.argv[1], "w"))
PY
rm -f "$GW_WORK/enroll-b.json"
GW_ORG="$saved_org"
expect_refused "other-org-token" "$(relay_with "$GW_WORK/tok-b.hdr" other-org-token)"

# The agent token at internal routes of the control plane, and the gateway's own routes.
auth="$(gw_auth_header)"
for spec in "GET /internal/v1/agents/$GW_AGENT_ID/grants" \
            "GET /internal/v1/secrets/$GW_SECRET_ID/versions/1/material" \
            "POST /internal/v1/audit/events"; do
  set -- $spec
  st="$(gw_curl -X "$1" -H "@$auth" -H "X-Locksmith-Dev-Org: $GW_ORG" -H 'Content-Type: application/json' \
    --data-binary '{}' -o "$ARTIFACT_DIR/internal-$(echo "$2" | tr '/{}' '___' | cut -c1-60).out" -w '%{http_code}' \
    "$GW_API$2" 2>/dev/null || echo 000)"
  echo "internal $1 gateway=$st" >>"$ARTIFACT_DIR/results.txt"
  [[ "$st" == 401 ]] || gw_fail "agent token at $1 internal route: $st (expected 401)"
done

# Refused probes never decrypted: attempts unchanged.
gw_ledger refused
attempts_refused="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
[[ "$attempts_refused" == "$attempts_ok" ]] || gw_fail "relay.attempt moved across refused probes: $attempts_ok -> $attempts_refused"

# Revoke the grant, wait past the cache TTL, replay the still-valid token.
gw_cp DELETE "/v1/agents/$GW_AGENT_ID/grants/$GW_GRANT_ID" "" revoke
[[ "$GW_STATUS" == 204 ]] || gw_fail "grant revoke returned $GW_STATUS"
sleep 12
status="$(gw_relay_raw after-revoke "$GW_WORK/relay.json")"
echo "after-revoke gateway=$status" >>"$ARTIFACT_DIR/results.txt"
[[ "$status" == 403 ]] || gw_fail "replay after revoke returned $status (expected 403)"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("error") in ("denied","no_grant") else 1)' \
  "$ARTIFACT_DIR/raw-after-revoke.out" || gw_fail "replay after revoke was not a denied/no_grant error"
gw_ledger after
attempts_after="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
denied_after="$(gw_ledger_count "$GW_LEDGER" relay.denied)"
[[ "$attempts_after" == "$attempts_ok" ]] || gw_fail "relay.attempt moved after revoke: $attempts_ok -> $attempts_after"
[[ "$denied_after" -ge 1 ]] || gw_fail "no relay.denied event after the revoked replay"

# Provider: exactly the one baseline request, the key in the bound header only.
hits="$(grep -c . "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits" == 1 ]] || gw_fail "provider saw $hits requests (expected 1)"
gw_unwrap "$ARTIFACT_DIR"/raw-*.out
echo "G6 ok"
