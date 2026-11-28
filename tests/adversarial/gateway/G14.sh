#!/usr/bin/env bash
# G14: OAuth connect-flow integrity (change c1-oauth-connections task 7.2), against the provider
# stub of G13 (fixtures/oauth_provider.py through oauth_lib.sh; it issues the case canary as the
# access and refresh token, so the oracle also covers every failure path). Probes:
#   - state: a forged state, a state with one character changed, no state, and a replayed
#     callback all answer `flow_not_found` and make no token request;
#   - PKCE: a code stolen from the provider's redirect is refused by the provider without the
#     verifier and with a wrong one (then the gateway redeems it with its own); an attacker's own
#     code injected into alice's callback (her state, the attacker's challenge) is refused by the
#     provider, so no connection is created and her flow is spent;
#   - fixation: a flow bob started, completed in a browser and confirmed by alice is `403
#     wrong_person`: the tokens are revoked at the provider and deleted, no connection exists for
#     either, and bob cannot confirm it afterwards;
#   - return_to on another origin (host, port, scheme, look-alikes, userinfo, javascript:, a
#     scheme-relative URL) and an unknown provider are 400 with their slug and write no flow;
#   - a token endpoint that redirects (302, 307) to an internal address: the gateway does not
#     follow, the callback fails, and the internal listener receives nothing (no code, verifier
#     or client secret);
#   - relay: an agent with no grant is `403 no_grant` and the provider API is not called; with a
#     grant, a host that is not the provider's API host (another host, the same host on another
#     port, a `localhost` alias, userinfo tricks) is refused and nothing reaches it;
#   - bob cannot disconnect alice's connection;
#   - the ledger holds the `wrong_person` connect failure and the agent's relay denials.
# Skips when the stack is down.
set -euo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
. "$here/lib.sh"
gw_init
. "$here/oauth_lib.sh"

oa_start
gw_fixture evil internal
internal="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup
oa_people
: >>"$ARTIFACT_DIR/results.txt"
cid="$(gw_env LOCKSMITH_OAUTH_MOCK_CLIENT_ID)"
callback="$GW_GATEWAY_URL/oauth/callback"
conns() { oa_count "SELECT count(*) FROM oauth_connections WHERE org_id = :'org'"; }
flows() { oa_count "SELECT count(*) FROM oauth_flows WHERE org_id = :'org'"; }
codes() { oa_hits token grant=authorization_code; }
# cb_url CODE STATE: a gateway callback URL with these parameters (either may be empty: left out).
cb_url() {
  python3 -I -c '
import sys, urllib.parse
q = [(k, v) for k, v in (("code", sys.argv[2]), ("state", sys.argv[3])) if v]
print(sys.argv[1] + ("?" + urllib.parse.urlencode(q) if q else ""))
' "$callback" "$1" "$2"
}
# not_found NAME URL: the callback answers a redirect with flow_not_found and no token request.
not_found() {
  local n0
  n0="$(codes)"
  oa_callback "$1" "$2"
  [[ "$OA_STATUS" == 302 && "$OA_RESULT" == flow_not_found ]] ||
    gw_fail "$1: callback returned $OA_STATUS result=$OA_RESULT (expected flow_not_found)"
  [[ -z "$OA_RFLOW" ]] || gw_fail "$1: the redirect names a flow"
  oa_redirect_clean "$1"
  [[ "$(codes)" == "$n0" ]] || gw_fail "$1: the gateway made a token request"
}
rand() { python3 -I -c 'import secrets; print(secrets.token_urlsafe(32))'; }

# 1. Forged and missing state, before any flow exists.
not_found forged "$(cb_url "$(rand)" "$(rand)")"
not_found no-state "$(cb_url "$(rand)" "")"
not_found empty "$(cb_url "" "")"
[[ "$(codes)" == 0 ]] || gw_fail "a forged callback reached the token endpoint"

# 2. PKCE on a stolen code: the provider wants the verifier only the gateway holds.
oa_connect alice f1 "{\"provider\":\"mock\",\"return_to\":\"$OA_RETURN_TO\"}"
[[ "$OA_STATUS" == 200 ]] || gw_fail "connect as alice returned $OA_STATUS"
f1="$OA_FLOW"
oa_consent f1
# steal MODE: redeem the code of GW_WORK/f1.cb at the provider as an attacker who even holds the
# client secret, without (`missing`) or with a made-up (`wrong`) verifier. Prints the status only.
steal() {
  python3 -I - "$GW_WORK/f1.cb" "$OA_ISSUER/protocol/openid-connect/token" "$cid" \
    "$GW_WORK/oauth-client.secret" "$callback" "$1" <<'PY'
import secrets, sys, urllib.error, urllib.parse, urllib.request
cbf, url, cid, secf, redirect, mode = sys.argv[1:7]
code = urllib.parse.parse_qs(urllib.parse.urlsplit(open(cbf).read().strip()).query)["code"][0]
form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
        "client_id": cid, "client_secret": open(secf).read().strip()}
if mode == "wrong":
    form["code_verifier"] = secrets.token_urlsafe(48)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    print(opener.open(urllib.request.Request(url, data=urllib.parse.urlencode(form).encode()), timeout=10).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
}
st="$(steal missing)"
[[ "$st" == 400 ]] || gw_fail "the provider redeemed a code without the PKCE verifier ($st)"
[[ "$(oa_hits token pkce=missing)" == 1 ]] || gw_fail "the provider did not see the verifier-less request"
st="$(steal wrong)"
[[ "$st" == 400 ]] || gw_fail "the provider redeemed a code with a wrong PKCE verifier ($st)"
[[ "$(oa_hits token pkce=wrong)" == 1 ]] || gw_fail "the provider did not see the wrong-verifier request"
# The same code through the gateway: its sealed verifier is the right one.
oa_callback f1 "$OA_CB"
[[ "$OA_STATUS" == 302 && "$OA_RESULT" == pending_confirm && "$OA_RFLOW" == "$f1" ]] ||
  gw_fail "f1: callback returned $OA_STATUS result=$OA_RESULT"
oa_redirect_clean f1
[[ "$(oa_hits token pkce=ok)" == 1 ]] || gw_fail "the gateway did not redeem the code with the right verifier"

# 3. Replayed and tampered state.
f1_cb="$OA_CB"
not_found replay "$f1_cb"
f1_state="$(oa_param "$f1_cb" state)"
f1_code="$(oa_param "$f1_cb" code)"
last="${f1_state: -1}"
[[ "$last" == A ]] && swap=B || swap=A
not_found tampered "$(cb_url "$f1_code" "${f1_state%?}$swap")"
oa_confirm alice "$f1" f1-confirm
[[ "$OA_STATUS" == 200 ]] || gw_fail "confirm of f1 as alice returned $OA_STATUS"
conn="$OA_CONN"
[[ "$(conns)" == 1 ]] || gw_fail "expected alice's one connection"

# 4. Code injection: the attacker's own code (their challenge) with alice's state.
att_url="$(python3 -I -c '
import base64, hashlib, secrets, sys, urllib.parse
v = secrets.token_urlsafe(48)
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
print(sys.argv[1] + "?" + urllib.parse.urlencode({"response_type": "code", "client_id": sys.argv[2],
    "redirect_uri": sys.argv[3], "state": "attacker-" + secrets.token_hex(8), "code_challenge": c,
    "code_challenge_method": "S256", "scope": "openid offline_access"}))
' "$OA_ISSUER/protocol/openid-connect/auth" "$cid" "$callback")"
oa_consent attacker "$att_url"
att_code="$(oa_param "$OA_CB" code)"
oa_connect alice f2 "{\"provider\":\"mock\",\"return_to\":\"$OA_RETURN_TO\"}"
[[ "$OA_STATUS" == 200 ]] || gw_fail "connect f2 returned $OA_STATUS"
f2="$OA_FLOW"
oa_consent f2
f2_cb="$OA_CB"
wrong0="$(oa_hits token pkce=wrong)"
oa_callback inject "$(cb_url "$att_code" "$(oa_param "$f2_cb" state)")"
[[ "$OA_STATUS" == 302 && "$OA_RESULT" != pending_confirm && -n "$OA_RESULT" ]] ||
  gw_fail "inject: callback returned $OA_STATUS result=$OA_RESULT (expected a failure slug)"
[[ "$OA_RFLOW" == "$f2" ]] || gw_fail "inject: the redirect names another flow"
oa_redirect_clean inject
[[ "$(oa_hits token pkce=wrong)" == $((wrong0 + 1)) ]] || gw_fail "inject: the provider did not refuse the injected code's verifier"
[[ "$(conns)" == 1 ]] || gw_fail "inject: a connection was created from the attacker's code"
not_found inject-replay "$f2_cb"

# 5. Fixation: bob starts, alice completes the consent and confirms.
oa_flow bob f3
f3="$OA_FLOW"
rev0="$(oa_hits revoke token_ok=true)"
oa_confirm alice "$f3" f3-alice
[[ "$OA_STATUS" == 403 ]] || gw_fail "alice confirming bob's flow returned $OA_STATUS (expected 403)"
[[ "$(oa_slug "$ARTIFACT_DIR/oauth-f3-alice.out")" == wrong_person ]] || gw_fail "alice confirming bob's flow: not wrong_person"
[[ "$(oa_hits revoke token_ok=true)" == $((rev0 + 1)) ]] || gw_fail "the tokens of the refused flow were not revoked at the provider"
[[ "$(conns)" == 1 ]] || gw_fail "a connection survived the wrong_person confirm"
[[ "$(oa_count "SELECT count(*) FROM oauth_connections WHERE org_id = :'org' AND user_id = '$OA_BOB'")" == 0 ]] ||
  gw_fail "bob has a connection"
[[ "$(oa_count "SELECT count(*) FROM oauth_token_material WHERE org_id = :'org'")" == 1 ]] ||
  gw_fail "the refused flow's token material was not deleted"
oa_confirm bob "$f3" f3-bob
[[ "$OA_STATUS" == 404 ]] || gw_fail "bob confirming the spent flow returned $OA_STATUS (expected 404)"
[[ "$(oa_slug "$ARTIFACT_DIR/oauth-f3-bob.out")" == flow_not_found ]] || gw_fail "bob confirming the spent flow: not flow_not_found"

# 6. return_to on another origin, and an unknown provider: 400, no flow written.
n_flows="$(flows)"
i=0
for rt in "http://evil.example/settings" "http://localhost:5174/settings" "https://localhost:5173/settings" \
  "http://localhost:5173.evil.example/" "http://localhost:5173@evil.example/" "http://evil.example@localhost:5173/" \
  "http://127.0.0.1:5173/" "javascript:alert(1)" "//evil.example/" "/settings" "http://[::1]:5173/" \
  "$GW_GATEWAY_URL/" "data:text/html,x"; do
  i=$((i + 1))
  oa_connect alice "rt-$i" "$(python3 -I -c 'import json,sys; print(json.dumps({"provider": "mock", "return_to": sys.argv[1]}))' "$rt")"
  [[ "$OA_STATUS" == 400 ]] || gw_fail "return_to #$i returned $OA_STATUS (expected 400)"
  [[ "$(oa_slug "$ARTIFACT_DIR/oauth-rt-$i.out")" == return_to_not_allowed ]] || gw_fail "return_to #$i: not return_to_not_allowed"
done
oa_connect alice unknown "{\"provider\":\"dropbox\",\"return_to\":\"$OA_RETURN_TO\"}"
[[ "$OA_STATUS" == 400 && "$(oa_slug "$ARTIFACT_DIR/oauth-unknown.out")" == unknown_provider ]] ||
  gw_fail "an unknown provider returned $OA_STATUS"
oa_connect none anon "{\"provider\":\"mock\",\"return_to\":\"$OA_RETURN_TO\"}"
[[ "$OA_STATUS" == 401 ]] || gw_fail "connect without a person's token returned $OA_STATUS"
[[ "$(flows)" == "$n_flows" ]] || gw_fail "a refused connect wrote a flow"

# 7. A token endpoint that redirects to an internal address.
for code in 302 307; do
  oa_mode "redirect-$code" "$internal/token-steal"
  oa_connect alice "redir-$code" "{\"provider\":\"mock\",\"return_to\":\"$OA_RETURN_TO\"}"
  [[ "$OA_STATUS" == 200 ]] || gw_fail "connect redir-$code returned $OA_STATUS"
  oa_consent "redir-$code"
  oa_callback "redir-$code" "$OA_CB"
  [[ "$OA_STATUS" == 302 && "$OA_RESULT" != pending_confirm && -n "$OA_RESULT" ]] ||
    gw_fail "redir-$code: callback returned $OA_STATUS result=$OA_RESULT (expected a failure slug)"
  oa_redirect_clean "redir-$code"
  [[ "$(oa_hits token mode="redirect-$code")" == 1 ]] || gw_fail "redir-$code: the token endpoint was not called once"
  [[ ! -s "$ARTIFACT_DIR/internal-hits.log" ]] || gw_fail "redir-$code: the gateway followed the redirect to the internal address"
done
oa_mode normal
[[ "$(conns)" == 1 ]] || gw_fail "a redirecting token endpoint created a connection"

# 8. Relay: no grant first (the provider API is not called), then hosts outside the provider.
api="$OA_BASE/api/me"
st="$(oa_relay_raw nogrant "$conn" GET "$api")"
[[ "$st" == 403 && "$(oa_slug "$ARTIFACT_DIR/raw-nogrant.out")" == no_grant ]] || gw_fail "relay without a grant returned $st"
st="$(oa_relay_raw unknown-conn "$(python3 -I -c 'import uuid; print(uuid.uuid4())')" GET "$api")"
[[ "$st" == 403 && "$(oa_slug "$ARTIFACT_DIR/raw-unknown-conn.out")" == no_grant ]] || gw_fail "relay with an unknown connection returned $st"
if gw_smith nogrant relay --connection "$conn" "$api"; then gw_fail "smith relay without a grant succeeded"; fi
grep -q no_grant "$ARTIFACT_DIR/smith-nogrant.err" || gw_fail "smith relay without a grant: no no_grant"
[[ "$(oa_hits api-me)" == 0 ]] || gw_fail "a relay without a grant reached the provider API"
oa_grant "$conn"
sleep 11 # the gateway caches a "no grant" answer for at most 10 s
st="$(oa_relay_raw granted "$conn" GET "$api")"
[[ "$st" == 200 ]] || gw_fail "relay with the grant returned $st (the host probes below need a working grant)"
[[ "$(oa_hits api-me bearer_ok=true)" == 1 ]] || gw_fail "the granted relay did not reach the provider API"
evil_host="${internal#http://}"
i=0
for url in "$internal/x" "http://localhost:${OA_HOST#*:}/api/me" "http://127.0.0.1:$((${OA_HOST#*:} == 65535 ? 1 : ${OA_HOST#*:} + 1))/api/me" \
  "http://$OA_HOST@$evil_host/x" "http://$evil_host/x?h=$OA_HOST" "http://$evil_host/$OA_HOST/api/me" \
  "http://127.0.0.1.nip.io:${OA_HOST#*:}/api/me"; do
  i=$((i + 1))
  st="$(oa_relay_raw "host-$i" "$conn" GET "$url")"
  slug="$(oa_slug "$ARTIFACT_DIR/raw-host-$i.out")"
  echo "host-$i status=$st slug=$slug" >>"$ARTIFACT_DIR/results.txt"
  [[ "$st" == 403 || "$st" == 400 ]] || gw_fail "relay to a non-provider host (#$i) returned $st"
  [[ "$st" == 400 || "$slug" == host_not_allowed ]] || gw_fail "relay to a non-provider host (#$i): slug $slug, not host_not_allowed"
done
[[ "$(oa_slug "$ARTIFACT_DIR/raw-host-1.out")" == host_not_allowed ]] || gw_fail "relay to another host: not host_not_allowed"
if gw_smith evil-host relay --connection "$conn" "$internal/x"; then gw_fail "smith relay to a non-provider host succeeded"; fi
[[ ! -s "$ARTIFACT_DIR/internal-hits.log" ]] || gw_fail "a relay with the connection reached a non-provider host"
[[ "$(oa_hits api-me)" == 1 ]] || gw_fail "a refused relay reached the provider API"

# 9. bob cannot disconnect alice's connection.
rev0="$(oa_hits revoke)"
st="$(oa_call bob POST "/v1/oauth/connections/$conn/disconnect" bob-disconnect)"
[[ "$st" == 403 ]] || gw_fail "bob disconnecting alice's connection returned $st (expected 403)"
[[ "$(oa_count "SELECT status FROM oauth_connections WHERE id = '$conn'")" == connected ]] || gw_fail "bob's disconnect changed the connection"
[[ "$(oa_hits revoke)" == "$rev0" ]] || gw_fail "bob's disconnect revoked at the provider"
[[ "$(oa_count "SELECT count(*) FROM oauth_token_material WHERE org_id = :'org'")" == 1 ]] || gw_fail "bob's disconnect deleted the material"
oa_dump final

# 10. Ledger: the wrong_person failure names bob (the flow's person); the agent's denials.
gw_ledger final
wrong="$(oa_ledger_has "$GW_LEDGER" oauth.connect_failed wrong_person "" "$OA_BOB")"
denied="$(oa_ledger_has "$GW_LEDGER" relay.denied "" "agent:$GW_AGENT_ID")"
connected="$(oa_ledger_has "$GW_LEDGER" oauth.connected ok "" "$OA_ALICE")"
echo "ledger wrong_person=$wrong denied=$denied connected=$connected" >>"$ARTIFACT_DIR/results.txt"
[[ "$wrong" == 1 ]] || gw_fail "expected one oauth.connect_failed wrong_person event naming bob"
((denied >= 3)) || gw_fail "expected relay.denied events for the agent's refused relays"
[[ "$connected" == 1 ]] || gw_fail "expected exactly one oauth.connected event (alice's f1)"
echo "G14 ok"
