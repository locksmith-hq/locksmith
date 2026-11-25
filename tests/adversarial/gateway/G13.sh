#!/usr/bin/env bash
# G13: a person's OAuth tokens never leave the gateway (change c1-oauth-connections task 7.1).
# The provider is fixtures/oauth_provider.py (oauth_lib.sh): it issues the case canary as the
# access and the refresh token, and its API reflects the bearer it receives. Through the gateway's
# real OAuth endpoints, as alice (a person of the case's org, with a token from the stub issuer):
#   - connect (a body with extra scope fields; the authorize URL must carry exactly the registry's
#     scopes and PKCE S256), the browser's consent and the callback (a redirect to the console with
#     `flow` and `result=pending_confirm` only), confirm (a ConnectionSummary, `connected`);
#   - grant: alice lets the case's agent use the connection (the row task 6.1's NestJS route would
#     write, inserted by the operator because that route is not in this stack);
#   - relay as the agent: `smith relay --connection` (API call and a reflecting endpoint),
#     `smith grants`, the gateway's `/mcp` (`list_my_keys`, `relay_http_request`), the stdio
#     `locksmith-mcp` `relay_request`, and the agent's own HTTP client on `/v1/relay`;
#   - refresh: the first exchange answers expires_in 30 (inside the 60 s window), so the first
#     relay refreshes once with the canary refresh token, and later relays do not;
#   - disconnect: revoked at the provider with the canary token, the material row is gone, the
#     next relay is refused; `locksmith_app` cannot read `oauth_token_material` at all.
# The oracle scans every response (`oauth-*`, `raw-*`, `smith-*`, `mcp-*` and their decoded
# views), the agent HOME, gateway.log, the stub's request log and stderr, a dump of the org's
# OAuth rows (ciphertext as hex) and the ledger export. The NestJS API (`apps/api`) is scanned
# only when it runs (E2E_NEST_API_URL, and E2E_NEST_API_LOG for its log); its OAuth routes are
# task 6.1, so the case prints a note and goes on without it. The agent transcript is the live
# prompt prompts/oauth.md (live.sh). Skips when the stack is down.
set -euo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
. "$here/lib.sh"
gw_init
. "$here/oauth_lib.sh"

oa_start
oa_mode short
gw_setup
oa_people
: >"$ARTIFACT_DIR/results.txt"
api="$OA_BASE/api"

# 1. Connect: extra scopes in the body are ignored; the authorize URL is the registry's.
oa_connect alice connect "{\"provider\":\"mock\",\"return_to\":\"$OA_RETURN_TO\",\"scope\":\"admin\",\"scopes\":[\"admin\",\"write\"],\"extra_scopes\":\"repo\"}"
st="$OA_STATUS"
[[ "$st" != 503 ]] || gw_fail "connect returned 503: the gateway's OAuth endpoints are off (see gateway.log)"
[[ "$st" == 200 ]] || gw_fail "connect as alice returned $st (see oauth-connect.out)"
[[ "$(oa_param "$OA_AUTHORIZE" scope)" == "openid offline_access" ]] ||
  gw_fail "the authorize URL does not carry exactly the registry's scopes"
[[ "$(oa_param "$OA_AUTHORIZE" code_challenge_method)" == S256 ]] || gw_fail "the authorize URL is not PKCE S256"
[[ -z "$(oa_param "$OA_AUTHORIZE" code_verifier)" ]] || gw_fail "the authorize URL carries the PKCE verifier"
[[ "$(oa_param "$OA_AUTHORIZE" redirect_uri)" == "$GW_GATEWAY_URL/oauth/callback" ]] ||
  gw_fail "the authorize URL names another redirect URI"

# 2. Consent and callback: a redirect to the console with the flow id and pending_confirm only.
oa_consent connect
[[ "$(oa_hits authorize challenge_method=S256 challenge_len=43 has_verifier=false)" == 1 ]] ||
  gw_fail "the provider did not get one S256 authorize request"
oa_callback connect "$OA_CB"
st="$OA_STATUS"
[[ "$st" == 302 && "$OA_RESULT" == pending_confirm ]] || gw_fail "callback returned $st result=$OA_RESULT"
[[ "$OA_RFLOW" == "$OA_FLOW" ]] || gw_fail "the callback redirect names another flow"
oa_redirect_clean connect
[[ "$(oa_hits token grant=authorization_code pkce=ok client_ok=true redirect_ok=true)" == 1 ]] ||
  gw_fail "the code exchange did not present the client, the redirect URI and the right PKCE verifier"
[[ "$(oa_hits userinfo bearer_ok=true)" == 1 ]] || gw_fail "the gateway did not read the account with the token"

# 3. Confirm as alice: connected, metadata only.
oa_confirm alice "$OA_RFLOW" confirm
st="$OA_STATUS"
[[ "$st" == 200 ]] || gw_fail "confirm as alice returned $st (see oauth-confirm.out)"
conn="$OA_CONN"
[[ "$(oa_field confirm status)" == connected ]] || gw_fail "the confirmed connection is not connected"
[[ "$(oa_field confirm provider)" == mock ]] || gw_fail "the confirmed connection is not the mock provider's"
python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
bad = [k for k in d if any(w in k.lower() for w in ("token", "secret", "code", "verifier", "state"))
       and k not in ("status",)]
assert not bad, bad
' "$ARTIFACT_DIR/oauth-confirm.out" || gw_fail "the ConnectionSummary has a token-like field"
[[ "$(oa_count "SELECT count(*) FROM oauth_token_material WHERE org_id = :'org'")" == 1 ]] ||
  gw_fail "expected one sealed token set"
oa_dump connected

# 4. Grant, then the agent's connection grants.
oa_grant "$conn"
gw_smith grants grants || gw_fail "smith grants failed (see smith-grants.err)"
grep -qF -- "$conn" "$ARTIFACT_DIR/smith-grants.out" || gw_fail "smith grants does not list the connection"

# 5. smith relay: the first call refreshes (expires_in 30), the API sees the canary bearer.
gw_smith relay-me relay --connection "$conn" --show all "$api/me" || gw_fail "smith relay --connection failed (see smith-relay-me.err)"
grep -q '^HTTP 200' "$ARTIFACT_DIR/smith-relay-me.out" || gw_fail "smith relay: no 200 from the provider API"
[[ "$(oa_hits api-me bearer_ok=true)" == 1 ]] || gw_fail "the provider API did not get the connection's token"
[[ "$(oa_hits token grant=refresh_token token_ok=true client_ok=true)" == 1 ]] ||
  gw_fail "the first relay did not refresh the nearly expired token once"
[[ "$(oa_count "SELECT generation FROM oauth_connections WHERE id = '$conn'")" == 2 ]] ||
  gw_fail "the refresh did not reseal generation 2"
rc=0
gw_smith relay-echo relay --connection "$conn" --show all "$api/echo" || rc=$?
if [[ $rc -eq 0 ]]; then
  grep -q '^HTTP 200' "$ARTIFACT_DIR/smith-relay-echo.out" || gw_fail "smith relay echo: no upstream status"
  echo "smith echo redacted" >>"$ARTIFACT_DIR/results.txt"
elif grep -q 'response_withheld\|redaction_failed' "$ARTIFACT_DIR/smith-relay-echo.err"; then
  echo "smith echo refused" >>"$ARTIFACT_DIR/results.txt"
else
  gw_fail "smith relay echo: exit $rc without a redaction refusal (see smith-relay-echo.err)"
fi

# 6. The agent's own HTTP client on /v1/relay.
st="$(oa_relay_raw raw-me "$conn" GET "$api/me")"
[[ "$st" == 200 ]] || gw_fail "raw relay with the connection returned $st"
st="$(oa_relay_raw raw-echo "$conn" GET "$api/echo")"
[[ "$st" == 200 || "$st" == 502 ]] || gw_fail "raw relay to the echo returned $st (expected 200 redacted or 502)"
echo "raw echo status=$st" >>"$ARTIFACT_DIR/results.txt"
gw_unwrap "$ARTIFACT_DIR/raw-raw-me.out" "$ARTIFACT_DIR/raw-raw-echo.out"

# 7. The gateway's /mcp: list_my_keys lists the connection; relay_http_request uses it.
auth="$(gw_auth_header)"
{
  printf '{"jsonrpc":"2.0","id":"keys","method":"tools/call","params":{"name":"list_my_keys","arguments":{}}}\n'
  printf '{"jsonrpc":"2.0","id":"me","method":"tools/call","params":{"name":"relay_http_request","arguments":{"connection_id":"%s","method":"GET","url":"%s/me"}}}\n' "$conn" "$api"
  printf '{"jsonrpc":"2.0","id":"echo","method":"tools/call","params":{"name":"relay_http_request","arguments":{"connection_id":"%s","method":"GET","url":"%s/echo"}}}\n' "$conn" "$api"
} >"$GW_WORK/gw-mcp.jsonl"
python3 -I "$here/mcp_check.py" call "$GW_GATEWAY_URL" "$auth" "$GW_WORK/gw-mcp.jsonl" "$ARTIFACT_DIR/mcp-gw" ||
  gw_fail "gateway /mcp session failed (see mcp-gw.out)"
gw_unwrap "$ARTIFACT_DIR/mcp-gw.out"
python3 -I - "$ARTIFACT_DIR/mcp-gw.out" "$conn" <<'PY' || gw_fail "gateway /mcp: unexpected replies (see mcp-gw.out)"
import json, sys
replies = {}
for line in open(sys.argv[1]):
    if line.strip():
        m = json.loads(line)
        replies[m.get("id")] = m
keys = replies["keys"]["result"]
assert not keys.get("isError"), "list_my_keys failed"
assert sys.argv[2] in json.dumps(keys), "list_my_keys does not list the connection"
me = replies["me"]["result"]
assert not me.get("isError"), "relay_http_request with the connection failed"
assert '"status": 200' in json.dumps(me.get("structuredContent", me)) or "200" in json.dumps(me), "no 200"
assert "echo" in replies, "no reply for the echo relay"
PY
[[ "$(oa_hits api-me bearer_ok=true)" == 3 ]] || gw_fail "the /mcp relay did not reach the provider API with the token"

# 8. The stdio locksmith-mcp relay_request.
printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"relay_request","arguments":{"connection_id":"%s","url":"%s/me"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"relay_request","arguments":{"connection_id":"%s","url":"%s/echo"}}}\n' \
  "$conn" "$api" "$conn" "$api" >"$GW_WORK/mcp-calls.jsonl"
gw_mcp stdio "$GW_WORK/mcp-calls.jsonl" || gw_fail "locksmith-mcp failed (see mcp-stdio.err)"
gw_unwrap "$ARTIFACT_DIR/mcp-stdio.out"
[[ -s "$ARTIFACT_DIR/mcp-stdio-1.view" ]] && grep -q '^HTTP 200' "$ARTIFACT_DIR/mcp-stdio-1.view" ||
  gw_fail "locksmith-mcp relay_request with the connection did not answer 200 (see mcp-stdio.out)"
[[ "$(oa_hits api-me bearer_ok=true)" == 4 ]] || gw_fail "the stdio MCP relay did not reach the provider API"
(($(oa_hits api-echo bearer_ok=true) >= 1)) || gw_fail "the echo endpoint never got the token (nothing was reflected)"
[[ "$(oa_hits token grant=refresh_token)" == 1 ]] || gw_fail "a relay refreshed a token that was not due"

# 9. NestJS API (task 6.1) when it runs: its OAuth responses as alice, and its log.
if [[ -n "${E2E_NEST_API_URL:-}" ]] && gw_curl -f -o /dev/null -m 3 "${E2E_NEST_API_URL%/}/healthz" 2>/dev/null; then
  for p in providers connections; do
    gw_curl -H "@$GW_WORK/alice.hdr" -o "$ARTIFACT_DIR/nest-$p.out" "${E2E_NEST_API_URL%/}/v1/oauth/$p" 2>>"$ARTIFACT_DIR/nest.err" || true
  done
  [[ -n "${E2E_NEST_API_LOG:-}" && -f "$E2E_NEST_API_LOG" ]] && cp "$E2E_NEST_API_LOG" "$ARTIFACT_DIR/nest-api.log"
  echo "nest api scanned" >>"$ARTIFACT_DIR/results.txt"
else
  echo "note: apps/api is not running here (E2E_NEST_API_URL unset or down); its OAuth routes are c1 task 6.1, so its responses and logs are not scanned"
fi

# 10. Disconnect: revoked at the provider with the token, material gone, the next relay refused.
st="$(oa_call alice POST "/v1/oauth/connections/$conn/disconnect" disconnect)"
[[ "$st" == 200 ]] || gw_fail "disconnect as alice returned $st"
[[ "$(oa_field disconnect status)" == revoked ]] || gw_fail "the disconnected connection is not revoked"
[[ "$(oa_field disconnect revoked_at_provider)" == true ]] || gw_fail "disconnect did not revoke at the provider"
[[ "$(oa_hits revoke token_ok=true client_ok=true)" == 1 ]] || gw_fail "the provider did not get one revoke for the token"
[[ "$(oa_count "SELECT count(*) FROM oauth_token_material WHERE org_id = :'org'")" == 0 ]] ||
  gw_fail "the token material survived the disconnect"
n0="$(oa_hits api-me)"
st="$(oa_relay_raw after "$conn" GET "$api/me")"
[[ "$st" == 403 ]] || gw_fail "a relay after disconnect returned $st (expected 403)"
[[ "$(oa_hits api-me)" == "$n0" ]] || gw_fail "a relay after disconnect reached the provider"
if gw_smith after relay --connection "$conn" "$api/me"; then gw_fail "smith relay after disconnect succeeded"; fi
oa_dump revoked

# 11. The app role has no privilege on the token material (C1 decision 7).
if PGCONNECT_TIMEOUT=5 psql "$(gw_env DATABASE_URL)" -X -q -At -c 'SELECT count(*) FROM oauth_token_material' \
  >/dev/null 2>"$ARTIFACT_DIR/app-role.err"; then
  gw_fail "locksmith_app could read oauth_token_material"
fi
grep -q 'permission denied' "$ARTIFACT_DIR/app-role.err" || gw_fail "locksmith_app was not refused with a permission error"

# 12. Ledger: connected, relays naming the agent and alice, disconnected. The oracle scans it.
gw_ledger final
actor="agent:$GW_AGENT_ID"
connected="$(oa_ledger_has "$GW_LEDGER" oauth.connected ok "" "$OA_ALICE")"
relays="$(oa_ledger_has "$GW_LEDGER" relay.outcome "" "$actor" "$OA_ALICE")"
disconnected="$(oa_ledger_has "$GW_LEDGER" oauth.disconnected "" "" "$OA_ALICE")"
echo "ledger connected=$connected relays=$relays disconnected=$disconnected" >>"$ARTIFACT_DIR/results.txt"
[[ "$connected" == 1 ]] || gw_fail "expected one oauth.connected event naming alice"
((relays >= 4)) || gw_fail "expected relay.outcome events with the agent as actor and alice as person"
[[ "$disconnected" == 1 ]] || gw_fail "expected one oauth.disconnected event naming alice"
[[ "$(oa_ledger_has "$GW_LEDGER" oauth.refresh_failed)" == 0 ]] || gw_fail "a refresh failed"
echo "G13 ok"
