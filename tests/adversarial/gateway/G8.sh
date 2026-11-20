#!/usr/bin/env bash
# G8: Git delegation (D1 task 3.2): the error channel and header echo of /git/{host}/{owner}/{repo}/...
# The secret is bound as a Git credential (`[[git_binding]]`, fetch only, owner `acme`) to
# fixtures/http_upstream.py as the provider, which for `.git/` paths echoes the injected
# `Authorization: Basic base64(x-access-token:<canary>)` in many forms in the body and in
# X-Echo-*, Set-Cookie, Location and WWW-Authenticate, and also in Cache-Control, Pragma and
# Expires (the headers the Git route passes back); a repository named `errNNN` answers with that
# status, the echo being the error page. The agent speaks smart HTTP to the gateway with its token,
# as a Git client would (curl; the `smith git` helper arrives with D1 task 4.1):
#   - ok:    GET info/refs of `acme/echo` and POST git-upload-pack: the echo comes back as 200 text
#            (not a Git stream, so it is scanned);
#   - error: the same two calls against `acme/err403`, `err404` and `err500`: the upstream's
#            error status and page pass through, with the credential redacted;
#   - denied: a push (git-receive-pack, a fetch-only binding), an unbound owner and a non-Git
#            path: 403, with no request reaching the provider;
#   - unauthenticated: 401 with the gateway's own Basic challenge, no provider request.
# Checks: the control (`echo`) reply carries `[REDACTED`, so redaction is on and a leak is the
# redactor missing a form; the response head has no X-Echo-*, Set-Cookie, Location or
# WWW-Authenticate (the route passes an allow-list); the provider received the key once per call
# that was allowed, in the Authorization header only; the ledger holds one `git.fetch` event per
# allowed call (status the upstream's), one `git.denied` per refusal, no `git.push`, no
# `relay.attempt` (a Git call has no attempt) and nothing for the unauthenticated call. run.sh
# scans every saved file for the canary (the ledger export included).
# Not covered, by design: a 2xx `application/x-git-*` body (pack data and pkt-lines) is relayed raw,
# because rewriting it would corrupt the protocol; only its headers are scanned.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture api provider
provider_port="$GW_FIXTURE_PORT"

# The Git binding replaces the relay binding gw_setup writes (same file, same gateway).
gw_bind() {
  GW_BINDINGS="$GW_WORK/bindings.toml"
  python3 -I -c '
import json, sys
org, sid, port, out = sys.argv[1:5]
q = json.dumps  # a JSON string is a valid TOML basic string
with open(out, "w") as fh:
    fh.write("org_id = %s\n[[git_binding]]\nsecret_id = %s\nhost = \"127.0.0.1\"\nrepo_prefix = \"acme\"\n"
             "services = [\"fetch\"]\nallow_private_hosts = true\nplain_http = true\nport = %s\n"
             % (q(org), q(sid), port))
' "$GW_ORG" "$GW_SECRET_ID" "$provider_port" "$GW_BINDINGS"
}
gw_setup "http://127.0.0.1:$provider_port"

auth="$(gw_auth_header)"
git_url="$GW_GATEWAY_URL/git/127.0.0.1/acme"
: >"$ARTIFACT_DIR/results.txt"

# git_call NAME METHOD URL [extra curl args]: the response head and body go to
# ARTIFACT_DIR/git-NAME.hdr and .out; prints the HTTP status.
git_call() {
  local name="$1" method="$2" url="$3"
  shift 3
  gw_curl -X "$method" -H "@$auth" "$@" -D "$ARTIFACT_DIR/git-$name.hdr" -o "$ARTIFACT_DIR/git-$name.out" \
    -w '%{http_code}' "$url" 2>>"$ARTIFACT_DIR/git-$name.err" || echo 000
}

# expect NAME STATUS: record and check a status.
expect() {
  echo "$1 gateway=$2" >>"$ARTIFACT_DIR/results.txt"
  [[ "$2" == "$3" ]] || gw_fail "$1: gateway answered $2 (expected $3)"
}

# The response head an agent gets must not carry the provider's echo headers.
no_echo_headers() {
  if grep -qiE '^(x-echo-|set-cookie:|location:|www-authenticate:)' "$ARTIFACT_DIR/git-$1.hdr"; then
    gw_fail "$1: an echo header reached the agent"
  fi
}

allowed=0
fetch_ok() { # NAME REPO STATUS
  local name="$1" repo="$2" want="$3" st
  st="$(git_call "$name-refs" GET "$git_url/$repo.git/info/refs?service=git-upload-pack")"
  expect "$name-refs" "$st" "$want"
  no_echo_headers "$name-refs"
  st="$(git_call "$name-pack" POST "$git_url/$repo.git/git-upload-pack" \
    -H 'Content-Type: application/x-git-upload-pack-request' --data-binary '0000')"
  expect "$name-pack" "$st" "$want"
  no_echo_headers "$name-pack"
  allowed=$((allowed + 2))
}

fetch_ok ok echo 200
fetch_ok err403 err403 403
fetch_ok err404 err404 404
fetch_ok err500 err500 500

# The control: the echo is there, redacted (and the marker is in the body, not only the headers).
grep -q '\[REDACTED' "$ARTIFACT_DIR/git-ok-refs.out" || gw_fail "control: no [REDACTED marker in the echoed body (is redaction on?)"
grep -q '\[REDACTED' "$ARTIFACT_DIR/git-err403-refs.out" || gw_fail "err403: no [REDACTED marker in the error page"
grep -qi '^cache-control:.*\[REDACTED' "$ARTIFACT_DIR/git-ok-refs.hdr" || gw_fail "control: the echo in Cache-Control was not redacted in place"

# Denials: no request reaches the provider.
hits_before="$(grep -c . "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits_before" == "$allowed" ]] || gw_fail "provider saw $hits_before requests before the denials (expected $allowed)"
expect push "$(git_call push POST "$git_url/echo.git/git-receive-pack" -H 'Content-Type: application/x-git-receive-pack-request' --data-binary '0000')" 403
grep -q 'service_denied' "$ARTIFACT_DIR/git-push.out" || gw_fail "push: not a service_denied refusal"
expect refs-push "$(git_call refs-push GET "$git_url/echo.git/info/refs?service=git-receive-pack")" 403
expect unbound-owner "$(git_call unbound-owner GET "$GW_GATEWAY_URL/git/127.0.0.1/other/echo.git/info/refs?service=git-upload-pack")" 403
expect other-path "$(git_call other-path GET "$git_url/echo.git/objects/info/packs")" 403
denied=4
hits_after="$(grep -c . "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits_after" == "$hits_before" ]] || gw_fail "a denied call reached the provider ($hits_before -> $hits_after)"

# Unauthenticated: the gateway's own challenge, nothing upstream.
st="$(gw_curl -D "$ARTIFACT_DIR/git-anon.hdr" -o "$ARTIFACT_DIR/git-anon.out" -w '%{http_code}' \
  "$git_url/echo.git/info/refs?service=git-upload-pack" 2>/dev/null || echo 000)"
expect anon "$st" 401
grep -qi '^www-authenticate: Basic realm="locksmith"' "$ARTIFACT_DIR/git-anon.hdr" || gw_fail "anon: no gateway Basic challenge"

# The provider got the key once per allowed call, in the Authorization header only.
grep -c 'key=ok where=authorization$' "$ARTIFACT_DIR/provider-hits.log" | grep -qx "$allowed" ||
  gw_fail "provider: the key did not arrive $allowed times in the Authorization header only"
[[ "$(grep -c 'key=no' "$ARTIFACT_DIR/provider-hits.log" || true)" == 0 ]] || gw_fail "provider: a request arrived without the key"

# Ledger: one event per allowed call and per refusal; no attempt; nothing for the anonymous call.
gw_ledger final
fetches="$(gw_ledger_count "$GW_LEDGER" git.fetch ok)"
[[ "$fetches" == "$allowed" ]] || gw_fail "git.fetch ok events: $fetches (expected $allowed)"
[[ "$(gw_ledger_count "$GW_LEDGER" git.denied denied)" == "$denied" ]] || gw_fail "git.denied events: expected $denied"
[[ "$(gw_ledger_count "$GW_LEDGER" git.push)" == 0 ]] || gw_fail "a git.push event for a push that was refused"
[[ "$(gw_ledger_count "$GW_LEDGER" relay.attempt)" == 0 ]] || gw_fail "a relay.attempt event for a Git call"
python3 -I -c '
import json, sys
ev = [e for e in json.load(open(sys.argv[1])) if e["kind"] == "git.fetch"]
def status(e):
    v = e.get("attrs", {}).get("status")
    return str(v["int"] if isinstance(v, dict) else v)
st = sorted(status(e) for e in ev)
want = sorted(["200"] * 2 + ["403"] * 2 + ["404"] * 2 + ["500"] * 2)
sys.exit(0 if st == want else "git.fetch statuses %s, expected %s" % (st, want))
' "$GW_LEDGER" || gw_fail "git.fetch events do not carry the upstream statuses"
echo "G8 ok"
