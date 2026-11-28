#!/usr/bin/env bash
# Harness self-check for `run.sh gateway` and the residual register (S6 task 2.3). Offline: it
# plants gateway cases and a register in a temporary directory (ADVERSARIAL_GATEWAY_DIR) and
# checks that an unlisted leak fails, a listed form reports RESIDUAL, a stale entry fails, an
# entry with `artifacts` is judged per listed file, a register entry for a missing case fails, a bad register fails, case filters work, skips follow
# ADVERSARIAL_REQUIRE_ALL, lib.sh skips with `skip: stack not running`, the OAuth provider stub
# (fixtures/oauth_provider.py) enforces what G13 and G14 rely on, ADVERSARIAL_KEEP=1 keeps
# the work directory, and run.sh never prints a canary. Usage: tests/adversarial/run_test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run="$here/run.sh"
umask 077
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
fail=0
ok() { echo "PASS  $1"; }
bad() {
  echo "FAIL  $1"
  fail=1
}

# Every planted case copies its canary to $t/spy so the final check can look for it in the output.
mkdir -p "$t/spy" "$t/g"
plant() { # plant <id> <body>
  cat >"$t/g/$1.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cp "\$CANARY_FILE" "$t/spy/$1.canary"
c="\$(cat "\$CANARY_FILE")"
$2
EOF
}
plant G1-clean 'echo "nothing here" >"$ARTIFACT_DIR/out.txt"'
plant G2-unlisted 'printf "%s\n" "$c" >"$ARTIFACT_DIR/out.txt"; echo "case printed $c"'
plant G3-listed 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/out.txt"'
plant G4-stale 'echo "nothing here" >"$ARTIFACT_DIR/out.txt"'
plant G5-mixed 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/a.txt"; printf "%s" "$c" | base64 >"$ARTIFACT_DIR/b.txt"'
plant G6-skip 'echo "skip: planted skip"; exit 77'
plant G7-joined 'printf "%s" "$c" | gzip >"$ARTIFACT_DIR/out.bin"'
# Per-route entries (`artifacts`): both routes leak; one route stops; a third file leaks.
plant G10-routes 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/smith.out"; printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/mcp.view"'
plant G11-oneroute 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/smith.out"; echo "nothing here" >"$ARTIFACT_DIR/mcp.view"'
plant G12-otherfile 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/smith.out"; printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/mcp.view"; printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/extra.txt"'
# A case that uses the real lib.sh against a control plane that is not there.
cat >"$t/g/G8-nostack.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cp "\$CANARY_FILE" "$t/spy/G8-nostack.canary"
. "$here/gateway/lib.sh"
gw_init
echo "should not get here" >&2
exit 1
EOF

entry() { # entry <case> <encoding>
  printf '[[residual]]\ncase = "%s"\nencoding = "%s"\nlabel = "containment"\nreason = "planted"\n\n' "$1" "$2"
}
{
  entry G3-listed text-reversed
  entry G4-stale b32-offset0
  entry G5-mixed text-reversed
  # The canary text is base64url, so one plain copy also hits b64url-offset0: list each label.
  entry G7-joined gzip/utf8
  entry G7-joined gzip/b64url-offset0
  for c in G10-routes G11-oneroute G12-otherfile; do
    printf '[[residual]]\ncase = "%s"\nencoding = "text-reversed"\nlabel = "containment"\nreason = "planted"\nartifacts = ["smith.out", "mcp.view"]\n\n' "$c"
  done
} >"$t/g/residuals.toml"

# gw <out-name> [env...] -- [run.sh args]: run run.sh with the planted directory.
gw() {
  local name="$1" rc=0
  shift
  local envs=()
  while [[ $# -gt 0 && "$1" != -- ]]; do
    envs+=("$1")
    shift
  done
  shift
  env ADVERSARIAL_GATEWAY_DIR="$t/g" E2E_API_URL=http://127.0.0.1:9 ${envs[@]+"${envs[@]}"} \
    bash "$run" "$@" >"$t/$name.out" 2>&1 || rc=$?
  echo "$rc" >"$t/$name.rc"
}
has() { grep -qF -- "$2" "$t/$1.out"; }
rc_is() { [[ "$(cat "$t/$1.rc")" == "$2" ]]; }
check() { # check <name> <description> <condition...>
  local n="$1" d="$2"
  shift 2
  if "$@"; then ok "$d"; else
    bad "$d"
    sed 's/^/    /' "$t/$n.out" | tail -n 30
  fi
}

gw filtered -- gateway G1-clean G3-listed
check filtered "filter runs only the named cases; clean case is PASS" \
  bash -c "grep -qx 'PASS case G1-clean' '$t/filtered.out' && ! grep -q 'G4-stale\|G2-unlisted' '$t/filtered.out'"
check filtered "listed form reports RESIDUAL and passes" \
  bash -c "grep -qF 'RESIDUAL G3-listed text-reversed (containment)' '$t/filtered.out' && grep -qx 'RESIDUAL case G3-listed' '$t/filtered.out' && [[ \$(cat '$t/filtered.rc') == 0 ]]"
check filtered "summary counts the residual" has filtered "summary: 1 passed, 0 failed, 0 skipped, 1 residual"

gw unlisted -- gateway G2-unlisted
check unlisted "unlisted leak fails naming case and encoding" \
  bash -c "grep -q '^FAIL case G2-unlisted: unlisted leak utf8' '$t/unlisted.out' && grep -qx 'FAIL case G2-unlisted' '$t/unlisted.out' && [[ \$(cat '$t/unlisted.rc') == 1 ]]"

gw stale -- gateway G4-stale
check stale "stale entry fails as STALE RESIDUAL" \
  bash -c "grep -qF 'STALE RESIDUAL G4-stale b32-offset0' '$t/stale.out' && grep -qx 'FAIL case G4-stale' '$t/stale.out' && [[ \$(cat '$t/stale.rc') == 1 ]]"

gw mixed -- gateway G5-mixed
check mixed "a listed form does not excuse an unlisted one" \
  bash -c "grep -qF 'RESIDUAL G5-mixed text-reversed' '$t/mixed.out' && grep -q '^FAIL case G5-mixed: unlisted leak text-b64' '$t/mixed.out' && grep -qx 'FAIL case G5-mixed' '$t/mixed.out'"

gw joined -- gateway G7-joined
check joined "an entry matches one name of a joined label in a view (gzip/utf8)" \
  bash -c "grep -q '^RESIDUAL G7-joined gzip/utf8' '$t/joined.out' && grep -qx 'RESIDUAL case G7-joined' '$t/joined.out' && [[ \$(cat '$t/joined.rc') == 0 ]]"

gw routes -- gateway G10-routes
check routes "an entry with artifacts reports RESIDUAL when every listed file leaks" \
  bash -c "grep -qF 'RESIDUAL G10-routes text-reversed (containment)' '$t/routes.out' && grep -qx 'RESIDUAL case G10-routes' '$t/routes.out' && [[ \$(cat '$t/routes.rc') == 0 ]]"
gw oneroute -- gateway G11-oneroute
check oneroute "a listed file without a hit is STALE RESIDUAL even when another listed file leaks" \
  bash -c "grep -qF 'STALE RESIDUAL G11-oneroute text-reversed in mcp.view (registered, no hit)' '$t/oneroute.out' && grep -qx 'FAIL case G11-oneroute' '$t/oneroute.out' && [[ \$(cat '$t/oneroute.rc') == 1 ]]"
gw otherfile -- gateway G12-otherfile
check otherfile "an entry with artifacts does not excuse the same encoding in another file" \
  bash -c "grep -qF 'FAIL case G12-otherfile: unlisted leak text-reversed in extra.txt' '$t/otherfile.out' && grep -qx 'FAIL case G12-otherfile' '$t/otherfile.out' && [[ \$(cat '$t/otherfile.rc') == 1 ]]"

gw skip -- gateway G6-skip G8-nostack
check skip "skips are SKIP without ADVERSARIAL_REQUIRE_ALL; lib.sh says stack not running" \
  bash -c "grep -qx 'SKIP case G6-skip (planted skip)' '$t/skip.out' && grep -q '^SKIP case G8-nostack (stack not running' '$t/skip.out' && [[ \$(cat '$t/skip.rc') == 0 ]]"
gw skipreq ADVERSARIAL_REQUIRE_ALL=1 -- gateway G8-nostack
check skipreq "ADVERSARIAL_REQUIRE_ALL=1 turns a skip into FAIL" \
  bash -c "grep -qx 'FAIL case G8-nostack' '$t/skipreq.out' && [[ \$(cat '$t/skipreq.rc') == 1 ]]"

# A register entry for a case that does not exist is stale in a full run only.
entry G9-gone text-reversed >>"$t/g/residuals.toml"
gw full -- gateway
check full "full run: entry for a missing case is STALE RESIDUAL and the run fails" \
  bash -c "grep -qF 'STALE RESIDUAL G9-gone text-reversed (no case G9-gone' '$t/full.out' && [[ \$(cat '$t/full.rc') == 1 ]]"
gw filtered2 -- gateway G3-listed
check filtered2 "filtered run ignores entries of cases it did not run" rc_is filtered2 0

# A bad register (no reason, unknown label, wildcard) fails before any case runs.
cp "$t/g/residuals.toml" "$t/residuals.good"
printf '[[residual]]\ncase = "G3-listed"\nencoding = "*"\nlabel = "hope"\nartifacts = ["../x"]\n' >>"$t/g/residuals.toml"
gw badreg -- gateway G1-clean
check badreg "invalid register fails the run" \
  bash -c "grep -q 'residual register' '$t/badreg.out' && grep -q 'reason. is missing' '$t/badreg.out' && grep -q 'no wildcards' '$t/badreg.out' && grep -q 'label must be one of' '$t/badreg.out' && grep -q 'artifacts. must be' '$t/badreg.out' && [[ \$(cat '$t/badreg.rc') == 1 ]]"
cp "$t/residuals.good" "$t/g/residuals.toml"

gw nocase -- gateway G42
check nocase "unknown gateway case exits 2" bash -c "grep -q 'no case matches: gateway G42' '$t/nocase.out' && [[ \$(cat '$t/nocase.rc') == 2 ]]"

# ADVERSARIAL_KEEP=1 keeps the work directory with each case's artifacts.
gw keep ADVERSARIAL_KEEP=1 -- gateway G3-listed
kept="$(sed -n 's/^kept: \([^ ]*\) .*/\1/p' "$t/keep.out")"
check keep "ADVERSARIAL_KEEP=1 keeps the artifacts" \
  bash -c "[[ -n '$kept' && -f '$kept/G3-listed.artifacts/out.txt' && -f '$kept/G3-listed.log' ]]"
[[ -n "$kept" && -d "$kept" ]] && rm -rf "$kept"
gw nokeep -- gateway G3-listed
check nokeep "without ADVERSARIAL_KEEP nothing is kept" bash -c "! grep -q '^kept:' '$t/nokeep.out'"

# The remote-MCP cases (G9, G10) share gateway/mcp_check.py: its value-like rule must match
# `ls_mcp_server::FORBIDDEN_LAST_WORDS`, and its scans must fail on planted tool lists and results.
chk="$here/gateway/mcp_check.py"
rust_words="$(sed -n '/FORBIDDEN_LAST_WORDS: \[&str; [0-9]*\] = \[/,/^\];/p' "$here/../../crates/ls-mcp-server/src/lib.rs" |
  sed -n 's/^ *"\([a-z]*\)",$/\1/p' | tr '\n' ' ')"
if [[ -n "$rust_words" && "$(python3 -I "$chk" words | tr -d '\n')" == "${rust_words% }" ]]; then
  ok "mcp_check.py forbidden words match ls-mcp-server"
else
  bad "mcp_check.py forbidden words differ from crates/ls-mcp-server (rust: $rust_words)"
fi
mcp_tools() { # mcp_tools <file> <input-props-json> <output-props-json-or-null> [extra output schema keys]
  python3 -I - "$@" <<'PY'
import json, sys
f, inp, out = sys.argv[1:4]
tool = {"name": "t", "inputSchema": {"type": "object", "properties": json.loads(inp), "additionalProperties": False}}
if out != "null":
    tool["outputSchema"] = {"type": "object", "properties": json.loads(out), "additionalProperties": False}
open(f, "w").write(json.dumps({"jsonrpc": "2.0", "id": "list", "result": {"tools": [tool]}}) + "\n")
PY
}
mcp_scan() { python3 -I "$chk" scan-tools "$@" >"$t/mcp-scan.out" 2>&1; }
mcp_tools "$t/mcp-clean.json" '{"secret_id":{"type":"string"},"token_expires_at":{"type":"string"}}' '{"status":{"type":"integer"},"body":{"type":"string"}}'
if mcp_scan "$t/mcp-clean.json" --present t --absent other; then ok "mcp_check scan-tools accepts a clean tool list (secret_id, token_expires_at)"; else bad "mcp_check rejected a clean tool list"; fi
for field in apiKey client-secret accessToken PRIVATE_PEM db.password; do
  mcp_tools "$t/mcp-bad.json" "{\"$field\":{\"type\":\"string\"}}" '{"ok":{"type":"boolean"}}'
  if mcp_scan "$t/mcp-bad.json"; then bad "mcp_check missed the value-like input field $field"; else ok "mcp_check flags the value-like input field $field"; fi
done
mcp_tools "$t/mcp-bad.json" '{"id":{"type":"string"}}' '{"nested":{"type":"object","properties":{"value":{"type":"string"}},"additionalProperties":false}}'
if mcp_scan "$t/mcp-bad.json"; then bad "mcp_check missed a nested value-like output field"; else ok "mcp_check flags a nested value-like output field"; fi
mcp_tools "$t/mcp-bad.json" '{"id":{"type":"string"}}' null
if mcp_scan "$t/mcp-bad.json"; then bad "mcp_check accepted a tool with no output schema"; else ok "mcp_check flags a tool with no output schema"; fi
printf '%s\n' '{"jsonrpc":"2.0","id":"list","result":{"tools":[{"name":"t","inputSchema":{"type":"object","patternProperties":{"^.*$":{"type":"string"}},"additionalProperties":false},"outputSchema":{"type":"object","properties":{},"additionalProperties":false}}]}}' >"$t/mcp-bad.json"
if mcp_scan "$t/mcp-bad.json"; then bad "mcp_check missed an open map"; else ok "mcp_check flags an open map"; fi
if mcp_scan "$t/mcp-clean.json" --absent t; then bad "mcp_check missed a listed tool that must be off"; else ok "mcp_check flags a listed tool that must be off"; fi
if mcp_scan "$t/mcp-clean.json" --present nothere; then bad "mcp_check missed a missing tool"; else ok "mcp_check flags a missing tool"; fi
printf '%s\n' '{"jsonrpc":"2.0","id":"a","result":{"structuredContent":{"items":[{"secret_id":"x","accessToken":"y"}]}}}' >"$t/mcp-keys.json"
if python3 -I "$chk" scan-keys "$t/mcp-keys.json" >/dev/null 2>&1; then bad "mcp_check scan-keys missed a value-like result key"; else ok "mcp_check scan-keys flags a value-like result key"; fi
printf '%s\n' '{"jsonrpc":"2.0","id":"a","result":{"structuredContent":{"items":[{"secret_id":"x","token_expires_at":"y"}]}}}' >"$t/mcp-keys.json"
if python3 -I "$chk" scan-keys "$t/mcp-keys.json" >/dev/null 2>&1; then ok "mcp_check scan-keys accepts metadata keys"; else bad "mcp_check scan-keys rejected metadata keys"; fi

# The OAuth provider stub of G13 and G14 (fixtures/oauth_provider.py) must really enforce what the
# cases rely on: PKCE S256 at authorize and at the token endpoint, single-use codes, client
# credentials, the canary refresh token, the redirect modes, and a request log without values.
if command -v openssl >/dev/null 2>&1; then
  oap="$here/fixtures/oauth_provider.py"
  o="$t/oauth"
  mkdir -p "$o"
  python3 -I "$here/../kit/oracle.py" gen >"$o/canary"
  cp "$o/canary" "$t/spy/oauth.canary"
  echo normal >"$o/mode"
  printf 'acme-client-secret' >"$o/secret"
  python3 -I "$oap" keygen "$o/idp"
  python3 -I "$oap" serve "$o/port" "$o/hits.log" "$o/mode" "$o/canary" "$o/idp" acme-client "$o/secret" 2>"$o/err" &
  oap_pid=$!
  for _ in $(seq 1 100); do [[ -s "$o/port" ]] && break; sleep 0.05; done
  python3 -I - "http://127.0.0.1:$(cat "$o/port")" "$o" >"$t/oauth-stub.out" 2>&1 <<'PY' && ok "oauth_provider.py enforces PKCE S256, single-use codes, client and refresh checks" || bad "oauth_provider.py: $(tail -n 1 "$t/oauth-stub.out")"
import base64, hashlib, json, secrets, sys, urllib.error, urllib.parse, urllib.request
base, o = sys.argv[1:3]
realm = base + "/realms/provider/protocol/openid-connect"
canary = open(o + "/canary").read().strip()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):
        return None
op = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
def call(url, form=None, headers=None):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode() if form else None,
                                 headers=headers or {})
    try:
        r = op.open(req, timeout=10)
        return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
def check(cond, what):
    if not cond:
        sys.exit("FAILED: " + what)
redirect = "http://127.0.0.1:9/oauth/callback"
v = secrets.token_urlsafe(48)
ch = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
def authorize(method="S256"):
    q = {"response_type": "code", "client_id": "acme-client", "redirect_uri": redirect, "state": "s1",
         "code_challenge": ch, "code_challenge_method": method}
    st, h, _ = call(realm + "/auth?" + urllib.parse.urlencode(q))
    check(st == 302, "authorize answers 302")
    return urllib.parse.parse_qs(urllib.parse.urlsplit(h.get("Location", "")).query)
check(json.loads(call(base + "/idp/jwks")[2])["keys"][0]["kid"] == "adv-1", "jwks served")
check("error" in authorize("plain") and "code" not in authorize("plain"), "plain PKCE refused")
code = authorize()["code"][0]
tok = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": "acme-client",
       "client_secret": "acme-client-secret"}
check(call(realm + "/token", tok)[0] == 400, "a code without the verifier is refused")
check(call(realm + "/token", dict(tok, code_verifier="wrong" * 10))[0] == 400, "a wrong verifier is refused")
check(call(realm + "/token", dict(tok, code_verifier=v, client_secret="nope"))[0] == 401, "a wrong client secret is refused")
check(call(realm + "/token", dict(tok, code_verifier=v, redirect_uri=redirect + "x"))[0] == 400, "another redirect_uri is refused")
st, _, body = call(realm + "/token", dict(tok, code_verifier=v))
check(st == 200 and json.loads(body)["access_token"] == canary, "the right verifier gets the canary token")
check(call(realm + "/token", dict(tok, code_verifier=v))[0] == 400, "a code is single use")
ref = {"grant_type": "refresh_token", "client_id": "acme-client", "client_secret": "acme-client-secret"}
check(call(realm + "/token", dict(ref, refresh_token="other"))[0] == 400, "another refresh token is refused")
check(call(realm + "/token", dict(ref, refresh_token=canary))[0] == 200, "the canary refresh token refreshes")
check(call(base + "/api/me")[0] == 401, "the API wants the bearer")
check(call(base + "/api/me", headers={"Authorization": "Bearer " + canary})[0] == 200, "the API takes the canary bearer")
open(o + "/mode", "w").write("redirect-307\nhttp://127.0.0.1:9/steal\n")
st, h, _ = call(realm + "/token", dict(tok, code_verifier=v))
check(st == 307 and h.get("Location") == "http://127.0.0.1:9/steal", "redirect mode answers 307 to the target")
hits = open(o + "/hits.log").read()
check(canary not in hits and v not in hits and code not in hits and "acme-client-secret" not in hits,
      "the request log holds no value")
print("ok")
PY
  kill "$oap_pid" 2>/dev/null || true
  wait "$oap_pid" 2>/dev/null || true
  python3 -I "$here/fixtures/oauth_provider.py" mint "$o/idp" http://idp.example acme-api alice "$o/alice.hdr"
  if grep -q '^Authorization: Bearer [A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$' "$o/alice.hdr"; then
    ok "oauth_provider.py mints an RS256 token header"
  else
    bad "oauth_provider.py mint wrote no bearer header"
  fi
else
  echo "SKIP  oauth_provider.py checks (openssl is not installed)"
fi
for f in "$here"/gateway/*.sh; do
  bash -n "$f" || bad "syntax: $f"
done

# Nothing run.sh printed holds a canary in any encoding the oracle knows.
cat "$t/spy"/*.canary >"$t/all.canaries"
cat "$t"/*.out >"$t/printed.txt"
if python3 -I "$here/../kit/oracle.py" scan --canary-file "$t/all.canaries" "$t/printed.txt" >"$t/leak.out" 2>&1; then
  ok "run.sh output holds no canary ($(wc -l <"$t/all.canaries" | tr -d ' ') canaries)"
else
  bad "run.sh output holds a canary: $(head -n 3 "$t/leak.out")"
fi

if [[ $fail -ne 0 ]]; then
  echo "run_test: FAILED"
  exit 1
fi
echo "run_test: all passed"
