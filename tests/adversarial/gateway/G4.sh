#!/usr/bin/env bash
# G4: encodings. The secret is bound to fixtures/http_upstream.py as the provider; with `?g4=FORM`
# it returns only the injected credential, in one form per call: base32 (upper, and lower
# unpadded), UTF-16LE, UTF-16BE, `\u` escapes, HTML decimal and hex entities, quoted-printable,
# gzip without a Content-Encoding label, reversed, split across four response headers and one
# character per line. A `plain` control call checks that redaction is on (the reply must carry
# `[REDACTED`), so a leak in another form is the redactor not knowing that form, not a broken
# binding. The agent relays through `smith relay --show all` (headers and the body bytes as
# received) and through the `locksmith-mcp` tool `relay_request`; everything it receives (and the
# bytes it gets by decoding a `body_base64`) goes to ARTIFACT_DIR for the oracle.
#
# Forms the redactor does not catch are oracle hits; design decision 4 leaves some of them to
# containment and task 4.1 teaches `ls-redact` the others. Each expected hit is registered in
# residuals.toml, so run.sh reports it as RESIDUAL; a hit that is not registered fails, and a
# registered form that stops leaking fails as STALE RESIDUAL until its entry is removed.
#
# Checks, as in G2: each reply is relayed (2xx from the gateway) or refused with
# `response_withheld`; the ledger has one `relay.outcome` per call, `redaction_failed` per refusal
# and `ok` per relayed reply; the provider got the key on every call, in the bound header only.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$api"

forms=(plain b32 b32-lower utf16le utf16be json-u html-dec html-hex qp gzip reversed split-headers char-lines)
calls=0
refused=0
relayed=0
: >"$ARTIFACT_DIR/results.txt"

# result VIA FORM KIND: one line per call in results.txt (`refused` or `ok`).
result() {
  echo "$1 $2 $3" >>"$ARTIFACT_DIR/results.txt"
  calls=$((calls + 1))
  case "$3" in
    refused) refused=$((refused + 1)) ;;
    ok) relayed=$((relayed + 1)) ;;
  esac
}

# 1. smith relay, human output with headers: the header lines and body bytes as the agent sees them.
for f in "${forms[@]}"; do
  name="enc-$f"
  rc=0
  gw_smith "$name" relay --secret-id "$GW_SECRET_ID" --show all "$api/g4/smith?g4=$f" || rc=$?
  if [[ $rc -eq 0 ]]; then
    grep -q '^HTTP 200' "$ARTIFACT_DIR/smith-$name.out" || gw_fail "smith $f: no upstream status"
    result smith "$f" ok
  elif grep -q 'response_withheld' "$ARTIFACT_DIR/smith-$name.err"; then
    result smith "$f" refused
  else
    gw_fail "smith $f: exit $rc without response_withheld (see smith-$name.err)"
  fi
done
# The control: the plain form must come back redacted, or the case proves nothing.
grep -q '\[REDACTED' "$ARTIFACT_DIR/smith-enc-plain.out" ||
  gw_fail "the plain control reply was not redacted (see smith-enc-plain.out)"

# 2. The same forms through the MCP tool, in one server session.
id=0
: >"$GW_WORK/mcp-calls.jsonl"
for f in "${forms[@]}"; do
  id=$((id + 1))
  printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"relay_request","arguments":{"secret_id":"%s","url":"%s/g4/mcp?g4=%s"}}}\n' \
    "$id" "$GW_SECRET_ID" "$api" "$f" >>"$GW_WORK/mcp-calls.jsonl"
done
gw_mcp enc "$GW_WORK/mcp-calls.jsonl" || gw_fail "locksmith-mcp failed (see mcp-enc.err)"
gw_unwrap "$ARTIFACT_DIR/mcp-enc.out"
python3 -I - "$ARTIFACT_DIR/mcp-enc.out" "${forms[@]}" >"$GW_WORK/mcp-results.txt" <<'PY' || gw_fail "unexpected MCP replies"
import json, sys
path, forms = sys.argv[1], sys.argv[2:]
replies = {}
for line in open(path):
    line = line.strip()
    if line:
        msg = json.loads(line)
        replies[msg.get("id")] = msg
for i, f in enumerate(forms, 1):
    r = replies.get(i)
    if r is None or "result" not in r:
        sys.exit("no tool result for %s" % f)
    text = "".join(c.get("text", "") for c in r["result"].get("content", []))
    if r["result"].get("isError"):
        if "response_withheld" not in text:
            sys.exit("mcp %s: error without response_withheld" % f)
        print("mcp %s refused" % f)
    else:
        if json.loads(text).get("status") is None:
            sys.exit("mcp %s: no upstream status" % f)
        print("mcp %s ok" % f)
PY
while read -r via f kind; do result "$via" "$f" "$kind"; done <"$GW_WORK/mcp-results.txt"

# 3. The provider received the key on every call, in the bound header only.
hits="$(grep -c ' /g4/' "$ARTIFACT_DIR/provider-hits.log" || true)"
good="$(grep -c ' /g4/.* key=ok where=authorization$' "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits" -eq "$calls" && "$good" -eq "$calls" ]] ||
  gw_fail "the provider saw $hits calls, $good with the key in the bound header only; expected $calls"

# 4. Every refusal is a `redaction_failed` outcome in the ledger, and every attempt has an outcome.
gw_ledger after
attempts="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
outcomes="$(gw_ledger_count "$GW_LEDGER" relay.outcome)"
failed="$(gw_ledger_count "$GW_LEDGER" relay.outcome redaction_failed)"
ok="$(gw_ledger_count "$GW_LEDGER" relay.outcome ok)"
{
  echo "calls=$calls relayed=$relayed refused=$refused"
  echo "ledger attempts=$attempts outcomes=$outcomes ok=$ok redaction_failed=$failed"
} | tee "$ARTIFACT_DIR/summary.txt"
[[ "$attempts" -eq "$calls" && "$outcomes" -eq "$calls" ]] ||
  gw_fail "ledger has $attempts attempts and $outcomes outcomes for $calls calls"
[[ "$failed" -eq "$refused" ]] || gw_fail "$refused refusals but $failed redaction_failed events"
[[ "$ok" -eq "$relayed" ]] || gw_fail "$relayed relayed replies but $ok ok events"
