#!/usr/bin/env bash
# G2: reflection. The secret is bound to fixtures/http_upstream.py as the provider, which
# reflects the injected header back in many encodings, in the response headers and body. The
# agent relays to it through `smith relay` and the `locksmith-mcp` tool `relay_request` in every
# reflection mode the fixture has: plain, Content-Encoding gzip, deflate, br, zstd, stacked
# gzip,gzip, a duplicated Content-Encoding line, Transfer-Encoding gzip, a body chunked byte by
# byte, and a slow event stream. Everything the agent receives (and the bytes it gets by decoding
# a `body_base64`) goes to ARTIFACT_DIR for the oracle.
#
# Each reply must be either redacted (2xx from the gateway) or a refusal; every refusal must be
# `response_withheld` and the ledger must hold exactly one `relay.outcome` event with outcome
# `redaction_failed` per refusal. The provider must have received the key, in the bound header
# only, on every call.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
gw_init

gw_fixture api provider
api="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$api"

modes=(plain enc=gzip enc=deflate enc=br enc=zstd enc=gzip,gzip dup=1 te=gzip split=1 sse=1)
calls=0
refused=0
redacted=0
: >"$ARTIFACT_DIR/results.txt"

# result VIA MODE KIND: one line per call in results.txt (`refused` or `ok`).
result() {
  echo "$1 $2 $3" >>"$ARTIFACT_DIR/results.txt"
  calls=$((calls + 1))
  case "$3" in
    refused) refused=$((refused + 1)) ;;
    ok) redacted=$((redacted + 1)) ;;
  esac
}

# 1. smith relay, human output with headers: the body bytes as the agent sees them.
for m in "${modes[@]}" post; do
  name="reflect-${m//[=,]/-}"
  q="?$m"
  [[ $m == plain || $m == post ]] && q=""
  args=(relay --secret-id "$GW_SECRET_ID" --show all)
  [[ $m == post ]] && args+=(-X POST --data "g2 body")
  rc=0
  gw_smith "$name" "${args[@]}" "$api/g2/smith$q" || rc=$?
  if [[ $rc -eq 0 ]]; then
    grep -q '^HTTP 200' "$ARTIFACT_DIR/smith-$name.out" || gw_fail "smith $m: no upstream status"
    result smith "$m" ok
  elif grep -q 'response_withheld' "$ARTIFACT_DIR/smith-$name.err"; then
    result smith "$m" refused
  else
    gw_fail "smith $m: exit $rc without response_withheld (see smith-$name.err)"
  fi
done

# 2. The same modes through the MCP tool, in one server session.
id=0
: >"$GW_WORK/mcp-calls.jsonl"
for m in "${modes[@]}"; do
  id=$((id + 1))
  q="?$m"
  [[ $m == plain ]] && q=""
  printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"relay_request","arguments":{"secret_id":"%s","url":"%s/g2/mcp%s"}}}\n' \
    "$id" "$GW_SECRET_ID" "$api" "$q" >>"$GW_WORK/mcp-calls.jsonl"
done
gw_mcp reflect "$GW_WORK/mcp-calls.jsonl" || gw_fail "locksmith-mcp failed (see mcp-reflect.err)"
gw_unwrap "$ARTIFACT_DIR/mcp-reflect.out"
python3 -I - "$ARTIFACT_DIR/mcp-reflect.out" "${modes[@]}" >"$GW_WORK/mcp-results.txt" <<'PY' || gw_fail "unexpected MCP replies"
import json, sys
path, modes = sys.argv[1], sys.argv[2:]
replies = {}
for line in open(path):
    line = line.strip()
    if line:
        msg = json.loads(line)
        replies[msg.get("id")] = msg
for i, m in enumerate(modes, 1):
    r = replies.get(i)
    if r is None or "result" not in r:
        sys.exit("no tool result for %s" % m)
    text = "".join(c.get("text", "") for c in r["result"].get("content", []))
    if r["result"].get("isError"):
        if "response_withheld" not in text:
            sys.exit("mcp %s: error without response_withheld" % m)
        print("mcp %s refused" % m)
    else:
        if json.loads(text).get("status") is None:
            sys.exit("mcp %s: no upstream status" % m)
        print("mcp %s ok" % m)
PY
while read -r via m kind; do result "$via" "$m" "$kind"; done <"$GW_WORK/mcp-results.txt"

# 3. The provider received the key on every call, in the bound header only.
hits="$(grep -c ' /g2/' "$ARTIFACT_DIR/provider-hits.log" || true)"
good="$(grep -c ' /g2/.* key=ok where=authorization$' "$ARTIFACT_DIR/provider-hits.log" || true)"
[[ "$hits" -eq "$calls" && "$good" -eq "$calls" ]] ||
  gw_fail "the provider saw $hits calls, $good with the key in the bound header only; expected $calls"

# 4. Every refusal is a `redaction_failed` outcome in the ledger, and every attempt has an outcome.
gw_ledger after
attempts="$(gw_ledger_count "$GW_LEDGER" relay.attempt)"
outcomes="$(gw_ledger_count "$GW_LEDGER" relay.outcome)"
failed="$(gw_ledger_count "$GW_LEDGER" relay.outcome redaction_failed)"
ok="$(gw_ledger_count "$GW_LEDGER" relay.outcome ok)"
{
  echo "calls=$calls redacted=$redacted refused=$refused"
  echo "ledger attempts=$attempts outcomes=$outcomes ok=$ok redaction_failed=$failed"
} | tee "$ARTIFACT_DIR/summary.txt"
[[ "$attempts" -eq "$calls" && "$outcomes" -eq "$calls" ]] ||
  gw_fail "ledger has $attempts attempts and $outcomes outcomes for $calls calls"
[[ "$failed" -eq "$refused" ]] || gw_fail "$refused refusals but $failed redaction_failed events"
[[ "$ok" -eq "$redacted" ]] || gw_fail "$redacted redacted replies but $ok ok events"
[[ "$redacted" -ge 2 ]] || gw_fail "no reply was relayed redacted; the case proves nothing"
