#!/usr/bin/env bash
# F1 leak-scan check (needs `just up`). Plants a fresh canary in each source in turn (Postgres,
# Loki, Tempo, a directory, a transcript) and expects `just leak-scan` to report it there; checks
# SOURCE-UNREACHABLE; then expects a clean scan with full coverage. Finally every line the scanner
# printed is checked for any encoding, or any 8-byte fragment, of every canary used.
# Canaries go to throwaway files (LOCKSMITH_CANARIES), never infra/compose/.canaries.
# Usage: tests/kit/leak_scan_test.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
umask 077
work="$(mktemp -d)"
out="$work/scanner-output.log" # everything the scanner printed, checked at the end
all="$work/all.canaries"       # every canary this run minted
: >"$out"
: >"$all"

eval "$(grep -E '^POSTGRES_(USER|PASSWORD|DB)=' infra/compose/.env.example)"
export PGHOST=127.0.0.1 PGPORT=5432 PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE="$POSTGRES_DB"
pg() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -f "$1" >/dev/null; }

cleanup() {
  printf 'DROP TABLE IF EXISTS leak_scan_test, leak_scan_clean;\n' >"$work/drop.sql"
  pg "$work/drop.sql" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

fail=0
pass() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

# mint <phase>: a fresh canary becomes the only active one.
mint() {
  export LOCKSMITH_CANARIES="$work/$1.canaries"
  just canary new >>"$out"
  cat "$LOCKSMITH_CANARIES" >>"$all"
}

# render <encoding> <template>: the template with @CANARY@ replaced by the active canary in that
# encoding. Output always goes to a file, never the terminal.
render() {
  python3 -I -c '
import base64, sys
v = open(sys.argv[1]).read().split()[-1]
raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
b64 = base64.b64encode(raw).decode()
enc = {
    "utf8": v,
    "hex-lower": raw.hex(),
    "b64": b64,
    "b64-json2": b64.replace("/", "\\\\/"),  # an escaped slash inside a JSON-in-JSON string
    "basic-auth": base64.b64encode(b"user:" + v.encode()).decode(),
}[sys.argv[2]]
sys.stdout.write(sys.argv[3].replace("@CANARY@", enc))
' "$LOCKSMITH_CANARIES" "$1" "$2"
}

# scan [args]: run `just leak-scan`, keep its output in $work/last and $out, return its exit code.
scan() {
  local rc=0
  just leak-scan "$@" >"$work/last" 2>&1 || rc=$?
  cat "$work/last" >>"$out"
  return "$rc"
}

# expect_hit <name> <regex> <timeout-s> [scan args]: retry until exit 1 with a line matching regex.
expect_hit() {
  local name="$1" re="$2" deadline=$((SECONDS + $3)) rc
  shift 3
  while :; do
    rc=0
    scan "$@" || rc=$?
    if [[ $rc -eq 1 ]] && grep -Eq "$re" "$work/last"; then
      pass "$name: $(grep -Em1 "$re" "$work/last")"
      return
    fi
    if [[ $SECONDS -ge $deadline ]]; then
      bad "$name (exit $rc)"
      tail -n 5 "$work/last" | sed 's/^/      /'
      return
    fi
    sleep 3
  done
}

now_ns() { date +%s%N; }

otlp_log() { # <body-template> <encoding>
  local t
  t="$(now_ns)"
  render "$2" '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"leak-scan-test"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"'"$t"'","severityText":"INFO","body":{"stringValue":"'"$1"'"}}]}]}]}' >"$work/log.json"
  curl -sf -X POST -H 'Content-Type: application/json' --data-binary @"$work/log.json" http://127.0.0.1:4318/v1/logs >/dev/null
}

otlp_span() { # <attribute-template> <encoding>
  local t trace span
  t="$(now_ns)"
  trace="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  span="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  render "$2" '{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"leak-scan-test"}}]},"scopeSpans":[{"spans":[{"traceId":"'"$trace"'","spanId":"'"$span"'","name":"leak-scan-test","kind":1,"startTimeUnixNano":"'"$t"'","endTimeUnixNano":"'"$((t + 1000000))"'","attributes":[{"key":"test.note","value":{"stringValue":"'"$1"'"}}]}]}]}]}' >"$work/span.json"
  curl -sf -X POST -H 'Content-Type: application/json' --data-binary @"$work/span.json" http://127.0.0.1:4318/v1/traces >/dev/null
}

# 1. Postgres: base64 in a text column, the raw bytes in a bytea column.
mint postgres
render b64 "DROP TABLE IF EXISTS leak_scan_test;
CREATE TABLE leak_scan_test (id serial PRIMARY KEY, note text, blob bytea);
INSERT INTO leak_scan_test (note) VALUES ('token=@CANARY@');
INSERT INTO leak_scan_test (note) VALUES ('nothing here');
" >"$work/plant.sql"
pg "$work/plant.sql"
render hex-lower "INSERT INTO leak_scan_test (blob) VALUES (decode('@CANARY@', 'hex'));" >"$work/plant.sql"
pg "$work/plant.sql"
expect_hit "postgres text" '^LEAK [^ ]*b64-offset0[^ ]* postgres:leak_scan_test\.note$' 10
expect_hit "postgres bytea" '^LEAK raw postgres:leak_scan_test\.blob$' 10
printf 'DROP TABLE leak_scan_test;\n' >"$work/drop.sql"
pg "$work/drop.sql"

# 2. Loki: the canary's hex form in an OTLP log line.
mint loki
otlp_log 'upstream said @CANARY@' hex-lower
expect_hit "loki" '^LEAK hex-lower loki:\{.*service_name="leak-scan-test"' 90

# 3. Tempo: the canary in a span attribute.
mint tempo
otlp_span '@CANARY@' utf8
expect_hit "tempo" '^LEAK [^ ]*utf8[^ ]* tempo:[0-9a-fA-F]+$' 120

# 4. Directory: a Basic auth header (base64 of user:<canary>, so text-b64 at offset 2).
mint dir
mkdir -p "$work/tree/sub"
printf 'clean\n' >"$work/tree/readme.txt"
render basic-auth 'GET / HTTP/1.1
Authorization: Basic @CANARY@
' >"$work/tree/sub/request.txt"
expect_hit "dir" '^LEAK [^ ]*text-b64-offset2[^ ]* dir:.*/tree/sub/request\.txt:[0-9]+$' 5 --dir "$work/tree"

# 5. Transcript: base64 inside a JSON string inside a JSONL line, slashes escaped.
mint transcript
{
  printf '%s\n' '{"type":"user","message":"hello"}'
  render b64-json2 '{"type":"tool_result","content":"{\"token\":\"@CANARY@\"}"}'
  printf '\n'
} >"$work/session.jsonl"
expect_hit "transcript" '^LEAK [^ ]*b64-offset0[^ ]* transcript:.*/session\.jsonl:2$' 5 --transcript "$work/session.jsonl"

# 6. Unreachable sources fail loudly.
rc=0
LEAK_SCAN_GRAFANA=http://127.0.0.1:9 LEAK_SCAN_PSQL="psql -p 9" scan --dir "$work/missing" || rc=$?
for s in postgres loki tempo dir; do
  if [[ $rc -eq 2 ]] && grep -qx "SOURCE-UNREACHABLE $s" "$work/last"; then
    pass "unreachable $s reported"
  else
    bad "unreachable $s (exit $rc)"
  fi
done

# 7. Clean stack: a fresh canary written nowhere; every source has something to scan.
mint clean
printf 'CREATE TABLE leak_scan_clean (id serial PRIMARY KEY, note text, blob bytea);
INSERT INTO leak_scan_clean (note, blob) VALUES (%s, %s);\n' "'plain row'" "'\\x00ff'" >"$work/clean.sql"
pg "$work/clean.sql"
otlp_log 'clean log line' utf8 # no @CANARY@ in the template, so nothing is planted
otlp_span 'clean attribute' utf8
mkdir -p "$work/clean-tree"
printf 'clean\n' >"$work/clean-tree/a.txt"
printf '%s\n' '{"type":"user","message":"clean"}' >"$work/clean.jsonl"
rc=0
scan --explain --require-coverage --dir "$work/clean-tree" --transcript "$work/clean.jsonl" || rc=$?
if [[ $rc -eq 0 ]] && grep -qx clean "$work/last"; then
  pass "clean stack exits 0"
else
  bad "clean stack (exit $rc)"
  tail -n 8 "$work/last" | sed 's/^/      /'
fi
for s in postgres loki tempo dir transcript; do
  line="$(grep -m1 "^COVERED $s " "$work/last" || true)"
  [[ -n "$line" ]] && pass "coverage: $line" || bad "coverage: $s missing"
done

# 8. Nothing the scanner printed holds any canary encoding, or any 8-byte fragment of one.
n="$(grep -c . "$all")"
if python3 -I tests/kit/oracle.py scan --canary-file "$all" "$out" >"$work/self.log" 2>&1; then
  pass "scanner output holds no encoding of the $n canaries"
else
  bad "scanner output holds a canary encoding: $(grep -c '^LEAK' "$work/self.log" || true) hits"
fi
if python3 -I -B -c '
import importlib.util, sys
spec = importlib.util.spec_from_file_location("oracle", sys.argv[1])
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
m = oracle.Matcher([v for _id, v in oracle.load_canaries(sys.argv[2])])
with open(sys.argv[3], "rb") as fh:
    bad = [n for n, line in enumerate(fh, 1) if m.safe(line.decode("utf-8", "surrogateescape")) != line.decode("utf-8", "surrogateescape")]
sys.exit(1 if bad else 0)
' tests/kit/oracle.py "$all" "$out"; then
  pass "scanner output holds no 8-byte fragment of any canary encoding"
else
  bad "scanner output holds a canary fragment"
fi

echo "lines checked: $(wc -l <"$out")"
exit "$fail"
