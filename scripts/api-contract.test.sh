#!/usr/bin/env bash
# Tests the transcript diff of scripts/api-contract.sh on two planted transcripts.
set -euo pipefail
cd "$(dirname "$0")/.."
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
ex='{"name":"orgs: create","method":"POST","path":"/v1/orgs","status":201,"headers":{"content-type":"application/json"},"body":{"id":"<id-1>","name":"x"}}'
echo "[$ex]" > "$t/a.json"
echo "[$ex]" > "$t/same.json"
echo "[${ex/\"name\":\"x\"/\"name\":\"y\"}]" > "$t/body.json"
echo "[${ex/\"status\":201/\"status\":200}]" > "$t/status.json"

bash scripts/api-contract.sh --diff-files "$t/a.json" "$t/same.json" | grep -q "transcripts match"
for case in body:body.name status:status; do
  f=${case%%:*}; want=${case##*:}
  if out=$(bash scripts/api-contract.sh --diff-files "$t/a.json" "$t/$f.json"); then echo "FAIL: $f diff exited 0" >&2; exit 1; fi
  grep -q "DIFF POST /v1/orgs (orgs: create): $want" <<<"$out" || { echo "FAIL: $f: $out" >&2; exit 1; }
done
echo "api-contract.test: OK"
