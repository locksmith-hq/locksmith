#!/usr/bin/env bash
# API contract suite runner (change B4).
#   api-contract.sh <base-url>                 run the scenarios, write target/api-contract/transcript.json
#   api-contract.sh --diff <url-a> <url-b>     run both, print the first difference per exchange, exit 1 on any
#   api-contract.sh --diff-files <a.json> <b.json>   compare two recorded transcripts (no servers needed)
set -euo pipefail
cd "$(dirname "$0")/.."
out=target/api-contract
run=(node tests/api-contract/src/run.ts)
# Secret-write scenarios send a canary (never printed or recorded); `just canary` keeps the oracle list.
if [ -z "${API_CONTRACT_CANARY:-}" ] && [ "${1:-}" != "--diff-files" ]; then
  API_CONTRACT_CANARY=$(python3 -I tests/kit/oracle.py canary-new --file "${LOCKSMITH_CANARIES:-infra/compose/.canaries}")
  export API_CONTRACT_CANARY
fi
# The `/internal/v1/*` scenarios need the gateway's service token: the dev default `just api` uses.
if [ -z "${LOCKSMITH_GATEWAY_SERVICE_TOKEN:-}" ]; then
  LOCKSMITH_GATEWAY_SERVICE_TOKEN=$(sed -n 's/^LOCKSMITH_GATEWAY_SERVICE_TOKEN=//p' infra/compose/.env.example)
  export LOCKSMITH_GATEWAY_SERVICE_TOKEN
fi
case "${1:-}" in
  --diff)
    [ $# -eq 3 ] || { echo "usage: $0 --diff <url-a> <url-b>" >&2; exit 2; }
    "${run[@]}" "$2" "$out/a.json"
    "${run[@]}" "$3" "$out/b.json"
    exec "${run[@]}" --diff "$out/a.json" "$out/b.json" ;;
  --diff-files)
    [ $# -eq 3 ] || { echo "usage: $0 --diff-files <a.json> <b.json>" >&2; exit 2; }
    exec "${run[@]}" --diff "$2" "$3" ;;
  ""|--*) echo "usage: $0 <base-url> | --diff <url-a> <url-b>" >&2; exit 2 ;;
  *) exec "${run[@]}" "$1" "$out/transcript.json" ;;
esac
