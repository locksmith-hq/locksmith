#!/usr/bin/env bash
# API contract suite runner (change B4).
#   api-contract.sh <base-url>                 run the scenarios, write target/api-contract/transcript.json
#   api-contract.sh --diff <url-a> <url-b>     run both, print the first difference per exchange, exit 1 on any
#   api-contract.sh --diff-files <a.json> <b.json>   compare two recorded transcripts (no servers needed)
set -euo pipefail
cd "$(dirname "$0")/.."
out=target/api-contract
run=(node tests/api-contract/src/run.ts)
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
