#!/usr/bin/env bash
# Starts each MCP server from .mcp.json through the MCP Inspector CLI and makes one read call per server.
# Requires `just up`. Exits non-zero if any server fails.
set -u
cd "$(dirname "$0")/.."
INSPECT="npx -y @modelcontextprotocol/inspector@0.17.2 --cli"
cfg=$(mktemp)
trap 'rm -f "$cfg"' EXIT
# Expand ${VAR:-default} the way Claude Code does, into a temp config.
node -e '
const fs=require("fs");
const t=fs.readFileSync(".mcp.json","utf8").replace(/\$\{([A-Z_]+):-([^}]*)\}/g,(_,k,d)=>process.env[k]||d);
fs.writeFileSync(process.argv[1],t)' "$cfg"
fail=0
run() { # name, expected substring, method args...
  local name=$1 want=$2; shift 2
  local out
  out=$($INSPECT --config "$cfg" --server "$name" "$@" 2>&1)
  if echo "$out" | grep -q "$want"; then echo "PASS  mcp $name"; else echo "FAIL  mcp $name"; echo "$out" | tail -5; fail=1; fi
}
run postgres 'public' --method tools/call --tool-name list_schemas
run grafana '\[' --method tools/call --tool-name list_loki_label_names
exit $fail
