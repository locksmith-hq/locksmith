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
run() { # name, expected substring (fixed string), method args...
  local name=$1 want=$2; shift 2
  local out rc
  out=$($INSPECT --config "$cfg" --server "$name" "$@" 2>&1); rc=$?
  if [ $rc -eq 0 ] && ! echo "$out" | grep -Eq '"isError": *true' && echo "$out" | grep -Fq "$want"; then
    echo "PASS  mcp $name"
  else echo "FAIL  mcp $name (exit $rc)"; echo "$out" | tail -5; fail=1; fi
}
# A call that must be rejected: non-zero exit or isError, and no table created.
reject() { # name, description, method args...
  local name=$1 desc=$2; shift 2
  local out rc
  out=$($INSPECT --config "$cfg" --server "$name" "$@" 2>&1); rc=$?
  if [ $rc -ne 0 ] || echo "$out" | grep -Eqi '"isError": *true|read-only|restricted|not allowed|error validating query'; then
    echo "PASS  mcp $name rejects $desc"
  else echo "FAIL  mcp $name accepted $desc"; echo "$out" | tail -5; fail=1; fi
}
run postgres "'public'" --method tools/call --tool-name list_schemas
run grafana '"content"' --method tools/call --tool-name list_loki_label_names --tool-arg datasourceUid=loki
reject postgres 'a write statement' --method tools/call --tool-name execute_sql \
  --tool-arg 'sql=CREATE TABLE mcp_check_should_fail (id int)'
exit $fail
