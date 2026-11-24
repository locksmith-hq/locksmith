#!/usr/bin/env bash
# B2 smoke check of the core service against `just up`: health, one audit append, one agent-token
# mint and verify, one DEK wrap and unwrap round trip. Needs the schema (`just api` once, or any
# migrated database). Prints verdicts only, never tokens or key material.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a; . "$root/infra/compose/.env.example"; set +a
[ -f "$root/infra/compose/.env" ] && . "$root/infra/compose/.env"
base="http://127.0.0.1:${LOCKSMITH_CORE_PORT:-8091}"
compose=(docker compose -f "$root/infra/compose/compose.yaml" --env-file "$root/infra/compose/.env.example")
org=aaaaaaaa-0000-4000-8000-0000000000b2
agent=bbbbbbbb-0000-4000-8000-0000000000b2
secret=cccccccc-0000-4000-8000-0000000000b2

fail() { echo "core-check: FAIL $*" >&2; exit 1; }
# call <path> <json>: prints the response body; fails unless HTTP 200.
call() {
  local out code
  out=$(curl -sS -o /dev/stderr -w '%{http_code}' -X POST "$base$1" \
    -H "Authorization: Bearer $LOCKSMITH_CORE_SERVICE_TOKEN" -H 'Content-Type: application/json' \
    -d "$2" 2>"$tmp") || fail "$1 unreachable"
  code=$out
  [ "$code" = 200 ] || fail "$1 returned $code"
  cat "$tmp"
}
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

[ "$(curl -sS -o /dev/null -w '%{http_code}' "$base/healthz")" = 200 ] || fail "healthz"
echo "core-check: health ok"
[ "$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$base/v1/deks/wrap" -d '{}')" = 401 ] || fail "unauthenticated call was not refused"
echo "core-check: unauthenticated call refused (401)"

# Audit append: needs the schema and one org row (written as the owner role).
"${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -q' <<SQL >/dev/null 2>&1 \
  || fail "no schema: run 'just api' once so the migrations apply"
INSERT INTO orgs (id, name) VALUES ('$org', 'core-check') ON CONFLICT DO NOTHING;
SQL
res=$(call /v1/audit/events "{\"org_id\":\"$org\",\"kind\":\"agent.created\",\"outcome\":\"ok\",\"actor\":{\"type\":\"service\",\"code\":\"control_plane\"},\"attrs\":{}}")
echo "$res" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["seq"]>=1 and len(d["hash"])==64' || fail "audit append body"
echo "core-check: audit append ok"

res=$(call /v1/agent-tokens/mint "{\"agent_id\":\"$agent\",\"org_id\":\"$org\"}")
token=$(echo "$res" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
res=$(call /v1/agent-tokens/verify "{\"token\":\"$token\"}")
echo "$res" | python3 -c 'import json,sys; assert json.load(sys.stdin)["valid"] is True' || fail "agent token did not verify"
echo "core-check: agent token mint and verify ok"

bind="{\"org_id\":\"$org\",\"purpose\":\"dek_wrap\",\"secret_id\":\"$secret\",\"version\":1}"
res=$(call /v1/deks/wrap "{\"binding\":$bind}")
blob=$(echo "$res" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert set(d)=={"dek_handle","key_id","wrapped_dek"}; print(d["wrapped_dek"])') || fail "wrap body"
call /v1/deks/unwrap "{\"binding\":$bind,\"wrapped_dek\":\"$blob\"}" >/dev/null
echo "core-check: DEK wrap and unwrap ok"
echo "core-check: ok"
