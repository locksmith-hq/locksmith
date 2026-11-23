#!/usr/bin/env bash
# F0 harness check: verifies the local dev stack. Prints one PASS/FAIL line per check.
# Uses only dev-only values from infra/compose/.env.example. Exits non-zero on any FAIL.
set -u
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f infra/compose/compose.yaml --env-file infra/compose/.env.example"
TOKEN="${OPENBAO_DEV_ROOT_TOKEN:-dev-only-root}"
fail=0
pass() { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fail=1; }

# 1. every service healthy
for svc in postgres lgtm openbao upstream floci; do
  cid=$($COMPOSE ps -q "$svc" 2>/dev/null)
  st=$([ -n "$cid" ] && docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)
  [ "$st" = healthy ] && pass "healthy: $svc" || bad "healthy: $svc (${st:-not running})"
done

# 2. no host port bound to 0.0.0.0 / ::
wide=$(docker ps --filter "label=com.docker.compose.project=locksmith-dev" --format '{{.Ports}}' | tr ',' '\n' | grep -E '(^|\s)(0\.0\.0\.0|\[::\]):[0-9]+->' || true)
[ -z "$wide" ] && pass "no port bound to 0.0.0.0" || bad "ports bound wide: $wide"

# 3. OTLP log reaches Loki
marker="harness-check-$(date +%s)-$$"
now=$(date +%s%N)
body=$(printf '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"harness-check"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"%s","severityText":"INFO","body":{"stringValue":"%s"}}]}]}]}' "$now" "$marker")
if curl -sf -X POST -H 'Content-Type: application/json' -d "$body" http://127.0.0.1:4318/v1/logs >/dev/null; then
  found=""
  for _ in $(seq 1 30); do
    out=$(curl -s -G http://127.0.0.1:3000/api/datasources/proxy/uid/loki/loki/api/v1/query_range --data-urlencode "query={service_name=\"harness-check\"} |= \"$marker\"" --data-urlencode "start=$((now - 600000000000))" --data-urlencode "limit=5" 2>/dev/null)
    case "$out" in *"$marker"*) found=1; break;; esac
    sleep 2
  done
  [ -n "$found" ] && pass "OTLP log found in Loki" || bad "OTLP log not found in Loki"
else
  bad "OTLP log POST to :4318 failed"
fi

# 4. OpenBao transit round trip
bao() { curl -sf -H "X-Vault-Token: $TOKEN" "$@"; }
bao -X POST http://127.0.0.1:8200/v1/transit/keys/harness-check >/dev/null 2>&1
plain=$(printf 'harness-test' | base64)
ct=$(bao -X POST -d "{\"plaintext\":\"$plain\"}" http://127.0.0.1:8200/v1/transit/encrypt/harness-check | sed -n 's/.*"ciphertext":"\([^"]*\)".*/\1/p')
back=""
[ -n "$ct" ] && back=$(bao -X POST -d "{\"ciphertext\":\"$ct\"}" http://127.0.0.1:8200/v1/transit/decrypt/harness-check | sed -n 's/.*"plaintext":"\([^"]*\)".*/\1/p')
[ -n "$ct" ] && [ "$back" = "$plain" ] && pass "OpenBao transit encrypt/decrypt" || bad "OpenBao transit encrypt/decrypt"

# 5. WireMock journal records a request
curl -sf -X DELETE http://127.0.0.1:8089/__admin/requests >/dev/null
curl -s -o /dev/null "http://127.0.0.1:8089/harness-check/$marker"
if curl -sf http://127.0.0.1:8089/__admin/requests | grep -q "$marker"; then pass "WireMock journal records request"; else bad "WireMock journal records request"; fi

exit $fail
