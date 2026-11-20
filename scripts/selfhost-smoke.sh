#!/usr/bin/env bash
# End-to-end smoke test of the self-host compose bundle (P2 packaging, task 3.5).
# Fresh bootstrap and up, API health, one relay through the gateway to a throwaway upstream,
# stop and start again (data and keys must persist, no secret regenerated), then secrets-file mode,
# difference between two fresh bootstraps, and absence of every secret value from the bootstrap
# output and `docker compose logs`. Values are only compared, never printed.
#
# Usage: scripts/selfhost-smoke.sh        (run `just images` first; `just selfhost-smoke` wraps this)
# Images: LOCKSMITH_CONTROL_PLANE_IMAGE / LOCKSMITH_GATEWAY_IMAGE (default locksmith-*:dev).
# Needs Docker with Compose, python3 and curl. Uses its own project, volumes and a temp directory.
# shellcheck disable=SC2015,SC2016  # A && ok || bad is the reporting idiom; the in-container script is single-quoted on purpose
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
SH=infra/compose/selfhost
export LOCKSMITH_CONTROL_PLANE_IMAGE="${LOCKSMITH_CONTROL_PLANE_IMAGE:-locksmith-control-plane:${IMAGE_TAG:-dev}}"
export LOCKSMITH_GATEWAY_IMAGE="${LOCKSMITH_GATEWAY_IMAGE:-locksmith-gateway:${IMAGE_TAG:-dev}}"
export LOCKSMITH_API_PORT="${SMOKE_API_PORT:-18080}" LOCKSMITH_GATEWAY_PORT="${SMOKE_GATEWAY_PORT:-18090}"
export COMPOSE_PROJECT_NAME="lsselfhost-smoke-$$"
for tool in docker python3 curl; do command -v "$tool" >/dev/null || { echo "selfhost-smoke: $tool is required" >&2; exit 2; }; done
docker compose version >/dev/null 2>&1 || { echo "selfhost-smoke: Docker Compose is required" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "selfhost-smoke: the Docker daemon is not reachable" >&2; exit 2; }
for img in "$LOCKSMITH_CONTROL_PLANE_IMAGE" "$LOCKSMITH_GATEWAY_IMAGE"; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "selfhost-smoke: image $img not found; run 'just images' first" >&2; exit 2; }
done

work=$(mktemp -d); chmod 700 "$work"
dir="$work/stack"; mkdir -p "$dir"
env_file="$dir/.env"
fails=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
dc() { docker compose --env-file "$env_file" -f "$SH/compose.yaml" -f "$SH/compose.smoke.yaml" --profile smoke "$@"; }
cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
get() { { grep -E "^$1=" "$env_file" || true; } | tail -n1 | cut -d= -f2-; }
SECRET_NAMES="POSTGRES_PASSWORD LOCKSMITH_OWNER_PASSWORD LOCKSMITH_APP_PASSWORD LOCKSMITH_AUDIT_VERIFIER_PASSWORD LOCKSMITH_GATEWAY_SERVICE_TOKEN LOCKSMITH_AGENT_SIGNING_KEY OPENBAO_CONTROL_PLANE_TOKEN OPENBAO_GATEWAY_TOKEN OPENBAO_AUDIT_CHECKPOINT_TOKEN"

# http SERVICE HOSTPORT METHOD PATH [ORG] [BODY]: raw HTTP/1.0 from inside a compose container
# (the images carry bash and no curl). Prints the status code, then the body.
http() {
  local svc=$1 hp=$2 method=$3 path=$4 org=${5:-} body=${6:-}
  dc exec -T -e H="${hp%:*}" -e P="${hp#*:}" -e M="$method" -e U="$path" -e ORG="$org" -e BODY="$body" "$svc" bash -c '
    exec 3<>"/dev/tcp/$H/$P"
    hdr=""; [ -z "$ORG" ] || hdr="X-Locksmith-Dev-Org: $ORG"$'"'"'\r\n'"'"'
    printf "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n%s\r\n%s" \
      "$M" "$U" "$H" "${#BODY}" "$hdr" "$BODY" >&3
    IFS= read -r -u3 status; echo "$status" | cut -d" " -f2
    while IFS= read -r -u3 l; do [ "$l" = $'"'"'\r'"'"' ] && break; done
    cat <&3'
}
json() { python3 -I -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
expect() { # name expected-status response ; returns the body on stdout via $BODY_OUT
  local name=$1 want=$2 resp=$3
  if [ "$(head -n1 <<<"$resp")" = "$want" ]; then ok "$name"; BODY_OUT=$(tail -n +2 <<<"$resp"); return 0; fi
  bad "$name (HTTP $(head -n1 <<<"$resp"), wanted $want)"; BODY_OUT=""; return 1
}
up() { dc up -d --wait --wait-timeout 240 >"$work/up.log" 2>&1 || { bad "stack did not become healthy"; tail -n 15 "$work/up.log"; dc ps -a; return 1; }; }

provision() { # creates org, secret, agent, grant, token, stub and bindings; sets TOKEN SID ORG_ID ENROLL
  local pid eid base
  expect "provisioner answers" 200 "$(http provisioner 127.0.0.1:8081 GET /readyz)" || return 1
  if [ -z "${ORG_ID:-}" ]; then
    expect "create org" 201 "$(http provisioner 127.0.0.1:8081 POST /v1/orgs "" '{"name":"smoke"}')" || return 1
    ORG_ID=$(json id <<<"$BODY_OUT")
    expect "create project" 201 "$(http provisioner 127.0.0.1:8081 POST /v1/projects "$ORG_ID" '{"name":"p"}')" || return 1
    pid=$(json id <<<"$BODY_OUT")
    expect "create environment" 201 "$(http provisioner 127.0.0.1:8081 POST "/v1/projects/$pid/environments" "$ORG_ID" '{"name":"e"}')" || return 1
    eid=$(json id <<<"$BODY_OUT"); base="/v1/projects/$pid/environments/$eid/secrets"
    expect "create secret" 201 "$(http provisioner 127.0.0.1:8081 POST "$base" "$ORG_ID" '{"name":"UPSTREAM_KEY"}')" || return 1
    SID=$(json id <<<"$BODY_OUT")
    expect "store secret version (wrapped by OpenBao)" 201 "$(http provisioner 127.0.0.1:8081 POST "$base/$SID/versions" "$ORG_ID" "{\"value\":\"$CANARY\"}")" || return 1
    expect "register agent" 201 "$(http provisioner 127.0.0.1:8081 POST /v1/agents "$ORG_ID" '{"name":"smoke-agent"}')" || return 1
    AGENT_ID=$(json id < <(python3 -I -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["agent"]))' <<<"$BODY_OUT"))
    ENROLL=$(json enrollment_secret <<<"$BODY_OUT")
    expect "grant secret to agent" 201 "$(http provisioner 127.0.0.1:8081 POST "/v1/agents/$AGENT_ID/grants" "$ORG_ID" "{\"secret_id\":\"$SID\"}")" || return 1
    cat > "$dir/gateway-bindings.toml" <<TOML
org_id = "$ORG_ID"
[[binding]]
secret_id = "$SID"
origin = "http://upstream:8080"
header = "Authorization"
template = "Bearer {secret}"
allow_private_hosts = true
TOML
    chmod 644 "$dir/gateway-bindings.toml"
    dc restart gateway >/dev/null 2>&1 && dc up -d --wait --wait-timeout 120 >/dev/null 2>&1 && ok "gateway restarted with real bindings" || { bad "gateway restart"; return 1; }
  fi
  expect "agent token issued" 200 "$(http provisioner 127.0.0.1:8081 POST /v1/agent-tokens "" "{\"enrollment_secret\":\"$ENROLL\"}")" || return 1
  TOKEN=$(json access_token <<<"$BODY_OUT")
  expect "upstream stub registered" 201 "$(http upstream upstream:8080 POST /__admin/mappings "" '{"request":{"method":"GET","url":"/smoke"},"response":{"status":200,"jsonBody":{"ok":true}}}')" || return 1
}

relay_once() { # label
  local code
  code=$(curl -sS -o "$work/relay.out" -w '%{http_code}' -K - -H 'Content-Type: application/json' \
    -d "{\"secret_id\":\"$SID\",\"version\":1,\"method\":\"GET\",\"url\":\"http://upstream:8080/smoke\"}" \
    "http://127.0.0.1:$LOCKSMITH_GATEWAY_PORT/v1/relay" <<<"header = \"Authorization: Bearer $TOKEN\"") || code=000
  if [ "$code" = 200 ]; then ok "$1: relay through the gateway returned 200"; else bad "$1: relay returned HTTP $code"; return 1; fi
  if grep -qF -- "$CANARY" "$work/relay.out"; then bad "$1: relay response contains the secret"; else ok "$1: relay response does not contain the secret"; fi
  http upstream upstream:8080 GET /__admin/requests > "$work/journal.out" 2>/dev/null
  if grep -qF -- "Bearer $CANARY" "$work/journal.out"; then ok "$1: upstream received the injected secret"; else bad "$1: upstream did not receive the injected secret"; fi
}

CANARY="smoke-canary-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ORG_ID=""

echo "== fresh start"
bash "$SH/bootstrap.sh" --dir "$dir" > "$work/bootstrap1.out" 2>&1 && ok "bootstrap succeeded" || { bad "bootstrap failed"; cat "$work/bootstrap1.out"; exit 1; }
[ "$(stat -c %a "$env_file")" = 600 ] && ok ".env mode is 0600" || bad ".env mode is not 0600"
keys_mode=$(dc exec -T openbao sh -c 'stat -c "%a %U" /openbao-keys /openbao-keys/init' 2>/dev/null | tr '\n' ' ')
[ "$keys_mode" = "700 root 600 root " ] && ok "unseal material is root-only (dir 0700, file 0600)" || bad "unseal material modes: $keys_mode"
up || exit 1
ok "all services healthy"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$LOCKSMITH_API_PORT/healthz")" = 200 ] && ok "API /healthz" || bad "API /healthz"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$LOCKSMITH_API_PORT/readyz")" = 200 ] && ok "API /readyz (migrations applied)" || bad "API /readyz"
pub=$(dc ps --format '{{.Publishers}}' | grep -o '[0-9.]*:[0-9]*->' | grep -vc '^127.0.0.1:' || true)
[ "$pub" = 0 ] && ok "every published port is on 127.0.0.1" || bad "a port is published on a non-loopback address"
provision || { echo; echo "selfhost-smoke: provisioning failed"; exit 1; }
relay_once "first run"
before_env=$(sha256sum "$env_file" | cut -d' ' -f1)

echo "== stop and start again"
dc down >"$work/down.log" 2>&1 && ok "stack stopped (volumes kept)" || bad "stack down"
bash "$SH/bootstrap.sh" --dir "$dir" > "$work/bootstrap2.out" 2>&1 && ok "bootstrap re-run succeeded" || bad "bootstrap re-run failed"
if grep -q '^generated:' "$work/bootstrap2.out"; then bad "re-run regenerated a secret"; else ok "re-run generated nothing"; fi
[ "$(sha256sum "$env_file" | cut -d' ' -f1)" = "$before_env" ] && ok ".env unchanged by re-run" || bad ".env changed by re-run"
up || exit 1
ok "all services healthy after restart"
provision || { echo; echo "selfhost-smoke: provisioning after restart failed"; exit 1; }
relay_once "after restart (stored secret decrypts with the persisted key)"

echo "== fresh runs differ"
other="$work/other"; mkdir -p "$other"
bash "$SH/bootstrap.sh" --dir "$other" --env-only >/dev/null 2>&1
same=0
for n in $SECRET_NAMES; do
  a=$(get "$n"); b=$({ grep -E "^$n=" "$other/.env" || true; } | tail -n1 | cut -d= -f2-)
  [ -n "$a" ] && [ "$a" = "$b" ] && same=1
done
[ "$same" = 0 ] && ok "two fresh bootstraps share no secret value" || bad "two fresh bootstraps share a secret value"

echo "== no secret in output or logs"
umask 077
valuesfile="$work/values"; : > "$valuesfile"
for n in $SECRET_NAMES; do get "$n" >> "$valuesfile"; done
dc exec -T openbao sh -c 'sed -n "s/^[a-z_]* //p" /openbao-keys/init' >> "$valuesfile" 2>/dev/null
grep -c . "$valuesfile" | grep -qE '^1[0-9]$' && ok "checking 9 settings plus the unseal key and root token" || bad "value list is incomplete"
# Services other than the throwaway upstream must not contain the canary either.
cp "$valuesfile" "$work/values-canary"; echo "$CANARY" >> "$work/values-canary"
leaks=0
for svc in postgres openbao control-plane gateway provisioner; do
  dc logs --no-color "$svc" > "$work/log.$svc" 2>&1
  grep -qF -f "$work/values-canary" "$work/log.$svc" && { bad "a secret value appears in the $svc logs"; leaks=1; }
done
dc logs --no-color upstream > "$work/log.upstream" 2>&1
grep -qF -f "$valuesfile" "$work/log.upstream" && { bad "a secret value appears in the upstream logs"; leaks=1; }
cat "$work/bootstrap1.out" "$work/bootstrap2.out" "$work/up.log" "$work/down.log" > "$work/cli.out"
grep -qF -f "$work/values-canary" "$work/cli.out" && { bad "a secret value appears in bootstrap or compose output"; leaks=1; }
[ "$leaks" = 0 ] && ok "no secret value in bootstrap output, compose output or service logs"
grep -rqi 'dev-only' "$env_file" && bad "dev-only string in .env" || ok "no dev-only string in .env"

echo
if [ "$fails" -eq 0 ]; then echo "selfhost-smoke: all checks passed"; else echo "selfhost-smoke: $fails check(s) failed"; exit 1; fi
