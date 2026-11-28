#!/usr/bin/env bash
# Tests for infra/compose/selfhost/bootstrap.sh that need no Docker: secret generation, file mode,
# idempotence, refusal of dev-only values, --external-keys, profiles, and that no secret value is
# ever printed. Usage: bash scripts/selfhost-bootstrap.test.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
BOOT="$PWD/infra/compose/selfhost/bootstrap.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fails=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
get() { { grep -E "^$2=" "$1/.env" || true; } | tail -n1 | cut -d= -f2-; }
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
# Run bootstrap, capturing stdout+stderr to $work/out; returns its exit code.
run() { local d=$1; shift; bash "$BOOT" --dir "$d" --env-only "$@" > "$work/out" 2>&1; }
# True when no value of a setting named like a secret appears in the captured output.
output_has_no_secret() {
  local d=$1 n v
  for n in POSTGRES_PASSWORD LOCKSMITH_OWNER_PASSWORD LOCKSMITH_APP_PASSWORD LOCKSMITH_AUDIT_VERIFIER_PASSWORD \
    LOCKSMITH_GATEWAY_SERVICE_TOKEN LOCKSMITH_AGENT_SIGNING_KEY OPENBAO_CONTROL_PLANE_TOKEN \
    OPENBAO_GATEWAY_TOKEN OPENBAO_AUDIT_CHECKPOINT_TOKEN KEYCLOAK_ADMIN_PASSWORD; do
    v=$(get "$d" "$n"); [ -n "$v" ] || continue
    grep -qF -- "$v" "$work/out" && return 1
  done
  return 0
}

SECRETS="POSTGRES_PASSWORD LOCKSMITH_OWNER_PASSWORD LOCKSMITH_APP_PASSWORD LOCKSMITH_AUDIT_VERIFIER_PASSWORD LOCKSMITH_GATEWAY_SERVICE_TOKEN LOCKSMITH_AGENT_SIGNING_KEY OPENBAO_CONTROL_PLANE_TOKEN OPENBAO_GATEWAY_TOKEN OPENBAO_AUDIT_CHECKPOINT_TOKEN"

# 1. fresh run: files, mode, every secret set and long enough, nothing printed
a="$work/a"
check "fresh run succeeds" run "$a"
check ".env mode is 0600" test "$(mode "$a/.env")" = 600
all_set=1; for n in $SECRETS; do [ "$(get "$a" "$n" | wc -c)" -gt 32 ] || all_set=0; done
check "every secret is generated and long" test "$all_set" = 1
check "output shows no secret value" output_has_no_secret "$a"
check "output names what it generated" grep -q 'generated: POSTGRES_PASSWORD' "$work/out"
check "agent signing key is a 32-byte base64 seed" test "$(get "$a" LOCKSMITH_AGENT_SIGNING_KEY | base64 -d 2>/dev/null | wc -c)" = 32
check "bundled-keys profile is set" test "$(get "$a" COMPOSE_PROFILES)" = bundled-keys
check "gateway bindings placeholder exists" test -s "$a/gateway-bindings.toml"
check "no dev-only string in .env" bash -c "! grep -qi 'dev-only' '$a/.env'"

# 2. idempotence: a second run keeps .env byte for byte and generates nothing
before=$(sha "$a/.env")
run "$a"; rc=$?
check "second run succeeds" test "$rc" = 0
check "second run keeps .env unchanged" test "$(sha "$a/.env")" = "$before"
check "second run generates nothing" bash -c "! grep -q '^generated:' '$work/out'"
chmod 644 "$a/.env"; run "$a"
check "a loose .env mode is tightened to 0600" test "$(mode "$a/.env")" = 600

# 3. a missing value is added without touching the others
sed -i '/^LOCKSMITH_GATEWAY_SERVICE_TOKEN=/d' "$a/.env"; keep=$(get "$a" POSTGRES_PASSWORD)
run "$a"
check "a deleted secret is regenerated" test -n "$(get "$a" LOCKSMITH_GATEWAY_SERVICE_TOKEN)"
check "other secrets are untouched" test "$(get "$a" POSTGRES_PASSWORD)" = "$keep"

# 4. two fresh runs share no secret value
b="$work/b"; run "$b"
same=0; for n in $SECRETS; do [ "$(get "$a" "$n")" = "$(get "$b" "$n")" ] && same=1; done
check "two fresh runs differ in every secret" test "$same" = 0

# 5. refusal of dev-only and placeholder values, naming the setting and not the value
for pair in "LOCKSMITH_APP_PASSWORD=locksmith-app-dev-only" "OPENBAO_GATEWAY_TOKEN=dev-only-gateway" \
  "LOCKSMITH_GATEWAY_SERVICE_TOKEN=dev-only-gateway-service-token-0123456789" "POSTGRES_PASSWORD=changeme"; do
  name=${pair%%=*} value=${pair#*=}
  d="$work/refuse-$name"; mkdir -p "$d"; printf '%s=%s\n' "$name" "$value" > "$d/.env"; chmod 600 "$d/.env"
  run "$d"; rc=$?
  check "refuses $name=$value-style value (non-zero exit)" test "$rc" -ne 0
  check "refusal names $name" grep -q "setting $name " "$work/out"
  check "refusal does not print the value ($name)" bash -c "! grep -qF -- '$value' '$work/out'"
done
d="$work/short"; mkdir -p "$d"; printf 'POSTGRES_PASSWORD=abc\n' > "$d/.env"; chmod 600 "$d/.env"
run "$d"; check "refuses a too-short secret" test "$?" -ne 0
d="$work/devother"; mkdir -p "$d"; printf 'LOCKSMITH_OIDC_AUDIENCE=my-dev-only-audience\n' > "$d/.env"; chmod 600 "$d/.env"
run "$d"; check "refuses dev-only in any setting" test "$?" -ne 0

# 6. --external-keys: skips bundled keys, generates no OpenBao tokens, needs yours
e="$work/ext"
run "$e" --external-keys; rc=$?
check "external keys without settings fails" test "$rc" -ne 0
check "failure names OPENBAO_ADDR" grep -q 'needs OPENBAO_ADDR' "$work/out"
check "no OpenBao token is generated" test -z "$(get "$e" OPENBAO_GATEWAY_TOKEN)"
check "bundled-keys profile is absent" bash -c "! grep -q 'bundled-keys' '$e/.env'"
fake=$(head -c 30 /dev/urandom | od -An -tx1 | tr -d ' \n')
set_env() { sed -i "s|^$2=.*|$2=$3|" "$1/.env"; }
set_env "$e" OPENBAO_ADDR https://bao.internal.test:8200
for n in OPENBAO_CONTROL_PLANE_TOKEN OPENBAO_GATEWAY_TOKEN OPENBAO_AUDIT_CHECKPOINT_TOKEN; do set_env "$e" "$n" "${fake}${n}"; done
run "$e" --external-keys; rc=$?
check "external keys with settings succeeds" test "$rc" = 0
check "external run keeps your token" test "$(get "$e" OPENBAO_GATEWAY_TOKEN)" = "${fake}OPENBAO_GATEWAY_TOKEN"
check "external run says bundled OpenBao is not started" grep -q 'bundled OpenBao is not started' "$work/out"
check "external output shows no token" bash -c "! grep -qF -- '$fake' '$work/out'"
set_env "$e" OPENBAO_CONTROL_PLANE_TOKEN dev-only-control-plane
run "$e" --external-keys; check "external dev-only token is refused" test "$?" -ne 0

# 7. profiles and OIDC
p="$work/prof"; run "$p" --tls --demo-oidc
check "tls and demo-oidc profiles are added" bash -c "grep -q '^COMPOSE_PROFILES=bundled-keys,tls,demo-oidc$' '$p/.env'"
check "demo issuer is set" bash -c "grep -q '^LOCKSMITH_OIDC_ISSUER=http://localhost:8180/realms/locksmith$' '$p/.env'"
check "keycloak admin password is generated" test "$(get "$p" KEYCLOAK_ADMIN_PASSWORD | wc -c)" -gt 32
check "demo output shows no secret" output_has_no_secret "$p"
o="$work/own"; mkdir -p "$o"; printf 'LOCKSMITH_OIDC_ISSUER=https://idp.example.org/realms/x\n' > "$o/.env"; chmod 600 "$o/.env"
run "$o" --demo-oidc
check "an own OIDC issuer is not replaced by the demo" test "$(get "$o" LOCKSMITH_OIDC_ISSUER)" = "https://idp.example.org/realms/x"

# 8. the bundle's compose file renders with a generated .env (only when Docker Compose is present)
if docker compose version >/dev/null 2>&1; then
  check "docker compose config renders" bash -c "docker compose --env-file '$a/.env' -f infra/compose/selfhost/compose.yaml config -q"
  published=$(docker compose --env-file "$a/.env" -f infra/compose/selfhost/compose.yaml --profile tls config 2>/dev/null | grep -E 'host_ip' | grep -vc '127.0.0.1')
  check "every published port is bound to 127.0.0.1" test "$published" = 0
else
  echo "skip docker compose config (Docker Compose not installed)"
fi

echo
if [ "$fails" -eq 0 ]; then echo "selfhost-bootstrap tests: all passed"; else echo "selfhost-bootstrap tests: $fails failed"; exit 1; fi
