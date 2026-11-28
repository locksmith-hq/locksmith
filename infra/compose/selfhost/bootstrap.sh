#!/usr/bin/env bash
# First-run setup for the self-host bundle. Safe to re-run: existing values are kept, only missing
# ones are generated. Prints setting names and status, never a secret value.
#
#   bootstrap.sh [--dir DIR] [--external-keys] [--tls] [--demo-oidc] [--env-only]
#
#   --dir DIR        where .env and gateway-bindings.toml live (default: this script's directory)
#   --external-keys  use your own OpenBao: bundled openbao is not started, and OPENBAO_ADDR and the
#                    three OPENBAO_*_TOKEN values must be set in .env by you
#   --tls            enable the Caddy profile
#   --demo-oidc      enable the Keycloak demo profile (NOT for production) and point OIDC at it
#   --env-only       write and validate .env only; do not start OpenBao (no Docker needed)
#
# Secrets are generated with `openssl rand` (or /dev/urandom) into DIR/.env, mode 0600.
set -euo pipefail
umask 077

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
dir=$here external=0 tls=0 demo=0 env_only=0
while [ $# -gt 0 ]; do
  case $1 in
    --dir) [ $# -ge 2 ] || { echo "bootstrap: --dir needs a value" >&2; exit 2; }; dir=$2; shift ;;
    --external-keys) external=1 ;;
    --tls) tls=1 ;;
    --demo-oidc) demo=1 ;;
    --env-only) env_only=1 ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "bootstrap: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
env_file="$dir/.env"
bindings="$dir/gateway-bindings.toml"

# Secrets this script generates (name:kind). hex = 48 hex chars (192 bits), b64 = 32 random bytes.
generated=(
  POSTGRES_PASSWORD:hex LOCKSMITH_OWNER_PASSWORD:hex LOCKSMITH_APP_PASSWORD:hex
  LOCKSMITH_AUDIT_VERIFIER_PASSWORD:hex LOCKSMITH_GATEWAY_SERVICE_TOKEN:hex LOCKSMITH_AGENT_SIGNING_KEY:b64
)
bundled_tokens=(OPENBAO_CONTROL_PLANE_TOKEN OPENBAO_GATEWAY_TOKEN OPENBAO_AUDIT_CHECKPOINT_TOKEN)
# Every setting that holds a secret (checked for dev-only values and minimum length).
secret_names=(POSTGRES_PASSWORD LOCKSMITH_OWNER_PASSWORD LOCKSMITH_APP_PASSWORD
  LOCKSMITH_AUDIT_VERIFIER_PASSWORD LOCKSMITH_GATEWAY_SERVICE_TOKEN LOCKSMITH_AGENT_SIGNING_KEY
  OPENBAO_CONTROL_PLANE_TOKEN OPENBAO_GATEWAY_TOKEN OPENBAO_AUDIT_CHECKPOINT_TOKEN KEYCLOAK_ADMIN_PASSWORD)
MIN_SECRET_BYTES=24

gen() { # hex | b64
  if command -v openssl >/dev/null 2>&1; then
    case $1 in hex) openssl rand -hex 24 ;; b64) openssl rand -base64 32 ;; esac
  else
    case $1 in
      hex) head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo ;;
      b64) head -c 32 /dev/urandom | base64 ;;
    esac
  fi
}

[ -f "$env_file" ] || { : > "$env_file"; }
chmod 600 "$env_file"

get() { # NAME -> value (last assignment wins, as in a shell)
  { grep -E "^$1=" "$env_file" || true; } | tail -n1 | cut -d= -f2-
}
set_kv() { # NAME VALUE: replace an existing line or append
  local name=$1 value=$2 tmp
  if grep -qE "^$name=" "$env_file"; then
    tmp=$(mktemp "$dir/.env.XXXXXX")
    NAME=$name VALUE=$value awk 'BEGIN{n=ENVIRON["NAME"]; v=ENVIRON["VALUE"]; done=0}
      index($0, n "=")==1 { if (!done) { print n "=" v; done=1 }; next } { print }' "$env_file" > "$tmp"
    mv "$tmp" "$env_file"
  else
    printf '%s=%s\n' "$name" "$value" >> "$env_file"
  fi
  chmod 600 "$env_file"
}
ensure() { # NAME VALUE: set only when missing or empty
  [ -n "$(get "$1")" ] || set_kv "$1" "$2"
}

# --- 1. generate what is missing ---------------------------------------------------------------
for entry in "${generated[@]}"; do
  name=${entry%%:*}
  if [ -z "$(get "$name")" ]; then set_kv "$name" "$(gen "${entry##*:}")"; echo "generated: $name"; fi
done

profiles=$(get COMPOSE_PROFILES)
has_profile() { case ",$profiles," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
add_profile() { has_profile "$1" || profiles=${profiles:+$profiles,}$1; }
del_profile() { profiles=$(printf '%s' ",$profiles," | sed "s/,$1,/,/g; s/^,//; s/,$//"); }

missing=()
if [ "$external" = 1 ]; then
  del_profile bundled-keys
  for name in OPENBAO_ADDR "${bundled_tokens[@]}"; do
    [ -n "$(get "$name")" ] || { set_kv "$name" ""; missing+=("$name"); }
  done
  # The bundled address left over from an earlier bundled run is not an external provider.
  [ "$(get OPENBAO_ADDR)" != "http://openbao:8200" ] || missing+=(OPENBAO_ADDR)
else
  add_profile bundled-keys
  ensure OPENBAO_ADDR http://openbao:8200
  for name in "${bundled_tokens[@]}"; do
    if [ -z "$(get "$name")" ]; then set_kv "$name" "$(gen hex)"; echo "generated: $name"; fi
  done
fi
if [ "$tls" = 1 ]; then add_profile tls; fi
if [ "$demo" = 1 ]; then
  add_profile demo-oidc
  if [ -z "$(get KEYCLOAK_ADMIN_PASSWORD)" ]; then set_kv KEYCLOAK_ADMIN_PASSWORD "$(gen hex)"; echo "generated: KEYCLOAK_ADMIN_PASSWORD"; fi
  # Demo issuer only when no issuer is configured yet: an operator's own issuer is never replaced.
  if [ -z "$(get LOCKSMITH_OIDC_ISSUER)" ]; then
    set_kv LOCKSMITH_OIDC_ISSUER "http://localhost:8180/realms/locksmith"
    set_kv LOCKSMITH_OIDC_AUDIENCE "locksmith-api"
    set_kv LOCKSMITH_OIDC_JWKS_URL "http://keycloak:8080/realms/locksmith/protocol/openid-connect/certs"
    echo "set: LOCKSMITH_OIDC_* to the demo issuer (not for production)"
  fi
fi
set_kv COMPOSE_PROFILES "$profiles"
ensure LOCKSMITH_BINDINGS_FILE "$bindings"
ensure LOCKSMITH_API_PORT 8080
ensure LOCKSMITH_GATEWAY_PORT 8090
for name in LOCKSMITH_OIDC_ISSUER LOCKSMITH_OIDC_AUDIENCE LOCKSMITH_OIDC_JWKS_URL; do
  grep -qE "^$name=" "$env_file" || set_kv "$name" ""
done

if [ ! -f "$bindings" ]; then
  # Placeholder so the gateway starts. Replace org_id and add [[binding]] entries (ids and origins
  # only, never values), then `docker compose restart gateway`.
  cat > "$bindings" <<'TOML'
org_id = "00000000-0000-7000-8000-000000000000"
TOML
  chmod 644 "$bindings"
  echo "wrote: placeholder gateway-bindings.toml"
fi

# --- 2. refuse unsafe values -------------------------------------------------------------------
fail=0
if [ "${#missing[@]}" -gt 0 ]; then
  for name in "${missing[@]}"; do echo "bootstrap: --external-keys needs $name set in $env_file" >&2; done
  fail=1
fi
is_dev_value() { # value: a known dev-only value; placeholders only count for secret settings
  local v
  v=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case $v in *dev-only*) return 0 ;; esac
  return 1
}
is_placeholder() {
  local v
  v=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case $v in
    *changeme*|*change-me*|*change_me*|*placeholder*|locksmith|admin|password|secret|root|token) return 0 ;;
  esac
  return 1
}
while IFS= read -r line; do
  case $line in ''|'#'*) continue ;; esac
  name=${line%%=*} value=${line#*=}
  [ -n "$value" ] || continue
  if is_dev_value "$value"; then
    echo "bootstrap: setting $name holds a known dev-only value; remove it and re-run to generate a real one" >&2
    fail=1
  fi
done < "$env_file"
for name in "${secret_names[@]}"; do
  value=$(get "$name")
  [ -n "$value" ] || continue
  if is_placeholder "$value"; then
    echo "bootstrap: setting $name holds a placeholder value; remove it and re-run to generate a real one" >&2
    fail=1
  fi
  if [ "${#value}" -lt "$MIN_SECRET_BYTES" ]; then
    echo "bootstrap: setting $name is shorter than $MIN_SECRET_BYTES characters" >&2
    fail=1
  fi
done
[ "$fail" = 0 ] || { echo "bootstrap: refusing to continue; nothing was started" >&2; exit 1; }
echo "env: $env_file ok (mode $(stat -c %a "$env_file" 2>/dev/null || stat -f %Lp "$env_file"))"

# --- 3. initialise the bundled OpenBao once ----------------------------------------------------
if [ "$external" = 1 ]; then
  echo "key provider: external ($(get OPENBAO_ADDR)); bundled OpenBao is not started"
elif [ "$env_only" = 1 ]; then
  echo "key provider: bundled OpenBao (init skipped: --env-only)"
else
  echo "key provider: bundled OpenBao, production mode (key custody is containment, see compose.yaml)"
  docker compose --env-file "$env_file" -f "$here/compose.yaml" up -d --wait openbao >/dev/null
  echo "openbao: initialised, unsealed and healthy"
fi
