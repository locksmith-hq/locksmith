#!/bin/sh
# Idempotent OpenBao dev setup, run as the `openbao` compose service's healthcheck (so it repeats
# every few seconds and must stay cheap, quiet about values, and safe to re-run).
# Enables transit, creates the `gateway` key and the permission split from
# openspec/changes/s2-envelope-crypto design decision 4:
#   control-plane token: update on transit/encrypt/gateway only (wrap, never unwrap)
#   gateway test token:  update on transit/decrypt/gateway only (unwrap)
# and the S5 checkpoint signer (openspec/changes/s5-audit-ledger design decision 4):
#   key audit-checkpoint: ed25519, not exportable (only its public key can be read)
#   audit-checkpoint token: update on transit/sign/audit-checkpoint only (sign, nothing else)
# and the OAuth connection token sets (openspec/changes/c1-oauth-connections design decision 6):
#   key oauth-connections: aes256-gcm96, wraps the DEKs of sealed OAuth token sets
#   gateway-oauth token: update on transit/encrypt|decrypt/oauth-connections only; the `gateway`
#   key and its policies above are unchanged
# Token ids are fixed dev-only fixtures from .env.example, never real credentials.
# Dev mode is in-memory; because this runs as the healthcheck, a restarted server is set up again.
# Re-run by hand: docker compose -f infra/compose/compose.yaml exec openbao sh /openbao-init.sh
set -eu

: "${BAO_ADDR:?}" "${BAO_TOKEN:?}"
CP_TOKEN="${OPENBAO_CONTROL_PLANE_TOKEN:-dev-only-control-plane}"
GW_OAUTH_TOKEN="${OPENBAO_GATEWAY_OAUTH_TOKEN:-dev-only-gateway-oauth}"
GW_TOKEN="${OPENBAO_GATEWAY_TOKEN:-dev-only-gateway}"
CK_TOKEN="${OPENBAO_AUDIT_CHECKPOINT_TOKEN:-dev-only-audit-checkpoint}"

if bao secrets list -format=json | grep -q '"transit/"'; then
  echo "transit: already enabled"
else
  bao secrets enable transit >/dev/null
  echo "transit: enabled"
fi

if bao read -format=json transit/keys/gateway >/dev/null 2>&1; then
  echo "key gateway: exists"
else
  bao write -f transit/keys/gateway type=aes256-gcm96 >/dev/null
  echo "key gateway: created (aes256-gcm96)"
fi

if bao read -format=json transit/keys/oauth-connections >/dev/null 2>&1; then
  echo "key oauth-connections: exists"
else
  bao write -f transit/keys/oauth-connections type=aes256-gcm96 >/dev/null
  echo "key oauth-connections: created (aes256-gcm96)"
fi

if bao read -format=json transit/keys/audit-checkpoint >/dev/null 2>&1; then
  echo "key audit-checkpoint: exists"
else
  bao write -f transit/keys/audit-checkpoint type=ed25519 exportable=false >/dev/null
  echo "key audit-checkpoint: created (ed25519)"
fi

# Policies are rewritten every run (same content, so idempotent).
printf 'path "transit/encrypt/gateway" {\n  capabilities = ["update"]\n}\n' \
  | bao policy write control-plane - >/dev/null
printf 'path "transit/decrypt/gateway" {\n  capabilities = ["update"]\n}\n' \
  | bao policy write gateway - >/dev/null
printf 'path "transit/encrypt/oauth-connections" {\n  capabilities = ["update"]\n}\npath "transit/decrypt/oauth-connections" {\n  capabilities = ["update"]\n}\n' \
  | bao policy write gateway-oauth - >/dev/null
printf 'path "transit/sign/audit-checkpoint" {\n  capabilities = ["update"]\n}\n' \
  | bao policy write audit-checkpoint - >/dev/null
echo "policies: control-plane, gateway, gateway-oauth, audit-checkpoint written"

# Tokens: created with fixed ids only if missing. Orphans without the default policy so each
# holds exactly one transit capability. The values are never printed.
ensure_token() {
  name=$1 id=$2
  if bao token lookup "$id" >/dev/null 2>&1; then
    echo "token $name: exists"
  else
    # A custom id makes OpenBao warn about SHA1 token hashing; acceptable for dev fixtures, so the
    # warning is dropped. On failure only the error is shown (stdout, which holds the token, never).
    if ! err=$(bao token create -id="$id" -policy="$name" -no-default-policy -orphan \
      -display-name="$name" -ttl=768h 2>&1 >/dev/null); then
      echo "token $name: create failed: $err" >&2
      exit 1
    fi
    echo "token $name: created"
  fi
}
ensure_token control-plane "$CP_TOKEN"
ensure_token gateway "$GW_TOKEN"
ensure_token gateway-oauth "$GW_OAUTH_TOKEN"
ensure_token audit-checkpoint "$CK_TOKEN"
echo "openbao-init: done"
