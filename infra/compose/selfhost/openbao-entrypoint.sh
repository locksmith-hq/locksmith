#!/bin/sh
# OpenBao production-mode entrypoint for the self-host bundle. Idempotent on every start:
#   1. start the server (integrated raft storage) as the openbao user;
#   2. initialise once (1 key share), writing the unseal key and root token to the openbao-keys
#      volume, mode 0600 in a 0700 directory (this volume is mounted by this service only);
#   3. unseal from that file;
#   4. enable transit, create the `gateway` and `audit-checkpoint` keys, the three one-capability
#      policies, and the three scoped tokens whose ids come from the environment.
# Nothing secret is printed: the unseal key goes to the CLI as an argument (no stdin without a tty),
# tokens are never echoed.
# KEY CUSTODY LABEL: containment, not prevention. Root on the host can read the keys volume.
set -eu
umask 077
export BAO_ADDR=http://127.0.0.1:8200
KEYS_DIR=/openbao-keys
INIT_FILE="$KEYS_DIR/init"
rm -f /tmp/openbao-ready

chown openbao /openbao/file
mkdir -p "$KEYS_DIR"; chmod 700 "$KEYS_DIR"

su-exec openbao bao server -config=/openbao/config/config.hcl &
server_pid=$!
trap 'kill -TERM "$server_pid" 2>/dev/null || true' TERM INT

# `bao status` exits 0 unsealed, 2 sealed, 1 when the server does not answer yet.
n=0
while :; do
  rc=0; bao status >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 1 ] && break
  n=$((n + 1)); [ "$n" -lt 60 ] || { echo "openbao: server did not answer" >&2; exit 1; }
  kill -0 "$server_pid" 2>/dev/null || { echo "openbao: server exited" >&2; exit 1; }
  sleep 1
done

field() { sed -n "s/^$1 //p" "$INIT_FILE" | head -n1; }

if bao status -format=json 2>/dev/null | grep -q '"initialized"[[:space:]]*:[[:space:]]*true'; then
  [ -s "$INIT_FILE" ] || { echo "openbao: initialised but no unseal material in $KEYS_DIR; restore the openbao-keys volume" >&2; exit 1; }
else
  tmp="$KEYS_DIR/init.partial"
  bao operator init -key-shares=1 -key-threshold=1 > "$tmp"
  awk '/^Unseal Key 1:/ {print "unseal_key", $4} /^Initial Root Token:/ {print "root_token", $4}' "$tmp" > "$INIT_FILE"
  rm -f "$tmp"; chmod 600 "$INIT_FILE"
  echo "openbao: initialised once; unseal material stored in the openbao-keys volume"
fi

if bao status >/dev/null 2>&1; then :; else
  # The CLI refuses stdin without a tty, so the key is an argument: visible only to root in this container.
  bao operator unseal "$(field unseal_key)" >/dev/null
  echo "openbao: unsealed"
fi

root=$(field root_token)
bao_root() { BAO_TOKEN="$root" bao "$@"; }

# Right after an unseal the raft node is still electing itself leader; wait until it serves requests.
n=0
until bao_root secrets list >/dev/null 2>&1; do
  n=$((n + 1)); [ "$n" -lt 60 ] || { echo "openbao: no active node after unseal" >&2; exit 1; }
  sleep 1
done

bao_root secrets list -format=json | grep -q '"transit/"' || bao_root secrets enable transit >/dev/null
bao_root read transit/keys/gateway >/dev/null 2>&1 || bao_root write -f transit/keys/gateway type=aes256-gcm96 >/dev/null
bao_root read transit/keys/audit-checkpoint >/dev/null 2>&1 \
  || bao_root write -f transit/keys/audit-checkpoint type=ed25519 exportable=false >/dev/null

printf 'path "transit/encrypt/gateway" {\n  capabilities = ["update"]\n}\n' | bao_root policy write control-plane - >/dev/null
printf 'path "transit/decrypt/gateway" {\n  capabilities = ["update"]\n}\n' | bao_root policy write gateway - >/dev/null
printf 'path "transit/sign/audit-checkpoint" {\n  capabilities = ["update"]\n}\n' | bao_root policy write audit-checkpoint - >/dev/null

ensure_token() { # policy-name token-id (the id is a secret: never printed)
  name=$1; id=$2
  [ -n "$id" ] || { echo "openbao: token id for $name is empty" >&2; exit 1; }
  if BAO_TOKEN="$id" bao token lookup >/dev/null 2>&1; then
    echo "token $name: exists"
  else
    if err=$(bao_root token create -id="$id" -policy="$name" -no-default-policy -orphan \
      -display-name="$name" -ttl=87600h 2>&1 >/dev/null); then
      echo "token $name: created"
    elif printf '%s' "$err" | grep -q 'duplicate ID'; then
      echo "token $name: exists"
    else
      echo "token $name: create failed: $(printf '%s' "$err" | sed "s/$id/<token>/g")" >&2; exit 1
    fi
  fi
}
ensure_token control-plane "${OPENBAO_CONTROL_PLANE_TOKEN:-}"
ensure_token gateway "${OPENBAO_GATEWAY_TOKEN:-}"
ensure_token audit-checkpoint "${OPENBAO_AUDIT_CHECKPOINT_TOKEN:-}"

touch /tmp/openbao-ready
echo "openbao: ready"
wait "$server_pid"
