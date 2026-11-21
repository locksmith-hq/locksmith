#!/usr/bin/env bash
# Assert the self-host images are non-root, carry no dev-only values, and answer /healthz.
# Usage: scripts/image-check.sh   (run `just images` first). Secrets here are random and throwaway.
set -euo pipefail
cd "$(dirname "$0")/.."
TAG="${IMAGE_TAG:-dev}"
CP="locksmith-control-plane:$TAG"; GW="locksmith-gateway:$TAG"
fail=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; fail=1; }
rand() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

for img in "$CP" "$GW"; do
  user=$(docker image inspect -f '{{.Config.User}}' "$img")
  case "$user" in ""|0|root|0:*) bad "$img runs as root ('$user')";; *) ok "$img runs as user $user";; esac
  if docker history --no-trunc --format '{{.CreatedBy}}' "$img" | grep -qi 'dev-only'; then
    bad "$img has a dev-only string in a layer"; else ok "$img has no dev-only string in layers"; fi
  docker image inspect -f '{{.Config.Healthcheck}}' "$img" | grep -q . && ok "$img has a healthcheck" || bad "$img has no healthcheck"
done

work=$(mktemp -d); net="lsimgchk-$$"; pg="$net-pg"; cp_c="$net-cp"; gw_c="$net-gw"
cleanup() { docker rm -f "$pg" "$cp_c" "$gw_c" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
docker network create "$net" >/dev/null
pgpass=$(rand)
docker run -d --name "$pg" --network "$net" -e POSTGRES_PASSWORD="$pgpass" -e POSTGRES_DB=locksmith postgres:18.7 >/dev/null
for _ in $(seq 60); do docker exec "$pg" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
dsn="postgres://postgres:$pgpass@$pg:5432/locksmith"
cat > "$work/bindings.toml" <<TOML
org_id = "0197c1f0-0000-7000-8000-000000000001"
[[binding]]
secret_id = "0197c1f0-0000-7000-8000-000000000002"
origin = "https://api.example.com"
header = "Authorization"
template = "Bearer {secret}"
TOML
chmod 644 "$work/bindings.toml"

wait_healthy() { # container
  for _ in $(seq 60); do
    s=$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo gone)
    [ "$s" = healthy ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] || return 1
    sleep 2
  done
  return 1
}

docker run -d --name "$cp_c" --network "$net" -e DATABASE_URL="$dsn" -e DATABASE_OWNER_URL="$dsn" \
  -e LOCKSMITH_GATEWAY_SERVICE_TOKEN="$(rand)" "$CP" >/dev/null
if wait_healthy "$cp_c"; then ok "control plane container is healthy"; else bad "control plane not healthy"; docker logs --tail 20 "$cp_c" 2>&1 | sed 's/postgres:\/\/[^ ]*/<dsn>/g' || true; fi

docker run -d --name "$gw_c" --network "$net" -v "$work/bindings.toml:/etc/locksmith/bindings.toml:ro" \
  -e DATABASE_URL="$dsn" -e LOCKSMITH_CONTROL_PLANE_URL="http://$cp_c:8080" \
  -e LOCKSMITH_GATEWAY_SERVICE_TOKEN="$(rand)" -e OPENBAO_ADDR="http://openbao.invalid:8200" \
  -e OPENBAO_GATEWAY_TOKEN="$(rand)" -e LOCKSMITH_GATEWAY_BINDINGS=/etc/locksmith/bindings.toml "$GW" >/dev/null
if wait_healthy "$gw_c"; then ok "gateway container is healthy"; else bad "gateway not healthy"; docker logs --tail 20 "$gw_c" 2>&1 | sed 's/postgres:\/\/[^ ]*/<dsn>/g' || true; fi
exit "$fail"
