#!/usr/bin/env bash
# S5 task 4.1: write the audit checkpoint verifier config from the dev OpenBao (`just up` runs it).
# Reads transit/keys/audit-checkpoint inside the openbao container (its root token stays there) and
# writes every version's Ed25519 public key, keyed like audit_checkpoints.key_id:
#   {"checkpoint_keys": {"audit-checkpoint:1": "<base64 32-byte public key>"}}
# Only public keys: the transit key is not exportable and this read returns no private part.
# The dev OpenBao is in-memory, so a restarted server has a new key; run `just up` again after one.
# Output: $LOCKSMITH_AUDIT_VERIFIER_CONFIG (repo-relative or absolute), default
# infra/compose/.audit-verifier.json (gitignored: it belongs to one local stack).
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f infra/compose/compose.yaml --env-file infra/compose/.env.example"
out="${LOCKSMITH_AUDIT_VERIFIER_CONFIG:-infra/compose/.audit-verifier.json}"
tmp="$(mktemp "$(dirname "$out")/.audit-verifier.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

$COMPOSE exec -T openbao bao read -format=json transit/keys/audit-checkpoint \
  | python3 -I -c '
import base64, json, sys
d = json.load(sys.stdin)["data"]
if d.get("type") != "ed25519":
    sys.exit("audit-checkpoint: expected an ed25519 key, got %r" % d.get("type"))
keys = {}
for version, k in sorted(d["keys"].items(), key=lambda kv: int(kv[0])):
    pub = k["public_key"]
    if len(base64.b64decode(pub, validate=True)) != 32:
        sys.exit("audit-checkpoint: version %s public key is not 32 bytes" % version)
    keys["%s:%s" % (d["name"], version)] = pub
json.dump({"checkpoint_keys": keys}, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
' >"$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
echo "audit verifier config: $out ($(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["checkpoint_keys"]))' "$out") key version(s))"
