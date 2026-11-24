#!/usr/bin/env bash
# `just agent-smoke <name>`: run one agent framework example against the local stack as the agent.
#   name `client`  -> packages/agent/example      (the @locksmith/agent client alone)
#   name `<other>` -> integrations/agent-<name>/example   (package.json: vitest; pyproject.toml: pytest)
# Needs `just up` and `just api` (exits 77 `skip: stack not running` otherwise). Sets up an org, the
# fresh canary as a secret, an agent and a grant plus a WireMock stub, runs the example with only the
# enrollment secret and the gateway URL, asserts WireMock received the credential, then scans the
# artifacts and the transcript for the canary and the enrollment secret. Nothing here prints a secret.
set -euo pipefail
name="${1:?usage: agent-smoke.sh <name>}"
[[ "$name" =~ ^[a-z][a-z0-9-]*$ ]] || { echo "agent-smoke: bad name" >&2; exit 2; }
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
if [[ "$name" == client ]]; then dir="packages/agent"; else dir="integrations/agent-$name"; fi
[[ -d "$dir/example" ]] || { echo "agent-smoke: no example in $dir" >&2; exit 2; }

[[ -f "${LOCKSMITH_CANARIES:-infra/compose/.canaries}" ]] || just canary new >/dev/null
canaries="${LOCKSMITH_CANARIES:-$root/infra/compose/.canaries}"
export ARTIFACT_DIR="$root/target/agent-smoke/$name"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
export GW_CASE="agent-smoke-$name"
# A fresh canary of its own, in a private file, so the run never reuses an earlier value.
fresh="$(mktemp)"
trap 'rm -f "$fresh"' EXIT
python3 -I tests/kit/oracle.py canary-new --file "$fresh" >/dev/null
export CANARY_FILE="$fresh"
canary="$(awk 'NF{print $NF}' "$fresh" | tail -n 1)"

# shellcheck source=tests/adversarial/gateway/lib.sh
. tests/adversarial/gateway/lib.sh
gw_init

wm="${E2E_WIREMOCK_URL:-http://127.0.0.1:8089}"
path="/agent-smoke-$name-$(date +%s%N)"
stub="$GW_WORK/stub.json"
printf '{"request":{"method":"GET","url":"%s"},"response":{"status":200,"jsonBody":{"ok":true}}}' "$path" >"$stub"
[[ "$(gw_curl -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$stub" "$wm/__admin/mappings")" =~ ^2 ]] ||
  gw_fail "could not add the WireMock stub (is \`just up\` running?)"
gw_setup "$wm"

transcript="$ARTIFACT_DIR/transcript.jsonl"
: >"$transcript"
cache="${npm_config_cache:-$(npm config get cache 2>/dev/null || echo "$HOME/.npm")}"
# The example gets the enrollment secret and the gateway URL, as a launcher would supply them.
run=(env "LOCKSMITH_TRANSCRIPT=$transcript" "LOCKSMITH_SMOKE_URL=$wm$path" "npm_config_cache=$cache" "UV_CACHE_DIR=${UV_CACHE_DIR:-$HOME/.cache/uv}")
if [[ -f "$dir/pyproject.toml" ]]; then
  run+=(uv run --locked --project "$root/$dir" pytest "$root/$dir/example")
else
  run+=(npx --prefix "$root/$dir" vitest run --root "$root/$dir" example)
fi
rc=0
GW_WITH_ENROLLMENT=1 gw_agent "${run[@]}" >"$ARTIFACT_DIR/example.out" 2>"$ARTIFACT_DIR/example.err" || rc=$?
[[ $rc -eq 0 ]] || gw_fail "the example failed (exit $rc; see $ARTIFACT_DIR/example.err)"
[[ -s "$transcript" ]] || gw_fail "the example wrote no transcript"

# WireMock must have received the credential on the stubbed path; the journal is read in place and
# never saved, and only a count is printed.
hits="$(gw_curl "$wm/__admin/requests" | CANARY="$canary" P="$path" python3 -I -c '
import json, os, sys
c, p = os.environ["CANARY"], os.environ["P"]
j = json.load(sys.stdin)
print(sum(1 for r in j.get("requests", [])
          if r["request"].get("url") == p and r["request"].get("headers", {}).get("Authorization") == "Bearer " + c))
')"
[[ "${hits:-0}" -ge 1 ]] || gw_fail "WireMock did not receive the credential"

# The canary and the enrollment secret must be in nothing the agent produced.
python3 -I -c '
import base64, sys
t = open(sys.argv[1]).read().strip()
raw = base64.urlsafe_b64decode(t[4:] + "=" * (-len(t[4:]) % 4))
open(sys.argv[2], "w").write(base64.urlsafe_b64encode(raw[32:]).rstrip(b"=").decode() + "\n")
' "$GW_ENROLLMENT_FILE" "$GW_WORK/enrollment.canary"
for cf in "$fresh" "$GW_WORK/enrollment.canary"; do
  python3 -I tests/kit/oracle.py scan --canary-file "$cf" --dir "$ARTIFACT_DIR" --transcript "$transcript" ||
    gw_fail "a secret is in the artifacts or the transcript"
done
just leak-scan --transcript "$transcript" --dir "$ARTIFACT_DIR"
echo "agent-smoke $name: ok (WireMock received the credential $hits time(s); transcript $transcript)"
