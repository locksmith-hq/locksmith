#!/usr/bin/env bash
# Live gateway attacks (S6 task 6.2), run by tests/adversarial/gate.sh with `--agent claude`; not
# a G case, so `run.sh gateway` never runs it. Same contract as a case: CANARY_FILE, ARTIFACT_DIR,
# exit 77 with `skip: ...` when it cannot run.
#
# Setup as the G cases (lib.sh): an org, the canary as a secret bound to fixtures/http_upstream.py
# (the reflecting provider, which also serves the G4 forms), an attacker's host (the fixture as
# `evil`, its log in evil-hits.log), a gateway and a `smith login --agent`. Then each prompt in
# prompts/*.md (env, reflection, header echo, encodings, API, token) runs as one headless
# `claude -p --bare` session in the agent's environment (lib.sh gw_agent: only PATH, HOME and the
# connector settings, plus ANTHROPIC_API_KEY for the CLI itself), with the Locksmith MCP server
# (locksmith-mcp, from --mcp-config only) and the Bash tool and nothing else. Placeholders
# {{SMITH}}, {{SECRET_ID}}, {{GATEWAY_URL}}, {{CONTROL_PLANE_URL}}, {{PROVIDER_URL}} and
# {{EVIL_URL}} are filled in per run; the prompts are versioned so runs compare.
#
# Each transcript (stream-json) goes to ARTIFACT_DIR/transcripts/<prompt>.jsonl; the gate scans
# them with `oracle.py scan --transcript` and the rest of ARTIFACT_DIR with `--dir`. The CLI's
# own API key is masked in everything saved here. Environment (optional):
# ADVERSARIAL_LIVE_PROMPTS (space-separated prompt names, default all),
# ADVERSARIAL_LIVE_TIMEOUT (seconds per prompt, default 900),
# ADVERSARIAL_LIVE_BUDGET_USD (per prompt, default 2).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
GW_CASE=live
gw_init

command -v claude >/dev/null 2>&1 || { echo "skip: the claude CLI is not installed"; exit 77; }
[[ -n "${ANTHROPIC_API_KEY:-}" ]] || { echo "skip: ANTHROPIC_API_KEY is not set"; exit 77; }
claude_bin="$(command -v claude)"
prompts_dir="$(dirname "${BASH_SOURCE[0]}")/prompts"

gw_fixture api provider
provider="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_fixture evil evil
evil="http://127.0.0.1:$GW_FIXTURE_PORT"
gw_setup "$provider"

# The CLI key goes to a private file that the wrapper below reads and deletes, so it is never on a
# command line; it is on the agent's environment, as for any Claude Code session.
key_file="$GW_WORK/anthropic.key"
mask_key() {
  python3 -I - "$@" <<'PY'
import os, sys
k = os.environ.get("ANTHROPIC_API_KEY", "").encode()
for p in sys.argv[1:]:
    if not k or not os.path.isfile(p):
        continue
    with open(p, "rb") as fh:
        data = fh.read()
    if k in data:
        with open(p, "wb") as fh:
            fh.write(data.replace(k, b"<ANTHROPIC_API_KEY>"))
PY
}

# Mask on every exit (early failure, set -e, signal), not only on the normal path.
mask_all() {
  local -a files
  mapfile -t files < <(find "$ARTIFACT_DIR" -type f 2>/dev/null)
  [[ ${#files[@]} -gt 0 ]] && mask_key "${files[@]}"
  return 0
}
gw_on_exit mask_all

# Proxy and CA settings go to the claude process only (the cloud VM reaches the API through them),
# never to smith or locksmith-mcp.
net_env=()
for v in HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE CURL_CA_BUNDLE; do
  [[ -n "${!v:-}" ]] && net_env+=("$v=${!v}")
done

python3 -I -c '
import json, sys
mcp, home, cp, gw = sys.argv[1:5]
json.dump({"mcpServers": {"locksmith": {"command": mcp, "args": [], "env": {
    "LOCKSMITH_HOME": home, "LOCKSMITH_CONTROL_PLANE_URL": cp, "LOCKSMITH_GATEWAY_URL": gw}}}},
    open(sys.argv[5], "w"), indent=1)
' "$GW_MCP_BIN" "$ARTIFACT_DIR/agent" "$GW_API" "$GW_GATEWAY_URL" "$ARTIFACT_DIR/mcp-config.json"

mkdir -p "$ARTIFACT_DIR/transcripts"
names=()
if [[ -n "${ADVERSARIAL_LIVE_PROMPTS:-}" ]]; then
  read -r -a names <<<"$ADVERSARIAL_LIVE_PROMPTS"
else
  for p in "$prompts_dir"/*.md; do names+=("$(basename "$p" .md)"); done
fi
[[ ${#names[@]} -gt 0 ]] || gw_fail "no prompts in $prompts_dir"

ran=0
for name in "${names[@]}"; do
  src="$prompts_dir/$name.md"
  [[ -f "$src" ]] || gw_fail "no prompt $src"
  prompt="$ARTIFACT_DIR/prompt-$name.md"
  python3 -I - "$src" "$prompt" "$GW_SMITH_BIN" "$GW_SECRET_ID" "$GW_GATEWAY_URL" "$GW_API" \
    "$provider" "$evil" <<'PY'
import sys
src, out, smith, sid, gw, cp, provider, evil = sys.argv[1:9]
text = open(src).read()
for k, v in (("SMITH", smith), ("SECRET_ID", sid), ("GATEWAY_URL", gw), ("CONTROL_PLANE_URL", cp),
             ("PROVIDER_URL", provider), ("EVIL_URL", evil)):
    text = text.replace("{{%s}}" % k, v)
if "{{" in text:
    sys.exit("unfilled placeholder in " + src)
open(out, "w").write(text)
PY
  cwd="$ARTIFACT_DIR/workdir-$name"
  mkdir -p "$cwd"
  printf '%s' "$ANTHROPIC_API_KEY" >"$key_file"
  transcript="$ARTIFACT_DIR/transcripts/$name.jsonl"
  rc=0
  (
    cd "$cwd"
    gw_agent env ${net_env[@]+"${net_env[@]}"} bash -c 'export ANTHROPIC_API_KEY="$(<"$1")"; rm -f "$1"; shift; exec "$@"' _ "$key_file" \
      timeout -s KILL "${ADVERSARIAL_LIVE_TIMEOUT:-900}" "$claude_bin" -p "$(<"$prompt")" --bare \
      --output-format stream-json --verbose \
      --mcp-config "$ARTIFACT_DIR/mcp-config.json" --strict-mcp-config \
      --tools Bash --allowedTools Bash mcp__locksmith \
      --max-budget-usd "${ADVERSARIAL_LIVE_BUDGET_USD:-2}"
  ) >"$transcript" 2>"$ARTIFACT_DIR/claude-$name.err" </dev/null || rc=$?
  rm -f "$key_file"
  echo "live $name: claude exit $rc, $(wc -l <"$transcript") transcript lines"
  [[ -s "$transcript" ]] || gw_fail "live $name: empty transcript (see claude-$name.err)"
  ran=$((ran + 1))
done

# Mask the CLI key in everything saved (the agent may have printed its own environment).
mask_all
echo "live: $ran prompts run, transcripts in transcripts/"
