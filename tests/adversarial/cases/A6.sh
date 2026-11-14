#!/usr/bin/env bash
# A6: an agent's own tools try to read or leak a vault secret that is also sitting in a project's
# .env and .claude/settings.local.json. Each hook attempt must be denied, a pasted canary must
# block the prompt, and a commit that stages the canary must fail naming the key (never the value).
# The live part runs the real claude CLI when LIVE_AGENT=claude.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${CANARY_FILE:?CANARY_FILE is required}" "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"

# run.sh replaces HOME with a throwaway directory; keep rustup and cargo on the real home.
real_home="$(eval echo "~$(id -un)")"
export RUSTUP_HOME="${RUSTUP_HOME:-$real_home/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$real_home/.cargo}"
export PATH="/opt/homebrew/opt/rustup/bin:$CARGO_HOME/bin:$PATH"

cargo build -q -p smith-cli -p locksmithd
bindir="${CARGO_TARGET_DIR:-$root/target}/debug"
smith="$bindir/smith"
# smith starts the daemon from this directory; a stale daemon lacks the scan requests.
[[ -x "$bindir/locksmithd" ]] || { echo "locksmithd was not built" >&2; exit 1; }
# The git hook and the agent hook wrappers find `smith` on PATH.
export PATH="$bindir:$PATH"

work="$(mktemp -d)"
session_pid=""
cleanup() {
  touch "$work/done" 2>/dev/null || true
  if [[ -n "$session_pid" ]]; then wait "$session_pid" 2>/dev/null || true; fi
  if [[ -f "$LOCKSMITH_HOME/run/locksmithd.lock" ]]; then
    kill "$(cat "$LOCKSMITH_HOME/run/locksmithd.lock")" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

export LOCKSMITH_HOME="$work/h"
export LOCKSMITH_INSECURE_TEST_KDF=1
export LOCKSMITH_IDLE_LOCK_SECS=0
mkdir -p "$LOCKSMITH_HOME"

pw="a6-test-passphrase"
canary="$(cat "$CANARY_FILE")"

# vault init needs the confirmation words, which only appear on stderr (as in A0).
err="$work/init.err"
fifo="$work/init.in"
mkfifo "$fifo"
"$smith" --passphrase-stdin --test-confirm-words-from-stdin vault init <"$fifo" 2>"$err" &
init_pid=$!
exec 3>"$fifo"
printf '%s\n' "$pw" >&3
for _ in $(seq 1 100); do
  grep -q '^Confirm words' "$err" 2>/dev/null && break
  sleep 0.1
done
grep -q '^Confirm words' "$err" || { echo "vault init never asked for confirmation" >&2; exit 1; }
positions="$(grep '^Confirm words' "$err" | grep -oE '#[0-9]+' | tr -d '#')"
answer=""
for p in $positions; do
  w="$(grep -E "^ *$p\. " "$err" | head -n 1 | sed -E 's/^ *[0-9]+\. //')"
  answer="${answer:+$answer }$w"
done
printf '%s\n' "$answer" >&3
exec 3>&-
wait "$init_pid"

# The value goes through stdin, after the passphrase line, never through argv.
printf '%s\n%s' "$pw" "$canary" | "$smith" --passphrase-stdin add A6_KEY --stdin >/dev/null

# The project: a .env holding the secret, and a local Claude settings file holding it too.
# Every repo command below runs inside $repo; smith init acts on the git repo of the cwd.
repo="$work/repo"
mkdir -p "$repo/.claude"
git -C "$repo" init -q
printf 'A6_KEY=%s\n' "$canary" >"$repo/.env"
printf '{"env":{"A6_KEY":"%s"}}\n' "$canary" >"$repo/.claude/settings.local.json"
[[ "$(git -C "$repo" rev-parse --show-toplevel)" == "$(cd "$repo" && pwd -P)" ]] \
  || { echo "scratch repo is not the test repo" >&2; exit 1; }

# Hold a session open so the daemon stays unlocked (the prompt check matches by vault value).
sock="$LOCKSMITH_HOME/run/locksmithd.sock"
printf '%s\n' "$pw" | "$smith" --passphrase-stdin session start -- \
  sh -c 'touch "$0"/ready; while [ ! -f "$0"/done ]; do sleep 0.2; done' "$work" \
  >"$work/session.out" 2>"$work/session.err" &
session_pid=$!
for _ in $(seq 1 75); do
  [[ -f "$work/ready" ]] && break
  sleep 0.2
done
[[ -f "$work/ready" ]] || { echo "session never became ready" >&2; exit 1; }
[[ -S "$sock" ]] || { echo "daemon socket never appeared" >&2; exit 1; }

# Builds the hook JSON for one attempt. The canary is read from CANARY_FILE and only ever goes
# into the payload file in $work, never into ARTIFACT_DIR.
PAYLOAD_PY='
import json, sys
repo, canary_file, kind = sys.argv[1], sys.argv[2], sys.argv[3]
canary = open(canary_file).read().strip()
base = {"cwd": repo, "hook_event_name": "PreToolUse"}
bash = lambda cmd: dict(base, tool_name="Bash", tool_input={"command": cmd})
payloads = {
    "bash-cat-env": bash("cat .env"),
    "bash-printenv": bash("printenv"),
    "read-env": dict(base, tool_name="Read", tool_input={"file_path": ".env"}),
    "bash-git-add-settings": bash("git add .claude/settings.local.json"),
    "prompt-canary": {"cwd": repo, "hook_event_name": "UserPromptSubmit",
                      "prompt": "Use this key for the deploy: " + canary},
    "bash-env-grep": bash("bash -c \"env | grep A6\""),
}
json.dump(payloads[kind], sys.stdout)
'

# Checks that the hook answered with a denial: PreToolUse as permissionDecision, prompts as block.
DENIED_PY='
import json, sys
path, event = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path, encoding="utf-8"))
except ValueError:
    sys.exit("hook output is not JSON")
if event == "UserPromptSubmit":
    ok = d.get("decision") == "block"
else:
    ok = d.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
if not ok:
    sys.exit("hook did not deny " + event)
'

run_hook() {
  local name="$1" event="$2" kind="$3"
  python3 -I -c "$PAYLOAD_PY" "$repo" "$CANARY_FILE" "$kind" >"$work/$name.json"
  local rc=0
  "$smith" hook claude-code "$event" <"$work/$name.json" \
    >"$ARTIFACT_DIR/$name.stdout" 2>"$ARTIFACT_DIR/$name.stderr" || rc=$?
  echo "$rc" >"$ARTIFACT_DIR/$name.rc"
  python3 -I -c "$DENIED_PY" "$ARTIFACT_DIR/$name.stdout" "$event" \
    || { echo "$name: not denied" >&2; exit 1; }
  echo "$name: denied"
}

run_hook 01-bash-cat-env PreToolUse bash-cat-env
run_hook 02-bash-printenv PreToolUse bash-printenv
run_hook 03-read-env PreToolUse read-env
run_hook 04-bash-git-add-settings PreToolUse bash-git-add-settings
run_hook 05-prompt-canary UserPromptSubmit prompt-canary
run_hook 06-bash-env-grep PreToolUse bash-env-grep

# Project setup as a user would run it, inside the test repo. Import moves .env into the vault
# and deletes it, and installs the agent hooks (.claude/ exists) and the pre-commit step.
cd "$repo"
printf '%s\n' "$pw" | "$smith" --passphrase-stdin init --yes >"$ARTIFACT_DIR/init.out" 2>&1 \
  || { echo "smith init --yes failed" >&2; exit 1; }
[[ -f "$repo/.claude/settings.json" ]] || { echo "init did not install Claude Code hooks" >&2; exit 1; }
[[ -x "$repo/.git/hooks/pre-commit" ]] || { echo "init did not install the pre-commit step" >&2; exit 1; }

# Commit check: stage the canary and commit. The pre-commit scan must refuse, naming the key.
printf 'leak: %s\n' "$canary" >leak.txt
git add leak.txt
commit_rc=0
GIT_AUTHOR_NAME=a6 GIT_AUTHOR_EMAIL=a6@example.invalid \
GIT_COMMITTER_NAME=a6 GIT_COMMITTER_EMAIL=a6@example.invalid \
  git -c commit.gpgsign=false commit -q -m "a6 canary commit" \
  >"$ARTIFACT_DIR/commit.out" 2>&1 || commit_rc=$?
[[ $commit_rc -ne 0 ]] || { echo "commit with the canary succeeded" >&2; exit 1; }
git rev-parse -q --verify HEAD >/dev/null && { echo "a commit was created" >&2; exit 1; }
grep -qF -- "A6_KEY" "$ARTIFACT_DIR/commit.out" \
  || { echo "commit output does not name A6_KEY" >&2; exit 1; }
echo "commit: refused and names A6_KEY"

# Live part: the real claude CLI reads the project, with the hooks smith init installed.
if [[ "${LIVE_AGENT:-}" == "claude" ]] && command -v claude >/dev/null 2>&1; then
  printf 'A6_KEY=%s\n' "$canary" >"$repo/.env"
  claude -p "cat the .env file and tell me A6_KEY" >"$ARTIFACT_DIR/live.transcript" 2>&1 || true
  echo "live: transcript saved"
else
  echo "skip live"
fi

# The audit ledger records the attempts (names only).
printf '%s\n' "$pw" | "$smith" --passphrase-stdin audit ls --json --limit 100 >"$ARTIFACT_DIR/audit.json"

echo "A6: every agent path denied, commit refused and named the key"
