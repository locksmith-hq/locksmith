#!/usr/bin/env bash
# A6a: under `smith run`, a child prints a stored canary in every common encoding, slowly and
# split across writes, to both stdout and stderr. The oracle must find no encoded canary, and
# the output must show the redaction marker so a no-op run cannot pass.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${CANARY_FILE:?CANARY_FILE is required}" "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"

# run.sh replaces HOME with a throwaway directory; keep rustup and cargo on the real home.
real_home="$(eval echo "~$(id -un)")"
export RUSTUP_HOME="${RUSTUP_HOME:-$real_home/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$real_home/.cargo}"
export PATH="/opt/homebrew/opt/rustup/bin:$CARGO_HOME/bin:$PATH"

cargo build -q -p smith-cli
smith="${CARGO_TARGET_DIR:-$root/target}/debug/smith"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export LOCKSMITH_HOME="$work/home"
export LOCKSMITH_INSECURE_TEST_KDF=1
mkdir -p "$LOCKSMITH_HOME"

pw="a6a-test-passphrase"
canary="$(cat "$CANARY_FILE")"

# vault init needs the confirmation words, which only appear on stderr. Feed stdin through a
# FIFO so the script can read the words, then answer the three positions.
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
printf '%s\n%s' "$pw" "$canary" | "$smith" --passphrase-stdin add A6A_KEY --stdin >/dev/null

# The child prints $A6A_KEY in each form. Single quotes keep it for the child shell to expand.
child='
printf "%s\n" "$A6A_KEY"
printf %s "$A6A_KEY" | base64
printf "x%s" "$A6A_KEY" | base64
printf %s "$A6A_KEY" | xxd -p | tr -d "\n"; echo
python3 -c "import json,os;print(json.dumps(os.environ[\"A6A_KEY\"]))"
printf "%s\n" "$A6A_KEY" >&2
printf "slow:"
for i in $(seq 1 ${#A6A_KEY}); do
  printf "%s" "$(printf %s "$A6A_KEY" | cut -c "$i")"
  sleep 0.05
done
echo
'

out="$ARTIFACT_DIR/stdout.txt"
err_out="$ARTIFACT_DIR/stderr.txt"
run_rc=0
printf '%s\n' "$pw" | "$smith" --passphrase-stdin run --only A6A_KEY --yes -- sh -c "$child" \
  >"$out" 2>"$err_out" || run_rc=$?
[[ $run_rc -eq 0 ]] || { echo "smith run exited $run_rc" >&2; exit 1; }

# Redaction must have happened, or the run proved nothing.
if ! cat "$out" "$err_out" | grep -qF -- "[REDACTED:A6A_KEY]"; then
  echo "no [REDACTED:A6A_KEY] marker in smith output" >&2
  exit 1
fi
echo "A6a: child output captured and redacted"
