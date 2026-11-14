#!/usr/bin/env bash
# A0-offline: a canary stored in a fresh vault must not appear in the raw vault files, and the
# secret's name must not either. Runs fully offline with the debug-only weak KDF.
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

pw="a0-offline-test-passphrase"
canary="$(cat "$CANARY_FILE")"
key="KEY_$(printf '%s' "${canary:0:12}" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')"

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
printf '%s\n%s' "$pw" "$canary" | "$smith" --passphrase-stdin add "$key" --stdin >/dev/null

vault="$LOCKSMITH_HOME/vault"
[[ -f "$vault/vault.header" ]] || { echo "no vault header was written" >&2; exit 1; }

# Oracle input: every raw vault file, plus a text listing that contains the key name.
cp -R "$vault/." "$ARTIFACT_DIR/"
printf '%s\n' "$pw" | "$smith" --passphrase-stdin ls >"$ARTIFACT_DIR/ls.txt"
grep -qF -- "$key" "$ARTIFACT_DIR/ls.txt" || { echo "secret was not stored" >&2; exit 1; }

if grep -rqF -- "$key" "$vault"; then
  echo "secret name appears in raw vault files" >&2
  exit 1
fi
echo "A0-offline: no plaintext secret name in vault files"
