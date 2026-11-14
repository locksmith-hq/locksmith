#!/usr/bin/env bash
# A4a: a rogue same-user client (python, node, socat, or a modified copy of smith) connects to the
# unlocked daemon socket and asks for operations. Each must be refused with Denied, and each must
# leave a BLOCKED/DENY/attestation audit row naming its executable.
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
locksmithd="$bindir/locksmithd"
[[ -x "$locksmithd" ]] || { echo "locksmithd was not built" >&2; exit 1; }

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

pw="a4a-test-passphrase"
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
printf '%s\n%s' "$pw" "$canary" | "$smith" --passphrase-stdin add A4A_KEY --stdin >/dev/null

# Hold a session open so the daemon (auto-started by smith) stays unlocked for the attack.
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

# Well-formed frames: 4-byte big-endian length, then CBOR {"v":1,"body":...}.
status_hex="00000010a261760164626f647966537461747573"
audit_frame_hex="$(python3 -I -c '
import struct
def txt(s):
    b = s.encode()
    return bytes([0x60 + len(b)]) + b
body = bytes([0xa2]) + txt("v") + bytes([0x01]) + txt("body") \
     + bytes([0xa1]) + txt("AuditList") + bytes([0xa1]) + txt("limit") + bytes([0x0a])
print((struct.pack(">I", len(body)) + body).hex())
')"
[[ "$status_hex" == 00000010* ]] || { echo "bad status frame" >&2; exit 1; }

rogue_ran=()

# Each rogue reply must contain the Denied error.
check_reply() {
  local name="$1" file="$ARTIFACT_DIR/$1.reply"
  grep -aq 'Denied' "$file" || { echo "$name: no Denied in reply" >&2; exit 1; }
  grep -aq 'not an attested Locksmith binary' "$file" \
    || { echo "$name: reply lacks attestation message" >&2; exit 1; }
  echo "$name: rejected"
}

# 1. python3: one connection per frame (Status, then AuditList). Replies are concatenated.
python3 -I - "$sock" "$status_hex" "$audit_frame_hex" >"$ARTIFACT_DIR/python.reply" <<'PY'
import socket, sys
sock_path = sys.argv[1]
for frame_hex in sys.argv[2:]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall(bytes.fromhex(frame_hex))
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    sys.stdout.buffer.write(data)
PY
check_reply python
rogue_ran+=(python)

# 2. node, if installed.
if command -v node >/dev/null 2>&1; then
  node -e '
    const net = require("net");
    const chunks = [];
    const c = net.createConnection(process.argv[1]);
    c.setTimeout(10000, () => c.destroy());
    c.on("connect", () => c.end(Buffer.from(process.argv[2], "hex")));
    c.on("data", (d) => chunks.push(d));
    c.on("error", (e) => { console.error(e.message); process.exit(1); });
    c.on("close", () => process.stdout.write(Buffer.concat(chunks)));
  ' "$sock" "$status_hex" >"$ARTIFACT_DIR/node.reply"
  check_reply node
  rogue_ran+=(node)
else
  echo "node: skipped (not installed)"
fi

# 3. socat, if installed.
if command -v socat >/dev/null 2>&1; then
  printf '\x00\x00\x00\x10\xa2\x61\x76\x01\x64\x62\x6f\x64\x79\x66\x53\x74\x61\x74\x75\x73' \
    | socat -t 2 - UNIX-CONNECT:"$sock" >"$ARTIFACT_DIR/socat.reply" || true
  check_reply socat
  rogue_ran+=(socat)
else
  echo "socat: skipped (not installed)"
fi

# 4. A copy of smith with one byte of its help string changed and re-signed ad hoc (new cdhash).
copy="$work/smith-copy"
cp "$smith" "$copy"
python3 -I - "$copy" <<'PY'
import sys
path = sys.argv[1]
needle = b'Locksmith: credentials for AI agents'
with open(path, 'rb') as f:
    data = f.read()
i = data.find(needle)
assert i >= 0, 'help string not found in binary'
off = i + needle.index(b'credentials')
with open(path, 'r+b') as f:
    f.seek(off)
    f.write(b'C')
PY
if [[ "$(uname -s)" == "Darwin" ]]; then
  codesign -f -s - "$copy" >/dev/null 2>&1
fi
copy_rc=0
LOCKSMITH_HOME="$LOCKSMITH_HOME" "$copy" revoke --all >"$ARTIFACT_DIR/smith-copy.out" \
  2>"$ARTIFACT_DIR/smith-copy.reply" || copy_rc=$?
[[ $copy_rc -eq 3 ]] || { echo "smith-copy: expected exit 3, got $copy_rc" >&2; exit 1; }
grep -q 'not an attested' "$ARTIFACT_DIR/smith-copy.reply" \
  || { echo "smith-copy: stderr lacks 'not an attested'" >&2; exit 1; }
echo "smith-copy: rejected"
rogue_ran+=(smith-copy)

# The real smith must still see the session, so the rogue revoke did nothing.
LOCKSMITH_HOME="$LOCKSMITH_HOME" "$smith" status --json >"$ARTIFACT_DIR/status.json"
python3 -I -c '
import json, sys
st = json.load(open(sys.argv[1]))
n = len(st.get("sessions", []))
if n != 1:
    sys.exit(f"expected 1 active session after rogue revoke, found {n}")
' "$ARTIFACT_DIR/status.json" || { echo "session check failed" >&2; exit 1; }

# Audit ledger: each client that ran must have a BLOCKED / DENY / attestation row naming its exe.
printf '%s\n' "$pw" | "$smith" --passphrase-stdin audit ls --json --limit 100 >"$ARTIFACT_DIR/audit.json"
python3 -I -c '
import json, sys
events = json.load(open(sys.argv[1]))["events"]
wanted = sys.argv[2:]
for name in wanted:
    hits = [
        e for e in events
        if e.get("action") == "BLOCKED"
        and e.get("decision") == "DENY"
        and e.get("policy_rule") == "attestation"
        and name.lower() in e.get("actor_exe", "").lower()
    ]
    if not hits:
        sys.exit(f"no BLOCKED/DENY/attestation event with actor_exe containing {name!r}")
' "$ARTIFACT_DIR/audit.json" "${rogue_ran[@]}" || { echo "audit check failed" >&2; exit 1; }

echo "A4a: all rogue clients rejected and audited"
