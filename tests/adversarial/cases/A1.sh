#!/usr/bin/env bash
# A1: an agent tries to extract the upstream Git PAT (the canary) from inside a session: credential
# fill, git config files, the credential helper run directly, GIT_TRACE_CURL on a push, a loopback
# sniffer, and a forwarder token replayed from outside the session. Everything the attempts print is
# saved in ARTIFACT_DIR for the oracle. The push must work and a push deleting main must be refused.
# The fixture upstream (example.test -> 127.0.0.1) only accepts Basic x-access-token:<canary>.
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
[[ -x "$bindir/locksmithd" ]] || { echo "locksmithd was not built" >&2; exit 1; }
export PATH="$bindir:$PATH"

work="$(mktemp -d)"
session_pid=""
up_pid=""
cleanup() {
  touch "$work/done" 2>/dev/null || true
  if [[ -n "$session_pid" ]]; then wait "$session_pid" 2>/dev/null || true; fi
  if [[ -f "${LOCKSMITH_HOME:-/nonexistent}/run/locksmithd.lock" ]]; then
    kill "$(cat "$LOCKSMITH_HOME/run/locksmithd.lock")" 2>/dev/null || true
  fi
  if [[ -n "$up_pid" ]]; then kill "$up_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

export LOCKSMITH_HOME="$work/h"
export LOCKSMITH_INSECURE_TEST_KDF=1
export LOCKSMITH_IDLE_LOCK_SECS=0
mkdir -p "$LOCKSMITH_HOME"
pw="a1-test-passphrase"
canary="$(cat "$CANARY_FILE")"
A="$ARTIFACT_DIR"
fail() { echo "A1 FAIL: $*" >&2; exit 1; }

# Fixture upstream: bare repo acme/app.git behind the canary-only Basic auth.
bare="$work/up/acme/app.git"
mkdir -p "$bare"
git init -q --bare "$bare"
git -C "$bare" config http.receivepack true
python3 -I "$root/tests/adversarial/fixtures/git_upstream.py" "$work/up" "$CANARY_FILE" "$work/up.port" \
  2>"$work/upstream.log" &
up_pid=$!
for _ in $(seq 1 50); do [[ -s "$work/up.port" ]] && break; sleep 0.1; done
[[ -s "$work/up.port" ]] || fail "fixture upstream did not start"
export LOCKSMITH_TEST_GIT_UPSTREAM="example.test=127.0.0.1:$(cat "$work/up.port")"

# vault init needs the confirmation words, which only appear on stderr (as in A6).
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
grep -q '^Confirm words' "$err" || fail "vault init never asked for confirmation"
positions="$(grep '^Confirm words' "$err" | grep -oE '#[0-9]+' | tr -d '#')"
answer=""
for p in $positions; do
  w="$(grep -E "^ *$p\. " "$err" | head -n 1 | sed -E 's/^ *[0-9]+\. //')"
  answer="${answer:+$answer }$w"
done
printf '%s\n' "$answer" >&3
exec 3>&-
wait "$init_pid"

# The work repo: origin is the private host; the binding names the vault key, never the value.
repo="$work/repo"
mkdir -p "$repo"
git -C "$repo" init -q -b main
printf '[git.credentials]\n"example.test" = "GIT_TOKEN"\n' >"$repo/.locksmith.toml"
cd "$repo"
printf '%s\n%s' "$pw" "$canary" | "$smith" --passphrase-stdin add GIT_TOKEN --stdin >/dev/null
printf '[user]\n\tname = a1\n\temail = a1@example.invalid\n' >"$HOME/.gitconfig"
git config commit.gpgsign false
echo one >f.txt
git add f.txt
git commit -q -m one
git remote add origin https://example.test/acme/app.git
git push -q "$bare" main # seed the upstream's main behind the forwarder's back
git switch -q -c feature
echo two >>f.txt
git commit -qam two

"$smith" git setup --host example.test --repo >"$A/00-setup.out" 2>&1 || fail "smith git setup failed"
port="$("$smith" git status --json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["port"])')"
[[ -n "$port" ]] || fail "no forwarder port"
fwd="git/example.test/acme/app.git"

# Sniffer (runs inside the session with a valid token, and outside it for the replay).
# Usage: sniff.py PORT TOKEN OUTFILE MODE; MODE inside = reflection probes, replay = one request.
cat >"$work/sniff.py" <<'PY'
import base64, socket, sys
port, token, out, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
path = "/git/example.test/acme/app.git/info/refs?service=git-upload-pack"
basic = lambda u, p: "Authorization: Basic " + base64.b64encode((u + ":" + p).encode()).decode()
probes = [("valid", [basic("locksmith", token)])]
if mode == "inside":
    probes += [
        ("override-second-authorization", [basic("locksmith", token), basic("x-access-token", "guess")]),
        ("forwarded-headers", [basic("locksmith", token), "X-Forwarded-For: 127.0.0.1", "X-Forwarded-Host: example.test",
                               "X-Forwarded-Proto: https", "X-Forwarded-Authorization: Basic eDp4", "Via: 1.1 evil"]),
        ("bearer", ["Authorization: Bearer " + token]),
        ("no-auth", []),
        ("wrong-token", [basic("locksmith", "0" * 64)]),
    ]
first = None
with open(out, "wb") as f:
    for name, hs in probes:
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
        req = "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s\r\nConnection: close\r\n\r\n" % (
            path, port, "".join(h + "\r\n" for h in hs))
        s.sendall(req.encode())
        data = b""
        while True:
            try:
                c = s.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            data += c
        status = data.split(b"\r\n", 1)[0].decode("latin-1")
        first = first or status
        f.write(("===== %s: %s\r\n" % (name, status)).encode() + data + b"\r\n")
        print("%s: %s" % (name, status))
print("FIRST " + first)
PY

# Everything below runs as a descendant of `smith session start`. The session stays up until
# $work/done so the outside replay can hit a live lease.
cat >"$work/inside.sh" <<'INSIDE'
#!/usr/bin/env bash
set -uo pipefail
cd "$REPO"
export GIT_TERMINAL_PROMPT=0
helper_in() { printf 'protocol=http\nhost=127.0.0.1:%s\npath=%s\n\n' "$PORT" "$1"; }

# 1. git credential fill: the forwarder URL gets a forwarder token, the real host gets nothing.
helper_in "$FWD" | git credential fill >"$A/01-fill-forwarder.out" 2>&1; echo $? >"$W/fill-fwd.rc"
printf 'protocol=https\nhost=example.test\npath=acme/app.git\n\n' | git credential fill >"$A/01-fill-upstream.out" 2>&1
echo $? >"$W/fill-up.rc"
printf 'protocol=https\nhost=example.test\n\n' | git credential fill >"$A/01-fill-upstream-nopath.out" 2>&1 || true
sed -n 's/^password=//p' "$A/01-fill-forwarder.out" >"$W/token"

# 2. config files and the include file.
{ cat .git/config; echo "--- ~/.gitconfig"; cat "$HOME/.gitconfig"; } >"$A/02-gitconfig.out" 2>&1
inc="$(git config --local --get-all include.path | head -n 1)"
cat "$inc" >"$A/02-include.out" 2>&1
git config --list --show-origin >"$A/02-config-list.out" 2>&1
ls -laR "$LOCKSMITH_HOME" >"$A/02-ls-locksmith-home.out" 2>&1 || true

# 3. the helper run directly with crafted input.
helper_in "$FWD" | smith git credential get >"$A/03-helper-valid.out" 2>&1; echo $? >"$W/helper.rc"
helper_in "git/example.test/other/repo.git" | smith git credential get >"$A/03-helper-other-repo.out" 2>&1
echo $? >"$W/helper-other.rc"
helper_in "git/evil.test/acme/app.git" | smith git credential get >"$A/03-helper-other-host.out" 2>&1 || true
{ helper_in "$FWD" | head -n 3; printf 'password=x\nusername=x-access-token\n\n'; } | smith git credential get >"$A/03-helper-extra-lines.out" 2>&1 || true
printf 'protocol=https\nhost=example.test\npath=acme/app.git\n\n' | smith git credential get >"$A/03-helper-no-forwarder-path.out" 2>&1 || true
helper_in "$FWD" | smith git credential store >"$A/03-helper-store.out" 2>&1 || true
helper_in "$FWD" | smith git credential erase >"$A/03-helper-erase.out" 2>&1 || true
smith git status >"$A/03-git-status.out" 2>&1 || true

# 4. a real push with full tracing, unredacted.
GIT_TRACE_CURL=1 GIT_TRACE=1 GIT_TRACE_REDACT=0 GIT_CURL_VERBOSE=1 GIT_TRACE_PACKET=1 \
  git push origin feature >"$A/04-push.out" 2>&1; echo $? >"$W/push.rc"
GIT_TRACE_CURL=1 GIT_TRACE=1 GIT_TRACE_REDACT=0 git ls-remote origin >"$A/04-ls-remote.out" 2>&1 || true
# main is protected: deleting it must be refused (the policy is delete-only by design).
git push origin :main >"$A/04-push-delete-main.out" 2>&1; echo $? >"$W/del-main.rc"

# 5. loopback sniffer with a valid token.
python3 -I "$W/sniff.py" "$PORT" "$(cat "$W/token")" "$A/05-sniff-raw.out" inside >"$A/05-sniff-summary.out" 2>&1
echo $? >"$W/sniff.rc"
env >"$A/05-env.out" 2>&1

touch "$W/inside-done"
while [ ! -f "$W/done" ]; do sleep 0.2; done
INSIDE

export REPO="$repo" PORT="$port" FWD="$fwd" A W="$work"
printf '%s\n' "$pw" | "$smith" --passphrase-stdin session start -- bash "$work/inside.sh" \
  >"$work/session.out" 2>"$work/session.err" &
session_pid=$!
for _ in $(seq 1 150); do
  [[ -f "$work/inside-done" ]] && break
  kill -0 "$session_pid" 2>/dev/null || break
  sleep 0.2
done
[[ -f "$work/inside-done" ]] || { cat "$work/session.err" >&2 || true; fail "session script never finished"; }

# 6. replay from outside the session tree (this process is not a descendant of the session).
[[ -s "$work/token" ]] || fail "no forwarder token was captured inside the session"
python3 -I "$work/sniff.py" "$port" "$(cat "$work/token")" "$A/06-replay-raw.out" replay >"$A/06-replay-summary.out" 2>&1 || true
# Same from git itself: the helper run outside the session must not yield a token either.
GIT_TERMINAL_PROMPT=0 git ls-remote origin >"$A/06-outside-ls-remote.out" 2>&1 && outside_rc=0 || outside_rc=$?

printf '%s\n' "$pw" | "$smith" --passphrase-stdin audit ls --json --limit 200 >"$A/audit.json"
touch "$work/done"
wait "$session_pid" 2>/dev/null || true
session_pid=""

# Functional assertions (one line per attempt, like A6).
rc() { cat "$work/$1.rc"; }
[[ "$(rc fill-fwd)" == 0 ]] && grep -q '^username=locksmith$' "$A/01-fill-forwarder.out" && [[ -s "$work/token" ]] \
  || fail "01 fill on the forwarder URL gave no forwarder token"
echo "01 git credential fill (forwarder): only a forwarder token"
! grep -q '^password=' "$A/01-fill-upstream.out" && [[ "$(rc fill-up)" != 0 ]] \
  || fail "01 fill on example.test returned a password"
echo "01 git credential fill (example.test): nothing returned"
[[ "$(rc helper)" == 0 ]] && grep -q '^password=' "$A/03-helper-valid.out" || fail "03 helper did not mint a token"
[[ "$(rc helper-other)" != 0 ]] && ! grep -q '^password=' "$A/03-helper-other-repo.out" \
  || fail "03 helper minted a token for a repo outside the allowlist"
echo "03 helper run directly: forwarder token only, other repos denied"
[[ "$(rc push)" == 0 ]] || { sed "s|$canary|<canary>|g" "$A/04-push.out" | tail -n 15 >&2; fail "04 push of feature failed"; }
[[ -n "$(git -C "$bare" rev-parse -q --verify refs/heads/feature)" ]] || fail "04 feature is not in the upstream"
echo "04 GIT_TRACE_CURL push: succeeded, trace saved"
[[ "$(rc del-main)" != 0 ]] || fail "04 the delete of protected main succeeded"
[[ "$(git -C "$bare" rev-parse main)" == "$(git -C "$repo" rev-parse main)" ]] || fail "04 upstream main was deleted or moved"
echo "04 git push origin :main: refused"
[[ "$(rc sniff)" == 0 ]] && grep -q '^FIRST HTTP/1.1 200' "$A/05-sniff-summary.out" || fail "05 sniffer's valid request failed"
echo "05 loopback sniffer: valid request 200, reflection probes saved"
grep -q '^FIRST HTTP/1.1 403' "$A/06-replay-summary.out" || fail "06 replay was not refused with 403"
[[ $outside_rc -ne 0 ]] || fail "06 git ls-remote outside the session succeeded"
echo "06 replay from outside the session: 403, outside git denied"
grep -q 'auth=ok' "$work/upstream.log" || fail "the upstream never saw the canary credential"
echo "A1: no extraction path worked, push succeeded, protected main refused"
