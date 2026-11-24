#!/usr/bin/env bash
# Self-test for run-lock.sh with a fake gh: a GitHub failure must read as "unknown" (exit 3), never as free.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/run-lock.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/gh" <<'GH'
#!/usr/bin/env bash
case "$*" in
  *labels=change*) [ "${FAIL:-}" = lookup ] && exit 1; echo 626 ;;
  *-f\ body=*) exit 0 ;;
  */comments*) [ "${FAIL:-}" = comments ] && exit 1; printf '%b' "${COMMENTS:-}" ;;
esac
GH
chmod +x "$tmp/gh"; export PATH="$tmp:$PATH"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run() { set +e; out=$(env -u CLAUDE_CODE_SESSION_ID "$@" bash "$script" "${args[@]}" 2>/dev/null); rc=$?; set -e; }
expect() { [ "$rc:$out" = "$1" ] || { echo "FAIL: ${args[*]} expected '$1', got '$rc:$out'"; exit 1; }; echo "ok: ${args[*]} -> $1"; }

args=(holder x b1); run COMMENTS="$now\tLOCK worker-b-1553\n";  expect "0:worker-b-1553"
args=(holder x b1); run COMMENTS="";                            expect "0:"
args=(holder x b1); run FAIL=comments;                          expect "3:"
args=(holder x b1); run FAIL=lookup;                            expect "3:"
args=(acquire worker-a b1); run FAIL=comments;                  expect "3:"
args=(acquire worker-a b1); run COMMENTS="$now\tLOCK worker-b-1553\n"
if [ "$rc" = 1 ]; then echo "ok: acquire busy"; else echo "FAIL: acquire while held rc=$rc"; exit 1; fi
# A release under another prefix but the same session frees the lock (stale b1 lock, 2026-11-24); another session's does not.
rel() { env -i PATH="$PATH" HOME="$HOME" CLAUDE_CODE_SESSION_ID="$1" COMMENTS="$now\tLOCK worker-b-1566@s1\n" bash "$script" release worker-b-7 b1 2>/dev/null; }
[ "$(rel s1)" = "run-lock: released" ] && echo "ok: release by session id" || { echo "FAIL: release by session id"; exit 1; }
[ -z "$(rel s2)" ] && echo "ok: other session cannot release" || { echo "FAIL: other session released"; exit 1; }
