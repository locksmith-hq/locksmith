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
