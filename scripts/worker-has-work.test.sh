#!/usr/bin/env bash
# Tests for worker-has-work.sh against a stubbed `gh` (fixture JSON per URL, filtered by the script's own -q).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir -p "$t/scripts" "$t/bin" "$t/fx"
cp "$HERE/worker-has-work.sh" "$t/scripts/"
printf '#!/usr/bin/env bash\n' >"$t/scripts/change-status.sh"  # no takeable or plannable changes
cat >"$t/bin/gh" <<'EOF'
#!/usr/bin/env bash
# gh api <url> -q <filter>: the fixture named for the url, through jq
url=$2; q=${4:-.}
case "$url" in
  *hold-workers*) f=hold ;; *needs-rescue*) f=rescue ;; *issues*) f=empty ;;
  *ci.yml/runs?branch=main*) f=main ;; *ci.yml/runs*) f=red ;; *pulls*) f=pulls ;; *) exit 1 ;;
esac
jq -r "$q" "$FX/$f.json"
EOF
chmod +x "$t/bin/gh"
echo '[]' >"$t/fx/empty.json"
echo '{"workflow_runs":[{"conclusion":"success"}]}' >"$t/fx/main.json"
echo '{"workflow_runs":[{"conclusion":"failure"}]}' >"$t/fx/red.json"
echo '[{"user":{"login":"x"},"head":{"ref":"claude/change-a1-red"},"auto_merge":null},
       {"user":{"login":"x"},"head":{"ref":"claude/change-b2-red"},"auto_merge":null}]' >"$t/fx/pulls.json"
fail=0
check() { # <name> <hold json> <rescue json> <expected output> <expected exit>
  echo "$2" >"$t/fx/hold.json"; echo "$3" >"$t/fx/rescue.json"
  got=$(cd "$t" && PATH="$t/bin:$PATH" FX="$t/fx" AGENT_PERSONA='' AGENT_ID_DIR=/nonexistent bash scripts/worker-has-work.sh 2>/dev/null); code=$?
  if [ "$got" = "$(printf '%b' "$4")" ] && [ "$code" = "$5" ]; then echo "ok: $1"; else echo "FAIL: $1: exit $code, got '$got'"; fail=1; fi
}
both='work: CI is red on claude/change-a1-red\nwork: CI is red on claude/change-b2-red'
check "red PRs are work" '[]' '[]' "$both" 0
check "hold-workers blocker: idle despite work" '[{"number":1}]' '[]' 'idle' 1
check "rescued change's red PR skipped" '[]' '[{"title":"Rescue: CI","body":"Change: a1-red\nstuck"}]' 'work: CI is red on claude/change-b2-red' 0
check "rescue naming another change keeps both" '[]' '[{"title":"Rescue: z9-other","body":null}]' "$both" 0
check "every red PR rescued: idle" '[]' '[{"title":"Rescue: a1-red and b2-red","body":""}]' 'idle' 1
[ "$fail" = 0 ] && echo "worker-has-work test: OK"; exit "$fail"
