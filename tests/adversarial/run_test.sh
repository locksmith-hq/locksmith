#!/usr/bin/env bash
# Harness self-check for `run.sh gateway` and the residual register (S6 task 2.3). Offline: it
# plants gateway cases and a register in a temporary directory (ADVERSARIAL_GATEWAY_DIR) and
# checks that an unlisted leak fails, a listed form reports RESIDUAL, a stale entry fails, an
# entry with `artifacts` is judged per listed file, a register entry for a missing case fails, a bad register fails, case filters work, skips follow
# ADVERSARIAL_REQUIRE_ALL, lib.sh skips with `skip: stack not running`, ADVERSARIAL_KEEP=1 keeps
# the work directory, and run.sh never prints a canary. Usage: tests/adversarial/run_test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run="$here/run.sh"
umask 077
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
fail=0
ok() { echo "PASS  $1"; }
bad() {
  echo "FAIL  $1"
  fail=1
}

# Every planted case copies its canary to $t/spy so the final check can look for it in the output.
mkdir -p "$t/spy" "$t/g"
plant() { # plant <id> <body>
  cat >"$t/g/$1.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cp "\$CANARY_FILE" "$t/spy/$1.canary"
c="\$(cat "\$CANARY_FILE")"
$2
EOF
}
plant G1-clean 'echo "nothing here" >"$ARTIFACT_DIR/out.txt"'
plant G2-unlisted 'printf "%s\n" "$c" >"$ARTIFACT_DIR/out.txt"; echo "case printed $c"'
plant G3-listed 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/out.txt"'
plant G4-stale 'echo "nothing here" >"$ARTIFACT_DIR/out.txt"'
plant G5-mixed 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/a.txt"; printf "%s" "$c" | base64 >"$ARTIFACT_DIR/b.txt"'
plant G6-skip 'echo "skip: planted skip"; exit 77'
plant G7-joined 'printf "%s" "$c" | gzip >"$ARTIFACT_DIR/out.bin"'
# Per-route entries (`artifacts`): both routes leak; one route stops; a third file leaks.
plant G10-routes 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/smith.out"; printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/mcp.view"'
plant G11-oneroute 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/smith.out"; echo "nothing here" >"$ARTIFACT_DIR/mcp.view"'
plant G12-otherfile 'printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/smith.out"; printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/mcp.view"; printf "%s\n" "$c" | rev >"$ARTIFACT_DIR/extra.txt"'
# A case that uses the real lib.sh against a control plane that is not there.
cat >"$t/g/G8-nostack.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cp "\$CANARY_FILE" "$t/spy/G8-nostack.canary"
. "$here/gateway/lib.sh"
gw_init
echo "should not get here" >&2
exit 1
EOF

entry() { # entry <case> <encoding>
  printf '[[residual]]\ncase = "%s"\nencoding = "%s"\nlabel = "containment"\nreason = "planted"\n\n' "$1" "$2"
}
{
  entry G3-listed text-reversed
  entry G4-stale b32-offset0
  entry G5-mixed text-reversed
  # The canary text is base64url, so one plain copy also hits b64url-offset0: list each label.
  entry G7-joined gzip/utf8
  entry G7-joined gzip/b64url-offset0
  for c in G10-routes G11-oneroute G12-otherfile; do
    printf '[[residual]]\ncase = "%s"\nencoding = "text-reversed"\nlabel = "containment"\nreason = "planted"\nartifacts = ["smith.out", "mcp.view"]\n\n' "$c"
  done
} >"$t/g/residuals.toml"

# gw <out-name> [env...] -- [run.sh args]: run run.sh with the planted directory.
gw() {
  local name="$1" rc=0
  shift
  local envs=()
  while [[ $# -gt 0 && "$1" != -- ]]; do
    envs+=("$1")
    shift
  done
  shift
  env ADVERSARIAL_GATEWAY_DIR="$t/g" E2E_API_URL=http://127.0.0.1:9 ${envs[@]+"${envs[@]}"} \
    bash "$run" "$@" >"$t/$name.out" 2>&1 || rc=$?
  echo "$rc" >"$t/$name.rc"
}
has() { grep -qF -- "$2" "$t/$1.out"; }
rc_is() { [[ "$(cat "$t/$1.rc")" == "$2" ]]; }
check() { # check <name> <description> <condition...>
  local n="$1" d="$2"
  shift 2
  if "$@"; then ok "$d"; else
    bad "$d"
    sed 's/^/    /' "$t/$n.out" | tail -n 30
  fi
}

gw filtered -- gateway G1-clean G3-listed
check filtered "filter runs only the named cases; clean case is PASS" \
  bash -c "grep -qx 'PASS case G1-clean' '$t/filtered.out' && ! grep -q 'G4-stale\|G2-unlisted' '$t/filtered.out'"
check filtered "listed form reports RESIDUAL and passes" \
  bash -c "grep -qF 'RESIDUAL G3-listed text-reversed (containment)' '$t/filtered.out' && grep -qx 'RESIDUAL case G3-listed' '$t/filtered.out' && [[ \$(cat '$t/filtered.rc') == 0 ]]"
check filtered "summary counts the residual" has filtered "summary: 1 passed, 0 failed, 0 skipped, 1 residual"

gw unlisted -- gateway G2-unlisted
check unlisted "unlisted leak fails naming case and encoding" \
  bash -c "grep -q '^FAIL case G2-unlisted: unlisted leak utf8' '$t/unlisted.out' && grep -qx 'FAIL case G2-unlisted' '$t/unlisted.out' && [[ \$(cat '$t/unlisted.rc') == 1 ]]"

gw stale -- gateway G4-stale
check stale "stale entry fails as STALE RESIDUAL" \
  bash -c "grep -qF 'STALE RESIDUAL G4-stale b32-offset0' '$t/stale.out' && grep -qx 'FAIL case G4-stale' '$t/stale.out' && [[ \$(cat '$t/stale.rc') == 1 ]]"

gw mixed -- gateway G5-mixed
check mixed "a listed form does not excuse an unlisted one" \
  bash -c "grep -qF 'RESIDUAL G5-mixed text-reversed' '$t/mixed.out' && grep -q '^FAIL case G5-mixed: unlisted leak text-b64' '$t/mixed.out' && grep -qx 'FAIL case G5-mixed' '$t/mixed.out'"

gw joined -- gateway G7-joined
check joined "an entry matches one name of a joined label in a view (gzip/utf8)" \
  bash -c "grep -q '^RESIDUAL G7-joined gzip/utf8' '$t/joined.out' && grep -qx 'RESIDUAL case G7-joined' '$t/joined.out' && [[ \$(cat '$t/joined.rc') == 0 ]]"

gw routes -- gateway G10-routes
check routes "an entry with artifacts reports RESIDUAL when every listed file leaks" \
  bash -c "grep -qF 'RESIDUAL G10-routes text-reversed (containment)' '$t/routes.out' && grep -qx 'RESIDUAL case G10-routes' '$t/routes.out' && [[ \$(cat '$t/routes.rc') == 0 ]]"
gw oneroute -- gateway G11-oneroute
check oneroute "a listed file without a hit is STALE RESIDUAL even when another listed file leaks" \
  bash -c "grep -qF 'STALE RESIDUAL G11-oneroute text-reversed in mcp.view (registered, no hit)' '$t/oneroute.out' && grep -qx 'FAIL case G11-oneroute' '$t/oneroute.out' && [[ \$(cat '$t/oneroute.rc') == 1 ]]"
gw otherfile -- gateway G12-otherfile
check otherfile "an entry with artifacts does not excuse the same encoding in another file" \
  bash -c "grep -qF 'FAIL case G12-otherfile: unlisted leak text-reversed in extra.txt' '$t/otherfile.out' && grep -qx 'FAIL case G12-otherfile' '$t/otherfile.out' && [[ \$(cat '$t/otherfile.rc') == 1 ]]"

gw skip -- gateway G6-skip G8-nostack
check skip "skips are SKIP without ADVERSARIAL_REQUIRE_ALL; lib.sh says stack not running" \
  bash -c "grep -qx 'SKIP case G6-skip (planted skip)' '$t/skip.out' && grep -q '^SKIP case G8-nostack (stack not running' '$t/skip.out' && [[ \$(cat '$t/skip.rc') == 0 ]]"
gw skipreq ADVERSARIAL_REQUIRE_ALL=1 -- gateway G8-nostack
check skipreq "ADVERSARIAL_REQUIRE_ALL=1 turns a skip into FAIL" \
  bash -c "grep -qx 'FAIL case G8-nostack' '$t/skipreq.out' && [[ \$(cat '$t/skipreq.rc') == 1 ]]"

# A register entry for a case that does not exist is stale in a full run only.
entry G9-gone text-reversed >>"$t/g/residuals.toml"
gw full -- gateway
check full "full run: entry for a missing case is STALE RESIDUAL and the run fails" \
  bash -c "grep -qF 'STALE RESIDUAL G9-gone text-reversed (no case G9-gone' '$t/full.out' && [[ \$(cat '$t/full.rc') == 1 ]]"
gw filtered2 -- gateway G3-listed
check filtered2 "filtered run ignores entries of cases it did not run" rc_is filtered2 0

# A bad register (no reason, unknown label, wildcard) fails before any case runs.
cp "$t/g/residuals.toml" "$t/residuals.good"
printf '[[residual]]\ncase = "G3-listed"\nencoding = "*"\nlabel = "hope"\nartifacts = ["../x"]\n' >>"$t/g/residuals.toml"
gw badreg -- gateway G1-clean
check badreg "invalid register fails the run" \
  bash -c "grep -q 'residual register' '$t/badreg.out' && grep -q 'reason. is missing' '$t/badreg.out' && grep -q 'no wildcards' '$t/badreg.out' && grep -q 'label must be one of' '$t/badreg.out' && grep -q 'artifacts. must be' '$t/badreg.out' && [[ \$(cat '$t/badreg.rc') == 1 ]]"
cp "$t/residuals.good" "$t/g/residuals.toml"

gw nocase -- gateway G42
check nocase "unknown gateway case exits 2" bash -c "grep -q 'no case matches: gateway G42' '$t/nocase.out' && [[ \$(cat '$t/nocase.rc') == 2 ]]"

# ADVERSARIAL_KEEP=1 keeps the work directory with each case's artifacts.
gw keep ADVERSARIAL_KEEP=1 -- gateway G3-listed
kept="$(sed -n 's/^kept: \([^ ]*\) .*/\1/p' "$t/keep.out")"
check keep "ADVERSARIAL_KEEP=1 keeps the artifacts" \
  bash -c "[[ -n '$kept' && -f '$kept/G3-listed.artifacts/out.txt' && -f '$kept/G3-listed.log' ]]"
[[ -n "$kept" && -d "$kept" ]] && rm -rf "$kept"
gw nokeep -- gateway G3-listed
check nokeep "without ADVERSARIAL_KEEP nothing is kept" bash -c "! grep -q '^kept:' '$t/nokeep.out'"

# Nothing run.sh printed holds a canary in any encoding the oracle knows.
cat "$t/spy"/*.canary >"$t/all.canaries"
cat "$t"/*.out >"$t/printed.txt"
if python3 -I "$here/../kit/oracle.py" scan --canary-file "$t/all.canaries" "$t/printed.txt" >"$t/leak.out" 2>&1; then
  ok "run.sh output holds no canary ($(wc -l <"$t/all.canaries" | tr -d ' ') canaries)"
else
  bad "run.sh output holds a canary: $(head -n 3 "$t/leak.out")"
fi

if [[ $fail -ne 0 ]]; then
  echo "run_test: FAILED"
  exit 1
fi
echo "run_test: all passed"
