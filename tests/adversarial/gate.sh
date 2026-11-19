#!/usr/bin/env bash
# Stack adversarial gate (`just adversarial-gate [--agent claude]`), S6 task 6.1.
#
#   1. Fails fast, before any case runs, when the stack is not running (`just up`, `just api`).
#   2. Builds the gateway, smith and locksmith-mcp once (each case starts its own gateway from
#      this build, bound to its own org; LOCKSMITH_*_BIN skip the per-case builds).
#   3. Runs `run.sh gateway` with ADVERSARIAL_REQUIRE_ALL=1 (a skip is a failure) and
#      ADVERSARIAL_KEEP=1 (the artifacts stay for step 6).
#   4. With `--agent claude`: runs gateway/live.sh (every prompt in gateway/prompts/ as a
#      headless `claude -p`) and scans each transcript with `oracle.py scan --transcript`. Without
#      the claude CLI or ANTHROPIC_API_KEY it prints `skip live` and the gate fails.
#   5. `just audit-export` (LOCKSMITH_AUDIT_EXPORT_DIR, default infra/compose/.audit-export).
#   6. `just leak-scan --explain --require-coverage` over Postgres, Loki and Tempo plus `--dir`
#      over the audit export and the kept artifacts, for every canary this run minted (and the
#      `just canary new` ones). Files the residual register lists for a case were already judged
#      by run.sh, and the live artifacts by step 4, so they are left out of this scan (a
#      registered leak is expected there); the live canary is still searched for in the stack.
#
# Exits 0 only when every case is PASS or RESIDUAL, live ran clean (when asked) and the leak scan
# is clean. Prints labels, file names and counts only, never a value. ADVERSARIAL_KEEP=1 keeps the
# gate's work directory (mode 0700) and prints its path.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
oracle="$root/tests/kit/oracle.py"
gateway_dir="$here/gateway"
residuals="$gateway_dir/residuals.toml"

usage() {
  echo "usage: just adversarial-gate [--agent claude]" >&2
  exit 2
}

agent=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      [[ $# -ge 2 && "$2" == claude ]] || usage
      agent=claude
      shift 2
      ;;
    *) usage ;;
  esac
done

api="${E2E_API_URL:-http://127.0.0.1:8080}"
api="${api%/}"
env_file="$root/infra/compose/.env.example"
env_val() { sed -n "s/^$1=//p" "$env_file" | head -n 1; }
curl_local() { curl --noproxy '*' -sS "$@"; }

# 1. The stack, before anything else: no case runs, so none can report PASS.
missing=()
curl_local -f -o /dev/null -m 3 "$api/readyz" 2>/dev/null || missing+=("control plane at $api (just api)")
curl_local -o /dev/null -m 3 "$(env_val OPENBAO_ADDR)/v1/sys/health" 2>/dev/null || missing+=("OpenBao (just up)")
(exec 3<>/dev/tcp/127.0.0.1/5432) 2>/dev/null || missing+=("Postgres (just up)")
curl_local -f -o /dev/null -m 3 "${LEAK_SCAN_GRAFANA:-http://127.0.0.1:3000}/api/health" 2>/dev/null ||
  missing+=("Grafana LGTM (just up)")
if [[ ${#missing[@]} -gt 0 ]]; then
  (
    IFS=,
    echo "adversarial-gate: FAIL: stack not running (${missing[*]}); run just up and just api. No case ran."
  ) >&2
  exit 1
fi

umask 077
gate="$(mktemp -d)"
cleanup() {
  if [[ "${ADVERSARIAL_KEEP:-}" == 1 ]]; then
    echo "kept: $gate (gate work directory: run logs, artifacts, canary files; delete when done)" >&2
  else
    rm -rf "$gate"
  fi
}
trap cleanup EXIT

failures=()

# 2. One build for every case.
bindir="${CARGO_TARGET_DIR:-$root/target}/debug"
echo "adversarial-gate: building locksmith-gateway, smith and locksmith-mcp"
(cd "$root" && cargo build -q -p ls-gateway -p smith-cli -p locksmith-mcp)
export LOCKSMITH_GATEWAY_BIN="${LOCKSMITH_GATEWAY_BIN:-$bindir/locksmith-gateway}"
export LOCKSMITH_SMITH_BIN="${LOCKSMITH_SMITH_BIN:-$bindir/smith}"
export LOCKSMITH_MCP_BIN="${LOCKSMITH_MCP_BIN:-$bindir/locksmith-mcp}"

# 3. The scripted gateway cases.
echo "adversarial-gate: run.sh gateway (ADVERSARIAL_REQUIRE_ALL=1)"
cases_rc=0
ADVERSARIAL_KEEP=1 ADVERSARIAL_REQUIRE_ALL=1 bash "$here/run.sh" gateway \
  2> >(tee "$gate/run.err" >&2) | tee "$gate/run.out" || cases_rc=$?
wait  # the stderr tee
work="$(sed -n 's/^kept: \([^ ]*\) .*/\1/p' "$gate/run.err" | tail -n 1)"
if [[ "${ADVERSARIAL_KEEP:-}" != 1 && -n "$work" ]]; then
  # The run's work directory is removed with the gate's unless the caller asked to keep it.
  trap 'rm -rf "$work"; cleanup' EXIT
fi
[[ $cases_rc -eq 0 ]] || failures+=("run.sh gateway exited $cases_rc")
if [[ -z "$work" || ! -d "$work" ]]; then
  failures+=("run.sh kept no work directory, so the artifacts cannot be leak-scanned")
  work=""
fi

# 4. Live mode.
live_dir=""
if [[ "$agent" == claude ]]; then
  if command -v claude >/dev/null 2>&1 && [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    live_dir="$gate/live.artifacts"
    mkdir -p "$live_dir" "$gate/live.home"
    python3 -I "$oracle" gen >"$gate/live.canary"
    echo "adversarial-gate: live prompts (claude -p)"
    live_rc=0
    HOME="$gate/live.home" CANARY_FILE="$gate/live.canary" ARTIFACT_DIR="$live_dir" \
      bash "$gateway_dir/live.sh" >"$gate/live.log" 2>&1 || live_rc=$?
    # The log tail, with the canary masked (read from its file, never on a command line).
    python3 -I -c 'import sys; c = open(sys.argv[1]).read().strip()
print("".join(open(sys.argv[2], errors="replace").readlines()[-20:]).replace(c, "<canary>"), end="")' \
      "$gate/live.canary" "$gate/live.log"
    [[ $live_rc -eq 0 ]] || failures+=("live: live.sh exited $live_rc (see the log above)")
    shopt -s nullglob
    transcripts=("$live_dir"/transcripts/*.jsonl)
    shopt -u nullglob
    if [[ ${#transcripts[@]} -eq 0 ]]; then
      failures+=("live: no transcript was saved")
    else
      targs=()
      for t in "${transcripts[@]}"; do targs+=(--transcript "$t"); done
      scan_rc=0
      python3 -I "$oracle" scan --canary-file "$gate/live.canary" "${targs[@]}" --dir "$live_dir" \
        >"$gate/live.scan" 2>&1 ||
        scan_rc=$?
      # The transcripts (--transcript) and everything else live.sh saved (--dir). A hit is excused
      # only by an encoding the register already accepts (the forms decision 4 leaves to
      # containment); live output varies, so nothing here can be stale.
      judge_rc=0
      python3 -I - "$residuals" "$gate/live.scan" "$live_dir" <<'PY' || judge_rc=$?
import os, sys, tomllib
reg, scan, adir = sys.argv[1:4]
known = {e["encoding"]: e["label"] for e in tomllib.load(open(reg, "rb")).get("residual", [])}
def forms(label):
    views, _, names = label.rpartition("/")
    prefix = views + "/" if views else ""
    return {label} | {prefix + n for n in names.split("+")}
ok = True
for line in open(scan, encoding="utf-8", errors="replace"):
    p = line.split()
    if len(p) >= 3 and p[0] == "LEAK":
        loc = p[2][len("transcript:"):] if p[2].startswith("transcript:") else p[2]
        where = os.path.relpath(loc.rpartition(":")[0] or loc, adir)
        hit = [known[f] for f in forms(p[1]) if f in known]
        if hit:
            print("RESIDUAL live %s in %s (%s)" % (p[1], where, hit[0]))
        else:
            ok = False
            print("FAIL live: unlisted leak %s in %s" % (p[1], where))
    elif p and p[0] != "clean":
        print("live scan: %s" % line.strip())
sys.exit(0 if ok else 1)
PY
      if [[ $scan_rc -eq 2 ]]; then
        failures+=("live: transcript scan error (exit 2)")
      elif [[ $judge_rc -ne 0 ]]; then
        failures+=("live: unlisted leak in a transcript")
      else
        echo "PASS live (${#transcripts[@]} transcripts scanned)"
      fi
    fi
  else
    echo "skip live"
    failures+=("skip live: the claude CLI or ANTHROPIC_API_KEY is missing, and the gate counts skips as failures")
  fi
fi

# 5. The audit export.
export_dir="${LOCKSMITH_AUDIT_EXPORT_DIR:-$root/infra/compose/.audit-export}"
echo "adversarial-gate: just audit-export"
(cd "$root" && just audit-export) >"$gate/export.log" 2>&1 || {
  tail -n 5 "$gate/export.log" >&2
  failures+=("just audit-export failed")
}

# 6. The stack leak scan, for every canary of this run.
canaries="$gate/canaries"
: >"$canaries"
stack_canaries="${LOCKSMITH_CANARIES:-$root/infra/compose/.canaries}"
[[ -f "$stack_canaries" ]] && cat "$stack_canaries" >>"$canaries"
n=0
if [[ -n "$work" ]]; then
  for c in "$work"/*.canary; do
    [[ -f "$c" ]] || continue
    n=$((n + 1))
    printf 'gate-%s %s\n' "$(basename "$c" .canary)" "$(<"$c")" >>"$canaries"
  done
fi
if [[ -n "$live_dir" ]]; then
  printf 'gate-live %s\n' "$(<"$gate/live.canary")" >>"$canaries"
fi
scan_dirs=()
[[ -d "$export_dir" ]] && scan_dirs+=(--dir "$export_dir")
if [[ -n "$work" ]]; then
  # Copy the artifacts, leaving out the files the register lists for their case. A case with an
  # entry that names no `artifacts` is left out whole (its entry excuses the case anywhere).
  python3 -I - "$residuals" "$gate/scan" "$work" <<'PY'
import os, shutil, sys, tomllib
reg, dest, work = sys.argv[1:4]
entries = tomllib.load(open(reg, "rb")).get("residual", [])
skip_files, skip_cases = {}, set()
for e in entries:
    if "artifacts" in e:
        skip_files.setdefault(e["case"], set()).update(e["artifacts"])
    else:
        skip_cases.add(e["case"])
os.makedirs(dest, exist_ok=True)
left = 0
sources = [(n[:-len(".artifacts")], os.path.join(work, n)) for n in sorted(os.listdir(work))
           if n.endswith(".artifacts")]
for case, src in sources:
    if case in skip_cases:
        print("leak-scan: %s left out (a register entry for it names no artifacts)" % case)
        continue
    skip = skip_files.get(case, set())
    for d, _dirs, files in os.walk(src):
        for f in files:
            rel = os.path.relpath(os.path.join(d, f), src)
            if rel in skip:
                left += 1
                continue
            path, out = os.path.join(d, f), os.path.join(dest, case, rel)
            if os.path.islink(path):
                continue
            os.makedirs(os.path.dirname(out), exist_ok=True)
            shutil.copyfile(path, out)
print("leak-scan: %d artifact files left out (registered residuals, judged by run.sh)" % left)
PY
  scan_dirs+=(--dir "$gate/scan")
fi
echo "adversarial-gate: just leak-scan over Postgres, Loki, Tempo, the audit export and the artifacts ($n case canaries)"
leak_rc=0
(cd "$root" && LOCKSMITH_CANARIES="$canaries" just leak-scan --explain --require-coverage \
  ${scan_dirs[@]+"${scan_dirs[@]}"}) || leak_rc=$?
[[ $leak_rc -eq 0 ]] || failures+=("just leak-scan exited $leak_rc")

if [[ ${#failures[@]} -gt 0 ]]; then
  for f in "${failures[@]}"; do echo "adversarial-gate: FAIL: $f"; done
  exit 1
fi
echo "adversarial-gate: PASS"
