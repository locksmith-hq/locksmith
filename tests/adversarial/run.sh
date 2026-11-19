#!/usr/bin/env bash
# Adversarial secret-leak harness.
# Usage: run.sh <case|selftest|all|gateway [G<n>...]>... [--agent claude]
# `gateway` runs tests/adversarial/gateway/G*.sh (only the named ones when G<n> follow) against
# the local stack and judges hits against gateway/residuals.toml. ADVERSARIAL_KEEP=1 keeps the
# work directory (logs, artifacts, canary files) and prints where it is.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
oracle="$here/../kit/oracle.py"
cases_dir="$here/cases"
# Overridable only so the harness self-check (run_test.sh) can plant cases and residuals.
gateway_dir="${ADVERSARIAL_GATEWAY_DIR:-$here/gateway}"
residuals="$gateway_dir/residuals.toml"

usage() {
  echo "usage: run.sh <case|selftest|all|gateway [G<n>...]>... [--agent claude]" >&2
  exit 2
}

# Each target is one word; a gateway target carries its case filters: "gateway G2 G4".
targets=()
agent=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)
      [[ $# -ge 2 && "$2" == "claude" ]] || usage
      agent="$2"
      shift 2
      ;;
    -*) usage ;;
    *)
      [[ "$1" =~ ^(selftest|all|[A-Za-z0-9_-]+)$ ]] || usage
      last=$((${#targets[@]} - 1))
      if [[ "$1" =~ ^G[0-9][A-Za-z0-9_-]*$ && $last -ge 0 && "${targets[$last]}" == gateway* ]]; then
        targets[$last]="${targets[$last]} $1"
      else
        targets+=("$1")
      fi
      shift
      ;;
  esac
done
[[ ${#targets[@]} -ge 1 ]] || usage

work="$(mktemp -d)"
umask 077
cleanup() {
  if [[ "${ADVERSARIAL_KEEP:-}" == 1 ]]; then
    echo "kept: $work (logs, artifacts, canary files and the cases' private work files, mode 0600; delete when done)" >&2
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

fake_home="$work/home"
mkdir -p "$fake_home"
export HOME="$fake_home"

unset LIVE_AGENT
if [[ "$agent" == "claude" ]]; then
  if command -v claude >/dev/null 2>&1 && [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    export LIVE_AGENT=claude
  else
    echo "skip live"
  fi
fi

pass=0
fail=0
skipped=0
residual=0
record() {
  if [[ "$1" -eq 0 ]]; then
    pass=$((pass + 1))
    echo "PASS $2"
  else
    fail=$((fail + 1))
    echo "FAIL $2"
  fi
}

run_selftest() {
  local rc=0
  python3 -I "$oracle" selftest || rc=$?
  record "$rc" selftest
}

# judge <residuals> <case id> <oracle output> [artifact dir]: compare the oracle's LEAK lines with
# the case's entries in the residual register. Prints `RESIDUAL <enc> <label>`,
# `UNLISTED <enc> <file>` and `STALE <enc> [<file>]` lines (encoding labels and artifact paths
# relative to the artifact dir only, never a value). An entry with `artifacts` matches only hits
# in those files and is stale for each listed file without a hit. Exit 0 when every hit is listed
# and every entry was hit, 1 otherwise, 2 when the register is invalid.
judge() {
  python3 -I - "$@" <<'PY'
import os, re, sys
residuals, case, scan = sys.argv[1:4]
adir = sys.argv[4] if len(sys.argv) > 4 else ""
try:
    import tomllib
except ImportError:
    print("error: the residual register needs Python 3.11+ (tomllib)", file=sys.stderr)
    sys.exit(2)
LABELS = ("prevention", "containment", "detection")
try:
    with open(residuals, "rb") as fh:
        doc = tomllib.load(fh)
except (OSError, ValueError) as e:
    print("error: cannot read %s: %s" % (residuals, e.__class__.__name__), file=sys.stderr)
    sys.exit(2)
unknown = set(doc) - {"residual"}
entries = doc.get("residual", [])
bad = ["unknown top-level key %s" % k for k in sorted(unknown)]
if not isinstance(entries, list):
    bad.append("`residual` must be an array of tables ([[residual]])")
    entries = []
for n, e in enumerate(entries, 1):
    if not isinstance(e, dict):
        bad.append("entry %d is not a table" % n)
        continue
    extra = set(e) - {"case", "encoding", "label", "reason", "artifacts"}
    if extra:
        bad.append("entry %d: unknown key(s) %s" % (n, ", ".join(sorted(extra))))
    for k in ("case", "encoding", "label", "reason"):
        if not isinstance(e.get(k), str) or not e[k].strip():
            bad.append("entry %d: `%s` is missing or empty" % (n, k))
    if isinstance(e.get("case"), str) and not re.fullmatch(r"G[0-9][A-Za-z0-9_-]*", e["case"]):
        bad.append("entry %d: case %r is not a gateway case id" % (n, e["case"]))
    if isinstance(e.get("encoding"), str) and not re.fullmatch(r"[a-z0-9-]+(/[a-z0-9-]+)*", e["encoding"]):
        bad.append("entry %d: encoding %r is not an oracle label (no wildcards)" % (n, e["encoding"]))
    if e.get("label") not in LABELS:
        bad.append("entry %d: label must be one of %s" % (n, ", ".join(LABELS)))
    if "artifacts" in e:
        a = e["artifacts"]
        if not isinstance(a, list) or not a or not all(
                isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*", x)
                for x in a):
            bad.append("entry %d: `artifacts` must be a non-empty array of relative file paths (no wildcards)" % n)
if bad:
    for b in bad:
        print("error: %s: %s" % (residuals, b), file=sys.stderr)
    sys.exit(2)
if case == "--validate":
    # Print the case of every entry so run.sh can find entries for cases that do not exist.
    for e in entries:
        print("%s %s" % (e["case"], e["encoding"]))
    sys.exit(0)

# An oracle label is `<view>/.../<name>[+<name>...]`: encodings that give the same needle share
# one label. An entry matches the whole label, or the view path with one of the names
# (`gzip/utf8` matches `gzip/utf8+percent+json`).
def forms(label):
    views, _, names = label.rpartition("/")
    prefix = views + "/" if views else ""
    return {label} | {prefix + n for n in names.split("+")}

mine = [e for e in entries if e["case"] == case]
hits = []  # (oracle label, artifact path), in scan order
with open(scan, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "LEAK":
            path = parts[2].rpartition(":")[0] or parts[2]
            if adir and os.path.isabs(path):
                rel = os.path.relpath(path, adir)
                path = rel if not rel.startswith("..") else path
            if (parts[1], path) not in hits:
                hits.append((parts[1], path))
used = set()  # (entry index, artifact or None)
shown = set()
unlisted = set()
ok = True
for h, path in hits:
    f = forms(h)
    match = [i for i, e in enumerate(mine)
             if e["encoding"] in f and ("artifacts" not in e or path in e["artifacts"])]
    if match:
        for i in match:
            used.add((i, path if "artifacts" in mine[i] else None))
        if h not in shown:
            shown.add(h)
            print("RESIDUAL %s %s" % (h, mine[match[0]]["label"]))
    elif (h, path) not in unlisted:
        unlisted.add((h, path))
        ok = False
        print("UNLISTED %s %s" % (h, path))
for i, e in enumerate(mine):
    for a in e.get("artifacts", [None]):
        if (i, a) not in used:
            ok = False
            print("STALE %s %s" % (e["encoding"], a) if a else "STALE %s" % e["encoding"])
sys.exit(0 if ok else 1)
PY
}

# run_case <file> [residuals]: run one case under the case contract; with a residual register,
# listed hits report RESIDUAL instead of failing and listed entries without a hit fail.
run_case() {
  local case_file="$1" reg="${2:-}"
  local id canary_file artifact log scan verdict case_rc=0 scan_rc=0 judge_rc=0 canary
  id="$(basename "$case_file" .sh)"
  canary_file="$work/$id.canary"
  artifact="$work/$id.artifacts"
  log="$work/$id.log"
  scan="$work/$id.scan"
  verdict="$work/$id.verdict"
  mkdir -p "$artifact"
  python3 -I "$oracle" gen >"$canary_file"
  (CANARY_FILE="$canary_file" ARTIFACT_DIR="$artifact" bash "$case_file") >"$log" 2>&1 || case_rc=$?
  python3 -I "$oracle" scan --canary-file "$canary_file" "$artifact" >"$scan" 2>&1 || scan_rc=$?
  cat "$scan" >>"$log"
  # The register can excuse oracle hits (exit 1) only; a scan error (exit 2) always fails.
  if [[ -n "$reg" && $case_rc -ne 77 && ($scan_rc -eq 0 || $scan_rc -eq 1) ]]; then
    judge "$reg" "$id" "$scan" "$artifact" >"$verdict" 2>>"$log" || judge_rc=$?
    cat "$verdict" >>"$log"
    if [[ $judge_rc -ne 2 ]]; then
      scan_rc=$judge_rc
    fi
  fi
  if [[ ($case_rc -ne 0 && $case_rc -ne 77) || $scan_rc -ne 0 || $judge_rc -ne 0 ]]; then
    # Show the tail of the log, with the canary redacted so it never reaches the terminal.
    canary="$(cat "$canary_file")"
    echo "--- last lines of $id (case exit $case_rc, oracle exit $scan_rc) ---" >&2
    sed "s|$canary|<canary>|g" "$log" | tail -n 20 >&2
  fi
  if [[ $case_rc -eq 77 && $scan_rc -eq 0 ]]; then
    # Exit 77: the case cannot run here (e.g. Postgres is not installed). CI sets
    # ADVERSARIAL_REQUIRE_ALL=1 so a gate never passes by skipping.
    if [[ "${ADVERSARIAL_REQUIRE_ALL:-}" == 1 ]]; then
      echo "--- $id skipped but ADVERSARIAL_REQUIRE_ALL=1: $(grep -m1 '^skip' "$log" || true)" >&2
      record 1 "case $id"
    else
      skipped=$((skipped + 1))
      echo "SKIP case $id ($(grep -m1 '^skip' "$log" | sed 's/^skip: *//' || true))"
    fi
    return
  fi
  if [[ -s "$verdict" ]]; then
    local kind enc label
    while read -r kind enc label; do
      case "$kind" in
        RESIDUAL) echo "RESIDUAL $id $enc ($label)" ;;
        UNLISTED) echo "FAIL case $id: unlisted leak $enc in $label" ;;
        STALE) echo "STALE RESIDUAL $id $enc ${label:+in $label }(registered, no hit)" ;;
      esac
    done <"$verdict"
  fi
  if [[ $case_rc -eq 0 && $scan_rc -eq 0 && $judge_rc -eq 0 ]]; then
    if grep -q '^RESIDUAL ' "$verdict" 2>/dev/null; then
      residual=$((residual + 1))
      echo "RESIDUAL case $id"
    else
      record 0 "case $id"
    fi
  else
    record 1 "case $id"
  fi
}

collect_cases() {
  local dir="$1" t="$2" f
  shopt -s nullglob
  for f in "$dir/$t.sh" "$dir/$t"-*.sh; do
    [[ -f "$f" ]] && echo "$f"
  done
  shopt -u nullglob
}

# run_gateway [G<n>...]: the stack cases, judged against the residual register. A full run also
# fails on register entries whose case does not exist.
run_gateway() {
  local files=() f t m reg="" ran=" "
  if [[ $# -eq 0 ]]; then
    shopt -s nullglob
    files=("$gateway_dir"/G*.sh)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
      echo "no gateway cases in $gateway_dir" >&2
      exit 2
    fi
  else
    for t in "$@"; do
      m="$(collect_cases "$gateway_dir" "$t")"
      if [[ -z "$m" ]]; then
        echo "no case matches: gateway $t" >&2
        exit 2
      fi
      while IFS= read -r f; do files+=("$f"); done <<<"$m"
    done
  fi
  if [[ -f "$residuals" ]]; then
    reg="$residuals"
    if ! judge "$reg" --validate /dev/null >"$work/residuals.cases"; then
      record 1 "residual register $reg"
      return
    fi
  fi
  for f in "${files[@]}"; do
    run_case "$f" "$reg"
    ran+="$(basename "$f" .sh) "
  done
  if [[ -n "$reg" && $# -eq 0 ]]; then
    local c enc
    while read -r c enc; do
      if [[ "$ran" != *" $c "* ]]; then
        echo "STALE RESIDUAL $c $enc (no case $c in $gateway_dir)"
        record 1 "residual $c $enc"
      fi
    done <"$work/residuals.cases"
  fi
}

for target in "${targets[@]}"; do
  case "$target" in
    selftest)
      run_selftest
      ;;
    all)
      run_selftest
      shopt -s nullglob
      for f in "$cases_dir"/*.sh; do
        run_case "$f"
      done
      shopt -u nullglob
      ;;
    gateway | gateway\ *)
      read -r -a filters <<<"${target#gateway}"
      run_gateway ${filters[@]+"${filters[@]}"}
      ;;
    *)
      matches="$(collect_cases "$cases_dir" "$target")"
      if [[ -z "$matches" ]]; then
        echo "no case matches: $target" >&2
        exit 2
      fi
      while IFS= read -r f; do
        run_case "$f"
      done <<<"$matches"
      ;;
  esac
done

if [[ $residual -ne 0 ]]; then
  echo "summary: $pass passed, $fail failed, $skipped skipped, $residual residual"
else
  echo "summary: $pass passed, $fail failed, $skipped skipped"
fi
if [[ $fail -ne 0 ]]; then
  exit 1
fi
