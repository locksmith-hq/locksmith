#!/usr/bin/env bash
# Adversarial secret-leak harness. Usage: run.sh <case|selftest|all>... [--agent claude]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
oracle="$here/oracle.py"
cases_dir="$here/cases"

usage() {
  echo "usage: run.sh <case|selftest|all>... [--agent claude]" >&2
  exit 2
}

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
      targets+=("$1")
      shift
      ;;
  esac
done
[[ ${#targets[@]} -ge 1 ]] || usage

work="$(mktemp -d)"
umask 077
cleanup() { rm -rf "$work"; }
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

run_case() {
  local case_file="$1"
  local id canary_file artifact log case_rc=0 scan_rc=0 canary
  id="$(basename "$case_file" .sh)"
  canary_file="$work/$id.canary"
  artifact="$work/$id.artifacts"
  log="$work/$id.log"
  mkdir -p "$artifact"
  python3 -I "$oracle" gen >"$canary_file"
  (CANARY_FILE="$canary_file" ARTIFACT_DIR="$artifact" bash "$case_file") >"$log" 2>&1 || case_rc=$?
  python3 -I "$oracle" scan --canary-file "$canary_file" "$artifact" >>"$log" 2>&1 || scan_rc=$?
  if [[ ($case_rc -ne 0 && $case_rc -ne 77) || $scan_rc -ne 0 ]]; then
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
  if [[ $case_rc -eq 0 && $scan_rc -eq 0 ]]; then
    record 0 "case $id"
  else
    record 1 "case $id"
  fi
}

collect_cases() {
  local t="$1" f
  shopt -s nullglob
  for f in "$cases_dir/$t.sh" "$cases_dir/$t"-*.sh; do
    [[ -f "$f" ]] && echo "$f"
  done
  shopt -u nullglob
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
    *)
      matches="$(collect_cases "$target")"
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

echo "summary: $pass passed, $fail failed, $skipped skipped"
if [[ $fail -ne 0 ]]; then
  exit 1
fi
