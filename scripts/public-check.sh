#!/usr/bin/env bash
# Public-readiness check (g1-go-public). Seconds-long hygiene, no network.
# Usage: public-check.sh [all|licenses|docs|links|denylist|canary]
# ROOT overrides the repo root (used by the test script).
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 2
fail=0
bad() { echo "public-check FAIL: $*" >&2; fail=1; }

list_files() {
  if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 && [ -z "${NO_GIT:-}" ]; then
    git -C "$ROOT" ls-files -co --exclude-standard
  else
    find . -type f -not -path './node_modules/*' -not -path './target/*' -not -path './.git/*' | sed 's#^\./##'
  fi
}

check_licenses() {
  [ -s LICENSE ] || bad "LICENSE missing"
  [ -s LICENSE-APACHE ] || bad "LICENSE-APACHE missing"
  [ -s THIRD_PARTY.md ] || bad "THIRD_PARTY.md missing"
  local f
  while IFS= read -r f; do
    case "$f" in
      Cargo.toml|*/Cargo.toml|package.json|*/package.json) ;;
      *) continue ;;
    esac
    case "$f" in node_modules/*|*/node_modules/*|target/*|*/target/*) continue ;; esac
    if grep -q 'UNLICENSED' "$f"; then bad "$f declares UNLICENSED"; fi
    case "$f" in
      Cargo.toml) continue ;; # workspace root has [workspace.package].license
    esac
    if [ "${f##*/}" = Cargo.toml ]; then
      grep -qE '^\[package\]' "$f" || continue
      grep -qE '^license(\.workspace)? *=' "$f" || bad "$f has no license"
    else
      grep -q '"license"' "$f" || bad "$f has no license field"
    fi
  done < <(list_files)
}

check_docs() {
  local d
  for d in README.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md LICENSE LICENSE-APACHE THIRD_PARTY.md; do
    [ -s "$d" ] || bad "$d missing"
  done
  if grep -qE 'M0.M16' README.md 2>/dev/null; then bad "README.md still mentions M0-M16"; fi
}

check_links() {
  local f link target
  for f in README.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md THIRD_PARTY.md; do
    [ -f "$f" ] || continue
    while IFS= read -r link; do
      target="${link%%#*}"
      [ -z "$target" ] && continue
      case "$target" in http://*|https://*|mailto:*) continue ;; esac
      [ -e "$(dirname "$f")/$target" ] || bad "$f: broken link $link"
    done < <(grep -oE '\]\([^)]+\)' "$f" | sed -E 's/^\]\(//; s/\)$//')
  done
}

check_denylist() {
  # One extended regex per line; '#' starts a comment. Files may be exempted in the allow file.
  local deny=scripts/public-denylist.txt allow=scripts/public-denylist.allow
  [ -f "$deny" ] || { bad "$deny missing"; return; }
  local pat f hits
  while IFS= read -r pat; do
    case "$pat" in ''|'#'*) continue ;; esac
    while IFS= read -r f; do
      case "$f" in node_modules/*|*/node_modules/*|target/*|*/target/*|scripts/public-denylist.txt|scripts/public-check.test.sh|package-lock.json|Cargo.lock) continue ;; esac
      [ -f "$f" ] || continue
      if [ -f "$allow" ] && grep -qxF "$f" "$allow"; then continue; fi
      if grep -IEq -- "$pat" "$f" 2>/dev/null; then bad "denylisted pattern '$pat' in $f"; fi
    done < <(list_files)
  done < "$deny"
}

check_canary() {
  command -v gitleaks >/dev/null 2>&1 || { echo "public-check: gitleaks not installed, canary scan skipped" >&2; return; }
  if ! gitleaks detect --no-git --source . --no-banner --redact >/dev/null 2>&1; then
    bad "gitleaks found a secret in the working tree"
  fi
}

mode="${1:-all}"
case "$mode" in
  licenses) check_licenses ;;
  docs) check_docs ;;
  links) check_links ;;
  denylist) check_denylist ;;
  canary) check_canary ;;
  all) check_licenses; check_docs; check_links; check_denylist; check_canary ;;
  *) echo "usage: $0 [all|licenses|docs|links|denylist|canary]" >&2; exit 2 ;;
esac
[ "$fail" = 0 ] && echo "public-check: OK"
exit "$fail"
