#!/usr/bin/env bash
# Tests for public-check.sh: the real tree passes; each planted defect makes it fail.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
pass=0; failn=0
ok() { echo "ok   $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; failn=$((failn+1)); }

if bash "$HERE/public-check.sh" >/dev/null 2>&1; then ok "real tree passes"; else no "real tree passes"; fi

mk() { # fresh minimal scratch tree
  S="$(mktemp -d)"
  for f in README.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md LICENSE LICENSE-APACHE THIRD_PARTY.md; do echo "x $f" > "$S/$f"; done
  mkdir -p "$S/scripts" "$S/crates/a"
  cp "$HERE/public-denylist.txt" "$S/scripts/"
  : > "$S/scripts/public-denylist.allow"
  printf '[workspace]\nmembers=["crates/a"]\n[workspace.package]\nlicense = "Apache-2.0"\n' > "$S/Cargo.toml"
  printf '[package]\nname="a"\nlicense.workspace = true\n' > "$S/crates/a/Cargo.toml"
  echo "$S"
}
run() { ROOT="$1" NO_GIT=1 bash "$HERE/public-check.sh" "${2:-all}" >/dev/null 2>&1; }

S=$(mk); if run "$S"; then ok "clean scratch tree passes"; else no "clean scratch tree passes"; fi; rm -rf "$S"

S=$(mk); printf '[package]\nname="a"\nlicense = "UNLICENSED"\n' > "$S/crates/a/Cargo.toml"
if run "$S" licenses; then no "UNLICENSED manifest fails"; else ok "UNLICENSED manifest fails"; fi; rm -rf "$S"

S=$(mk); echo "mail owner@gmail.com" >> "$S/README.md"
if run "$S" denylist; then no "denylisted string fails"; else ok "denylisted string fails"; fi; rm -rf "$S"

S=$(mk); echo "start https://d-0123456789.awsapps.com/start" >> "$S/README.md"
if run "$S" denylist; then no "SSO portal URL fails"; else ok "SSO portal URL fails"; fi; rm -rf "$S"

S=$(mk); echo "image 999988887777.dkr.ecr.us-east-1.amazonaws.com/x" >> "$S/README.md"
if run "$S" denylist; then no "ECR account URL fails"; else ok "ECR account URL fails"; fi; rm -rf "$S"

S=$(mk); echo "999988887777" > "$S/scripts/public-denylist.local"; echo "acct 999988887777" >> "$S/README.md"
if run "$S" denylist; then no "local literal denylist fails"; else ok "local literal denylist fails"; fi; rm -rf "$S"

S=$(mk); echo "[gone](docs/missing.md)" >> "$S/README.md"
if run "$S" links; then no "broken link fails"; else ok "broken link fails"; fi; rm -rf "$S"

if command -v gitleaks >/dev/null 2>&1; then
  S=$(mk)
  # Canary built at runtime so this file itself holds no token-shaped literal.
  printf 'token = "ghp_%s"\n' "$(printf 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5')" > "$S/leak.txt"
  if run "$S" canary; then no "secret canary fails"; else ok "secret canary fails"; fi; rm -rf "$S"
else
  echo "skip canary test (gitleaks missing)"
fi

echo "public-check.test: $pass passed, $failn failed"
[ "$failn" = 0 ]
