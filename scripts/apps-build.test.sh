#!/usr/bin/env bash
# Plants a type error in each app's frontend and checks that the build step `just apps-build`
# runs (npm run build) fails, then removes it and checks the build passes again.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
planted=()
cleanup() { for f in "${planted[@]}"; do rm -f "$f"; done; }
trap cleanup EXIT
for app in web desktop; do
  f="apps/$app/src/__planted_error.ts"
  echo 'export const planted: number = "not a number";' > "$f"; planted+=("$f")
  if npm run build --workspace "apps/$app" >/dev/null 2>&1; then
    echo "FAIL: apps/$app build passed with a planted type error"; fail=1
  else
    echo "ok: apps/$app build fails on a planted error"
  fi
  rm -f "$f"
  if npm run build --workspace "apps/$app" >/dev/null 2>&1; then
    echo "ok: apps/$app build passes once the error is removed"
  else
    echo "FAIL: apps/$app build still fails without the planted error"; fail=1
  fi
done
exit $fail
