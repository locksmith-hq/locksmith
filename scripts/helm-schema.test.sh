#!/usr/bin/env bash
# Good and bad values files against infra/helm/locksmith/values.schema.json (P2 packaging, task 4.3).
# Uses `helm lint` when helm is installed (the same schema check Helm runs); otherwise python3's
# jsonschema (Draft 7). Prints names only, never values. Exit 0 = every good file passes and every bad one is rejected.
# shellcheck disable=SC2015  # A && ok || bad is the reporting idiom
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
chart=infra/helm/locksmith
fails=0

if command -v helm >/dev/null 2>&1; then
  echo "helm-schema: engine = helm lint"
  lint() { helm lint "$chart" -f "$1" >/dev/null 2>&1; }
elif python3 -c 'import jsonschema, yaml' >/dev/null 2>&1; then
  echo "helm-schema: engine = python jsonschema (helm not installed)"
  lint() {
    python3 -I - "$chart/values.schema.json" "$chart/values.yaml" "$1" <<'PY' >/dev/null 2>&1
import json, sys, yaml, jsonschema
schema = json.load(open(sys.argv[1]))
def merge(a, b):
    for k, v in b.items():
        a[k] = merge(a[k], v) if isinstance(v, dict) and isinstance(a.get(k), dict) else v
    return a
vals = merge(yaml.safe_load(open(sys.argv[2])), yaml.safe_load(open(sys.argv[3])))
jsonschema.Draft7Validator.check_schema(schema)
sys.exit(0 if not list(jsonschema.Draft7Validator(schema).iter_errors(vals)) else 1)
PY
  }
else
  echo "helm-schema: SKIPPED (neither helm nor python3 with jsonschema and yaml is available); not a pass" >&2
  exit 0
fi

for f in "$chart"/tests/good-*.yaml; do
  if lint "$f"; then echo "ok   accepts $(basename "$f")"; else echo "FAIL rejects good file $(basename "$f")"; fails=$((fails + 1)); fi
done
for f in "$chart"/tests/bad/*.yaml; do
  if lint "$f"; then echo "FAIL accepts bad file $(basename "$f")"; fails=$((fails + 1)); else echo "ok   rejects $(basename "$f")"; fi
done
# The shipped defaults must be rejected too: secret names are required, never defaulted.
if lint /dev/null; then echo "FAIL default values accepted without secret names"; fails=$((fails + 1)); else echo "ok   rejects default values (secret names required)"; fi

[ "$fails" -eq 0 ] && echo "helm-schema: OK" || { echo "helm-schema: $fails FAILED" >&2; exit 1; }
