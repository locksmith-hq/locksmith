#!/usr/bin/env bash
# Recomputes the totals in docs/design/aws-dev-cost.md from aws-dev-cost.csv and fails if they differ
# or if the budget ($5/month: idle + 4 two-hour sessions) is exceeded.
set -euo pipefail
cd "$(dirname "$0")/.."
csv=docs/design/aws-dev-cost.csv
md=docs/design/aws-dev-cost.md
sessions=${SESSIONS_PER_MONTH:-4}
read -r idle session < <(awk -F, 'NR>1{i+=$2*$3; s+=$2*$4} END{printf "%.2f %.2f\n", i, s}' "$csv")
total=$(awk -v i="$idle" -v s="$session" -v n="$sessions" 'BEGIN{printf "%.2f", i+s*n}')
echo "idle/month=\$$idle session=\$$session x$sessions total/month=\$$total"
grep -q "Idle per month: \$$idle" "$md" || { echo "aws-cost-check: idle total in $md differs from CSV (\$$idle)" >&2; exit 1; }
grep -q "Per session: \$$session" "$md" || { echo "aws-cost-check: session total in $md differs from CSV (\$$session)" >&2; exit 1; }
grep -q "Total per month (4 sessions): \$$total" "$md" || { echo "aws-cost-check: monthly total in $md differs from CSV (\$$total)" >&2; exit 1; }
awk -v t="$total" 'BEGIN{exit !(t<5.00)}' || { echo "aws-cost-check: total \$$total exceeds the \$5 budget" >&2; exit 1; }
echo "aws-cost-check: OK"
