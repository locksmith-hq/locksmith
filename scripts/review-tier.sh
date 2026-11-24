#!/usr/bin/env bash
# Which reviewer a PR's merge review needs, from its changed paths (one per line on stdin): opus | sonnet | none.
# Reviews ran Opus with up to 40 turns on every PR (about 270 a week); most diffs don't touch secrets (owner 2026-11-23).
#   opus:   any path that holds or moves secrets, keys or proxies (AGENTS.md: Rust core), or the trust root.
#   none:   every path is prose that runs nowhere: docs/ outside docs/agents/, or OpenSpec planning files
#           (not tasks.md, whose ticks claim verified work). CI and the task guard still run.
#   sonnet: everything else.
#   scripts/review-tier.sh < files    |    scripts/review-tier.sh selftest
set -euo pipefail

opus_re='^(crates/(ls-crypto|ls-ipc|ls-broker|ls-update|ls-license|ls-entitlements|ls-envelope|ls-audit|locksmith-audit|ls-vault|ls-proxy|ls-connector|ls-redact|ls-http|ls-platform|ls-hooks|locksmithd|smith-cli)/|ee/|services/|\.github/|\.claude/|scripts/review-tier|AGENTS\.md$|CLAUDE\.md$|openspec/config\.yaml$)'
none_re='^(docs/|openspec/changes/)'
keep_re='^docs/agents/|/tasks\.md$'

tier() {
  local f any=0 all_none=1
  while IFS= read -r f || [ -n "$f" ]; do
    [ -n "$f" ] || continue
    any=1
    [[ "$f" =~ $opus_re ]] && { echo opus; return; }
    if ! [[ "$f" =~ $none_re ]] || [[ "$f" =~ $keep_re ]]; then all_none=0; fi
  done
  # An empty diff is reviewed: never skip on missing input.
  if [ "$any" = 1 ] && [ "$all_none" = 1 ]; then echo none; else echo sonnet; fi
}

selftest() {
  local fail=0 got
  t() { got=$(printf '%b' "$2" | tier); [ "$got" = "$1" ] && echo "ok: $1 <- $2" || { echo "FAIL: want $1 got $got <- $2"; fail=1; }; }
  t opus   'crates/ls-crypto/src/lib.rs'
  t opus   'docs/x.md\nservices/gateway/src/main.rs'
  t opus   '.github/workflows/ci.yml'
  t opus   'scripts/review-tier.sh'
  t sonnet 'apps/web/src/App.tsx'
  t sonnet 'crates/ls-core/src/lib.rs\ndocs/a.md'
  t sonnet 'openspec/changes/x/tasks.md'
  t sonnet 'docs/agents/owner.md'
  t sonnet 'openspec/decisions.md'
  t sonnet ''
  t none   'docs/research/x.md'
  t none   'openspec/changes/x/proposal.md\nopenspec/changes/x/specs/a/spec.md\nopenspec/changes/x/progress.md'
  [ "$fail" = 0 ] && echo "review-tier selftest: OK"; return "$fail"
}

case "${1:-}" in
  selftest) selftest ;;
  "") tier ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
