#!/usr/bin/env bash
# Proves a GitHub App identity can do what a scheduled agent does, without touching the real routines.
# Run it from the "Identity test" routine (no schedule) in the test environment that holds
# AGENT_PERSONA=test, AGENT_APP_KEY_TEST and AGENT_APP_IDS for the test App `locksmith-test` (docs/cloud-dev.md).
#   scripts/identity-smoke.sh [persona]   prints one PASS/FAIL line per step; exit 1 on any FAIL
# It opens one PR from claude/identity-smoke-<time>, comments, labels, then closes the PR (the branch stays:
# agents never delete branches).
set -uo pipefail
repo=locksmith-hq/locksmith
persona="${1:-${AGENT_PERSONA:-test}}"; bot=$(bash scripts/agent-identity.sh logins "$persona" | head -1); bot=${bot:-locksmith-${persona}[bot]}
fail=0; pr=""
step() { # <name> <command...>: run it, print PASS/FAIL
  local name=$1; shift
  if out=$("$@" 2>&1); then echo "PASS $name"; else echo "FAIL $name: $(tail -c 300 <<<"$out")"; fail=1; fi
}
is() { [ "$1" = "$2" ] || { echo "got '$1', want '$2'"; return 1; }; }

bash scripts/agent-identity.sh setup "$persona" >/dev/null || exit 1; echo "PASS identity"  # setup prints its own FAIL line
step git-author is "$(git config --local user.name)" "$bot"
step installation-repo is "$(gh api /installation/repositories -q '.repositories[0].full_name')" "$repo"

br="claude/identity-smoke-$(date -u +%Y%m%d-%H%M%S)"
step push bash -c "git fetch -q origin main && git switch -q -c '$br' origin/main &&
  git commit -q --allow-empty -m 'identity smoke: empty commit' -m 'Co-Authored-By: Claude <noreply@anthropic.com>' &&
  git push -q origin '$br'"
step commit-author is "$(gh api "repos/$repo/commits/$br" -q '.author.login // .commit.author.name' 2>/dev/null)" "$bot"

pr=$(gh api "repos/$repo/pulls" -f title="identity smoke ($persona)" -f head="$br" -f base=main -F draft=false \
  -f body=$'Automated identity smoke test; closes itself.\n\nGenerated with Claude Code' -q .number 2>/dev/null)
step open-pr test -n "$pr"
if [ -n "$pr" ]; then
  step pr-author is "$(gh api "repos/$repo/pulls/$pr" -q .user.login)" "$bot"
  step comment is "$(gh api "repos/$repo/issues/$pr/comments" -f body=$'<!-- agent -->\nidentity smoke comment' -q .user.login)" "$bot"
  step label gh api "repos/$repo/issues/$pr/labels" -f 'labels[]=in-progress'
  step close-pr is "$(gh api -X PATCH "repos/$repo/pulls/$pr" -f state=closed -q .state)" closed
fi
# Unlike GITHUB_TOKEN, an App token's push should start CI: this is informational, not a FAIL.
runs=$(gh api "repos/$repo/actions/runs?branch=$br&per_page=5" -q '.total_count' 2>/dev/null || echo "?")
echo "INFO workflow runs started by the push so far: $runs (PR #${pr:-none}, branch $br)"
[ "$fail" = 0 ] && echo "identity smoke: OK as $bot" || echo "identity smoke: FAILED"
exit "$fail"
