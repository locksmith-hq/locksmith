# Progress: g1-go-public

## 2026-11-18 worker
- Task: planning (proposal, spec, design, tasks) - done
- Verified: openspec validate g1-go-public -> valid
- Notes for next session: full-history gitleaks found 17 findings on 2026-11-18, not yet triaged (task 1.1). Open question for the owner in design.md: keep `.claude/` and `docs/agents/` public. Planned from #311.

## 2026-11-19 worker
- Task: 1.1-1.3, 2.1-2.3, 3.1-3.3, 4.1-4.2, 5.1, 5.3 - done (5.2 needs-owner issue + Artifact brief and 6.1 local verification remain)
- Verified: just ci green before the last small edits; public-check.test.sh 6/6, cargo deny check licenses bans ok, gitleaks history exit 0; Opus evaluator PASS after fixing a first-party AGPL ban gap
- Notes for next session: 23 history findings were all fake fixtures (now in .gitleaksignore). Do 5.2 (open needs-owner issue, link docs/going-public.md, push notification), then 6.1 (just up, public-check, just apps-build, just ci), then archive. Canary is skipped silently without gitleaks; integrations/ have no manifests.
