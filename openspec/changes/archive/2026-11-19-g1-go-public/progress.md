# Progress: g1-go-public

## 2026-11-18 worker
- Task: planning (proposal, spec, design, tasks) - done
- Verified: openspec validate g1-go-public -> valid
- Notes for next session: full-history gitleaks found 17 findings on 2026-11-18, not yet triaged (task 1.1). Open question for the owner in design.md: keep `.claude/` and `docs/agents/` public. Planned from #311.

## 2026-11-19 worker
- Task: 1.1-1.3, 2.1-2.3, 3.1-3.3, 4.1-4.2, 5.1, 5.3 - done (5.2 needs-owner issue + Artifact brief and 6.1 local verification remain)
- Verified: just ci green before the last small edits; public-check.test.sh 6/6, cargo deny check licenses bans ok, gitleaks history exit 0; Opus evaluator PASS after fixing a first-party AGPL ban gap
- Notes for next session: 23 history findings were all fake fixtures (now in .gitleaksignore). Do 5.2 (open needs-owner issue, link docs/going-public.md, push notification), then 6.1 (just up, public-check, just apps-build, just ci), then archive. Canary is skipped silently without gitleaks; integrations/ have no manifests.

## 2026-11-19 worker
- Task: 6.1 - done (5.2 remains: needs-owner issue is the lead's to raise; worker opened a needs-rescue Decision issue)
- Verified: just ci -> exit 0 (after merging main); just up + public-check.sh + just apps-build + just down -> exit 0
- Notes for next session: once 5.2 is done (lead opens needs-owner with Artifact brief, owner approval recorded), tick it and archive the change in the same PR.

## 2026-11-19 09:30 lead
- Task: 5.2 - blocked (owner)
- Verified: gitleaks detect --redact (355 commits) -> no leaks; bash scripts/public-check.sh -> OK
- Notes for next session: rescue #348 closed; owner decision raised as #349 with Artifact brief and push. On `approved`, record the line in openspec/decisions.md, tick 5.2 and archive in PR #344. Option B (hide harness) would need a history rewrite.

## 2026-11-19 lead
- Task: 5.2 - done (owner replied `approved`, option A, on #349)
- Verified: approval line G1-1 in openspec/decisions.md and owner.md; openspec validate --all and just ci (see below)
- Notes for next session: change archived in this PR. Owner runs the 8 steps in docs/going-public.md after merge; ci and claude-review come back then.
