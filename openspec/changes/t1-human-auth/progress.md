# Progress: T1 human authentication (append-only)

- 2026-11-19 · planning only: proposal, spec, design and tasks written by a worker; no code. Next: obtain owner approval for the sign-in UX direction before task 6.0.

## 2026-11-19 11:52 worker
- Task: planning - done
- Verified: openspec validate t1-human-auth -> valid; tree-check OK
- Notes for next session: task 6.0 is gated on owner approval of sign-in UX; verify OSS versions at apply.

## 2026-11-19 16:15 worker
- Task: 1.1-1.4 JWT verification (jsonwebtoken kept; JWKS cache, OrgBinding, forged/none/aud/exp/rotation tests) - done
- Verified: just ci -> green; nextest -p ls-control-plane auth -> pass; independent evaluator PASS
- Notes for next session: personal_org_id is an interim UUIDv5(issuer,sub) until 3.2 creates real personal orgs; no RS256 signing round-trip test (ES256 only); telemetry_export test updated since a bearer is no longer downgraded to the dev header; 2.x next (dev_auth gating), 6.0 gated on owner UX approval.
