# Tasks

## 1. Crypto and storage

- [ ] 1.1 Identity keys, HPKE wraps, signed changes (design D1). Verify: unit tests plus HPKE RFC 9180 test vectors.
- [ ] 1.2 Shared vault type in `ls-vault` with a local cache. Verify: tests for multi-member decrypt and removed-member denial.

## 2. Sync server

- [ ] 2.1 `services/sync-server`: axum, change log, wraps, members, OIDC SSO. Verify: integration tests plus the blind-storage test (grep the DB dump for canaries and key names).
- [ ] 2.2 Client sync engine (pull, push, conflict LWW per version, offline queue). Verify: a two-client convergence property test.

## 3. Membership and policy

- [ ] 3.1 Invites, safety numbers, key-change warnings (design D2). Verify: e2e for the substituted-key scenario.
- [ ] 3.2 Removal with rotation and the upstream rotate list. Verify: e2e.
- [ ] 3.3 Signed org policy, distribution and the strictest-merge rule (design D3). Verify: table tests per field.
- [ ] 3.4 Central audit stream and the admin timeline in desktop and web. Verify: e2e.

## 4. Acceptance

- [ ] 4.1 A design partner team of ≥4 people runs for 2 weeks. Verify: feedback notes and zero integrity errors in the logs.
