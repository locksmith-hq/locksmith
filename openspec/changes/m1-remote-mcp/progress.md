# Progress: M1 remote MCP (append-only)

- 2026-11-20 · planning only: proposal, spec, design and tasks written by a worker; no code. `x-depends_on` is t1-human-auth:contract (t1 is archived on main). Remote-MCP auth is unverified, so task 1.1 is a research note.
- 2026-11-20 · review follow-up: `x-depends_on: []` is deliberate because `t1-human-auth` is archived on main (the roadmap's `t1-human-auth:contract` is already satisfied). Design now states how a call is bound to an `mcp_clients` row (session id) and task 1.1 research covers it.
- 2026-11-20 · review follow-up 2: revoke now binds to the OAuth client_id (hub) or the agent (gateway), not the session id; task 4.2 test re-initializes after revoke.
- 2026-11-20 · review follow-up 3: spec revoke requirement now names the client_id/agent binding and adds a re-initialize-after-revoke scenario (maps to task 4.2).
- 2026-11-20 · lead: owner chose option A on [#493](https://github.com/locksmith-hq/locksmith/issues/493). Hub revoke refuses tokens whose `auth_time` is before `revoked_at` and revokes refresh tokens and consent at the issuer (refusing by `iat` is bypassed by a refresh). Design and spec updated; task 4.1 checks Keycloak keeps `auth_time` on refresh, else the strict rule applies. Task 1.1's note must use this rule.
