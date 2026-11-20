# Progress: M1 remote MCP (append-only)

- 2026-11-20 · planning only: proposal, spec, design and tasks written by a worker; no code. `x-depends_on` is t1-human-auth:contract (t1 is archived on main). Remote-MCP auth is unverified, so task 1.1 is a research note.
- 2026-11-20 · review follow-up: `x-depends_on: []` is deliberate because `t1-human-auth` is archived on main (the roadmap's `t1-human-auth:contract` is already satisfied). Design now states how a call is bound to an `mcp_clients` row (session id) and task 1.1 research covers it.
- 2026-11-20 · review follow-up 2: revoke now binds to the OAuth client_id (hub) or the agent (gateway), not the session id; task 4.2 test re-initializes after revoke.
