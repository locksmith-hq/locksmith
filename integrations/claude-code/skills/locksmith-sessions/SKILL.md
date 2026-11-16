---
name: locksmith-sessions
description: Use when Locksmith reports no session, a locked vault or an expired lease, or when you need to start, inspect or understand a Locksmith session, its scopes, TTL or the agent policy.
---

# Sessions and leases

A session is a time-limited lease for one project and environment with a set of scopes: `run`, `git`, `http`, `db`, `aws`. Without one, Locksmith operations fail.

- Inspect: `locksmith_status` (MCP) or `smith status`: lock state, project, environment, scopes, expiry.
- Humans start sessions with `smith session start [--ttl 8h] [--scope run,http] -p <project> -e <env> -- <agent command>` (needs the passphrase).
- You may start one yourself with `locksmith_start_session` (`project`, `env`, `scopes`, `ttl_secs`) only inside the human's agent policy (max TTL, allowed scopes, allowed project/env pairs). The vault must already be unlocked by the human. The session covers you and every command you run (`smith run`, Git, database, AWS), like a human-started one; calling it again replaces your earlier session.
- Out-of-policy requests are refused, not narrowed. Do not retry with other values or try other projects; tell the human what you need and why.
- The policy is read when the human unlocks; you cannot change it, and editing it has no effect.
- Revoke (`smith revoke`, human) takes effect immediately: every operation of that session stops, including relays and tokens. If you see "revoked", stop (`locksmith-blocked`).
- Expiry is normal: ask the human for a new session rather than looping.
