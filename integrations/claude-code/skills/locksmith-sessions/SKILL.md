---
name: locksmith-sessions
description: Use when Locksmith reports no session, a locked vault or an expired lease, or when you need to start, inspect or understand a Locksmith session, its scopes, TTL or the agent policy.
---

# Sessions and leases

A session is a time-limited lease for one project and environment with a set of scopes: `run`, `git`, `http`, `db`, `aws`. Without one, Locksmith operations fail.

- Inspect: `locksmith_status` (MCP) or `smith status`: lock state, project, environment, scopes, expiry.
- Humans start sessions with `smith session start [--ttl 8h] [--scope run,http] -p <project> -e <env> -- <agent command>` (needs the passphrase).
- You may start one yourself with `locksmith_start_session` (`project`, `env`, `scopes`, `ttl_secs`) only inside the human's agent policy (max TTL, allowed scopes, allowed project/env pairs). The vault must already be unlocked by the human. The session covers you and every command you run (`smith run`, Git, database, AWS), like a human-started one; calling it again replaces your earlier session.
- When you call `locksmith_start_session`, also pass `agent` (your client name, e.g. `claude-code`) and `model` (your exact model id, e.g. `claude-fable-5-2`) so the human can see who holds the session. Report what you know about yourself; omit a field rather than guess. They are shown as self-reported and never change what is granted. Locksmith shows where you run (for example "Claude Code in iTerm2") on its own.
- In a session you started, `smith run` (and `smith gh` with a personal access token) injects only the keys listed under `inject` for the project; `locksmith_status` shows them as `inject`, and every other key is relay-only (`relay_only`): reach it with an http token. The relay sends a key only to the hosts the policy lists for it; hosts in `.locksmith.toml` do not count for your sessions (`relay_host`). Sessions a human started are not restricted this way.
- Out-of-policy requests are refused, not narrowed. Do not retry with other values or try other projects; tell the human what you need and why.
- The policy is read when the human unlocks; you cannot change it, and editing it has no effect.
- Revoke (`smith revoke`, human) takes effect immediately: every operation of that session stops, including relays and tokens. If you see "revoked", stop (`locksmith-blocked`).
- Expiry is normal: ask the human for a new session rather than looping.
