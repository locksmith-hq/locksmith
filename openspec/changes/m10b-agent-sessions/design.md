# Design: M10b

## D1. Session grant without the passphrase
`SessionStart` carries the passphrase so no attested `smith` an agent double-forked can mint a
lease. Agent-started sessions need a separate path: the daemon (already unlocked by the human)
accepts `AgentSessionStart` from `Role::Mcp` only, and mints a lease only when the request fits the
policy file the human owns (path outside any agent-writable repo). Policy changes need the human.

## D2. Scoring
Signals come from the audit stream the daemon already writes. Strong = block now. Weak = weighted
score over a sliding window, block at threshold; weights and threshold are defaults in the policy
file. The scorer only revokes and cools down; it never widens anything.

## D3. Cooldown
Per project, persisted in the vault directory, cleared only by the desktop app or `smith` with a
fresh passphrase.

## Open
Exact strong-signal list and default weights; tuned during gate runs (A5/A7 live).

## D4. Lease root for agent-started sessions
A lease authorizes only its root and the root's descendants (`descends_from`, re-walked per
request). The MCP server is a stdio child of the agent, and the agent's shell commands (`smith run`,
`git`, database and AWS clients) are its siblings, so a lease rooted at the MCP server covered none
of them. The daemon therefore roots an `AgentSessionStart` lease at the MCP server's parent: the
agent process that launched it.

- The root comes from the kernel (`ls_broker::agent_root`: the caller's ppid read through
  `ls_platform::proc::info`), never from the request. Refused (`Denied`, audited
  `BLOCKED agent_root: <why>`) when the caller is gone or changed (pid plus start time), its parent
  is pid <= 1 (orphaned), cannot be read, belongs to another uid, is younger than the caller
  (recycled pid), or the caller was reparented while the daemon looked. The lease stores the
  parent's `ProcId`, so a later process reusing the pid never matches.
- Coverage is the agent and everything under it, the MCP server included, never its parent (the
  terminal). That is exactly what a human-started `smith session start -- claude` grants (its root
  is the `smith` process directly above the agent). The policy file stays the only authority on
  project, environment, scopes and TTL: widening the tree does not widen what may be asked for.
- No nesting: refused when the agent or the caller already sits inside an active lease, except an
  agent-started lease with this same root, which the new one replaces (revoked first, audited
  `REVOKE` "replaced by agent session <id>", its relays and tokens dropped as on `smith revoke`).
  A human-started lease is never replaced this way. The replacement passes the same policy check,
  so `max_ttl` bounds each lease; an agent can renew within policy until the human locks, revokes
  or narrows the policy (the auto-block of D2 is the intended brake).
- Shared hosts: the root is whatever process spawned `locksmith-mcp`. For the Claude Code and Codex
  CLIs that is the agent. Where an editor (Cursor, an IDE extension host) spawns MCP servers from one
  long-lived process, the lease covers that whole host, including the human's integrated terminals
  and other extensions. Not verified per host yet; a per-host check belongs with the `init` wiring.
- Audit: `SESSION_START` rule `agent_policy <scopes>; root pid <pid> (<exe file name>)`. The name
  is the executable path's file name only, never arguments or environment.
- Agent exit: nothing calls `Leases::end` for an agent lease (the agent never sends `SessionEnd`).
  It fails closed instead: once the agent exits its pid plus start time no longer exists, its
  children are reparented away, and no walk reaches the root. `smith status` still lists the
  lease as active until its TTL. A dead-root sweep in the daemon watcher is a possible follow-up.
