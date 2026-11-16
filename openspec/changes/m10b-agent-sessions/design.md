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
