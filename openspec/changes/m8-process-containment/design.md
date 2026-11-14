# Design: M8 Process Containment

## Decisions

### D1. Where trust drops
The broker classifies each descendant from its exec chain. The **trusted root** is the agent binary.
**Tool processes** are `git`, `aws`, `psql` and similar, invoked directly by the agent's shell.
**Untrusted** processes are anything under an installer or build entry point, matched by argv
patterns and well-known script hosts (`node .../npm-lifecycle`, `sh -c` under `npm`). The descendant
check from M3 now evaluates `(lease, classification, requested op)`. Untrusted processes need an
explicit capability.

### D2. Capability passing
Where the agent's tool runner supports it, `smith run --cap git:push` passes an inherited socketpair
FD (`LOCKSMITH_CAP_FD=3`). The FD is not reusable outside the child. Otherwise a token goes in env,
single use, valid for 60 s, and bound to a PID subtree.

### D3. Kill semantics
Order: close relays → revoke tokens → SIGTERM the tree → 3 s → SIGKILL. Then a re-scan for escaped
processes (setsid, double-fork) through subreaper adoption (Linux) or kqueue NOTE_FORK tracking
(macOS). Anything that escaped tracking is reported, not hidden.

### D4. Seatbelt (macOS, optional)
When the agent does not sandbox itself, `smith session start --sandbox` wraps it in a
`sandbox-exec` profile. The profile allows everything except reads and writes to the vault dir,
`~/.ssh`, `~/.aws`, `~/.config/gcloud` and keychain files. Claude Code and Codex ship their own
sandboxes. Locksmith detects them and only adds the deny-list paths through their settings.

## Risks / Trade-offs
- Classification by argv can be fooled. That only matters if the attacker wants *more* trust, and a
  fooled classifier still never grants a capability that the policy did not list for that
  operation. The worst case is the lease's own scope.
