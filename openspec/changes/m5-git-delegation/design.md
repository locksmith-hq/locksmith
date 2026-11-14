# Design: M5 Git Delegation

## Context
Git supports `url.<base>.insteadOf` rewriting and plain-HTTP remotes. Both work with every Git ≥2.0
and need no TLS interception.

## Goals / Non-Goals
**Goals:** pass gate A1, and add <5% overhead on clone/push of a 100 MB repo.
**Non-Goals:** a general HTTPS proxy (M6).

## Decisions

### D1. URL scheme
`http://127.0.0.1:<port>/git/<host>/<owner>/<repo>.git`. Rewrites are
`https://github.com/` and `git@github.com:` / `ssh://git@github.com/` → forwarder base. The port is
random at daemon start and written to the runtime dir. `smith git setup` uses an `include.path` file
that the daemon rewrites when the port changes.

### D2. Who may use the forwarder (confused deputy)
Any local process can open a loopback TCP connection. Each request must therefore carry a
**forwarder token**:
- Git gets it through the credential helper. The value is a random 256-bit token bound to
  `{lease_id, allowed remotes}`.
- The forwarder also resolves the TCP peer to a PID: Linux `/proc/net/tcp` inode → `/proc/*/fd`, macOS
  `proc_pidfdinfo` socket scan. It then applies the lease descendant check (M3 D3).
Disclosure of the forwarder token is acceptable. It is useless outside the session tree, dies with
the lease, and cannot be exchanged for the upstream credential.

### D3. Upstream auth
GitHub App installation token from `POST /app/installations/{id}/access_tokens` with
`repositories:[repo]`, `permissions:{contents:write, pull_requests:write, metadata:read}`. It is
cached per repo until 5 minutes before expiry. The App private key lives in the vault as a secret
of type `github_app`. PAT mode simply injects `Authorization: Basic base64("x-access-token:" + pat)`.

### D4. Push policy
Parse the `git-receive-pack` request's pkt-line ref-update commands before forwarding. A forced
non-fast-forward push is detected by asking upstream for the current ref (from the `info/refs`
advertisement in the same session) and checking ancestry. This is expensive, so v6 instead denies
updates where `old != advertised` or `new == 0000…` (delete) for protected refs. That is a simple
check that covers delete and stale force pushes. A true ancestry check is in the backlog.

### D5. `smith gh`
`gh` cannot be pointed at a plain-HTTP API base for github.com. So `smith gh` runs `gh` with
`GH_TOKEN=<installation token>` via Mode C plus redaction. It is labelled contained, not delegated.
The M6 local-CA mode can make it fully delegated for users who opt in.

## Risks / Trade-offs
- Some Git GUI clients ignore `insteadOf`. Out of scope, because agents use the CLI.
- Corporate proxies: the forwarder honours `HTTPS_PROXY` for its upstream leg.
