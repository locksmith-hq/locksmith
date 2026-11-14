# Proposal: M8 Process Containment

## Why

A session's lease covers the whole agent process tree. That tree includes `npm install`
postinstall scripts and build tools the agent did not write. v5 §5 calls for non-inheritable,
operation-scoped capabilities and OS containment. M8 builds them, so hostile code in the tree cannot
use the session, and revoke stops everything.

## What Changes

- **Capability tokens:** single-use or short-lived tokens bound to one operation (`git:push repo X`,
  `http:STRIPE_KEY`, `db:prod-ro`). They are passed to children by inherited file descriptor where
  possible, not by env.
- **Untrusted-command classification:** package installs and build scripts (`npm|pnpm|yarn install`,
  `pip install`, `cargo build` with build.rs, `make`, `postinstall`) run as **untrusted
  descendants**. The lease does not cover them unless the project policy grants a capability to that
  command.
- **Containment:** systemd user scope (Linux, when available), otherwise process group plus
  `PR_SET_CHILD_SUBREAPER`. On macOS, process group plus kqueue fork/exit tracking, and an optional
  Seatbelt profile that blocks reads of `~/.ssh`, `~/.aws` and the vault dir. Windows Job Objects
  come in M16.
- **Revoke kills the tree:** `smith revoke --kill` terminates every tracked process of the session,
  including reparented daemons, after relays close.
- Doctor checks: `containment.backend`, `containment.seatbelt`.

## Usable outcome

A malicious postinstall script in a dependency cannot push, call APIs or read DB data through the
session. `smith revoke --kill` leaves no orphaned agent processes.

## Capabilities

### New Capabilities
- `capability-tokens`: Operation-scoped authorizations for processes inside a session.
- `process-containment`: Tracking and terminating a session's process tree, and restricting untrusted descendants.

### Modified Capabilities

## Out of scope

- Network egress filtering (backlog: `nftables` per-cgroup on Linux, NetworkExtension on macOS).
- Containers and VMs as isolation. Docs recommend devcontainers plus the `devcontainer-feature`
  integration.

## Impact

`ls-broker` (capabilities), `ls-platform` (containment backends), and a policy schema extension in
`.locksmith.toml`.
