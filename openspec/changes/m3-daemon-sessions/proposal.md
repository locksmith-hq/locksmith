# Proposal: M3 Daemon and Sessions

## Why

Prompting for the passphrase on every command does not work with agents. Every delegated mode
(Git, HTTP, DB, AWS, MCP) also needs a long-lived process that holds keys and answers only verified
callers. This milestone creates the trust core: `locksmithd`, peer attestation, session leases,
revocation and the audit ledger.

## What Changes

- `locksmithd` runs as a per-user service (launchd LaunchAgent, systemd user unit). It listens on a
  Unix socket in a 0700 runtime dir. Windows named pipe comes in M16.
- Wire protocol: length-prefixed CBOR request/response, versioned, one operation per request. The
  daemon never has an operation that returns a plaintext secret to a client.
- Peer attestation through kernel handles: audit token and code signature on macOS, `SO_PEERCRED` +
  pidfd + exe hash on Linux (docs/v6-review.md §1.5).
- Session leases: `smith session start [--ttl 8h] [--scope ...] -- <agent cmd>` unlocks once and
  binds a lease to the agent's root process. `smith status`, `smith revoke <id>|--all`,
  `smith lock`.
- Auto-lock on idle, screen lock or sleep. Optional, on by default.
- Forward-secure audit ledger: hash chain, HMAC ratchet rooted at the recovery seed (fixes the v5
  bug, docs/v6-review.md §2.1), `smith audit ls|verify`.
- `smith run` uses the daemon when present, so there is no prompt inside an active session.
- Doctor checks: `daemon.running`, `daemon.socket_perms`, `daemon.attestation_selftest`,
  `platform.ptrace_scope`, `platform.core_dumps`, `audit.chain`.

## Usable outcome

`smith session start -- claude` asks for the passphrase once. Everything inside the session works
without prompts. `smith revoke` stops it instantly, and `smith audit ls` shows every access.

## Capabilities

### New Capabilities
- `broker-daemon`: The background service, its lifecycle and its request contract.
- `peer-attestation`: How the daemon decides which local process is talking to it.
- `session-leases`: Time- and process-bound authorizations and their revocation.
- `audit-ledger`: Tamper-evident record of every credential operation.

### Modified Capabilities

## Out of scope

- Biometric unlock (M9). Capability tokens for child processes and kill-tree containment (M8).
  M3 revocation invalidates the lease and ends future operations. Killing the agent tree comes in M8.

## Impact

New crates `locksmithd`, `ls-ipc`, `ls-broker`, plus platform code in `ls-platform` (the only crate
allowed `unsafe`). Service install files in `crates/locksmithd/dist/`.
