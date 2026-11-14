# Design: M3 Daemon and Sessions

## Context
v5 §5.1, §8.1 (`session_leases`, `audit_events`) and §9.3–9.4. v6 removes Noise
(docs/v6-review.md §2.4) and replaces PID+start time with kernel handles (§1.5).

## Goals / Non-Goals
**Goals:** one unlock per agent session, revocation that holds, a verifiable audit trail.
**Non-Goals:** multi-user or remote daemons.

## Decisions

### D1. Process model
One `locksmithd` per user. It is started on demand by `smith` if it is not running, and installed as
a LaunchAgent or systemd user unit by `smith daemon install`. The VK lives only in daemon memory
(mlocked). Its state is unlocked or locked. Leases live in memory and are mirrored to the encrypted
DB only for audit. A restart drops all leases, which is a deliberate fail-closed choice.

### D2. Attestation
| Platform | Identity | Signature / binary check |
|---|---|---|
| macOS | `getsockopt(LOCAL_PEERTOKEN)` → `audit_token_t` | `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` + `SecCodeCheckValidity` with a requirement string pinning our Team ID |
| Linux | `SO_PEERCRED` (uid, pid) + `SO_PEERPIDFD` (≥6.5) or `pidfd_open` + `/proc/pid/stat` starttime | SHA-256 of `/proc/<pid>/exe` matched against the installed binaries manifest |
Callers are classified into `smith` (CLI), `locksmith-mcp`, `locksmith-desktop`, `proxy-client`
(M5+) and `unknown`. Unknown callers get only `ping` and `version`.

### D3. Lease binding
A lease is `{id, root: ProcessIdentity, scopes, project, env, expires_at, created_by}`.
A request is authorized when the caller is an attested Locksmith binary AND the process that
requested the operation (passed by the caller and verified by walking the real parent chain from
the kernel) descends from `root`, AND the scope matches. Descendant checks use pidfd plus start
time at each hop. The chain is re-walked on every request, never cached.

### D4. Audit ledger
Row: `(seq, ts, session_id, actor{pid, starttime, exe_hash}, action, target_secret_id?, policy_rule, decision, prev_hash, mac)`.
`prev_hash = SHA256(prev_row_canonical)`. `mac = HMAC(K_i, row_canonical)`.
`K_{i+1} = HMAC(K_i, "ratchet")`. Only the current `K_i` is held. It is persisted wrapped by VK after
each append, in the same transaction. `K_0` comes from the recovery seed at vault init (M1 D1), and
`K_1` is stored then. `smith audit verify` checks the hash chain and the current MAC.
`smith audit verify --full` asks for the recovery phrase, re-derives `K_0` and checks every MAC.
External anchors (OS log, git notes) come in M9.

### D5. Auto-lock
macOS: `NSWorkspace` screen-lock and sleep notifications through a tiny `objc2` shim. Linux:
logind `Lock`/`PrepareForSleep` over D-Bus (`zbus`). The idle timeout defaults to 30 min.

## Risks / Trade-offs
- An older Linux kernel without pidfd falls back to PID+starttime, and doctor warns.
- Same-UID injection into an attested binary is a residual risk (docs/v6-review.md §1.6).
  Mitigations: `PR_SET_DUMPABLE=0` on the daemon, hardened runtime, and a doctor warning on
  `ptrace_scope=0`.
