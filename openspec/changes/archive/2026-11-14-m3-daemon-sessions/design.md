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

## As built (deviations from the decisions above)

- **D2 macOS pinning.** The release Team ID requirement needs a release signing identity we do
  not have yet, so it is not implemented. Instead the daemon pins the **cdhash** of the `smith`,
  `locksmith-mcp` and `locksmith-desktop` binaries installed beside it, at startup. It checks the
  caller with `SecCodeCopyGuestWithAttributes(audit token)` + `SecCodeCheckValidity` against
  `cdhash H"…"`, which the kernel enforces page by page. Unsigned x86_64 dev builds cannot be
  attested. Team ID pinning comes with release signing. Linux pins the file SHA-256 of the same
  binaries, read through `/proc/<pid>/exe` while a pidfd proves the process is still the peer.
  After `smith self update` the daemon must restart before it trusts the new binary.
- **D3 lease root.** The root is the `smith session start` process itself, identified by the
  kernel and never by a claim. The agent is its child. The process checked on each request is the
  attested `smith` peer. Children that the daemon spawns for `smith run` are added to the lease so
  that their descendants stay in-session. `LOCKSMITH_SESSION=<id>` marks an in-session process:
  with it set, `smith run` only goes through the daemon and any failure exits 4, so a revoked
  session never falls back to a passphrase prompt.
- **`smith run` in a session.** The daemon spawns the child (the only path where secrets leave
  it), receives the client's stdio over SCM_RIGHTS, and relays redacted output. It uses pipes, not
  a PTY.
- **D4 ledger.** `prev_hash = SHA256(canonical || mac)`. The stored key is the key of the
  *newest* event, so the daily verify can check the newest MAC and detect tail truncation. Forward
  security therefore covers every event except the newest one. Vaults created before M3 get an
  *unanchored* random root, and `verify --full` says so. `smith vault recovery rotate` re-anchors
  the ledger at the new phrase from the next event. `secure_delete` plus a best-effort WAL
  checkpoint after each append removes old wrapped keys from disk.
- **D5 auto-lock.** macOS polls `CGSessionCopyCurrentDictionary` once a second (within the 2 s
  bound) instead of an `objc2` NSWorkspace observer. Linux subscribes to logind `Session.Lock` and
  `PrepareForSleep(true)` with `zbus` 6.3 (its built-in `block_on` runtime, one thread per signal;
  zbus 5's crates are flagged unmaintained). On both OSes sleep is also detected by the wall clock
  jumping ahead of the monotonic clock.

## Residual risks (stated as prevention / containment / detection)

- **Inside a session the agent can obtain any secret the lease covers** (detection only, via the
  audit log). For example, `smith run --only K -- sh -c 'echo $K | base64 | rev'` is authorized
  by design, and redaction cannot catch arbitrary encodings. M3 leases bound *who* and *for how
  long*, not *what the child does*. Delegated modes (M5+) close this.
- **Same-UID attacker against attestation** (partially mitigated, docs/v6-review.md §1.6):
  LD_PRELOAD/DYLD injection into a real `smith`, ptrace where Yama allows it, or connecting and
  then passing the socket fd to another process before exec'ing `smith` can make a rogue client
  look attested. Attestation stops naive clients: scripts, `socat`, copied or modified binaries.
- **Same-UID attacker replacing installed binaries before the daemon starts** gets them pinned.
- **Process-tree binding** fails closed on PID reuse and on reparenting: an orphaned
  double-forked daemon loses the session.
- **BLOCKED events while the vault is locked** are queued in memory and lost if the daemon
  restarts before the next unlock.
- **Revocation** stops new operations. Children already running keep their environment until M8
  adds kill-tree containment.

## Risks / Trade-offs
- An older Linux kernel without pidfd falls back to PID+starttime, and doctor warns.
- Same-UID injection into an attested binary is a residual risk (docs/v6-review.md §1.6).
  Mitigations: `PR_SET_DUMPABLE=0` on the daemon, hardened runtime, and a doctor warning on
  `ptrace_scope=0`.
