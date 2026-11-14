# Locksmith v6: Review of the v5 Plan

The original plan is kept verbatim at [reference/locksmith-v5.md](reference/locksmith-v5.md).
This document lists what v6 changes and why. Each item names the milestone change in
`openspec/changes/` that carries it.

Labels used below:
- **Hole**: v5 claims a guarantee that an agent with a shell can break.
- **Bug**: the design does not work as written.
- **Simplify**: same or better security with less machinery.
- **Gap**: something a shippable product needs that v5 does not cover.

## 1. Security holes in v5

### 1.1 Git helper lineage check is bypassable (Hole), M5
v5 lets `git-credential-smith get` return a token when its parent process is `git`.
An agent can run `printf 'protocol=https\nhost=github.com\n\n' | git credential fill`.
Git becomes the parent, the check passes, and the token prints to stdout.
**v6:** the agent never gets a Git credential. Git talks to a loopback forwarder
(`url."http://127.0.0.1:<port>/git/github.com/".insteadOf "https://github.com/"`). The forwarder
adds the `Authorization` header upstream over TLS. No helper ever returns a real token.

### 1.2 GitHub cannot mint 60-second, single-operation tokens (Bug), M5
GitHub offers no such token. **v6:** the upstream credential is either a fine-grained PAT stored
in the vault, or (preferred, Pro) a GitHub App installation token. That token lasts one hour and
is limited to one repository and to `contents:write` and `pull_requests:write`. Either way it stays
in the daemon.

### 1.3 AWS `credential_process` is bypassable (Hole), M7
`aws configure export-credentials` prints whatever `credential_process` returns, and the parent is
the legitimate `aws` binary. **v6:** the primary path is a SigV4 re-signing proxy. The AWS CLI and
SDKs point at `AWS_ENDPOINT_URL=http://127.0.0.1:<port>` and sign with dummy keys. Locksmith checks
the request against policy, re-signs it with real or STS credentials, and forwards it. The fallback
is down-scoped 15-minute STS. v6 labels it honestly: **disclosed but contained**, not "never
exposed".

### 1.4 The shim lies to the agent (Bug), M4
v5 blocks `cat .env` and then "returns exit code zero and emits virtualized mock descriptors".
Fake success sends agents into long confusing loops, and nobody can tell that something was blocked.
**v6:** blocked commands exit non-zero with a short, fixed message. It says the command was blocked
by Locksmith and gives the supported alternative, e.g. `smith ls` or `smith run -- <cmd>`.

### 1.5 PID plus start time is not peer identity (Hole), M3
v6 uses kernel identity handles instead:
- macOS: `audit_token_t` from `LOCAL_PEERTOKEN`, then `SecCodeCopyGuestWithAttributes` with that
  token. This avoids the PID race.
- Linux: `SO_PEERCRED` plus `SO_PEERPIDFD` (kernel 6.5+, fallback: `pidfd_open` + start time).
- Windows: `GetNamedPipeClientProcessId`, then open the process handle and check the image signature.

### 1.6 Same-UID code injection is unaddressed (Hole, now documented), M3
A same-user process can attach to an allowed binary (`ptrace`, `task_for_pid` on unhardened
binaries, `/proc/<pid>/mem`) and act through it. v6 adds this to the threat matrix as **partially
mitigated**:
- The daemon sets `PR_SET_DUMPABLE=0` (Linux).
- Binaries use the hardened runtime without `get-task-allow` (macOS).
- `smith doctor` warns when Yama `ptrace_scope` is 0.
- Attestation verifies code signatures, not just paths.

### 1.7 Pasting secrets into chat stays a residual risk (Gap, now partly closed), M4
Claude Code `UserPromptSubmit` and Cursor `beforeSubmitPrompt` hooks run before the prompt reaches
the model. v6 runs the redactor automaton on submitted prompts and blocks prompts that contain a
known vault secret.

### 1.8 Env-var injection (Mode C) leaks through `/proc/<pid>/environ` and children (Hole, now labelled), M2
v6 keeps Mode C for legacy scripts and labels it **lowest assurance**. Any same-user process and
every child can read the environment. `smith run` says so in `--help` and in `smith doctor`, and
policy can disable Mode C for production environments.

## 2. Bugs in the cryptographic design

### 2.1 The audit key cannot be derived on biometric unlock (Bug), M3/M9
v5 derives the Audit MAC Key from the passphrase master key. A biometric unlock never derives that
key, so the audit chain would halt. v5 also never says how a verifier gets `K_0` without the
attacker being able to recompute it.
**v6:**
- `K_0 = HKDF(recovery_seed, "locksmith-v6-audit-root")` is computed once at vault creation, and
  then `K_1` is stored wrapped under the vault key (VK).
- The daemon only ever holds the current `K_i`.
- Full-chain verification (`smith audit verify --full`) needs the 24-word recovery phrase, which
  is offline by design.
- Day-to-day verification checks the hash chain and the external anchors.

### 2.2 The SQLCipher key is unspecified (Bug), M1
v6 sets `db_key = HKDF(VK, "locksmith-v6-sqlcipher")`. Page encryption hides metadata such as key
names, project names and audit rows. Per-secret envelope encryption stays, so one decrypted page
cannot expose other secrets and AAD binding keeps working.

### 2.3 The DEK revision counter (Simplify), M1
v5 caps each DEK at 2^16 revisions and then forces rotation. **v6:** every new secret version gets
a fresh random DEK. That removes nonce-reuse risk per key, the counter, and the forced-rotation
code path.

### 2.4 Noise protocol over a local socket (Simplify), M3
Kernel peer credentials, plus a socket inside a `0700` directory, already authenticate both ends.
Noise adds key management and no protection against a same-UID attacker. v6 drops it.

### 2.5 AAD binds mutable names (Bug), M1
v5 puts the canonical key name into the payload AAD. Renaming a key, or moving a secret between
environments, would make the old ciphertext fail to decrypt. **v6:** AAD binds immutable IDs only:
secret UUID, environment UUID, version and purpose. Names are mutable metadata.

## 3. Platform realism

| v5 claim | Reality | v6 decision |
|---|---|---|
| macOS "Mach audit session" contains the agent tree | It is an auditing primitive, not containment | Process group + `kqueue` `NOTE_EXIT`/`NOTE_FORK` tracking. Optional Seatbelt profile when the agent itself does not sandbox (M8) |
| Linux cgroup v2 slice per agent | Unprivileged users need systemd user delegation | `systemd-run --user --scope` when available, otherwise process group + `PR_SET_CHILD_SUBREAPER` (M8) |
| Secure Enclave from a CLI daemon | Data-protection keychain access needs a signed binary with entitlements and an embedded provisioning profile | M9 starts with a 2-day spike. Ship the daemon inside an app bundle (`Locksmith.app/Contents/MacOS/locksmithd`) |
| Biometric unlock on every platform | Linux has no Secure Enclave or Windows Hello equivalent | Linux: passphrase, optional TPM2 via `tss-esapi` (M16) |
| mlock sensitive pages | Fine | Kept. `smith doctor` reports the `RLIMIT_MEMLOCK` headroom |
| Redactor carry-over buffer | Holding back `max_len-1` bytes stalls interactive output | Flush the safe prefix after 20 ms idle. Hold back only the bytes that could still start a match. Minimum secret length is 8 (M2) |

## 4. Gaps in the product (v5 has none of these)

| Area | v6 milestone |
|---|---|
| Linux as a first-class platform, plus devcontainers and CI runners | M0 onwards |
| Diagnostics: `smith doctor`, support bundles, structured redacted logs, opt-in telemetry and crash reports | M0 (skeleton), M11 (full) |
| Auto-update delivery: signed TUF repository, channels, staged rollout, kill switch, rollback, daemon hot-swap | M0 (basic), M12 (full) |
| Subscription and licensing: tiers, offline-verifiable licenses, Stripe, entitlements, the never-hostage rule | M13, [product/subscription-plans.md](product/subscription-plans.md) |
| Team features: shared end-to-end encrypted vaults, policy as code, central audit | M15 |
| Import and export (`.env`, 1Password, Doppler, direnv) for adoption | M2 / M14 |
| A usable product every milestone instead of a 14-week waterfall | All |

## 5. Roadmap shape

v5 runs a 14-week phase plan, and the first thing a user can use arrives in Phase 2.
v6 has 17 vertical milestones (see [roadmap.md](roadmap.md)). From **M2** on, a developer can delete
their `.env` files and run their agent through Locksmith. The v5 Phase 0 adversarial gates are kept
and become the executable suite in `tests/adversarial`. Each gate becomes blocking in the milestone
that ships the capability under test.
