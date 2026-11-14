# Design: M1 Local Vault

## Context
v5 §2 and §8 are the baseline. Deviations are listed under Decisions.

## Goals / Non-Goals
**Goals:** a correct, tested key hierarchy that M3, M9 and M15 extend without a data migration.
**Non-Goals:** performance tuning beyond "unlock < 1 s on a 2020 laptop".

## Decisions

### D1. Key ladder (v6)
```
passphrase --Argon2id(m=64MiB,t=3,p=4,salt32)--> MK --HKDF info "locksmith-v6-passphrase-wrap"--> PWK
recovery words --BIP39 PBKDF2--> seed512 --HKDF "locksmith-v6-recovery-wrap"--> RWK
                                        \--HKDF "locksmith-v6-audit-root"--> AuditK0 (used once, M3)
VK (random 32B) wrapped by PWK, RWK (and HWK in M9)            -> vault_wraps rows
db_key   = HKDF(VK, "locksmith-v6-sqlcipher")                  -> SQLCipher raw key (PRAGMA key = "x'..'")
DEK_v    = random 32B per secret version, wrapped by VK         -> secret_versions.encrypted_dek
payload  = AES-256-GCM(DEK_v, value, AAD_payload)
```
v5 derived the Audit MAC Key from MK, which fails on biometric unlock. v6 moves the audit root to the
recovery seed (docs/v6-review.md §2.1).
Argon2 parameters are stored per wrap (`kdf_params` JSON), so they can be raised later without a
format change. `smith vault passwd --kdf-memory 256MiB` re-wraps with the new parameters.

### D2. Chicken-and-egg: SQLCipher key vs wraps
The wraps must be readable before the DB is decrypted. So the wraps live in a small sidecar file
`vault.header` (CBOR, versioned, with an HMAC-SHA256 under a key derived from VK so tampering is
detected after unlock), next to `vault.db`. v5 put `vault_wraps` inside the encrypted DB, which cannot
work.

### D3. AAD (canonical, length-prefixed: u16 len + bytes per field)
- DEK wrap: `"v6" | "dek-wrap" | secret_id | version_id | vk_version`
- Payload: `"v6" | "payload" | secret_id | version_id | environment_id`
Names are mutable metadata outside the AAD, so rename is free. A move between environments is an
explicit re-encrypt that creates a new version.

### D4. Value ingress and egress
Values come in only through a no-echo TTY prompt (`rpassword`), `--stdin`, or `--from-file`, never
argv, because shell history and `ps` would leak them. `reveal` requires all of: an interactive TTY on
stdin and stdout, fresh passphrase entry (no cached unlock), and no agent detected
(`CLAUDECODE`, `CURSOR_TRACE_ID`, `CODEX_*` env and parent-process heuristics). Default output is
the clipboard with a 30 s clear. `--print` shows the value on the TTY instead.
`export` is the never-hostage escape hatch. It writes a 0600 file and refuses to write to stdout
when stdout is not a TTY.

### D5. SQLCipher build
`rusqlite` with `bundled-sqlcipher` and a non-OpenSSL crypto provider. If that proves brittle on
musl, fallback plan: drop SQLCipher, keep plain SQLite with every metadata column AEAD-encrypted, and
an HMAC'd blind index for `key_name` lookup. The decision is made in task 1.1 after a 1-day spike and
recorded here.

### D6. Memory hygiene
Every key and plaintext type wraps `secrecy::SecretBox<[u8; 32]>` or `SecretString`, implements
`ZeroizeOnDrop` and has no `Debug`. mlock is best-effort through `region` (or `memsec`). Core dumps
are disabled with `setrlimit(RLIMIT_CORE, 0)`, plus `PR_SET_DUMPABLE=0` on Linux. A `#[deny]`
clippy lint stops `Debug` derives on types in `ls-crypto::secret`.

## Risks / Trade-offs
- Argon2 at 64 MiB on low-RAM CI runners is fine, but tests use a `test-kdf` feature with tiny
  parameters behind `cfg(test)` only.
- Losing both the passphrase and the recovery phrase means the data is gone. This is stated clearly
  at init, and init refuses to finish until the user re-types 3 random words of the phrase.
