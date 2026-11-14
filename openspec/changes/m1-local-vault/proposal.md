# Proposal: M1 Local Vault

## Why

Every later capability needs one place where secrets live encrypted, separate from projects,
repos and agent contexts. v5 §2 specifies an envelope design. v6 keeps it and fixes four defects
(docs/v6-review.md §2.2, §2.3, §2.5, plus the audit-key bug, which is handled in M3).

## What Changes

- Vault creation with a random 256-bit Vault Key (VK) and two wraps: passphrase (Argon2id) and
  recovery phrase (BIP-39, 24 words). The hardware wrap comes in M9.
- SQLCipher database keyed by `HKDF(VK, "locksmith-v6-sqlcipher")`. Schema: `projects`,
  `environments`, `secrets`, `secret_versions`, `vault_wraps`, `meta`.
- Per-version DEKs with AES-256-GCM, and AAD bound to immutable identifiers.
- CLI: `smith vault init|unlock-test|passwd|recover`, `smith project add|ls|rm`,
  `smith env add|ls`, `smith add|ls|rm|history|reveal`, `smith export`.
- Secret values are never accepted from argv: only a no-echo TTY prompt, stdin, or a file.
- Doctor checks: `vault.present`, `vault.perms`, `vault.kdf_params`, `vault.wraps`.

## Usable outcome

A developer moves their secrets out of `.env` files into an encrypted vault. They can list them,
rotate values with history, export them back out, and restore the vault from 24 words on a new
machine.

## Capabilities

### New Capabilities
- `vault-crypto`: Key hierarchy, wraps, AEAD and AAD binding rules.
- `vault-storage`: Encrypted persistence, schema versioning and integrity.
- `vault-recovery`: Recovery phrase generation, restore and passphrase change.
- `secret-management`: User-facing secret, project and environment CRUD and export.

### Modified Capabilities

## Out of scope

- Using secrets in commands (M2).
- The daemon and sessions (M3). In M1 every command that decrypts prompts for the passphrase.
- Biometric unlock and VK rotation (M9).

## Impact

Crates `ls-crypto`, `ls-vault`, `smith-cli`. Dependencies: `argon2`, `hkdf`, `sha2`, `aes-gcm`,
`rand_core` (OsRng), `secrecy`, `zeroize`, `bip39`, `rusqlite` (`bundled-sqlcipher-vendored-openssl`
is rejected because `cargo-deny` bans openssl. Use the `bundled-sqlcipher` feature with the
CommonCrypto backend on macOS and LibTomCrypt on Linux. See design D5).
