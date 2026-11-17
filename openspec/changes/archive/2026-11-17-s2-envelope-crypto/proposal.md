# Proposal: S2 envelope crypto

## Why
S1 stores secret metadata only. The product promise is that the control plane stores ciphertext and cannot read it; values are decrypted only inside a gateway (A0-10, roadmap "Product"). S2 adds secret values and the key hierarchy that makes that promise true, before the gateway (S3) exists to use it.

## What Changes
- Secret versions: `secret_versions` table (S1 deliberately left it out), with the ciphertext blob in the A0-7 header format, the wrapped data key, the gateway key id and a version number. `version_count` becomes real.
- Per-version envelope encryption: a fresh random DEK encrypts each value (AES-256-GCM, AAD = `org_id ‖ secret_id ‖ version ‖ purpose`); the DEK is wrapped to a **gateway key** held in a KMS. Locally the KMS is OpenBao transit; behind a `KeyWrapper` trait so AWS KMS can follow in P1 (A0-10, A0-14).
- Write path: a client submits a value, the control plane generates the DEK, encrypts, asks the KMS to wrap the DEK for the gateway key, stores ciphertext plus wrapped DEK, and zeroizes the plaintext and DEK. Read APIs never return a value.
- Decrypt-fails-in-control-plane: the control-plane process holds only the KMS *encrypt-side* permission for the gateway key (OpenBao policy allows `encrypt`, denies `decrypt`). A test proves that decrypt through the control plane's credential is refused.
- A `ls-envelope` library crate (reusing `ls-crypto`) with `seal_version` / `open_version`, the header codec promoted from `a0-spikes`, and known-answer tests.
- Leak checks: `just leak-scan` over Postgres, logs and traces after writing canary values.

## Capabilities

### New Capabilities
- `envelope-encryption`: per-version DEKs, KMS-wrapped to a gateway key, the versioned header, AAD binding, and the control plane's inability to decrypt.

### Modified Capabilities
- `control-plane-api` (from S1): adds write-only value submission and real `version_count`.

## Out of scope
- Gateway, unwrap and injection (S3). Agent identity and tokens (S4). Audit records (S5).
- AWS KMS and cloud deployment (P1). Key rotation of the gateway key beyond storing `key_id` (rewrap tooling is a later change).
- Client-side encryption in the console (T3).
- Reading or revealing a value over any API.

## Depends on
S1 (`s1-control-plane-skeleton`): service, schema and tenant transaction helper. A0 decisions A0-7, A0-10, A0-14 in `openspec/decisions.md`. F1 for `just leak-scan`.

## Impact
- New: `crates/ls-envelope`, `services/control-plane` migration `secret_versions`, OpenBao transit setup in `infra/compose`, `tests/e2e` leak test.
- Changed: `crates/a0-spikes` header code becomes a dependency-free re-export or is removed after promotion; `services/control-plane/openapi.json`.
- Dependencies: reuses `ls-crypto` (aes-gcm, zeroize); an HTTP client for OpenBao transit (`reqwest`, rustls).
