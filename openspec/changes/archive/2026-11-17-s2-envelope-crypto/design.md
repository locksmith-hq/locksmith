# Design: S2 envelope crypto

## Context
- S1 (in review, PR #106) provides the service, tenant transaction helper and `secrets` metadata with `version_count = 0`; it left `secret_versions` to S2.
- `ls-crypto` already has `SecretKey32`/`SecretBytes` (zeroize, no Debug/Display/Clone), `aead::{seal,open,Aad}` (AES-256-GCM) and DEK wrapping used by the desktop vault.
- `crates/a0-spikes/src/header.rs` proves the A0-7 header with property tests.
- F0 compose runs `openbao/openbao:2.7.2` in dev mode with the transit engine enabled.
- Binding decisions: A0-6, A0-7, A0-10, A0-14.

## Goals / Non-Goals
**Goals:** a stored value is unreadable to the control plane, database and logs; a KMS abstraction S3 and P1 can reuse; test vectors that pin the format.
**Non-Goals:** gateway unwrap path (S3), rotation tooling, client-side encryption, AWS KMS.

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **New crate `crates/ls-envelope`** with `seal_version`/`open_version`, the promoted header codec and a `KeyWrapper` trait. | Putting crypto in the service (S3 gateway must share it); extending `ls-crypto` (keeps it dependency-light for the desktop) | AGENTS.md: Rust for anything touching secrets; `a0-spikes` header |
| 2 | **AES-256-GCM, random 96-bit nonce, DEK per version.** One encryption per DEK keeps the random-nonce collision bound irrelevant. | XChaCha20-Poly1305 (header `alg_id` allows adding it later); a DEK per secret (a leaked DEK exposes every version) | NIST SP 800-38D; `a0-spikes` header_props tests |
| 3 | **`KeyWrapper` trait with an OpenBao transit implementation.** The wrapped DEK is stored in the A0-7 `dek-wrap` format around the transit ciphertext. `key_id` is the transit key name plus version. | Calling OpenBao inline (blocks AWS KMS later); a local file key (hides the permission split S2 must prove) | A0-10, A0-14; OpenBao transit docs (`encrypt`/`decrypt` endpoints, policy paths) |
| 4 | **Permission split.** The control plane's OpenBao token has a policy granting `update` on `transit/encrypt/gateway` only. A separate gateway test token holds `decrypt`. | One token for both (the "cannot decrypt" claim would be untestable) | OpenBao policy docs |
| 5 | **Plaintext handling:** the request body value is read into `SecretBytes` at the extractor, never into `String`/`serde_json::Value` that is logged; the body limit and `RedactInternal` telemetry from S1 apply; DTOs have no `Debug`. | Deserializing into a normal struct (derives Debug, risk of logging) | AGENTS.md security rules |
| 6 | **Schema `secret_versions`:** `org_id`, `secret_id`, `version` (int, unique per secret), `ciphertext bytea`, `wrapped_dek bytea`, `key_id text`, `created_at`; composite FK `(org_id, secret_id)`, RLS as in S1, no UPDATE grant to the app role (append-only versions). | Mutable current-value column (loses history, weakens AAD version binding) | A0-4, A0-7; S1 design decision 6 |
| 7 | **Honest label:** this is *containment* (a compromised control plane or DB dump yields ciphertext), not prevention against a compromised gateway. | Overclaiming | `openspec/config.yaml` rule on honest labels |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| aes-gcm (via ls-crypto; direct dev-dependency for the fixed-nonce KAT only) | MIT/Apache-2.0 | 0.10.3 | 2023-09-21 (0.11.1 exists; kept at ls-crypto's 0.10) | AEAD | not AGPL |
| zeroize (via ls-crypto `SecretKey32`/`SecretBytes`); secrecy not needed | MIT/Apache-2.0 | 1.9.1 | 2026-10-06 | secret types | not AGPL |
| reqwest (`rustls-no-provider`, no default features) | MIT/Apache-2.0 | 0.13.5 | 2026-09-08 | OpenBao transit HTTP client (already in the lockfile via opentelemetry-otlp) | not AGPL |
| rustls (`ring` provider) + ring | Apache-2.0/MIT/ISC; ring Apache-2.0 AND ISC | 0.23.46; ring 0.17.14 | 2026-10-14; 2025-03-11 | TLS to OpenBao without reqwest's default aws-lc-rs (no C/cmake build); both already in the lockfile | not AGPL |
| rustls-platform-verifier | MIT/Apache-2.0 | 0.7.1 | 2026-09-24 | verify OpenBao's certificate against the OS trust store (the range reqwest 0.13 uses) | not AGPL |
| base64, bytes | MIT/Apache-2.0 | 0.22.1, 1.12.1 | 2024-04-30, 2026-07-08 | transit's base64 fields; `Bytes::from_owner` so the request body is a zeroizing buffer | not AGPL |
| zeroize (direct, `Zeroizing`) | MIT/Apache-2.0 | 1.9.1 | 2026-10-06 | wipe the DEK's base64 form, request body and decrypt response | not AGPL |
| wiremock, tokio (dev only) | MIT/Apache-2.0; MIT | 0.6.5 (workspace), 1.54.1 | 2025-08-24, 2026-10-21 | in-process fake of the transit API for unit tests (no live OpenBao) | not AGPL |
| OpenBao (service) | MPL-2.0 | 2.7.2 | in compose | KMS stand-in | not AGPL |
| proptest | MIT/Apache-2.0 | 1.12.0 (workspace) | 2026-10-10 | header properties | not AGPL |
| getrandom | MIT/Apache-2.0 | 0.2.17 | 2026-01-11 | random DEK id (same version as ls-crypto) | not AGPL |
| hex, serde_json, trybuild (dev only) | MIT/Apache-2.0 | 0.4.3, 1.0.154, 1.0.122 | 2021-03-03, 2026-10-11, 2026-10-07 | KAT vector file, no-Debug/Clone compile-fail tests | not AGPL |

The implementer records exact versions and release dates from `Cargo.lock` / crates.io here.

## Built in-house
- Header codec and envelope sealing (about 300 lines, promoted from the A0 spike): no maintained crate implements this Locksmith-specific format. Searched crates.io for "envelope encryption" and found AWS-SDK-bound or unmaintained crates. The primitives come from audited RustCrypto crates.
- The OpenBao transit client (a few endpoints); `vaultrs` was found but pulls a large dependency tree. The implementer re-checks it and reuses it if the footprint is acceptable.
  - Re-checked for task 2.1: `vaultrs` 0.8.0 (MIT) was rejected. Its `VaultClientSettings` derives `Debug` and `Clone` over `token: String`, transit `encrypt` takes the plaintext as a `String`, and it adds `rustify`, `derive_builder`, `async-trait` and `tracing`. The thin client in `src/openbao.rs` covers `transit/encrypt` and `transit/decrypt` only, holds the token in a zeroizing `BaoToken` and sends it as a sensitive header.
  - Transit format, checked against `openbao/openbao:2.7.2` in dev mode: an `aes256-gcm96` ciphertext is `vault:v{N}:` then base64 of `nonce(12) ‖ ct ‖ tag(16)` (60 bytes for a DEK); `associated_data` is authenticated (a mismatch returns 400); `key_version` pins the encryption version; a bad token returns 403. The wrapped DEK is the 20-byte `dek-wrap` header (`key_id` = key name zero-padded to 12 bytes ‖ version u32 BE, stored as text `gateway:v1`) followed by those 60 bytes; the A0-7 AAD goes to transit as `associated_data`. Wrap pins `key_version` because the version is in the authenticated header, so it must be known before encrypting.

## How an agent debugs this
- `just up` starts Postgres, OpenBao and Grafana; `just harness-check` confirms them.
- Postgres MCP (`.mcp.json`): inspect `secret_versions` (only `bytea` ciphertext should appear).
- `bao` CLI in the container for `transit/keys/gateway` and policy checks.
- Tempo and Loki through Grafana: spans carry secret ids and version numbers, never values.
- `just canary new` then `just leak-scan` proves no leak.

## Risks / Trade-offs
- Random-nonce AES-GCM is safe at one use per DEK; if a later design reuses DEKs, revisit.
- The control plane is trusted with plaintext in memory during a write (before client-side encryption in T3). Mitigated by zeroize and no logging; documented as a known limit.
- OpenBao dev mode is in-memory: keys vanish on restart, so tests create the key idempotently.

## Open questions
- None blocking; the AWS KMS mapping of `key_id` is decided in P1.
