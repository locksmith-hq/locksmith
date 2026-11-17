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
| aes-gcm (via ls-crypto) | MIT/Apache-2.0 | 0.10 | implementer records | AEAD | not AGPL |
| zeroize, secrecy | MIT/Apache-2.0 | implementer records | | secret types | not AGPL |
| reqwest (rustls) | MIT/Apache-2.0 | implementer records | | OpenBao HTTP client | not AGPL |
| OpenBao (service) | MPL-2.0 | 2.7.2 | in compose | KMS stand-in | not AGPL |
| proptest | MIT/Apache-2.0 | workspace | | header properties | not AGPL |

The implementer records exact versions and release dates from `Cargo.lock` / crates.io here.

## Built in-house
- Header codec and envelope sealing (about 300 lines, promoted from the A0 spike): no maintained crate implements this Locksmith-specific format. Searched crates.io for "envelope encryption" and found AWS-SDK-bound or unmaintained crates. The primitives come from audited RustCrypto crates.
- The OpenBao transit client (a few endpoints); `vaultrs` was found but pulls a large dependency tree. The implementer re-checks it and reuses it if the footprint is acceptable.

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
