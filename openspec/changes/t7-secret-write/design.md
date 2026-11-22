# Design: T7 add a secret or a new version from the browser

## Context
Today `POST .../secrets/{id}/versions` (`services/control-plane/src/api/versions.rs`) reads the value into `SecretBytes`, calls `seal_version` (AES-256-GCM under a fresh DEK, header A0-7), wraps the DEK through `DekWrapper` (OpenBao transit, wrap-only credential) and stores `ciphertext`, `wrapped_dek` (CHECK length 80) and `key_id`. The gateway unwraps with its own credential (`services/gateway/src/decrypt.rs`). `docs/design/hub-technical-design.md` section 3.3 and decision H1-1 set the goal; this change builds it.

## Goals / Non-Goals
**Goals:** the control plane never receives a plaintext value or a plaintext DEK; one sealing implementation (Rust) for server, CLI and browser; unchanged gateway security (only the gateway can unwrap).
**Non-Goals:** viewing a value in the console; rotating keys on a schedule; protecting a value from malicious JavaScript served by a compromised control plane (see Risks).

## Decisions and evidence
| # | Decision | Alternatives rejected | Evidence |
|---|---|---|---|
| 1 | **Two-layer seal.** Browser: DEK random, `seal_version` payload (existing A0-7 format, purpose `secret-payload`), then HPKE base mode (RFC 9180, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the environment public key, with `info` = org ‖ secret ‖ version ‖ `dek-wrap` and the A0-7 header as AAD. The stored `wrapped_dek` carries a new `alg_id` for it; the DEK's wrapped form is `enc(32) ‖ ct(32) ‖ tag(16)` plus header. | Encrypting the whole value with HPKE: hybrid already is the HPKE design and reuses the payload format and gateway path. | RFC 9180; hub design 3.3; `ls-envelope` header and `Binding`. |
| 2 | **Private key in the KMS, gateway-generated.** The gateway generates the X25519 pair, wraps the private key with the KMS (OpenBao transit now, AWS KMS later, behind the existing wrapper trait) and posts the public key and the wrapped private key to the control plane over `/internal/v1`. The control plane never holds the private half, even briefly, which is the point of H1-1. On a version read the gateway unwraps the private key into zeroizing memory for one TTL and decapsulates. **The gateway signs `(org, environment, key_id, public key)` with its gateway identity key (Ed25519); the seal-key response carries the signature and every client pins the gateway's verifying key and checks the signature before sealing, so a compromised control plane cannot substitute its own key.** | Unsigned public key from the control plane (key substitution). Control plane generates and wraps (it would see the private key and could read ciphertext it stores: defeats H1-1). KMS-native ECDH (`DeriveSharedSecret`): AWS KMS only, not OpenBao, would split local and cloud behaviour. | `ls-envelope::wrap`, `kms.rs` (wrap-only credential); AWS KMS `DeriveSharedSecret` and OpenBao transit docs, checked in task 1.1. |
| 3 | **Version binding is known before sealing.** The version number is part of the AAD, so `GET .../seal-key` returns `next_version` for that secret. The write sends `version`; the server accepts it only if it is the secret's next version (else `409`, the form refetches and reseals once). | Server assigns the version after sealing: breaks the AEAD binding. | `Binding` in `crates/ls-envelope/src/header.rs`; `secret_versions` primary key `(org_id, secret_id, version)`. |
| 4 | **WebAssembly from the same crate.** New `crates/ls-seal-wasm` exports one function (seal value to key, returning two byte arrays) over `ls-envelope` with `wasm-bindgen`, built by `wasm-pack` or `cargo build --target wasm32-unknown-unknown` plus `wasm-bindgen`, packaged as `packages/seal`. The HPKE crate and its RNG must work on wasm32 (`getrandom` js feature). A known-answer vector shared by native and wasm tests proves they match. | A JavaScript HPKE library (`@hpke/core`) or WebCrypto: a second implementation of the format, against the "Rust for anything that touches secrets" rule. | hub design 3.3; AGENTS.md security rules; `docs/research/oss-building-blocks.md` row "Seal to public key". |
| 5 | **Seal key lifecycle.** One active key per environment, created when the environment is created or on first `seal-key` request (status `pending` until the gateway posts it, `503` retry-after meanwhile). Rotation adds a new active key; old keys stay `retired` so existing versions still open; the key id is stored on each version. | Rotate by re-encrypting: needs plaintext access. | `secret_versions.key_id` already stores the wrapping key. |
| 6 | **Plaintext route removed, not kept.** H1-1 says the API accepts only ciphertext; leaving the plaintext route would keep the control plane in the trust path. The CLI, MCP, SDK and desktop use the same sealing code (native `ls-envelope` call) against the same sealed route. | Keep both routes: weaker than H1-1 and doubles the test surface. | Decision H1-1. |
| 7 | **No secret in the page except while typing.** The form keeps the value in a single input, passes it directly to the wasm call, clears the input and the wasm buffers after the call, uses `autocomplete=off`, no persistence, no logging, and `Content-Security-Policy` blocks inline script and third-party origins. | Persisting drafts: a stored plaintext. | OWASP password-field guidance; AGENTS.md security rules. |

## OSS used
| Package | Licence | Version | Last release | Why | AGPL check |
|---|---|---|---|---|---|
| `hpke` (rust-hpke) | MIT/Apache-2.0 (verify at task 1.1) | 0.15.1 per `docs/research/oss-building-blocks.md` | 2026-10-28 | RFC 9180 HPKE with X25519 and AES-GCM; maintained; no C | permissive, usable in server and in the WASM build; not in SDKs under AGPL |
| `wasm-bindgen` | MIT/Apache-2.0 | confirm at task 1.1 | confirm | glue between the Rust crate and JavaScript | permissive |
| `getrandom` (js feature) | MIT/Apache-2.0 | already in the workspace (0.2) | existing | browser CSPRNG for wasm32 | permissive |

Built in-house: only the thin `ls-seal-wasm` wrapper and the seal-key lifecycle. Searched first: a JavaScript HPKE library (`@hpke/core`) and WebCrypto were rejected under decision 4.

## How an agent debugs this
`just up`, `just api`, `just gateway`. Tables: `environment_seal_keys` and `secret_versions` (Postgres MCP; `ciphertext`, `wrapped_dek`, `key_id` are bytes, never values). Ledger: `GET /v1/audit/events` for `secret.version.created` and `seal_key.provisioned`, then `just audit-verify`. `just leak-scan` over Postgres, Loki and Tempo with a canary. Gateway and control-plane spans and logs through the Grafana MCP. The wasm package: `npm test --workspace packages/seal`.

## Risks / Trade-offs
- **Malicious page script.** The browser is only as trustworthy as the JavaScript the control plane serves; a compromised control plane could serve code that exfiltrates the value. Sealing protects stored data and the control plane's memory, not this case. Mitigations: CSP, subresource integrity for the wasm, the hub served from a separate static origin. Label this containment, not prevention.
- **Gateway verifying key distribution.** Clients must obtain the gateway's verifying key out of band from the control plane (bundled in the CLI, desktop and wasm package build, or configured by the operator); if it is not pinned, key substitution by a compromised control plane is not prevented. Task 1.1 settles the pinning source.
- **Gateway availability** gates the first write to a new environment (key provisioning); the form shows "preparing the key" and retries.
- **WASM size and startup** (a few hundred KB): loaded lazily on the form.
- **Format change.** Existing versions keep their KMS-wrapped format; the gateway opens both by `alg_id`.

## Migration Plan
Additive migration (`environment_seal_keys`; `secret_versions.wrapped_dek` length check relaxed to the two formats; `alg_id` read from the header). Deploy gateway first (reads both formats), then control plane (sealed route and key routes), then clients. Existing environments get a key on first request. Rollback: the sealed route can be disabled; stored rows remain readable.
