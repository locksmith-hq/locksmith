# Research: sealing a secret to the environment key in the browser (t7 task 1.1)

Checked 2026-11-22 against the crates.io API and a throwaway wasm32 build (not committed). Feeds `openspec/changes/t7-secret-write/design.md` decisions 1, 2 and 4.

## Versions and licences
| Crate | Version | Released | Licence | Notes |
|---|---|---|---|---|
| `hpke` (rust-hpke) | 0.15.1 | 2026-10-28 | MIT/Apache-2.0 | RFC 9180; features `x25519`, `aes`, `hkdfsha2`, `alloc`, `getrandom`; no C |
| `wasm-bindgen` | 0.2.130 | 2026-10-30 | MIT OR Apache-2.0 | JS glue for `ls-seal-wasm` |
| `getrandom` | 0.4.3 (already in `Cargo.lock`) | 2026-06-17 | MIT OR Apache-2.0 | feature `wasm_js` for the browser CSPRNG |

All permissive, so usable in the server, the CLI and the wasm package (no AGPL concern).

## wasm32 build of `hpke`
- `hpke` 0.15.1 depends on `getrandom ^0.4` (feature `sys_rng`), **not 0.2**. Design said "`getrandom` js feature (0.2)"; the right switch is `getrandom` 0.4 with feature `wasm_js` (it pulls `wasm-bindgen` and `js-sys`).
- A scratch crate with `hpke = { version = "=0.15.1", default-features = false, features = ["alloc","x25519","aes"] }` and `getrandom = { version = "0.4", features = ["wasm_js"] }` compiled for `wasm32-unknown-unknown` on this VM, not committed (`hpke`, `x25519-dalek`, `wasm-bindgen` all built).
- Use `default-features = false`: the default set pulls `mlkem` and `chacha`, which the format does not need and which grow the wasm.
- The workspace still pins `getrandom 0.2` (`ls-envelope` and others); if `ls-seal-wasm` depends on `ls-envelope`, wasm32 also needs the 0.2 `js` feature next to 0.4 `wasm_js`. Carry into 1.2 and 3.1.
- Still to confirm in task 3.1: whether the build also needs `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`, and the final wasm size.

## Holding and using the private key
- **OpenBao transit:** encrypt and decrypt of arbitrary bytes with a named key (`aes256-gcm96`); the private key (32 bytes) is wrapped with `transit/encrypt`, unwrapped with `transit/decrypt` using the gateway-only credential. The control plane's credential stays wrap-only (existing `kms.rs` split), and holds no private half.
- **AWS KMS:** `Encrypt`/`Decrypt` accept up to 4096 bytes, enough for the 32-byte key. `DeriveSharedSecret` supports only NIST ECC curves and SM2, not X25519, so it cannot replace gateway-side decapsulation. That confirms design decision 2 (gateway generates the pair, KMS wraps the private half through the existing wrapper trait, same behaviour locally and in AWS).

## Pinning source for the gateway verifying key (design Risks)
Proposal for task 2.6 and 3.3: the Ed25519 verifying key is (a) compiled into the CLI, desktop and `packages/seal` at release time for the hosted service, and (b) set by operator config (`LS_GATEWAY_VERIFYING_KEY`) for self-hosters; clients never accept it from the control plane response.

## Not verified
Release dates and licences come from crates.io metadata; the OpenBao and AWS KMS limits are from their published docs as remembered, not fetched (outbound docs hosts are limited from this VM). Re-check in task 2.2 when the wrapper is built.
