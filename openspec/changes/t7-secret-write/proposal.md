# Proposal: T7 add a secret or a new version from the browser

## Why
The console (T3) lists secret names and versions but cannot create a value. Today a client posts the plaintext value over TLS and the control plane seals it. Decision H1-1 says a value is sealed in the browser before it is sent, so the control plane never sees it, even in memory: a compromised control plane then cannot read values it stores or captures.

## What Changes
- **Seal keys.** Each environment gets an HPKE key pair. The gateway generates it and keeps the private half wrapped by the KMS (only the gateway credential can unwrap); the control plane stores and publishes the public half.
- **Sealed write.** A new version format: the browser makes a random DEK, seals the value with AES-256-GCM under the existing binding (`org ‖ secret ‖ version ‖ purpose`), and wraps the DEK to the environment's public key with HPKE. The API accepts only these two blobs.
- **WebAssembly sealing.** The browser seals with `ls-envelope` compiled to WebAssembly, the only implementation (new `crates/ls-seal-wasm`, packaged in `packages/seal`).
- **Gateway.** Decrypt accepts the new wrapped-DEK format next to the KMS-wrapped one.
- **API.** `GET .../seal-key` returns the public key, its id and the next version number; version create takes ciphertext only. The plaintext `value` field is removed for all clients (CLI, MCP, desktop, SDK move to sealing through `ls-envelope`).
- **Console and desktop.** An "Add secret" and "Add version" form on the secret pages; the value never leaves the form unsealed, is never shown again, and is cleared on submit.

## Capabilities
### New Capabilities
- `secret-write-console`: adding a secret or a version from the console and desktop, the seal-key lifecycle, and the guarantees on what the browser does with the value.

### Modified Capabilities
- `envelope-encryption`: "Values are write-only through the API" becomes "the API accepts only ciphertext"; "DEK wrapped to a gateway key in a KMS" gains the HPKE-wrapped DEK format; "The control plane cannot decrypt" extends to "cannot see a value".

## Impact
`crates/ls-envelope` (HPKE wrap, new alg id), `crates/ls-seal-wasm` and `packages/seal` (new), `services/control-plane` (migration, seal-key routes, version create, OpenAPI), `services/gateway` (decrypt, key provisioning), `crates/smith-cli`, `crates/ls-mcp-server`, `crates/ls-vault`, `packages/sdk`, `packages/control-plane-client`, `apps/web`, `apps/desktop`, `tests/adversarial`, `tests/e2e`.

## Out of scope
Editing or viewing a stored value in the console (never), bulk import, secret rotation, per-secret sharing keys, rotating an environment's seal key beyond the lifecycle in design.md decision 5, hardware-key or passkey-gated sealing.

## Depends on
`t3-console-mvp` (routed shell, secret pages, shared client). Needs `d3-db-relay`/gateway decrypt only as already merged.
