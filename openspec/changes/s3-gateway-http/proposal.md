# Proposal: S3 gateway HTTP relay

## Why
S2 stores values the control plane cannot read. Nothing can use them yet. S3 adds the gateway: the only process that unwraps a data key and decrypts a value, and it uses the value only to make one authenticated HTTP call on behalf of a caller that never sees it. This is the product's core promise (roadmap "Product", A0-10).

## What Changes
- New service `services/gateway` (axum): `POST /v1/relay` takes a secret reference plus an upstream request (method, URL, headers, body) and returns the upstream response. The gateway fetches ciphertext and the wrapped DEK from the control plane, unwraps the DEK in OpenBao transit with the gateway credential, decrypts, injects the value into the configured header, calls the upstream, redacts every encoding of the value from the response, then zeroizes.
- Binding rules (in gateway config for S3): per secret, the allowed upstream hosts and the header template (for example `Authorization: Bearer {secret}`). A request to a host that is not allowed is refused before any decrypt. The existing `ls-proxy` network guard (no loopback, link-local or private targets unless the mock upstream is explicitly allowed) is reused.
- Response redaction with `ls-redact` (plain, base64, URL, hex encodings, streaming-safe) on body and headers; the caller can never learn the value from the response, including echoed headers.
- Control-plane internal endpoint `GET /internal/v1/secrets/{id}/versions/{n}/material` returning ciphertext, wrapped DEK and `key_id` only, behind a service token. It never returns plaintext.
- Audit record per relay call (secret id, version, caller, upstream host, status, outcome, no value) appended to a `gateway_audit` table. S5 replaces this with the hash chain.
- A short-lived DEK cache (A0-10): bounded TTL, zeroized on eviction.
- Smoke test in `just up`: the mock upstream (F0) receives the secret; the caller response, gateway logs, traces and Postgres hold no canary.

## Capabilities

### New Capabilities
- `gateway-http-relay`: authenticated HTTP relay that decrypts inside the gateway, injects the credential, redacts the response and audits the call.

### Modified Capabilities
None. The control-plane internal endpoint is part of the new capability; no S1/S2 requirement changes.

## Out of scope
- Agent identity and short-lived tokens (S4): S3 callers present one static gateway caller token from config.
- Policy engine and per-agent grants (T2), the hash-chained audit (S5), the adversarial suite (S6).
- Non-HTTP relays: git (D1), AWS STS (D2), database (D3). MITM or explicit-proxy mode (`ls-proxy` CONNECT path).
- AWS KMS (P1); gateway key rotation.

## Depends on
S2 (`s2-envelope-crypto`, archived): `ls-envelope`, `KeyWrapper`, `secret_versions`, OpenBao permission split. F0 (mock upstream, OTel stack), F1 (`just leak-scan`). Decisions A0-7, A0-10, A0-14.

## Impact
- New: `services/gateway`, migration `gateway_audit`, compose entries (gateway service, OpenBao token for the gateway), `tests/e2e` relay test.
- Changed: `services/control-plane` (internal material endpoint, service token), `crates/ls-proxy` (expose the network guard and header-injection helpers as a library API if not already public), `openapi.json`.
- Dependencies: `ls-envelope`, `ls-redact`, `ls-proxy` (workspace); `reqwest` already in the lockfile for the upstream call.
