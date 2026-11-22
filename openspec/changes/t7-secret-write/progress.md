# Progress: T7 secret write

Append-only session log. Read the last entries and `git log` before starting.

## 2026-11-22 worker (alfie)
- Task: none - planning
- Verified: `openspec validate t7-secret-write --strict`
- Notes for next session: design decision 2 (gateway generates the HPKE key, private half only KMS-wrapped) is the part to confirm first, in task 1.1's research note; the plaintext `value` route is removed (decision 6), so CLI/MCP/SDK callers move in task 3.2. Task 1.1 must record the `hpke` licence and wasm32 build before anything depends on it.

## 2026-11-22 worker
- Task: planning PR review fixes - done
- Verified: openspec validate t7-secret-write -> valid
- Notes for next session: gateway signs seal key (design decision 2, spec requirement); task 1.1 settles pinning source for the gateway verifying key.

- 2026-11-22 · worker alfie: review FAIL on #591 (signature requirement had no tasks). Added 1.4 (contract), 2.6 (gateway identity key and signing), 3.3 (client pinning and verification) with substituted-key refusal tests; e2e task 5.1 covers it too. `openspec validate` OK.

## 2026-11-22 worker
- Task: review-fix on #591 - done
- Verified: openspec validate t7-secret-write -> valid
- Notes for next session: replaced REMOVED "Values are write-only" with MODIFIED keeping no-leak and cross-org rules; awaiting re-review.

## 2026-11-22 worker alfie
- Task: 1.1 research note - done
- Verified: `bash scripts/public-check.sh`, `openspec validate t7-secret-write --strict`; evaluator PASS
- Notes for next session: hpke 0.15.1 needs getrandom 0.4 (`wasm_js`), workspace crates still on 0.2 (`js`): settle in 1.2/3.1. Pinning source proposed in the note (compiled-in key, or `LS_GATEWAY_VERIFYING_KEY`). Next: 1.2 (HPKE DEK format in ls-envelope) is [opus].

## 2026-11-22 worker alfie
- Task: 1.2 HPKE-wrapped DEK format - done
- Verified: `cargo nextest run -p ls-envelope` (56 pass, 13 hpke), clippy/fmt clean, cargo deny ok; Opus evaluator PASS; KATs from an independent RFC 9180 implementation
- Notes for next session: alg_id 2, 100-byte form; hpke built without its getrandom feature (seed via getrandom 0.2 `SecretKey32::random`), so wasm32 (3.1) needs the 0.2 `js` feature only. Next: 1.3 (OpenAPI and mock data, sonnet-sized), then 1.4.

## 2026-11-22 worker alfie
- Task: 1.3 seal-key and sealed version contract - done
- Verified: `cargo nextest run -p ls-control-plane openapi`, `npm test --workspace packages/control-plane-client` (15 pass), `just quick`; Sonnet evaluator PASS
- Notes for next session: sealed create is on `POST .../secrets/{id}/sealed-versions` (old `/versions` stays until 2.3 removes it; then move the route). `seal-key` takes an optional `secret_id` query for per-secret `next_version`. Handlers are 503 stubs with `#[allow(dead_code)]`, remove in 2.3; 503 should set `Retry-After`. Next: 1.4 (signature fields and KATs).

## 2026-11-22 10:20 worker
- Task: CI fix - ci-fix (cargo-deny failed on RUSTSEC-2026-0592, url 2.5.8)
- Verified: cargo deny check -> ok; cargo check --workspace -> ok; just quick -> ok
- Notes for next session: bumped url to 2.5.9 in Cargo.lock only; main will hit the same advisory until it merges a bump.

## 2026-11-22 worker alfie
- Task: 1.4 seal-key signature contract and KATs - done
- Verified: `cargo nextest run -p ls-control-plane openapi`, `cargo nextest run -p ls-envelope seal_key_sig` (3 vectors from an independent pyca Ed25519 script, substituted-key refusal), `npm test --workspace packages/control-plane-client`, `just quick`; Sonnet evaluator PASS
- Notes for next session: `ls-envelope` only verifies (`verify_seal_key`, `seal_key_message`); signing is the gateway's (2.6). SealKey now has `signature` and `signing_key_id`. Next: 2.1 migration, then 2.2.

## 2026-11-22 12:29 worker
- Task: CI fix (hygiene/gitleaks on seal-key KAT vectors) - ci-fix
- Verified: scripts/public-check.sh + gitleaks detect -> OK; just quick -> OK
- Notes for next session: other checks (rust/desktop/macos) were still running; tasks after 1.4 remain.
