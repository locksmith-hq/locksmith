# Tasks

## 1. Crypto core (`ls-crypto`)

- [x] 1.1 Spike the SQLCipher build on macOS and Linux musl without OpenSSL (design D5), and record the decision in design.md. Verify: `cargo build --target x86_64-unknown-linux-musl -p ls-vault` succeeds in CI.
- [x] 1.2 Implement the secret types (`SecretKey32`, `SecretBytes`) with zeroize, no Debug, a clippy lint, mlock best-effort and core-dump disable. Verify: a compile-fail test (`trybuild`) shows `format!("{:?}", key)` does not compile.
- [x] 1.3 Implement Argon2id derive, the HKDF labels and the AES-GCM seal/open with canonical AAD encoding (design D1, D3). Verify: known-answer tests against RFC 9106 / RFC 5869 vectors, plus an AAD-mismatch test.
- [x] 1.4 Implement the wrap types (passphrase, recovery) and the BIP-39 seed to RWK. Verify: BIP-39 official test vectors, plus a round-trip wrap/unwrap test.

## 2. Storage (`ls-vault`)

- [x] 2.1 Implement the `vault.header` CBOR format with HMAC and the SQLCipher open/create with migrations (`refinery` or embedded SQL). Verify: a test asserts header tamper detection and that the key name is absent in raw file bytes.
- [x] 2.2 Implement the schema (`projects`, `environments`, `secrets`, `secret_versions`, `meta`), the repository API and WAL-mode atomic writes. Verify: a kill-during-write test (fork, SIGKILL, reopen) passes 100 iterations.
- [x] 2.3 Add the permission enforcement and the forward migration with backup. Verify: the 0644 vault test exits 1, and the migration test leaves a backup file.

## 3. CLI (`smith-cli`)

- [x] 3.1 `smith vault init` (phrase display, 3-word confirmation), `passwd`, `recover`, `recovery rotate`. Verify: e2e tests using `--passphrase-stdin` and the `test-kdf` feature.
- [x] 3.2 `smith project|env add/ls/rm`, `smith add/ls/rm/history` with the value-ingress rules. Verify: e2e covers the arg-value rejection (exit 2) and stdin add.
- [x] 3.3 `smith reveal` with the agent detector and clipboard clear, and `smith export`. Verify: tests for non-TTY (exit 3), `CLAUDECODE=1` (exit 3), and the export file mode 0600.
- [x] 3.4 Add `smith import dotenv <file>` (moves `.env` values into the vault and offers to delete the file). Verify: an e2e import of a fixture `.env` with quotes, multiline and `export` prefixes.

## 4. Diagnostics and adversarial

- [x] 4.1 Register doctor checks `vault.present`, `vault.perms`, `vault.kdf_params` (warn below the minimum), `vault.wraps` (warns if no recovery wrap). Verify: doctor snapshot tests.
- [x] 4.2 Adversarial case `A0-offline`: copy the vault files and grep for canary names and values in any encoding. Verify: `tests/adversarial/run.sh A0-offline` passes.

## 5. Milestone acceptance

- [ ] 5.1 Dogfood: import a real project's `.env`, delete it, then restore the vault on a second machine from the phrase. Verify: the checklist in the PR is ticked by a second person.
