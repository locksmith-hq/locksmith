# Tasks: S6 adversarial gate 1

## 1. Oracle encodings [opus]
- [x] 1.1 Add base32, UTF-16LE, UTF-16BE, `\u` JSON escapes, HTML numeric entities, quoted-printable and gzip-wrapped forms, plus the reversed form and a separator-stripped form (the scanned text with whitespace and header framing removed, which finds a canary split across headers or one character per line), of the canary bytes and the canary text, to `tests/kit/oracle.py`, stdlib only; extend `selftest` with one planted hit per form and a clean-corpus check; output still never prints the canary.
- [x] 1.2 Verify: `bash tests/adversarial/run.sh selftest` and `bash tests/kit/leak_scan_test.sh` (with `just up`) pass.

## 2. Harness: gateway target and residual register [opus]
- [x] 2.1 `run.sh gateway [G<n>...]` runs `tests/adversarial/gateway/G*.sh` with the existing case contract; `all` stays unchanged. A shared `gateway/lib.sh` checks the stack (exit 77 with `skip: stack not running`), creates an org, a canary secret, a binding, an agent and a grant through the control plane, and logs the agent in with `smith`.
- [x] 2.2 `gateway/residuals.toml` (case, encoding, label, reason) and its handling in `run.sh`: unlisted hit is `FAIL`, listed hit is `RESIDUAL`, listed entry with no hit is `STALE RESIDUAL` and fails; `ADVERSARIAL_KEEP=1` keeps artifacts.
- [x] 2.3 Verify: `bash tests/adversarial/run.sh selftest` plus a harness self-check (a planted case that leaks an unlisted form fails, a listed form reports `RESIDUAL`, a stale entry fails); `ADVERSARIAL_REQUIRE_ALL=1 bash tests/adversarial/run.sh all` without the stack gives the same result as on `main`.

## 3. Scripted gateway cases [opus]
- [x] 3.1 `G1` environment and files: the agent environment, `/proc/<pid>/environ` and `cmdline` of `smith`, `locksmith-mcp` and the gateway, the `smith` state directory and shell history, after a login and a relay; enrollment secret also checked.
- [x] 3.2 `G2` reflection: a binding to `fixtures/http_upstream.py` as the provider; relay through `smith relay` and the MCP `relay_request` tool; every reflection mode, chunked byte by byte and a slow event stream; each refusal checked as a `redaction_failed` ledger event.
- [x] 3.3 `G3` header echo and request shaping: override, duplicate and re-cased injected header; `{secret}` in agent headers, path, query and body; CRLF in header values; Host and absolute-form tricks; 3xx to the attacker's host; an unbound host (decrypt counter unchanged). The attacker's host log goes to the artifacts.
- [x] 3.4 `G4` encodings: the fixture returns the secret as base32, UTF-16LE/BE, `\u` escapes, HTML entities, quoted-printable, unlabelled gzip, reversed, split across headers and one character per line; seed `residuals.toml` with the forms decision 4 leaves to containment.
- [x] 3.5 `G5` control-plane and ledger surfaces: every agent-reachable route from `openapi.json` with valid, malformed and cross-org inputs, the OpenAPI document, internal routes without the service token (401), request fields that reach audit event attributes, `GET /v1/audit/events` and the audit export directory.
- [ ] 3.6 `G6` token abuse: replay after grant revoke (after the cache TTL) and after expiry, a token for another org, a token at internal routes, a forged `kid`; each refused, no decrypt call; the revoke replay appends exactly one `relay.denied` ledger event and no `relay.attempt`, and the token failures append no ledger event (decision 10).
- [ ] 3.7 Verify: `just up && just api`, then `ADVERSARIAL_REQUIRE_ALL=1 bash tests/adversarial/run.sh gateway` reports only `PASS` (G4 may report `RESIDUAL` for registered forms).

## 4. Redactor hardening [opus]
- [ ] 4.1 `ls-redact`: add base32 (RFC 4648, padded and unpadded, upper and lower), UTF-16LE, UTF-16BE and `\u`-escaped forms to the matcher, with the same 8-byte minimum and streaming behaviour; unit tests per form, split across chunks.
- [ ] 4.2 Gateway relay uses the new forms for headers and body; a relay test per form.
- [ ] 4.3 Verify: `cargo nextest run -p ls-redact -p ls-gateway`, then `bash tests/adversarial/run.sh gateway G4` shows those forms no longer leak and no stale residual.

## 5. Fast tier in just ci [opus]
- [ ] 5.1 `services/gateway` adversarial test module: the G2 to G4 payloads against the in-process relay (fake KMS and material, wiremock provider and attacker host); writes what the caller received to a temp dir and runs `python3 -I tests/kit/oracle.py scan` on it; reads `residuals.toml` with the same rules; no Docker or network.
- [ ] 5.2 Verify: `cargo nextest run -p ls-gateway adversarial` passes, and fails when base64 redaction is disabled locally (record the check in progress.md, then revert it); `just ci` passes.

## 6. Stack gate and live mode [opus]
- [ ] 6.1 `just adversarial-gate [--agent claude]`: fails fast when the stack is down, starts the gateway, runs `run.sh gateway` with `ADVERSARIAL_REQUIRE_ALL=1`, then `just leak-scan` with `--dir` over the audit export and the kept artifacts.
- [ ] 6.2 Live prompts in `gateway/prompts/` (env, reflection, header echo, encodings, API, token), each run as headless `claude -p` limited to the Locksmith MCP tools and Bash, transcripts saved and scanned with `--transcript`.
- [ ] 6.3 `tests/adversarial/README.md` documents the G cases, the residual register, both tiers and a ready-to-paste nightly routine prompt; `docs/testing.md` lists `just adversarial-gate`.
- [ ] 6.4 Verify: `just up && just api && just adversarial-gate --agent claude` exits 0 with every transcript scanned (or, without a key, exits non-zero with `skip live`; record which in progress.md).

## 7. Console and desktop [sonnet]
- [ ] 7.1 Web audit page (S5): outcome filter for `denied` and `redaction_failed`.
- [ ] 7.2 Desktop audit view: the same filter.
- [ ] 7.3 Verify: `npm run lint`, `npm test --workspace apps/web`, and `just apps-build`.

## 8. Local verification
- [ ] 8.1 `just up`, `just api`, `just adversarial-gate`, `just leak-scan`, `just audit-verify`, `just apps-build`, then `just ci`.
